import express from "express";
import cors from "cors";
import { createHmac, timingSafeEqual } from "node:crypto";
import {MongoClient, ObjectId} from "mongodb";
import 'dotenv/config';
import {Stripe} from "stripe";

if (!process.env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is required");
if (!process.env.MONGO_DB_URI) throw new Error("MONGO_DB_URI is required");
if (!process.env.BETTER_AUTH_SECRET) throw new Error("BETTER_AUTH_SECRET is required");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)

const app = express();
const PORT = process.env.PORT || 5050;


const allowedOrigins = (process.env.CORS_ORIGINS || "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
app.use(cors({ origin: allowedOrigins, credentials: true }));

const client = new MongoClient(process.env.MONGO_DB_URI);

export async function connectToDatabase() {
    try{
        await client.connect();
        console.log("Connected to MongoDB");
        return client
    }
    catch (error) {
        console.error("Error connecting to MongoDB:", error);
        throw error;
    }
}

const dbClient = await connectToDatabase();
const db = dbClient.db("pizzahub");
const users = db.collection("user");
const menuCollection = db.collection("menu");
const orders = db.collection("orders");
const transactions = db.collection("transactions");

function userIdQuery(id) {
    return typeof id === "string" && /^[a-f\d]{24}$/i.test(id)
        ? { _id: new ObjectId(id) }
        : { id };
}

function userIdsQuery(ids) {
    const objectIds = ids.filter((id) => /^[a-f\d]{24}$/i.test(id)).map((id) => new ObjectId(id));
    const legacyIds = ids.filter((id) => !/^[a-f\d]{24}$/i.test(id));
    const clauses = [];
    if (objectIds.length) clauses.push({ _id: { $in: objectIds } });
    if (legacyIds.length) clauses.push({ id: { $in: legacyIds } });
    return clauses.length === 1 ? clauses[0] : { $or: clauses };
}

function mapUsersById(profiles) {
    const byId = new Map();
    for (const profile of profiles) {
        if (profile._id) byId.set(profile._id.toString(), profile);
        if (profile.id) byId.set(profile.id, profile);
    }
    return byId;
}

app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
    const signature = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret || !signature) {
        return res.status(400).send("Missing Stripe webhook configuration or signature");
    }

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
    } catch (error) {
        console.error("Stripe webhook signature verification failed:", error.message);
        return res.status(400).send("Invalid Stripe webhook signature");
    }

    try {
        if (event.type === "checkout.session.completed") {
            const session = event.data.object;
            if (session.mode !== "subscription") {
                return res.send({ received: true });
            }

            const userId = session.metadata?.userId || session.client_reference_id;
            const subscriptionId = session.subscription;
            if (!userId || typeof subscriptionId !== "string") {
                console.error("Subscription checkout is missing its vendor or subscription ID", session.id);
                return res.status(400).send("Missing subscription metadata");
            }

            const subscription = await stripe.subscriptions.retrieve(subscriptionId);
            const isActive = subscription.status === "active" || subscription.status === "trialing";
            if (isActive) {
                const expiresAt = new Date(subscription.current_period_end * 1000);
                await users.updateOne(
                    userIdQuery(userId),
                    { $set: { premium: true, subscriptionPlan: "premium", subscriptionExpiresAt: expiresAt, stripeSubscriptionId: subscription.id } }
                );
            }

            await transactions.updateOne(
                { stripeSessionId: session.id },
                {
                    $setOnInsert: {
                        vendorId: userId,
                        plan: "premium",
                        amount: session.amount_total ? session.amount_total / 100 : 19,
                        currency: session.currency || "usd",
                        stripeSessionId: session.id,
                        stripeSubscriptionId: subscription.id,
                        status: isActive ? "paid" : subscription.status,
                        createdAt: new Date(),
                    },
                },
                { upsert: true }
            );
        }

        if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
            const subscription = event.data.object;
            const userId = subscription.metadata?.userId;
            if (userId) {
                const isActive = subscription.status === "active" || subscription.status === "trialing";
                await users.updateOne(
                    userIdQuery(userId),
                    {
                        $set: {
                            premium: isActive,
                            subscriptionPlan: isActive ? "premium" : "free",
                            subscriptionExpiresAt: isActive ? new Date(subscription.current_period_end * 1000) : null,
                            stripeSubscriptionId: subscription.id,
                        },
                    }
                );
            }
        }

        return res.send({ received: true });
    } catch (error) {
        console.error("Stripe webhook handler failed:", error);
        return res.status(500).send("Webhook processing failed");
    }
});

app.use(express.json());

function unauthorized(res, message = "Authentication required") {
    return res.status(401).send({ error: message });
}

function forbidden(res, message = "You do not have permission to do that") {
    return res.status(403).send({ error: message });
}

function hasRole(user, ...roles) {
    return Boolean(user && roles.includes(user.role));
}

function hasActivePremium(user) {
    const expiresAt = user?.subscriptionExpiresAt ? new Date(user.subscriptionExpiresAt).getTime() : 0;
    return user?.subscriptionPlan === "premium" && Number.isFinite(expiresAt) && expiresAt > Date.now();
}

async function authenticateOptional(req, res, next) {
    const authorization = req.headers.authorization;
    if (!authorization) {
        req.user = null;
        return next();
    }

    const [scheme, token] = authorization.split(" ");
    if (scheme !== "Bearer" || !token) return unauthorized(res, "Invalid bearer token");

    try {
        const parts = token.split(".");
        if (parts.length !== 3) return unauthorized(res, "Invalid bearer token");
        const [headerPart, payloadPart, signaturePart] = parts;
        const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
        const claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
        if (header.alg !== "HS256" || header.typ !== "JWT") return unauthorized(res, "Invalid bearer token");

        const expected = createHmac("sha256", process.env.BETTER_AUTH_SECRET)
            .update(`${headerPart}.${payloadPart}`)
            .digest();
        const received = Buffer.from(signaturePart, "base64url");
        if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
            return unauthorized(res, "Invalid bearer token");
        }
        const now = Math.floor(Date.now() / 1000);
        if (claims.iss !== "pizzahub-client" || claims.aud !== "pizzahub-api" ||
            typeof claims.sub !== "string" || !Number.isInteger(claims.iat) ||
            !Number.isInteger(claims.exp) || claims.iat > now || claims.exp <= now || claims.exp > claims.iat + 300) {
            return unauthorized(res, "Expired or invalid bearer token");
        }

        const user = await users.findOne(
            userIdQuery(claims.sub),
            { projection: { id: 1, name: 1, email: 1, role: 1, blocked: 1, banned: 1, subscriptionPlan: 1, subscriptionExpiresAt: 1 } }
        );
        if (!user) return unauthorized(res, "Account no longer exists");
        if (user.blocked || user.banned) return forbidden(res, "This account is blocked");
        req.user = user;
        return next();
    } catch {
        return unauthorized(res, "Invalid bearer token");
    }
}

app.use(["/menu", "/orders", "/users", "/transactions"], authenticateOptional);


app.get("/", (req, res) => {
  res.send("Hello from the backend!");
});

app.get("/users", async (req, res) => {
  try {
    if (!hasRole(req.user, "admin")) return req.user ? forbidden(res) : unauthorized(res);
    const query = {};
    const { role, search } = req.query;
    if (role && role !== "all") query.role = role;
    if (search) {
      const safeSearch = String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      query.$or = [
        { name: { $regex: safeSearch, $options: "i" } },
        { email: { $regex: safeSearch, $options: "i" } },
      ];
    }
    const result = await users.find(query, {
      projection: { id: 1, name: 1, email: 1, image: 1, role: 1, blocked: 1, premium: 1, subscriptionPlan: 1, createdAt: 1 },
    }).toArray();
    res.json(result);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.patch("/users/:id", async (req, res) => {
  try {
    if (!hasRole(req.user, "admin")) return req.user ? forbidden(res) : unauthorized(res);
    const id = req.params.id;
    if (id === req.user.id) return forbidden(res, "You cannot change your own admin account");
    const updates = {};
    if (typeof req.body.blocked === "boolean") updates.blocked = req.body.blocked;
    if (typeof req.body.role === "string") {
      if (!["customer", "vendor", "admin"].includes(req.body.role)) {
        return res.status(400).send({ error: "Invalid account role" });
      }
      updates.role = req.body.role;
    }
    if (!Object.keys(updates).length) return res.status(400).send({ error: "No valid user changes provided" });
    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { id };
    const result = await users.updateOne(query, { $set: updates });
    if (!result.matchedCount) return res.status(404).send({ error: "User not found" });
    res.send(result);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/transactions", async (req, res) => {
  try {
    if (!hasRole(req.user, "admin")) return req.user ? forbidden(res) : unauthorized(res);
    const result = await transactions.find({}).sort({ createdAt: -1 }).toArray();
    const vendorIds = [...new Set(result.map((transaction) => transaction.vendorId).filter(Boolean))];
    const vendorProfiles = vendorIds.length
      ? await users.find(userIdsQuery(vendorIds), { projection: { id: 1, name: 1, businessName: 1, email: 1 } }).toArray()
      : [];
    const vendorsById = mapUsersById(vendorProfiles);
    return res.send(result.map((transaction) => ({
      ...transaction,
      vendorName: vendorsById.get(transaction.vendorId)?.businessName || vendorsById.get(transaction.vendorId)?.name || "Vendor account",
      vendorEmail: vendorsById.get(transaction.vendorId)?.email || "",
    })));
  } catch (error) {
    console.error("Error fetching transactions:", error);
    return res.status(500).send({ error: "Unable to fetch transactions" });
  }
});

// menu related Api
app.post("/menu", async (req, res) => {
  try {
    if (!hasRole(req.user, "vendor")) return req.user ? forbidden(res) : unauthorized(res);
    const { itemName, category, description, price, location, images } = req.body;
    if (typeof itemName !== "string" || !itemName.trim() ||
        typeof category !== "string" || !category.trim() ||
        typeof description !== "string" || !description.trim() ||
        typeof location !== "string" || !location.trim() ||
        !Number.isFinite(Number(price)) || Number(price) <= 0 ||
        !Array.isArray(images) || images.length === 0 ||
        images.some((image) => typeof image !== "string" || !/^https:\/\//i.test(image))) {
      return res.status(400).send({ error: "Provide a name, category, description, positive price, location, and image URL" });
    }

    const isPremium = hasActivePremium(req.user);
    const activeCount = await menuCollection.countDocuments({ vendorId: req.user.id, status: "approved" });
    if (!isPremium && activeCount >= 3) {
      return res.status(403).send({ error: "Free vendors can publish up to 3 menu items. Upgrade to Premium for more." });
    }

    const result = await menuCollection.insertOne({
      vendorId: req.user.id,
      itemName: itemName.trim(),
      category: category.trim(),
      description: description.trim(),
      price: Number(price),
      location: location.trim(),
      images,
      status: "pending",
      createdAt: new Date().toISOString(),
    });
    return res.send(result);
  } catch (error) {
    console.error("Error creating menu item:", error);
    return res.status(500).send({ error: "Unable to create menu item" });
  }
});

app.get("/menu", async (req, res) => {
  const query = {};
  const { category, location, name, search, status, vendorId, vendorID, sort } = req.query;

  if (category && category !== "all") query.category = category;
  if (location && location !== "all") query.location = location;
  if (hasRole(req.user, "admin")) {
    if (status && status !== "all") query.status = status;
    const vid = vendorId || vendorID;
    if (vid) query.vendorId = vid;
  } else if (hasRole(req.user, "vendor")) {
    query.vendorId = req.user.id;
    if (status && status !== "all") query.status = status;
  } else {
    query.status = "approved";
  }

  const text = String(search || name || "").trim();
  if (text) {
    const safeText = text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    query.$or = [
      { itemName: { $regex: safeText, $options: "i" } },
      { name: { $regex: safeText, $options: "i" } },
      { description: { $regex: safeText, $options: "i" } },
      { category: { $regex: safeText, $options: "i" } },
      { location: { $regex: safeText, $options: "i" } },
    ];
  }

  const sortOrder = sort === "price-asc"
    ? { price: 1 }
    : sort === "price-desc"
      ? { price: -1 }
      : { createdAt: -1 };
  try {
    const result = await menuCollection.find(query).sort(sortOrder).toArray();
    const vendorIds = [...new Set(result.map((item) => item.vendorId).filter(Boolean))];
    const vendorProfiles = vendorIds.length
      ? await users.find(
          userIdsQuery(vendorIds),
          { projection: { id: 1, name: 1, businessName: 1 } }
        ).toArray()
      : [];
    const vendorsById = mapUsersById(vendorProfiles);
    return res.send(result.map((item) => ({
      ...item,
      vendorName: vendorsById.get(item.vendorId)?.businessName || vendorsById.get(item.vendorId)?.name || "Local restaurant",
    })));
  } catch (error) {
    console.error("Error fetching menu items:", error);
    return res.status(500).send({ error: "Unable to fetch menu items" });
  }
});

app.get("/menu/count", async (req, res) => {
  const query = {};
  const { vendorId, vendorID, status } = req.query;
  if (hasRole(req.user, "admin")) {
    const vid = vendorId || vendorID;
    if (vid) query.vendorId = vid;
    if (status && status !== "all") query.status = status;
  } else if (hasRole(req.user, "vendor")) {
    query.vendorId = req.user.id;
    if (status && status !== "all") query.status = status;
  } else {
    query.status = "approved";
  }
  const result = await menuCollection.countDocuments(query);
  res.send({ count: result });
});

app.get("/menu/:id", async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid menu item ID" });
  const query = { _id: new ObjectId(id) };
  const result = await menuCollection.findOne(query);
  if (!result) return res.status(404).send({ error: "Menu item not found" });
  if (hasRole(req.user, "admin")) return res.send(result);
  if (hasRole(req.user, "vendor") && result.vendorId === req.user.id) return res.send(result);
  if (result.status !== "approved") return res.status(404).send({ error: "Menu item not found" });
  return res.send(result);
});

app.patch("/menu/:id", async (req, res) => {
  try {
    if (!hasRole(req.user, "admin", "vendor")) return req.user ? forbidden(res) : unauthorized(res);
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid menu item ID" });
    const item = await menuCollection.findOne({ _id: new ObjectId(id) });
    if (!item) return res.status(404).send({ error: "Menu item not found" });
    const isAdmin = hasRole(req.user, "admin");
    if (!isAdmin && item.vendorId !== req.user.id) return forbidden(res);

    const allowedFields = isAdmin
      ? ["itemName", "category", "description", "price", "location", "images", "status"]
      : ["itemName", "category", "description", "price", "location", "images", "status"];
    const updates = Object.fromEntries(Object.entries(req.body).filter(([key]) => allowedFields.includes(key)));
    delete updates._id;
    delete updates.vendorId;
    for (const key of ["itemName", "category", "description", "location"]) {
      if (key in updates && (typeof updates[key] !== "string" || !updates[key].trim())) {
        return res.status(400).send({ error: `${key} must be a non-empty string` });
      }
      if (typeof updates[key] === "string") updates[key] = updates[key].trim();
    }
    if ("price" in updates && (!Number.isFinite(Number(updates.price)) || Number(updates.price) <= 0)) {
      return res.status(400).send({ error: "Price must be greater than zero" });
    }
    if ("price" in updates) updates.price = Number(updates.price);
    if ("images" in updates && (!Array.isArray(updates.images) || updates.images.length === 0 ||
      updates.images.some((image) => typeof image !== "string" || !/^https:\/\//i.test(image)))) {
      return res.status(400).send({ error: "At least one valid image URL is required" });
    }
    if (updates.status && !isAdmin && updates.status !== "inactive") {
      return forbidden(res, "Vendors cannot approve or publish menu items");
    }
    if (updates.status && !["pending", "approved", "rejected", "inactive"].includes(updates.status)) {
      return res.status(400).send({ error: "Invalid menu item status" });
    }
    if (isAdmin && updates.status === "approved" && item.status !== "approved") {
      const vendor = await users.findOne(userIdQuery(item.vendorId), { projection: { subscriptionPlan: 1, subscriptionExpiresAt: 1 } });
      const isPremium = hasActivePremium(vendor);
      const approvedCount = await menuCollection.countDocuments({ vendorId: item.vendorId, status: "approved" });
      if (!isPremium && approvedCount >= 3) {
        return res.status(409).send({ error: "This vendor has reached the 3-item Free plan limit" });
      }
    }
    if (!Object.keys(updates).length) return res.status(400).send({ error: "No valid menu item changes provided" });
    const result = await menuCollection.updateOne({ _id: new ObjectId(id) }, { $set: updates });
    return res.send(result);
  } catch (error) {
    console.error("Error updating menu item:", error);
    return res.status(500).send({ error: "Unable to update menu item" });
  }
});

app.delete("/menu/:id", async (req, res) => {
  if (!hasRole(req.user, "admin", "vendor")) return req.user ? forbidden(res) : unauthorized(res);
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid menu item ID" });
  const item = await menuCollection.findOne({ _id: new ObjectId(id) });
  if (!item) return res.status(404).send({ error: "Menu item not found" });
  if (!hasRole(req.user, "admin") && item.vendorId !== req.user.id) return forbidden(res);
  const query = { _id: new ObjectId(id) };
  const result = await menuCollection.deleteOne(query);
  res.send(result);
});

// Order Related Api's
app.post("/orders", async (req, res) => {
  try {
    if (!hasRole(req.user, "customer")) return req.user ? forbidden(res, "Only customers can place orders") : unauthorized(res);
    const { menuItemId, quantity = 1, deliveryAddress, deliveryDate, note = "" } = req.body;
    if (typeof menuItemId !== "string" || !ObjectId.isValid(menuItemId) ||
        typeof deliveryAddress !== "string" || deliveryAddress.trim().length < 8 ||
        typeof deliveryDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(deliveryDate)) {
      return res.status(400).send({ error: "Provide a valid item, delivery date, and address" });
    }
    const requestedDate = new Date(`${deliveryDate}T00:00:00.000Z`);
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    if (Number.isNaN(requestedDate.getTime()) || requestedDate.toISOString().slice(0, 10) !== deliveryDate || requestedDate < today) {
      return res.status(400).send({ error: "Delivery date must be today or later" });
    }
    const safeQuantity = Number(quantity);
    if (!Number.isInteger(safeQuantity) || safeQuantity < 1 || safeQuantity > 20) {
      return res.status(400).send({ error: "Quantity must be between 1 and 20" });
    }

    const item = await menuCollection.findOne({ _id: new ObjectId(menuItemId), status: "approved" });
    if (!item) return res.status(404).send({ error: "This menu item is unavailable" });
    if (item.vendorId === req.user.id) return forbidden(res, "You cannot order your own menu item");

    const duplicate = await orders.findOne({
      customerId: req.user.id,
      menuItemId: item._id.toString(),
      deliveryDate,
      status: { $in: ["pending", "accepted"] },
    });
    if (duplicate) return res.status(409).send({ error: "You already have an active order for this item and date" });

    const payload = {
      menuItemId: item._id.toString(),
      vendorId: item.vendorId,
      itemName: item.itemName,
      itemImage: item.images?.[0] || "",
      unitPrice: Number(item.price),
      quantity: safeQuantity,
      totalPrice: Number(item.price) * safeQuantity,
      customerId: req.user.id,
      customerName: req.user.name,
      customerEmail: req.user.email,
      deliveryAddress: deliveryAddress.trim(),
      phone: typeof req.body.phone === "string" ? req.body.phone.trim().slice(0, 40) : "",
      deliveryDate,
      note: typeof note === "string" ? note.trim().slice(0, 1000) : "",
      status: "pending",
      createdAt: new Date().toISOString(),
    };
    const result = await orders.insertOne(payload);
    return res.send(result);
  } catch (error) {
    console.error("Error creating order:", error);
    return res.status(500).send({ error: "Unable to place order" });
  }
});

app.get("/orders", async (req, res) => {
  const query = {};
  const { customerId, vendorId, status } = req.query;
  if (hasRole(req.user, "admin")) {
    if (customerId) query.customerId = customerId;
    if (vendorId) query.vendorId = vendorId;
  } else if (hasRole(req.user, "vendor")) {
    query.vendorId = req.user.id;
  } else if (hasRole(req.user, "customer")) {
    query.customerId = req.user.id;
  } else {
    return req.user ? forbidden(res) : unauthorized(res);
  }
  if (status && status !== "all") query.status = status;
  try {
    const result = await orders.find(query).sort({ createdAt: -1 }).toArray();
    return res.send(result);
  } catch (error) {
    console.error("Error fetching orders:", error);
    return res.status(500).send({ error: "Unable to fetch orders" });
  }
});

app.get("/orders/count", async (req, res) => {
  const query = {};
  const { customerId, vendorId, status } = req.query;
  if (hasRole(req.user, "admin")) {
    if (customerId) query.customerId = customerId;
    if (vendorId) query.vendorId = vendorId;
  } else if (hasRole(req.user, "vendor")) {
    query.vendorId = req.user.id;
  } else if (hasRole(req.user, "customer")) {
    query.customerId = req.user.id;
  } else {
    return req.user ? forbidden(res) : unauthorized(res);
  }
  if (status && status !== "all") query.status = status;
  const result = await orders.countDocuments(query);
  res.send({ count: result });
});

app.patch("/orders/:id", async (req, res) => {
  try {
    if (!req.user) return unauthorized(res);
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).send({ error: "Invalid order ID" });
    if (Object.keys(req.body).some((key) => key !== "status")) {
      return res.status(400).send({ error: "Only order status can be changed" });
    }
    const nextStatus = req.body.status;
    if (!["accepted", "rejected", "cancelled"].includes(nextStatus)) {
      return res.status(400).send({ error: "Invalid order status" });
    }
    const existing = await orders.findOne({ _id: new ObjectId(id) });
    if (!existing) return res.status(404).send({ error: "Order not found" });

    const vendorAction = nextStatus === "accepted" || nextStatus === "rejected";
    const customerAction = nextStatus === "cancelled";
    if (vendorAction && (!hasRole(req.user, "vendor") || existing.vendorId !== req.user.id)) return forbidden(res);
    if (customerAction && (!hasRole(req.user, "customer") || existing.customerId !== req.user.id)) return forbidden(res);
    if (existing.status !== "pending") {
      return res.status(409).send({ error: "Only pending orders can be changed" });
    }

    const result = await orders.updateOne(
      { _id: new ObjectId(id), status: "pending" },
      { $set: { status: nextStatus, updatedAt: new Date().toISOString() } }
    );
    if (!result.modifiedCount) return res.status(409).send({ error: "Order status has already changed" });
    return res.send(result);
  } catch (error) {
    console.error("Error updating order:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
