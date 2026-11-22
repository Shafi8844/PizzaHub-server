import express from "express";
import cors from "cors";
import {MongoClient, ObjectId} from "mongodb";
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 5050;


app.use(cors());
app.use(express.json());

const client = new MongoClient(process.env.MONGO_DB_URI);

export async function connectToDatabase() {
    try{
        await client.connect();
        console.log("Connected to MongoDB");
        return client
    }
    catch (error) {
        console.error("Error connecting to MongoDB:", error);
        
    }
}

const dbClient = await connectToDatabase();
const db = dbClient.db("pizzahub");
const pizzasCollection = db.collection("pizza");
const menuCollection = db.collection("menu")
const orders = db.collection("orders");


app.get("/", (req, res) => {
  res.send("Hello from the backend!");
});

app.get("/users", async (req, res) => {
  try {
    const usersCollection = db.collection("user");
    const users = await usersCollection.find().toArray();
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// menu related Api
app.post("/menu", async (req,res)=>{
    const item=req.body;
    const result= await menuCollection.insertOne(item);
    res.send(result);
})

app.get("/menu",async (req,res)=>{

    const query = {};
    const { category, location, name, search } = req.query;

    if (category && category !== "all") query.category = category;
    if (location && location !== "all") query.location = location;
    if (name) query.name = { $regex: name, $options: "i" };
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
      ];
    }
    if(req.query.vendorID){
        query.vendorID = req.query.vendorID;
    }
    const result = await menuCollection.find(query).toArray();
    res.send(result);
})

app.get("/menu/count",async (req,res)=>{
    const query ={};
    if(req.query.vendorId){
        query.vendorId = req.query.vendorId;
    }
    const result = await menuCollection.countDocuments(query);
    res.send({count:result});
})

app.get("/menu/:id", async (req,res)=>{
    const id = req.params.id;
    const query = {_id:new ObjectId(id)};
    const result = await menuCollection.findOne(query);
    res.send(result);
})

app.delete("/menu/:id",async (req,res)=>{
    const id = req.params.id;
    const query = {_id:new ObjectId(id)}
    const result= await menuCollection.deleteOne(query);
    res.send(result);
})

// Order Related Api's
app.post("/orders", async (req,res)=>{
    const order = req.body;
    const result = await orders.insertOne(order);
    res.send(result);
})

app.get("/orders",async (req,res)=>{

    const query ={};
    if(req.query.customerId){
        query.customerId = req.query.customerId;
    }
    const cursor = orders.find(query);
    const result = await cursor.toArray();
    res.send(result);
})

app.get("/orders/count",async (req,res)=>{
    const query ={};
    if(req.query.customerId){
        query.customerId = req.query.customerId;
    }
    const result = await orders.countDocuments(query);
    res.send({count:result});
})
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});