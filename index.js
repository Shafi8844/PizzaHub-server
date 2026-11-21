import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
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
const foodsCollection=db.collection("foods");
const menuCollection = db.collection("menu")


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

app.get('/menu',async (req,res)=>{
    try {
        const menuItems= menuCollection.find();
        const result = menuItems.toArray();
        res.send(result)
    }catch (error){
        console.error("Error fetching menu:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
})
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});