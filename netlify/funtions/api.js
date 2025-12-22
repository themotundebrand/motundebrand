const express = require('express');
const serverless = require('serverless-http');
const { MongoClient } = require('mongodb');

const app = express();
const router = express.Router();

// Middleware
app.use(express.json());

// Database Connection Caching
const uri = process.env.MONGODB_URI;
let cachedClient = null;

async function getDb() {
  if (!cachedClient) {
    const client = new MongoClient(uri);
    await client.connect();
    cachedClient = client;
  }
  return cachedClient.db("themotundebrand");
}

// --- ROUTES ---

// 1. GET ALL PRODUCTS
router.get('/products', async (req, res) => {
  try {
    const db = await getDb();
    const perfumes = await db.collection("products").find({}).toArray();
    res.status(200).json(perfumes);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// 2. GET FEATURED PRODUCTS (For Landing Page)
router.get('/featured', async (req, res) => {
  try {
    const db = await getDb();
    const featured = await db.collection("products").find({ featured: true }).limit(3).toArray();
    res.status(200).json(featured);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch featured products" });
  }
});

// 3. POST AN ORDER
router.post('/orders', async (req, res) => {
  try {
    const db = await getDb();
    const orderData = req.body;
    orderData.createdAt = new Date();
    
    const result = await db.collection("orders").insertOne(orderData);
    res.status(201).json({ message: "Order placed successfully", id: result.insertedId });
  } catch (error) {
    res.status(500).json({ error: "Order failed" });
  }
});

// Netlify Function Path Compatibility
app.use('/.netlify/functions/api', router);
app.use('/api', router);

module.exports.handler = serverless(app);