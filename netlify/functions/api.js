const express = require('express');
const serverless = require('serverless-http');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const AWS = require('aws-sdk');
const nodemailer = require('nodemailer'); 

const app = express();
const router = express.Router();

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// --- GMAIL SMTP CONFIGURATION ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // e.g., yourbrand@gmail.com
        pass: process.env.EMAIL_PASS  // your 16-character App Password
    }
});

// --- IDRIVE E2 / S3 CONFIGURATION ---
let s3 = null;
if (process.env.E2_ENDPOINT) {
    s3 = new AWS.S3({
        accessKeyId: process.env.E2_ACCESS_KEY,
        secretAccessKey: process.env.E2_SECRET_KEY,
        endpoint: new AWS.Endpoint(process.env.E2_ENDPOINT),
        region: process.env.E2_REGION,
        s3ForcePathStyle: true,
        signatureVersion: 'v4'
    });
}
const BUCKET_NAME = process.env.E2_BUCKET;

let cachedDb = null;
async function getDb() {
    if (cachedDb) return cachedDb;
    const client = new MongoClient(uri);
    await client.connect();
    cachedDb = client.db("themotundebrand");
    return cachedDb;
}

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Unauthorized: No token provided" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Forbidden: Invalid Token" });
        if (!decoded.isAdmin) return res.status(403).json({ error: "Forbidden: Not an Admin" });
        req.user = decoded;
        next();
    });
};

// --- DASHBOARD ANALYTICS ---
router.get('/admin/analytics/stock-overview', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const products = await db.collection("products").find({}).toArray();

        let womenTotalStock = 0;
        let menTotalStock = 0;
        let kidTotalStock = 0;
        let mistTotalStock = 0;

        products.forEach(product => {
            const totalProductUnits = (product.variants || []).reduce((sum, v) => sum + (parseInt(v.stock) || 0), 0);
            const category = (product.category || "").toLowerCase().trim();
            
            if (category === 'women') womenTotalStock += totalProductUnits;
            else if (category === 'men') menTotalStock += totalProductUnits;
            else if (category === 'kids') kidTotalStock += totalProductUnits;
            else if (category === 'mist') mistTotalStock += totalProductUnits;
        });

        res.json({ womenTotalStock, menTotalStock, kidTotalStock, mistTotalStock });
    } catch (e) {
        res.status(500).json({ error: "Failed to calculate stock totals" });
    }
});

// --- ADMIN REGISTRATION (Add this to your index.js) ---
router.post('/admin/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password } = req.body;

        // Check if an admin already exists (Optional security measure)
        const existingAdmin = await db.collection("admins").findOne({ email: email.toLowerCase() });
        if (existingAdmin) return res.status(400).json({ error: "Admin email already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newAdmin = {
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            isAdmin: true,
            createdAt: new Date()
        };

        await db.collection("admins").insertOne(newAdmin);
        res.status(201).json({ message: "Admin account created successfully" });
    } catch (e) {
        res.status(500).json({ error: "System enrollment failed" });
    }
});

// --- ADMIN LOGIN ---
router.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const db = await getDb();
        const admin = await db.collection("admins").findOne({ email });

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: admin._id.toString(), isAdmin: true }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        res.json({ token, isAdmin: true });
    } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

// USE THIS FOR THE DASHBOARD CARD
router.get('/admin/users/count', async (req, res) => {
    try {
        const db = await getDb();
        const count = await db.collection("users").countDocuments();
        res.json({ count });
    } catch (e) {
        res.status(500).json({ error: "Failed to count users" });
    }
});

// USE THIS FOR THE CUSTOMER CRM TABLE
router.get('/admin/users', async (req, res) => {
    try {
        const db = await getDb();
        const users = await db.collection("users")
            .find({})
            .project({ password: 0 }) // SECURITY: Never send passwords to the frontend
            .sort({ createdAt: -1 })  // Show newest members first
            .toArray();
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch users" });
    }
});

// --- FETCH ALL ORDERS (Admin Only) ---
router.get('/admin/orders', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const orders = await db.collection("orders")
            .find({})
            .sort({ createdAt: -1 })
            .toArray();
        res.json(orders);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

// --- PRODUCT MANAGEMENT (CREATE) ---
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured.");
        const db = await getDb();
        const { name, variants, description, category, subCategory, imageBase64, fileName, contentType } = req.body;

        if (!imageBase64 || !fileName) return res.status(400).json({ error: "Image required" });

        const buffer = Buffer.from(imageBase64, 'base64');
        const uploadKey = `${category}/${Date.now()}-${fileName.replace(/\s+/g, '-')}`;

        await s3.upload({
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType || 'image/jpeg'
        }).promise();

        const product = { 
            name, 
            variants: (variants || []).map(v => ({ size: String(v.size), price: parseFloat(v.price), stock: parseInt(v.stock) })),
            description, 
            category: (category || "unassigned").toLowerCase().trim(),
            subCategory: subCategory || "", 
            imageKey: uploadKey,
            createdAt: new Date() 
        };

        await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Product added" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PRODUCT MANAGEMENT (UPDATE) ---
router.put('/admin/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const productId = req.params.id;
        const { name, variants, description, category, subCategory, imageBase64, fileName } = req.body;

        const existing = await db.collection("products").findOne({ _id: new ObjectId(productId) });
        if (!existing) return res.status(404).json({ error: "Product not found" });

        let imageKey = existing.imageKey;
        if (imageBase64 && fileName) {
            imageKey = `${category}/${Date.now()}-${fileName.replace(/\s+/g, '-')}`;
            await s3.upload({ Bucket: BUCKET_NAME, Key: imageKey, Body: Buffer.from(imageBase64, 'base64') }).promise();
            if (existing.imageKey) await s3.deleteObject({ Bucket: BUCKET_NAME, Key: existing.imageKey }).promise();
        }

        await db.collection("products").updateOne(
            { _id: new ObjectId(productId) },
            { $set: { name, variants, description, category, subCategory, imageKey, updatedAt: new Date() } }
        );
        res.json({ message: "Updated successfully" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- [NEW] FETCH STOCK FOR SPECIFIC PRODUCT (Used by Shop/Cart) ---
router.get('/products/:id/stock', async (req, res) => {
    try {
        const db = await getDb();
        const product = await db.collection("products").findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { variants: 1 } }
        );
        if (!product) return res.status(404).json({ error: "Product not found" });
        res.json({ variants: product.variants || [] });
    } catch (e) { res.status(500).json({ error: "Stock fetch failed" }); }
});

router.post('/orders', async (req, res) => {
    try {
        const db = await getDb();
        const { 
            items, // Now expected to include 'image' URL from the frontend
            customerDetails, 
            totalPrice, 
            paymentMethod, 
            receiptBase64, 
            receiptFileName 
        } = req.body; 

        // 1. Identification Logic
        const authHeader = req.headers.authorization;
        let finalUserId = "GUEST";
        let userStatusLabel = "Guest";

        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.split(' ')[1];
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                finalUserId = new ObjectId(decoded.userId); 
                userStatusLabel = "Registered Member";
            } catch (err) {
                console.log("Token invalid, processing as Guest.");
            }
        }

        // 2. Validation
        if (!items || items.length === 0) return res.status(400).json({ error: "Empty cart" });
        if (!customerDetails?.email) return res.status(400).json({ error: "Email is required." });

        // 3. Atomic stock decrement
        const updateResults = await Promise.all(items.map(async (item) => {
            const qty = Math.abs(parseInt(item.quantity));
            const result = await db.collection("products").updateOne(
                { 
                    _id: new ObjectId(item.productId), 
                    "variants.size": item.size,
                    "variants.stock": { $gte: qty } 
                },
                { $inc: { "variants.$.stock": -qty } }
            );
            return { name: item.name, success: result.modifiedCount > 0 };
        }));

        const failed = updateResults.filter(r => !r.success);
        if (failed.length > 0) return res.status(400).json({ error: "Stock error", failed });

        // 4. Create Order Object
        const finalOrder = {
            userId: finalUserId,
            email: customerDetails.email.toLowerCase(),
            customerDetails,
            items, // Contains productId, name, size, quantity, price, AND image
            totalPrice,
            paymentMethod,
            status: 'pending',
            isGuest: finalUserId === "GUEST",
            createdAt: new Date()
        };

        const result = await db.collection("orders").insertOne(finalOrder);
        const orderId = result.insertedId;
        const shortId = orderId.toString().slice(-6).toUpperCase();

        // 5. Prepare Email HTML with Images
        const orderItemsHtml = items.map(item => `
            <tr>
                <td style="padding: 10px 0; border-bottom: 1px solid #eee;">
                    <img src="${item.image || 'https://i.imgur.com/CVKXV7R.png'}" width="50" height="70" style="object-fit: cover; border-radius: 4px; display: block; float: left; margin-right: 15px;" />
                    <div style="float: left;">
                        <p style="margin: 0; font-size: 13px; font-weight: bold; text-transform: uppercase;">${item.name}</p>
                        <p style="margin: 0; font-size: 11px; color: #666;">SIZE: ${item.size} | QTY: ${item.quantity}</p>
                    </div>
                </td>
                <td style="padding: 10px 0; border-bottom: 1px solid #eee; font-size: 13px; text-align: right; vertical-align: middle;">
                    ₦${(item.price * item.quantity).toLocaleString()}
                </td>
            </tr>
        `).join('');

        const emailPromises = [];

        // --- CUSTOMER EMAIL ---
        emailPromises.push(transporter.sendMail({
            from: `"The Motunde Brand" <${process.env.EMAIL_USER}>`,
            to: customerDetails.email,
            subject: `Order Confirmation | #${shortId}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #f0f0f0; padding: 40px; color: #000;">
                    <center><h1 style="letter-spacing: 5px; font-size: 20px;">THE MOTUNDE BRAND</h1></center>
                    <p style="font-size: 14px;">Hello ${customerDetails.name},</p>
                    <p style="font-size: 14px; color: #555;">We have received your order. Our team is currently verifying your payment. Here is your summary:</p>
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        ${orderItemsHtml}
                    </table>
                    <div style="text-align: right; font-weight: bold; font-size: 16px;">
                        TOTAL PAID: ₦${totalPrice.toLocaleString()}
                    </div>
                    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
                    <p style="font-size: 12px; color: #888; text-align: center;">Order ID: ${orderId} | Status: ${userStatusLabel}</p>
                </div>`
        }));

        // --- ADMIN EMAIL ---
        const adminAttachments = [];
        if (receiptBase64) {
            adminAttachments.push({
                filename: receiptFileName || 'receipt.jpg',
                content: receiptBase64.split("base64,")[1],
                encoding: 'base64'
            });
        }

        emailPromises.push(transporter.sendMail({
            from: `"TMB Orders" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_USER,
            subject: `🚨 NEW ORDER #${shortId} - ${userStatusLabel}`,
            attachments: adminAttachments,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 2px solid #000; padding: 20px;">
                    <h2 style="background: #000; color: #fff; padding: 15px; text-align: center; margin: 0;">NEW ${userStatusLabel.toUpperCase()} ORDER</h2>
                    <div style="padding: 20px; background: #fafafa;">
                        <p><strong>Customer:</strong> ${customerDetails.name}</p>
                        <p><strong>Phone/WhatsApp:</strong> ${customerDetails.whatsapp}</p>
                        <p><strong>Address:</strong> ${customerDetails.address}, ${customerDetails.city}, ${customerDetails.state}</p>
                    </div>
                    <table style="width: 100%; margin-top: 20px;">
                        ${orderItemsHtml}
                    </table>
                    <h3 style="text-align: right;">Revenue: ₦${totalPrice.toLocaleString()}</h3>
                    <div style="background: #fff5f5; padding: 15px; border: 1px solid #feb2b2; margin-top: 15px;">
                        <strong>Payment:</strong> ${paymentMethod.toUpperCase()}<br>
                        <strong>Receipt:</strong> ${receiptBase64 ? "See attachment" : "NO RECEIPT UPLOADED"}
                    </div>
                    <a href="https://wa.me/${customerDetails.whatsapp.replace(/\D/g,'')}" style="display: block; background: #25D366; color: white; text-align: center; padding: 15px; text-decoration: none; margin-top: 20px; font-weight: bold; border-radius: 5px;">CHAT WITH CUSTOMER</a>
                </div>`
        }));

        Promise.all(emailPromises).catch(err => console.error("Email Error:", err));

        res.status(201).json({ orderId, status: userStatusLabel });

    } catch (e) {
        console.error("Order Error:", e);
        res.status(500).json({ error: e.message });
    }
});

router.get('/orders/:id', async (req, res) => {
    try {
        const db = await getDb();
        const order = await db.collection("orders").findOne({ _id: new ObjectId(req.params.id) });
        if (!order) return res.status(404).json({ error: "Order not found" });
        res.json(order);
    } catch (e) {
        res.status(500).json({ error: "Error fetching order" });
    }
});

// --- PUBLIC COLLECTION FETCH ---
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const items = await db.collection("products").find({}).sort({ createdAt: -1 }).toArray();
        
        const processed = items.map(item => {
            if (s3 && item.imageKey) {
                item.imageUrl = s3.getSignedUrl('getObject', { Bucket: BUCKET_NAME, Key: item.imageKey, Expires: 86400 });
            }
            // Fallback for missing variants
            if (!item.variants || item.variants.length === 0) {
                item.variants = [{ size: "Standard", price: item.price || 0, stock: item.stock || 0 }];
            }
            return item;
        });

        res.json(processed);
    } catch (e) { res.status(500).json({ error: "Load failed" }); }
});

// --- USER REGISTRATION (UPDATED FOR OTP) ---
router.post('/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password, phone, whatsapp, address } = req.body;

        const existingUser = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: "Email already registered" });

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            phone,
            whatsapp,
            address,
            isVerified: false, // User is locked until verified
            otp: otp,
            createdAt: new Date(),
            isAdmin: false
        };

        await db.collection("users").insertOne(newUser);

        // Send Luxury-Branded Email
      const mailOptions = {
    from: `"The Motunde Brand" <${process.env.EMAIL_USER}>`,
    to: email,
    replyTo: process.env.EMAIL_USER,
    subject: 'Confirm Your Access | The Motunde Brand',
    priority: 'high',
    headers: {
        'List-Unsubscribe': `<mailto:${process.env.EMAIL_USER}?subject=unsubscribe>`,
        'X-Entity-Ref-ID': Date.now().toString()
    },
    html: `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                @media only screen and (max-width: 600px) {
                    .container { width: 100% !important; padding: 20px !important; }
                }
            </style>
        </head>
        <body style="margin: 0; padding: 0; background-color: #ffffff;">
            <div style="display: none; max-height: 0px; overflow: hidden;">
                Your activation code for The Motunde Brand is inside.
            </div>

            <div class="container" style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 500px; margin: auto; padding: 40px; color: #000000; border: 1px solid #f2f2f2;">
                
                <div style="text-align: center; margin-bottom: 30px;">
                    <img src="https://i.imgur.com/CVKXV7R.png" alt="The Motunde Brand" style="width: 60px; height: auto; margin-bottom: 10px;">
                    <h2 style="margin: 0; font-size: 16px; letter-spacing: 4px; text-transform: uppercase; font-weight: 300; color: #000;">The Motunde Brand</h2>
                </div>

                <div style="text-align: center; margin-bottom: 30px;">
                    <p style="font-size: 14px; line-height: 1.6; color: #444; margin-bottom: 30px;">
                        Welcome to The Motunde Brand. To finalize your account registration, please use the activation code below:
                    </p>
                    
                    <div style="background-color: #000000; padding: 20px; display: inline-block; border-radius: 2px;">
                        <span style="letter-spacing: 8px; font-size: 28px; font-weight: bold; color: #F7C8D0; font-family: monospace;">
                            ${otp}
                        </span>
                    </div>
                    
                    <p style="font-size: 12px; color: #888; margin-top: 30px; font-style: italic;">
                        This code is valid for a limited time. If you did not request this, please ignore this email.
                    </p>
                </div>

                <hr style="border: 0; border-top: 1px solid #eeeeee; margin: 40px 0;">

                <div style="text-align: center;">
                    <p style="font-size: 10px; color: #aaa; letter-spacing: 1px; text-transform: uppercase;">
                        &copy; ${new Date().getFullYear()} The Motunde Brand <br>
                        Excellence in every stitch.
                    </p>
                </div>
            </div>
        </body>
        </html>
    `
};

        await transporter.sendMail(mailOptions);
        res.status(201).json({ message: "OTP sent to email" });
    } catch (e) {
        res.status(500).json({ error: "Registration failed: " + e.message });
    }
});

// --- NEW: VERIFY OTP ROUTE ---
// --- UPDATED VERIFY OTP ROUTE (Returns full details) ---
router.post('/verify-otp', async (req, res) => {
    try {
        const db = await getDb();
        const { email, otp } = req.body;

        const user = await db.collection("users").findOne({ 
            email: email.toLowerCase(), 
            otp: otp 
        });

        if (!user) return res.status(400).json({ error: "Invalid or expired verification code" });

        await db.collection("users").updateOne(
            { _id: user._id },
            { $set: { isVerified: true }, $unset: { otp: "" } }
        );

        const token = jwt.sign(
            { id: user._id, email: user.email, isAdmin: user.isAdmin || false },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Remove sensitive password before sending to frontend
        const { password, ...userProfile } = user;
        userProfile.isVerified = true; 

        res.json({ token, user: userProfile, message: "Account activated" });
    } catch (e) {
        res.status(500).json({ error: "Verification failed" });
    }
});

// --- UPDATED USER LOGIN (Ensures full profile is sent) ---
router.post('/login', async (req, res) => {
    try {
        const db = await getDb();
        const { email, password } = req.body;

        const user = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ error: "Invalid email or password" });
        if (!user.isVerified) return res.status(403).json({ error: "Please verify your email first" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid email or password" });

        const token = jwt.sign(
            { id: user._id, email: user.email, isAdmin: user.isAdmin || false },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Include all details needed for Shipping & Contact sections
        const { password: _, ...userProfile } = user;

        res.json({ 
            token, 
            user: userProfile, // Contains name, email, phone, whatsapp, address
            message: "Login successful" 
        });
    } catch (e) {
        res.status(500).json({ error: "Login failed" });
    }
});

// --- GET LOGGED-IN USER'S ORDERS ---
router.get('/orders/my-orders', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const db = await getDb();
        
        // Find orders where the email matches the logged-in user's email
        // (This is why we added the top-level email field in the previous step!)
        const orders = await db.collection("orders")
            .find({ userId: new ObjectId(decoded.id) })
            .sort({ createdAt: -1 })
            .toArray();

        res.json(orders);
    } catch (e) {
        res.status(401).json({ error: "Invalid Session" });
    }
});
// --- 1. UPDATE USER PROFILE (Name, Phone, WhatsApp, Address) ---
router.put('/update', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Not logged in" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const db = await getDb();
        
        const { name, phone, whatsapp, address, city, state } = req.body;

        // Update the user document
        const result = await db.collection("users").updateOne(
            { _id: new ObjectId(decoded.id) },
            { 
                $set: { 
                    name, 
                    phone, 
                    whatsapp, 
                    address, 
                    city, 
                    state,
                    updatedAt: new Date() 
                } 
            }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });

        res.json({ message: "Profile updated successfully" });
    } catch (e) {
        res.status(401).json({ error: "Unauthorized access" });
    }
});

// --- 2. CHANGE PASSWORD ---
router.post('/change-password', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Not logged in" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { password } = req.body;

        if (!password || password.length < 6) {
            return res.status(400).json({ error: "Password must be at least 6 characters" });
        }

        const db = await getDb();
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.collection("users").updateOne(
            { _id: new ObjectId(decoded.id) },
            { $set: { password: hashedPassword } }
        );

        res.json({ message: "Password updated successfully" });
    } catch (e) {
        res.status(401).json({ error: "Session expired" });
    }
});

// --- 3. GET ORDER HISTORY ---
router.get('/my-orders', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Not logged in" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const db = await getDb();
        
        // Find orders where the customer email matches the user email
        // Or link via user ID if you store user_id in your orders collection
        const user = await db.collection("users").findOne({ _id: new ObjectId(decoded.id) });
        
        const orders = await db.collection("orders")
            .find({ email: user.email })
            .sort({ createdAt: -1 })
            .toArray();

        res.json(orders);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

app.use('/.netlify/functions/api', router);
app.use('/api', router);
module.exports.handler = serverless(app);