// ===============================
// 1️⃣ Import required libraries
// ===============================
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// ===============================
// 2️⃣ Create Express app
// ===============================
const app = express();

// ===============================
// 3️⃣ Middleware
// ===============================
app.use(express.json());

// ===============================
// 4️⃣ In-memory user store (TEMP)
// ===============================
const users = [];

// ===============================
// 5️⃣ JWT Secret (TEMP – will move to env later)
// ===============================
const JWT_SECRET = "supersecretkey";

// ===============================
// 6️⃣ Health Check (Monitoring)
// ===============================
app.get("/health", (req, res) => {
    res.json({ status: "ok" });
});

// ===============================
// 7️⃣ SIGNUP API (WRITE PATH)
// ===============================
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        return res.status(400).json({
            error: "Email and password required",
        });
    }

    // Duplicate check (read-before-write)
    const existingUser = users.find((u) => u.email === email);
    if (existingUser) {
        return res.status(409).json({
            error: "User already exists",
        });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user
    users.push({
        email,
        password: hashedPassword,
    });

    res.json({
        message: "User signed up successfully",
    });
});

// ===============================
// 8️⃣ LOGIN API (READ PATH)
// ===============================
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        return res.status(400).json({
            error: "Email and password required",
        });
    }

    // Find user
    const user = users.find((u) => u.email === email);
    if (!user) {
        return res.status(401).json({
            error: "Invalid email or password",
        });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({
            error: "Invalid email or password",
        });
    }

    // Generate JWT
    const token = jwt.sign(
        { email: user.email },
        JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.json({
        message: "Login successful",
        token,
    });
});

// ===============================
// 9️⃣ AUTH MIDDLEWARE (JWT)
// ===============================
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            error: "Token missing",
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // attach user info to request
        next();
    } catch (err) {
        return res.status(401).json({
            error: "Invalid or expired token",
        });
    }
}

// ===============================
// 🔟 PROTECTED ROUTE
// ===============================
app.get("/profile", authMiddleware, (req, res) => {
    res.json({
        message: "Welcome to your profile",
        user: req.user,
    });
});

// ===============================
// 1️⃣1️⃣ Start Server (ALWAYS LAST)
// ===============================
app.listen(3000, () => {
    console.log("Server running on port 3000");
});
