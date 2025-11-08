// ติดตั้ง dependencies ก่อน:
// npm init -y
// npm install express mysql2 bcryptjs jsonwebtoken cors dotenv

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "Kon7076";

// Middleware
app.use(cors());
app.use(express.json());

// Database Configuration
const dbConfig = {
  host: process.env.DB_HOST || "sql12.freesqldatabase.com",
  user: process.env.DB_USER || "sql12806399",
  password: process.env.DB_PASSWORD || "pVMVdkg7U4",
  database: process.env.DB_NAME || "sql12806399",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

const pool = mysql.createPool(dbConfig);

// สร้างตารางในฐานข้อมูล (รันครั้งแรก)
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();

    //     // ตารางผู้ใช้
    //     await connection.query(`
    //       CREATE TABLE IF NOT EXISTS users (
    //         id INT AUTO_INCREMENT PRIMARY KEY,
    //         username VARCHAR(50) UNIQUE NOT NULL,
    //         email VARCHAR(100) UNIQUE NOT NULL,
    //         password VARCHAR(255) NOT NULL,
    //         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    //       )
    //     `);

    //     // ตารางสินค้า
    //     await connection.query(`
    //       CREATE TABLE IF NOT EXISTS products (
    //     id INT AUTO_INCREMENT PRIMARY KEY,
    //     name VARCHAR(100) NOT NULL,
    //     description TEXT,
    //     price DECIMAL(10,2) NOT NULL,
    //     stock INT DEFAULT 0,
    //     user_id INT,
    //     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    //     updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    //     FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    //   )
    //     `);

    connection.release();
    console.log("✅ Database tables initialized successfully");
  } catch (error) {
    console.error("❌ Error initializing database:", error);
  }
}

// Middleware: ตรวจสอบ JWT Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "ไม่พบ token การยืนยันตัวตน" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token ไม่ถูกต้อง" });
    }
    req.user = user;
    next();
  });
};

// ==================== ROUTES ====================

// Health Check
app.get("/", (req, res) => {
  res.json({ message: "API is running!", status: "OK" });
});

// 1. Register (สมัครสมาชิก)
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "กรุณากรอกข้อมูลให้ครบถ้วน" });
    }

    // ตรวจสอบว่า username หรือ email มีอยู่แล้วหรือไม่
    const [existing] = await pool.query(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [username, email]
    );

    if (existing.length > 0) {
      return res
        .status(400)
        .json({ message: "ชื่อผู้ใช้หรืออีเมลนี้ถูกใช้งานแล้ว" });
    }

    // เข้ารหัสรหัสผ่าน
    const hashedPassword = await bcrypt.hash(password, 10);

    // บันทึกข้อมูลผู้ใช้
    const [result] = await pool.query(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    res.status(201).json({
      message: "สมัครสมาชิกสำเร็จ",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการสมัครสมาชิก" });
  }
});

// 2. Login (เข้าสู่ระบบ)
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน" });
    }

    // ค้นหาผู้ใช้
    const [users] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (users.length === 0) {
      return res
        .status(401)
        .json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    const user = users[0];

    // ตรวจสอบรหัสผ่าน
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res
        .status(401)
        .json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    // สร้าง JWT Token
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "เข้าสู่ระบบสำเร็จ",
      token,
      userId: user.id,
      username: user.username,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเข้าสู่ระบบ" });
  }
});

// 3. GET All Products (ดูสินค้าทั้งหมด)
app.get("/api/products", authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.query(
      "SELECT * FROM products ORDER BY created_at DESC"
    );
    res.json(products);
  } catch (error) {
    console.error("Get products error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// 4. GET Product by ID (ดูสินค้าตาม ID)
app.get("/api/products/:id", authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.query("SELECT * FROM products WHERE id = ?", [
      req.params.id,
    ]);

    if (products.length === 0) {
      return res.status(404).json({ message: "ไม่พบสินค้านี้" });
    }

    res.json(products[0]);
  } catch (error) {
    console.error("Get product error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// 5. CREATE Product (เพิ่มสินค้าใหม่)
app.post("/api/products", authenticateToken, async (req, res) => {
  try {
    const { name, description, price, stock } = req.body;

    if (!name || !price) {
      return res.status(400).json({ message: "กรุณากรอกชื่อสินค้าและราคา" });
    }

    const [result] = await pool.query(
      "INSERT INTO products (name, description, price, stock, user_id) VALUES (?, ?, ?, ?, ?)",
      [name, description || "", price, stock || 0, req.user.id]
    );

    res.status(201).json({
      message: "เพิ่มสินค้าสำเร็จ",
      productId: result.insertId,
    });
  } catch (error) {
    console.error("Create product error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเพิ่มสินค้า" });
  }
});

// 6. UPDATE Product (แก้ไขสินค้า)
app.put("/api/products/:id", authenticateToken, async (req, res) => {
  try {
    const { name, description, price, stock } = req.body;
    const productId = req.params.id;

    // ตรวจสอบว่าสินค้ามีอยู่หรือไม่
    const [existing] = await pool.query(
      "SELECT id FROM products WHERE id = ?",
      [productId]
    );
    if (existing.length === 0) {
      return res.status(404).json({ message: "ไม่พบสินค้านี้" });
    }

    await pool.query(
      "UPDATE products SET name = ?, description = ?, price = ?, stock = ? WHERE id = ?",
      [name, description, price, stock, productId]
    );

    res.json({ message: "แก้ไขสินค้าสำเร็จ" });
  } catch (error) {
    console.error("Update product error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการแก้ไขสินค้า" });
  }
});

// 7. DELETE Product (ลบสินค้า)
app.delete("/api/products/:id", authenticateToken, async (req, res) => {
  try {
    const productId = req.params.id;

    const [result] = await pool.query("DELETE FROM products WHERE id = ?", [
      productId,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "ไม่พบสินค้านี้" });
    }

    res.json({ message: "ลบสินค้าสำเร็จ" });
  } catch (error) {
    console.error("Delete product error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการลบสินค้า" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server is running on Port ${PORT}`);
  await initializeDatabase();
});

module.exports = app;
