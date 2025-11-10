const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

// Multer for file upload (store as base64 or URL)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

// ==================== AUTH ROUTES ====================

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user exists
    db.query(
      "SELECT * FROM users WHERE username = ? OR email = ?",
      [username, email],
      async (err, results) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Database error", error: err });
        }
        if (results.length > 0) {
          return res
            .status(400)
            .json({ message: "Username or email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        db.query(
          "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
          [username, email, hashedPassword, "client"],
          (err, result) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "Failed to create user", error: err });
            }
            res.status(201).json({ message: "User created successfully" });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Login
app.post("/api/auth/login", (req, res) => {
  try {
    const { username, password } = req.body;

    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, results) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Database error", error: err });
        }
        if (results.length === 0) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const user = results[0];
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign(
          { id: user.id, username: user.username, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: "24h" }
        );

        res.json({
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
          },
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Get current user
app.get("/api/auth/me", authenticateToken, (req, res) => {
  db.query(
    "SELECT id, username, email, role FROM users WHERE id = ?",
    [req.user.id],
    (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }
      res.json(results[0]);
    }
  );
});

// ==================== PRODUCT ROUTES ====================

// Get all products (public)
app.get("/api/products", (req, res) => {
  db.query(
    "SELECT * FROM products ORDER BY created_at DESC",
    (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }
      res.json(results);
    }
  );
});

// Get single product (public)
app.get("/api/products/:id", (req, res) => {
  db.query(
    "SELECT * FROM products WHERE id = ?",
    [req.params.id],
    (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json(results[0]);
    }
  );
});

// Create product (admin only)
app.post("/api/products", authenticateToken, isAdmin, (req, res) => {
  const { name, description, image, price, stock } = req.body;

  db.query(
    "INSERT INTO products (name, description, image, price, stock) VALUES (?, ?, ?, ?, ?)",
    [name, description, image, price, stock],
    (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Failed to create product", error: err });
      }
      res
        .status(201)
        .json({ message: "Product created successfully", id: result.insertId });
    }
  );
});

// Update product (admin only)
app.put("/api/products/:id", authenticateToken, isAdmin, (req, res) => {
  const { name, description, image, price, stock } = req.body;

  db.query(
    "UPDATE products SET name = ?, description = ?, image = ?, price = ?, stock = ? WHERE id = ?",
    [name, description, image, price, stock, req.params.id],
    (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Failed to update product", error: err });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json({ message: "Product updated successfully" });
    }
  );
});

// Delete product (admin only)
app.delete("/api/products/:id", authenticateToken, isAdmin, (req, res) => {
  db.query(
    "DELETE FROM products WHERE id = ?",
    [req.params.id],
    (err, result) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Failed to delete product", error: err });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json({ message: "Product deleted successfully" });
    }
  );
});

// ==================== ORDER ROUTES ====================

// Create order (authenticated users)
app.post("/api/orders", authenticateToken, (req, res) => {
  const { items } = req.body; // items: [{ product_id, quantity }]

  // Calculate total and check stock
  const productIds = items.map((item) => item.product_id);

  db.query(
    "SELECT * FROM products WHERE id IN (?)",
    [productIds],
    (err, products) => {
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }

      let totalAmount = 0;
      const orderItems = [];

      for (const item of items) {
        const product = products.find((p) => p.id === item.product_id);
        if (!product) {
          return res
            .status(404)
            .json({ message: `Product ${item.product_id} not found` });
        }
        if (product.stock < item.quantity) {
          return res
            .status(400)
            .json({ message: `Insufficient stock for ${product.name}` });
        }
        totalAmount += product.price * item.quantity;
        orderItems.push({
          product_id: item.product_id,
          quantity: item.quantity,
          price: product.price,
        });
      }

      // Create order
      db.query(
        "INSERT INTO orders (user_id, total_amount) VALUES (?, ?)",
        [req.user.id, totalAmount],
        (err, result) => {
          if (err) {
            return res
              .status(500)
              .json({ message: "Failed to create order", error: err });
          }

          const orderId = result.insertId;

          // Insert order items and update stock
          const orderItemsValues = orderItems.map((item) => [
            orderId,
            item.product_id,
            item.quantity,
            item.price,
          ]);

          db.query(
            "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ?",
            [orderItemsValues],
            (err) => {
              if (err) {
                return res
                  .status(500)
                  .json({
                    message: "Failed to create order items",
                    error: err,
                  });
              }

              // Update stock
              for (const item of orderItems) {
                db.query("UPDATE products SET stock = stock - ? WHERE id = ?", [
                  item.quantity,
                  item.product_id,
                ]);
              }

              res
                .status(201)
                .json({ message: "Order created successfully", orderId });
            }
          );
        }
      );
    }
  );
});

// Get user orders
app.get("/api/orders", authenticateToken, (req, res) => {
  const query =
    req.user.role === "admin"
      ? "SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC"
      : "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC";

  const params = req.user.role === "admin" ? [] : [req.user.id];

  db.query(query, params, (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Database error", error: err });
    }
    res.json(results);
  });
});

// Get order details
app.get("/api/orders/:id", authenticateToken, (req, res) => {
  db.query(
    "SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
    [req.params.id],
    (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }
      res.json(results);
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
