const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ---------------- UPLOADS ---------------- */
const uploadsPath = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
}
app.use("/uploads", express.static(uploadsPath));

/* ---------------- ENV ---------------- */
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";

/* ---------------- DB CONNECTION (FIXED) ---------------- */
const db = mysql.createConnection(process.env.MYSQL_PUBLIC_URL);

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL connection error:", err);
  } else {
    console.log("✅ MySQL Connected");
  }
});

/* ---------------- MULTER ---------------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsPath),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/\s+/g, "_");
    cb(null, Date.now() + "-" + safeName);
  }
});
const upload = multer({ storage });

/* ---------------- JWT ---------------- */
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Token missing" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ---------------- ROOT ---------------- */
app.get("/", (req, res) => {
  res.send("Civil Club back-end running 🚀");
});

/* ---------------- ADMIN LOGIN ---------------- */
app.post("/admin-login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  db.query(
    "SELECT * FROM admins WHERE username = ? LIMIT 1",
    [username],
    async (err, results) => {
      if (err) {
        console.error("Admin login DB error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "Admin not found" });
      }

      const admin = results[0];

      try {
        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
          return res.status(401).json({ message: "Wrong password" });
        }

        const token = jwt.sign(
          {
            id: admin.id,
            username: admin.username,
            role: "admin"
          },
          JWT_SECRET,
          { expiresIn: "1d" }
        );

        return res.json({
          message: "Login success",
          token,
          username: admin.username
        });
      } catch (compareErr) {
        console.error("Password compare error:", compareErr);
        return res.status(500).json({ message: "Server error" });
      }
    }
  );
});

/* ---------------- NOTICES ---------------- */
app.get("/notices", (req, res) => {
  db.query("SELECT * FROM notices ORDER BY id DESC", (err, results) => {
    if (err) return res.status(500).json({ message: "Server error" });
    res.json(results);
  });
});

app.post("/add-notice", verifyAdmin, (req, res) => {
  const { title, content, type } = req.body;

  db.query(
    "INSERT INTO notices (title, content, type) VALUES (?, ?, ?)",
    [title, content, type],
    (err) => {
      if (err) return res.status(500).json({ message: "Server error" });
      res.json({ message: "Notice added" });
    }
  );
});

/* ---------------- GALLERY ---------------- */
app.get("/gallery", (req, res) => {
  db.query("SELECT * FROM gallery ORDER BY id DESC", (err, results) => {
    if (err) return res.status(500).json({ message: "Server error" });
    res.json(results);
  });
});

app.post("/add-gallery", verifyAdmin, upload.single("image"), (req, res) => {
  db.query(
    "INSERT INTO gallery (title, category, image) VALUES (?, ?, ?)",
    [req.body.title, req.body.category, req.file.filename],
    (err) => {
      if (err) return res.status(500).json({ message: "Server error" });
      res.json({ message: "Image uploaded" });
    }
  );
});
/* ---------------- NOTES ---------------- */
app.get("/notes", (req, res) => {
  db.query("SELECT * FROM notes ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Notes fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    return res.json(results);
  });
});

app.post("/add-note", verifyAdmin, (req, res) => {
  const { title, description, subject, pdf_link } = req.body;

  if (!title || !description || !subject) {
    return res.status(400).json({ message: "Title, description and subject are required" });
  }

  db.query(
    "INSERT INTO notes (title, description, subject, pdf_link) VALUES (?, ?, ?, ?)",
    [title, description, subject, pdf_link || ""],
    (err) => {
      if (err) {
        console.error("Add note error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      return res.json({ message: "Note added successfully" });
    }
  );
});

/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});