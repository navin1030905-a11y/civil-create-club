const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

app.use(cors({ origin: "*" }));
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

if (!process.env.MYSQL_PUBLIC_URL) {
  console.error("❌ MYSQL_PUBLIC_URL missing");
}

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

  if (!authHeader) {
    return res.status(401).json({ message: "Token missing" });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ message: "Invalid token format" });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ---------------- ROOT ---------------- */
app.get("/", (req, res) => {
  res.send("Civil Club back-end running 🚀");
});

/* ---------------- DEBUG ---------------- */
app.get("/debug-admins", (req, res) => {
  db.query("SELECT id, username FROM admins", (err, results) => {
    if (err) {
      console.error("Debug admins error:", err);
      return res.status(500).json({ message: "Server error", error: err.message });
    }
    return res.json(results);
  });
});

/* ---------------- ADMIN LOGIN ---------------- */
app.post("/admin-login", (req, res) => {
  const { username, password } = req.body;

  console.log("Login username received:", username);

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

      console.log("Admin query results:", results);

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

/* ---------------- ADMIN CHECK ---------------- */
app.get("/admin-check", verifyAdmin, (req, res) => {
  return res.json({
    message: "Authorized",
    admin: req.admin
  });
});

/* ---------------- ADMIN REQUEST ---------------- */
app.post("/admin-request", async (req, res) => {
  const { username, password, reason } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO admin_requests (username, password, reason) VALUES (?, ?, ?)",
      [username, hashedPassword, reason || ""],
      (err) => {
        if (err) {
          console.error("Admin request error:", err);
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Username already requested or exists" });
          }
          return res.status(500).json({ message: "Server error" });
        }

        return res.json({ message: "Admin request submitted successfully" });
      }
    );
  } catch (error) {
    console.error("Hash error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- ADMIN REQUESTS ---------------- */
app.get("/admin-requests", verifyAdmin, (req, res) => {
  db.query("SELECT * FROM admin_requests ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Admin requests fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    return res.json(results);
  });
});

app.post("/approve-admin/:id", verifyAdmin, (req, res) => {
  const requestId = req.params.id;

  db.query(
    "SELECT * FROM admin_requests WHERE id = ? LIMIT 1",
    [requestId],
    (err, results) => {
      if (err) {
        console.error("Approve read error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "Request not found" });
      }

      const request = results[0];

      db.query(
        "INSERT INTO admins (username, password) VALUES (?, ?)",
        [request.username, request.password],
        (insertErr) => {
          if (insertErr) {
            console.error("Approve insert error:", insertErr);
            if (insertErr.code === "ER_DUP_ENTRY") {
              return res.status(400).json({ message: "Admin already exists" });
            }
            return res.status(500).json({ message: "Server error" });
          }

          db.query(
            "DELETE FROM admin_requests WHERE id = ?",
            [requestId],
            (deleteErr) => {
              if (deleteErr) {
                console.error("Approve delete error:", deleteErr);
                return res.status(500).json({ message: "Admin added but request delete failed" });
              }

              return res.json({ message: "Admin approved successfully" });
            }
          );
        }
      );
    }
  );
});

app.post("/reject-admin/:id", verifyAdmin, (req, res) => {
  const requestId = req.params.id;

  db.query(
    "DELETE FROM admin_requests WHERE id = ?",
    [requestId],
    (err) => {
      if (err) {
        console.error("Reject request error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      return res.json({ message: "Request rejected successfully" });
    }
  );
});

/* ---------------- SITE CONTENT ---------------- */
app.get("/site-content", (req, res) => {
  db.query("SELECT * FROM site_content ORDER BY id DESC LIMIT 1", (err, results) => {
    if (err) {
      console.error("Site content fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      return res.json({
        hero_title: "Welcome to Civil Engineering Club",
        hero_subtitle: "A platform for technical growth, collaboration, and departmental excellence."
      });
    }

    return res.json(results[0]);
  });
});

app.post("/update-site-content", verifyAdmin, (req, res) => {
  const { hero_title, hero_subtitle } = req.body;

  db.query("SELECT * FROM site_content LIMIT 1", (err, results) => {
    if (err) {
      console.error("Site content read error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      db.query(
        "INSERT INTO site_content (hero_title, hero_subtitle) VALUES (?, ?)",
        [hero_title || "", hero_subtitle || ""],
        (insertErr) => {
          if (insertErr) {
            console.error("Site content insert error:", insertErr);
            return res.status(500).json({ message: "Server error" });
          }
          return res.json({ message: "Home page updated successfully" });
        }
      );
    } else {
      db.query(
        "UPDATE site_content SET hero_title = ?, hero_subtitle = ? WHERE id = ?",
        [hero_title || "", hero_subtitle || "", results[0].id],
        (updateErr) => {
          if (updateErr) {
            console.error("Site content update error:", updateErr);
            return res.status(500).json({ message: "Server error" });
          }
          return res.json({ message: "Home page updated successfully" });
        }
      );
    }
  });
});

/* ---------------- NOTICES ---------------- */
app.get("/notices", (req, res) => {
  db.query("SELECT * FROM notices ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Notices fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }
    return res.json(results);
  });
});

app.post("/add-notice", verifyAdmin, (req, res) => {
  const { title, content, type } = req.body;

  if (!title || !content || !type) {
    return res.status(400).json({ message: "All fields required" });
  }

  db.query(
    "INSERT INTO notices (title, content, type) VALUES (?, ?, ?)",
    [title, content, type],
    (err) => {
      if (err) {
        console.error("Add notice error:", err);
        return res.status(500).json({ message: "Server error" });
      }
      return res.json({ message: "Notice added successfully" });
    }
  );
});

/* ---------------- GALLERY ---------------- */
app.get("/gallery", (req, res) => {
  db.query("SELECT * FROM gallery ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Gallery fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }
    return res.json(results);
  });
});

app.post("/add-gallery", verifyAdmin, upload.single("image"), (req, res) => {
  const { title, category } = req.body;

  if (!req.file) {
    return res.status(400).json({ message: "Image required" });
  }

  db.query(
    "INSERT INTO gallery (title, category, image) VALUES (?, ?, ?)",
    [title || "", category || "", req.file.filename],
    (err) => {
      if (err) {
        console.error("Add gallery error:", err);
        return res.status(500).json({ message: "Server error" });
      }
      return res.json({ message: "Gallery image uploaded successfully" });
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
/* ---------------- DELETE NOTICE ---------------- */
app.delete("/delete-notice/:id", verifyAdmin, (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM notices WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Delete notice error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Notice not found" });
    }

    return res.json({ message: "Notice deleted successfully" });
  });
});

/* ---------------- DELETE GALLERY ---------------- */
app.delete("/delete-gallery/:id", verifyAdmin, (req, res) => {
  const id = req.params.id;

  db.query("SELECT * FROM gallery WHERE id = ? LIMIT 1", [id], (err, results) => {
    if (err) {
      console.error("Read gallery delete error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Gallery item not found" });
    }

    const item = results[0];
    const imagePath = path.join(uploadsPath, item.image);

    db.query("DELETE FROM gallery WHERE id = ?", [id], (deleteErr, result) => {
      if (deleteErr) {
        console.error("Delete gallery DB error:", deleteErr);
        return res.status(500).json({ message: "Server error" });
      }

      if (fs.existsSync(imagePath)) {
        fs.unlink(imagePath, (fileErr) => {
          if (fileErr) {
            console.error("Delete gallery file error:", fileErr);
          }
        });
      }

      return res.json({ message: "Gallery item deleted successfully" });
    });
  });
});

/* ---------------- DELETE NOTE ---------------- */
app.delete("/delete-note/:id", verifyAdmin, (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM notes WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Delete note error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Note not found" });
    }

    return res.json({ message: "Note deleted successfully" });
  });
});
/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});