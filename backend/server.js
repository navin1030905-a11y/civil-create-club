const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");
const streamifier = require("streamifier");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ---------------- ENV ---------------- */
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";

/* ---------------- CLOUDINARY ---------------- */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/* ---------------- DB CONNECTION ---------------- */
const db = mysql.createConnection(process.env.MYSQL_PUBLIC_URL);

db.connect((err) => {
  if (err) {
    console.error("MySQL connection error:", err);
  } else {
    console.log("MySQL Connected");
  }
});

/* ---------------- HELPERS ---------------- */
function logActivity(admin, actionType, actionDetails) {
  if (!admin || !admin.username) return;

  db.query(
    "INSERT INTO activity_logs (admin_username, admin_role, action_type, action_details) VALUES (?, ?, ?, ?)",
    [admin.username, admin.role || "admin", actionType, actionDetails || ""],
    (err) => {
      if (err) console.error("Activity log error:", err);
    }
  );
}

function uploadBufferToCloudinary(fileBuffer, folder = "civil-create-club", resourceType = "auto") {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        resource_type: resourceType
      },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );

    streamifier.createReadStream(fileBuffer).pipe(stream);
  });
}

function deleteFromCloudinary(fileUrl, resourceType = "image") {
  return new Promise((resolve) => {
    try {
      if (!fileUrl || !fileUrl.includes("cloudinary.com")) return resolve();

      const parts = fileUrl.split("/");
      const uploadIndex = parts.findIndex((p) => p === "upload");
      if (uploadIndex === -1) return resolve();

      let pathParts = parts.slice(uploadIndex + 1);

      if (pathParts[0] && pathParts[0].startsWith("v")) {
        pathParts = pathParts.slice(1);
      }

      const publicPathWithExt = pathParts.join("/");
      const publicId = publicPathWithExt.replace(/\.[^/.]+$/, "");

      cloudinary.uploader.destroy(publicId, { resource_type: resourceType }, () => {
        resolve();
      });
    } catch {
      resolve();
    }
  });
}

/* ---------------- MULTER ---------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

/* ---------------- AUTH ---------------- */
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
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function requireHead(req, res, next) {
  if (!req.admin || req.admin.role !== "head") {
    return res.status(403).json({ message: "Access denied: head admin only" });
  }
  next();
}

/* ---------------- ROOT ---------------- */
app.get("/", (req, res) => {
  res.send("Civil Club back-end running");
});

/* ---------------- DEBUG ---------------- */
app.get("/debug-admins", (req, res) => {
  db.query("SELECT id, username, role FROM admins ORDER BY id ASC", (err, results) => {
    if (err) {
      return res.status(500).json({ message: "DB error", error: err.message });
    }
    return res.json(results);
  });
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
            role: admin.role || "admin"
          },
          JWT_SECRET,
          { expiresIn: "1d" }
        );

        logActivity(
          { username: admin.username, role: admin.role || "admin" },
          "LOGIN",
          "Admin logged in"
        );

        return res.json({
          message: "Login success",
          token,
          username: admin.username,
          role: admin.role || "admin"
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
app.get("/admin-requests", verifyAdmin, requireHead, (req, res) => {
  db.query("SELECT * FROM admin_requests ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Admin requests fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    return res.json(results);
  });
});

app.post("/approve-admin/:id", verifyAdmin, requireHead, (req, res) => {
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
        "INSERT INTO admins (username, password, role) VALUES (?, ?, ?)",
        [request.username, request.password, "admin"],
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

              logActivity(req.admin, "APPROVE_ADMIN_REQUEST", `Approved request for ${request.username}`);
              return res.json({ message: "Admin approved successfully" });
            }
          );
        }
      );
    }
  );
});

app.post("/reject-admin/:id", verifyAdmin, requireHead, (req, res) => {
  const requestId = req.params.id;

  db.query("DELETE FROM admin_requests WHERE id = ?", [requestId], (err) => {
    if (err) {
      console.error("Reject request error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    logActivity(req.admin, "REJECT_ADMIN_REQUEST", `Rejected request id ${requestId}`);
    return res.json({ message: "Request rejected successfully" });
  });
});

/* ---------------- ADMIN LIST ---------------- */
app.get("/admins", verifyAdmin, requireHead, (req, res) => {
  db.query("SELECT id, username, role FROM admins ORDER BY id ASC", (err, results) => {
    if (err) {
      console.error("Admins fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    return res.json(results);
  });
});

app.post("/create-admin", verifyAdmin, requireHead, async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ message: "Username, password and role required" });
  }

  if (!["head", "admin"].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO admins (username, password, role) VALUES (?, ?, ?)",
      [username, hashedPassword, role],
      (err) => {
        if (err) {
          console.error("Create admin error:", err);
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Username already exists" });
          }
          return res.status(500).json({ message: "Server error" });
        }

        logActivity(req.admin, "CREATE_ADMIN", `Created ${role} admin ${username}`);
        return res.json({ message: "Admin created successfully" });
      }
    );
  } catch (error) {
    console.error("Create admin hash error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/update-admin-role/:id", verifyAdmin, requireHead, (req, res) => {
  const { role } = req.body;
  const adminId = req.params.id;

  if (!["head", "admin"].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  if (String(req.admin.id) === String(adminId)) {
    return res.status(400).json({ message: "You cannot change your own role" });
  }

  db.query(
    "UPDATE admins SET role = ? WHERE id = ?",
    [role, adminId],
    (err, result) => {
      if (err) {
        console.error("Update admin role error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Admin not found" });
      }

      logActivity(req.admin, "UPDATE_ADMIN_ROLE", `Updated admin id ${adminId} role to ${role}`);
      return res.json({ message: "Admin role updated successfully" });
    }
  );
});

app.delete("/delete-admin/:id", verifyAdmin, requireHead, (req, res) => {
  const adminId = req.params.id;

  if (String(req.admin.id) === String(adminId)) {
    return res.status(400).json({ message: "You cannot delete yourself" });
  }

  db.query("DELETE FROM admins WHERE id = ?", [adminId], (err, result) => {
    if (err) {
      console.error("Delete admin error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Admin not found" });
    }

    logActivity(req.admin, "DELETE_ADMIN", `Deleted admin id ${adminId}`);
    return res.json({ message: "Admin deleted successfully" });
  });
});

/* ---------------- ACTIVITY LOGS ---------------- */
app.get("/activity-logs", verifyAdmin, requireHead, (req, res) => {
  db.query("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 100", (err, results) => {
    if (err) {
      console.error("Activity logs fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    return res.json(results);
  });
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

app.post("/update-site-content", verifyAdmin, requireHead, (req, res) => {
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

          logActivity(req.admin, "UPDATE_HOME_CONTENT", "Inserted home page content");
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

          logActivity(req.admin, "UPDATE_HOME_CONTENT", "Updated home page content");
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

      logActivity(req.admin, "ADD_NOTICE", `Added notice: ${title}`);
      return res.json({ message: "Notice added successfully" });
    }
  );
});

app.delete("/delete-notice/:id", verifyAdmin, requireHead, (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM notices WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Delete notice error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Notice not found" });
    }

    logActivity(req.admin, "DELETE_NOTICE", `Deleted notice id ${id}`);
    return res.json({ message: "Notice deleted successfully" });
  });
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

app.post("/add-gallery", verifyAdmin, upload.single("image"), async (req, res) => {
  try {
    const { title, category } = req.body;

    if (!req.file) {
      return res.status(400).json({ message: "Image required" });
    }

    const uploaded = await uploadBufferToCloudinary(req.file.buffer, "civil-create-club/gallery", "image");

    db.query(
      "INSERT INTO gallery (title, category, image) VALUES (?, ?, ?)",
      [title || "", category || "", uploaded.secure_url],
      (err) => {
        if (err) {
          console.error("Add gallery error:", err);
          return res.status(500).json({ message: "Server error" });
        }

        logActivity(req.admin, "ADD_GALLERY", "Uploaded gallery item");
        return res.json({ message: "Gallery image uploaded successfully" });
      }
    );
  } catch (error) {
    console.error("Cloudinary gallery upload error:", error);
    return res.status(500).json({ message: "Image upload failed" });
  }
});

app.delete("/delete-gallery/:id", verifyAdmin, requireHead, (req, res) => {
  const id = req.params.id;

  db.query("SELECT * FROM gallery WHERE id = ? LIMIT 1", [id], async (err, results) => {
    if (err) {
      console.error("Read gallery delete error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Gallery item not found" });
    }

    const item = results[0];

    db.query("DELETE FROM gallery WHERE id = ?", [id], async (deleteErr) => {
      if (deleteErr) {
        console.error("Delete gallery DB error:", deleteErr);
        return res.status(500).json({ message: "Server error" });
      }

      await deleteFromCloudinary(item.image, "image");

      logActivity(req.admin, "DELETE_GALLERY", `Deleted gallery item id ${id}`);
      return res.json({ message: "Gallery item deleted successfully" });
    });
  });
});

/* ---------------- NOTES ---------------- */
app.get("/notes", (req, res) => {
  db.query("SELECT * FROM notes ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Notes fetch error:", err);
      return res.status(500).json({ message: "Server error while fetching notes" });
    }

    return res.json(results);
  });
});

app.post("/add-note", verifyAdmin, upload.single("pdf_file"), async (req, res) => {
  try {
    const { title, description, subject, pdf_link } = req.body;

    if (!title || !description || !subject) {
      return res.status(400).json({ message: "Title, description and subject are required" });
    }

    let finalPdfLink = pdf_link || "";

    if (req.file) {
      const uploaded = await uploadBufferToCloudinary(
        req.file.buffer,
        "civil-create-club/notes",
        "raw"
      );
      finalPdfLink = uploaded.secure_url;
    }

    db.query(
      "INSERT INTO notes (title, description, subject, pdf_link) VALUES (?, ?, ?, ?)",
      [title, description, subject, finalPdfLink],
      (err, result) => {
        if (err) {
          console.error("Add note error:", err);
          return res.status(500).json({ message: "Server error while adding note" });
        }

        logActivity(req.admin, "ADD_NOTE", `Added note: ${title}`);
        return res.json({
          message: "Note added successfully",
          noteId: result.insertId,
          pdf_link: finalPdfLink
        });
      }
    );
  } catch (error) {
    console.error("PDF upload error:", error);
    return res.status(500).json({ message: "PDF upload failed" });
  }
});

app.delete("/delete-note/:id", verifyAdmin, requireHead, (req, res) => {
  const id = req.params.id;

  db.query("SELECT id, title, pdf_link FROM notes WHERE id = ? LIMIT 1", [id], async (readErr, rows) => {
    if (readErr) {
      console.error("Read note before delete error:", readErr);
      return res.status(500).json({ message: "Server error while reading note" });
    }

    if (rows.length === 0) {
      return res.status(404).json({ message: "Note not found" });
    }

    const note = rows[0];

    db.query("DELETE FROM notes WHERE id = ?", [id], async (deleteErr, result) => {
      if (deleteErr) {
        console.error("Delete note error:", deleteErr);
        return res.status(500).json({ message: "Server error while deleting note" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Note not found" });
      }

      if (note.pdf_link && note.pdf_link.includes("cloudinary.com")) {
        await deleteFromCloudinary(note.pdf_link, "raw");
      }

      logActivity(req.admin, "DELETE_NOTE", `Deleted note id ${id} (${note.title})`);
      return res.json({
        message: "Note deleted successfully",
        deletedId: Number(id)
      });
    });
  });
});

/* ---------------- TEAM MEMBERS ---------------- */
app.get("/team", (req, res) => {
  db.query("SELECT * FROM team_members ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error("Team members fetch error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    return res.json(results);
  });
});

app.post("/add-member", verifyAdmin, requireHead, upload.single("image"), async (req, res) => {
  try {
    const { name, role, category, description } = req.body;

    if (!name || !role || !category) {
      return res.status(400).json({ message: "Name, role and category required" });
    }

    let imageUrl = "";
    if (req.file) {
      const uploaded = await uploadBufferToCloudinary(req.file.buffer, "civil-create-club/team", "image");
      imageUrl = uploaded.secure_url;
    }

    db.query(
      "INSERT INTO team_members (name, role, category, description, image) VALUES (?, ?, ?, ?, ?)",
      [name, role, category, description || "", imageUrl],
      (err) => {
        if (err) {
          console.error("Add member error:", err);
          return res.status(500).json({ message: "Server error" });
        }

        logActivity(req.admin, "ADD_TEAM_MEMBER", `Added ${category} member ${name}`);
        return res.json({ message: "Member added successfully" });
      }
    );
  } catch (error) {
    console.error("Cloudinary member upload error:", error);
    return res.status(500).json({ message: "Image upload failed" });
  }
});

app.put("/update-member/:id", verifyAdmin, requireHead, upload.single("image"), async (req, res) => {
  const id = req.params.id;
  const { name, role, category, description } = req.body;

  if (!name || !role || !category) {
    return res.status(400).json({ message: "Name, role and category required" });
  }

  db.query("SELECT * FROM team_members WHERE id = ? LIMIT 1", [id], async (err, results) => {
    if (err) {
      console.error("Read member update error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Member not found" });
    }

    try {
      const oldMember = results[0];
      let newImage = oldMember.image;

      if (req.file) {
        const uploaded = await uploadBufferToCloudinary(req.file.buffer, "civil-create-club/team", "image");
        newImage = uploaded.secure_url;
      }

      db.query(
        "UPDATE team_members SET name = ?, role = ?, category = ?, description = ?, image = ? WHERE id = ?",
        [name, role, category, description || "", newImage, id],
        async (updateErr) => {
          if (updateErr) {
            console.error("Update member error:", updateErr);
            return res.status(500).json({ message: "Server error" });
          }

          if (req.file && oldMember.image) {
            await deleteFromCloudinary(oldMember.image, "image");
          }

          logActivity(req.admin, "UPDATE_TEAM_MEMBER", `Updated team member id ${id}`);
          return res.json({ message: "Member updated successfully" });
        }
      );
    } catch (error) {
      console.error("Update member upload error:", error);
      return res.status(500).json({ message: "Image upload failed" });
    }
  });
});

app.delete("/delete-member/:id", verifyAdmin, requireHead, (req, res) => {
  const id = req.params.id;

  db.query("SELECT * FROM team_members WHERE id = ? LIMIT 1", [id], async (err, results) => {
    if (err) {
      console.error("Read team member delete error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Member not found" });
    }

    const member = results[0];

    db.query("DELETE FROM team_members WHERE id = ?", [id], async (deleteErr) => {
      if (deleteErr) {
        console.error("Delete team member DB error:", deleteErr);
        return res.status(500).json({ message: "Server error" });
      }

      if (member.image) {
        await deleteFromCloudinary(member.image, "image");
      }

      logActivity(req.admin, "DELETE_TEAM_MEMBER", `Deleted team member id ${id}`);
      return res.json({ message: "Member deleted successfully" });
    });
  });
});

/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});