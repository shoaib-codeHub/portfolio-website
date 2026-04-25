import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import db from "./db.js";
import jwt from "jsonwebtoken";
import authMiddleware from "./authmiddleware.js";
import dotenv from "dotenv";
import nodemailer from "nodemailer"


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("Hello world");
});

// 🔐 REGISTER
app.post("/admin/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      "INSERT INTO admins (username, password_hash) VALUES ($1, $2) RETURNING id, username",
      [username, hashedPassword]
    );

    res.status(201).json({
      message: "Admin created successfully",
      admin: result.rows[0],
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// 🔐 LOGIN
app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await db.query(
      "SELECT * FROM admins WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const admin = result.rows[0];

    const isMatch = await bcrypt.compare(password, admin.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

   
    const token = jwt.sign(
      {
        id: admin.id,
        username: admin.username,
        role: "admin"   
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({
      message: "Login successful",
      token,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// 🔒 PROTECTED ROUTE
app.get("/admin/dashboard", authMiddleware, (req, res) => {
  res.json({
    message: "Welcome to admin dashboard",
    user: req.user
  });
});

// 🚀 CREATE PROJECT 
app.post("/api/projects", authMiddleware, async (req, res) => {
  try {
    const { title, description, tech_stack, github_link, live_link } = req.body;

    const techArray = tech_stack.split(",").map(t => t.trim());

    const result = await db.query(
      `INSERT INTO projects 
      (title, description, tech_stack, github_link, live_link) 
      VALUES ($1, $2, $3, $4, $5) 
      RETURNING *`,
      [title, description, techArray, github_link, live_link]
    );

    res.status(201).json({
      message: "Project added successfully",
      project: result.rows[0],
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

app.get("/api/projects", async (req, res) => {
  const result = await db.query("SELECT * FROM projects ORDER BY id DESC");
  res.json(result.rows);
});


app.put("/api/projects/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, description, tech_stack, github_link, live_link } = req.body;

  const techArray = tech_stack.split(",").map(t => t.trim());

  const result = await db.query(
    `UPDATE projects 
     SET title=$1, description=$2, tech_stack=$3, github_link=$4, live_link=$5
     WHERE id=$6 RETURNING *`,
    [title, description, techArray, github_link, live_link, id]
  );

  res.json(result.rows[0]);
});
app.delete("/api/projects/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;

  await db.query("DELETE FROM projects WHERE id=$1", [id]);

  res.json({ message: "Deleted successfully" });
});


// EXTRA ROUTES
app.get("/about", (req, res) => {
  res.send("Hello my name is Shoaib");
});

// simple in-memory rate limit (per server run)
const rateLimit = new Map();

app.post("/contact", async (req, res) => {
  try {
    const { sender_name, sender_email, message } = req.body;

    // ✅ 1. Validation
    if (!sender_name || !sender_email || !message) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // ✅ 2. Basic spam protection (limit 1 request / 10 sec per email)
    const now = Date.now();
    const lastRequest = rateLimit.get(sender_email) || 0;

    if (now - lastRequest < 10000) {
      return res.status(429).json({ message: "Too many requests. Try again later." });
    }

    rateLimit.set(sender_email, now);

    // ✅ 3. Save to DB
    const result = await db.query(
      `INSERT INTO messages 
      (sender_name, sender_email, message) 
      VALUES ($1, $2, $3) 
      RETURNING *`,
      [sender_name.trim(), sender_email.trim(), message.trim()]
    );

    // ✅ 4. Mail transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const adminMail = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      replyTo: sender_email,
      subject: `📩 New Message from ${sender_name}`,

      html: `
      <div style="font-family:Arial; background:#f4f6f8; padding:20px;">
        <div style="max-width:600px; margin:auto; background:#fff; border-radius:10px; overflow:hidden;">
          
          <div style="background:linear-gradient(135deg,#5F9598,#2575fc); padding:20px; color:#fff; text-align:center;">
            <h2>New Contact Message</h2>
          </div>

          <div style="padding:20px;">
            <p><strong>Name:</strong> ${sender_name}</p>
            <p><strong>Email:</strong> 
              <a href="mailto:${sender_email}" style="color:#2575fc;">
                ${sender_email}
              </a>
            </p>

            <div style="margin-top:15px;">
              <strong>Message:</strong>
              <p style="background:#f1f5f9; padding:12px; border-radius:6px;">
                ${message}
              </p>
            </div>

            <div style="margin-top:20px; text-align:center;">
              <a href="mailto:${sender_email}" 
                style="background:#2575fc; color:#fff; padding:10px 20px; border-radius:6px; text-decoration:none;">
                Reply
              </a>
            </div>
          </div>

          <div style="text-align:center; padding:10px; font-size:12px; color:#777;">
            Portfolio Contact Form 🚀
          </div>

        </div>
      </div>
      `,
    };

   
    const userMail = {
      from: process.env.EMAIL_USER,
      to: sender_email,
      subject: "Thanks for contacting me 🚀",

      html: `
      <div style="font-family:Arial; padding:20px;">
        <h2 style="color:#2575fc;">Hi ${sender_name},</h2>

        <p>Thanks for reaching out! I’ve received your message and will get back to you soon.</p>

        <div style="margin-top:15px; padding:10px; background:#f1f5f9; border-radius:6px;">
          <strong>Your Message:</strong>
          <p>${message}</p>
        </div>

        <p style="margin-top:20px;">— Shoaib</p>
      </div>
      `,
    };

    // ✅ 5. Send both emails
    await transporter.sendMail(adminMail);
    await transporter.sendMail(userMail);

    // ✅ 6. Response
    res.status(201).json({
      message: "Message sent successfully 🚀",
      data: result.rows[0],
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});


app.post("/user/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validate
    if (!email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // 2. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Insert user
    const result = await db.query(
      `INSERT INTO users (email, password_hash) 
       VALUES ($1, $2) 
       RETURNING id, email`,
      [email, hashedPassword]
    );

    // 4. Response
    res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });

  } catch (err) {
    console.error(err);

    // handle duplicate email
    if (err.code === "23505") {
      return res.status(400).json({ message: "Email already exists" });
    }

    res.status(500).json({ message: err.message });
  }
});

app.post("/user/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Find user
    const result = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];

    // 2. Compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // 3. Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: "user" },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // 4. Response
    res.json({
      message: "Login successful",
      token,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

app.get("/user/profile", authMiddleware, (req, res) => {
  res.json(req.user);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
