const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();
const port = 3000;

// Konfigurasi koneksi ke PostgreSQL
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "CobaLogin",
  password: "jovandi",
  port: 5432,
});

// Konfigurasi multer untuk menyimpan file yang diunggah
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads"); // Tentukan folder untuk menyimpan file
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Nama file akan diberi timestamp
  },
});
const upload = multer({ storage: storage });

// Configure ejs and static files
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "views/public")));
app.use(express.static(path.join(__dirname, "public")));

// Middleware untuk menangani form data
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: "secret_key", // Ganti dengan key yang lebih aman
    resave: false,
    saveUninitialized: true,
  })
);

// Route untuk halaman index (halaman utama)
app.get("/", (req, res) => {
  res.render("index", { title: "Halaman Utama" });
});

// Halaman Signup
app.get("/signup", (req, res) => {
  res.render("signup", { title: "Halaman Signup" });
});

// Halaman Login
app.get("/login", (req, res) => {
  res.render("login", { title: "Halaman Login" });
});

// Proses Signup
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const query = "INSERT INTO users(email, password) VALUES($1, $2)";
  const values = [email, hashedPassword];

  try {
    await pool.query(query, values);
    res.redirect("/login"); // Setelah signup, arahkan ke halaman login
  } catch (error) {
    console.error("Error signing up:", error);
    res.send("Terjadi kesalahan saat signup.");
  }
});

// Halaman Login
app.get("/login", (req, res) => {
  res.render("login", { title: "Halaman Login" });
});

// Middleware untuk mengecek apakah user sudah login
function checkAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login"); // Redirect ke halaman login jika belum login
  }
  next();
}

// Tambahkan route untuk logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error during logout:", err);
    }
    res.redirect("/login"); // Arahkan ke halaman login setelah logout
  });
});

// Halaman Upload (hanya dapat diakses jika login)
app.get("/upload", checkAuth, async (req, res) => {
  const result = await pool.query("SELECT * FROM uploads");
  res.render("upload", {
    title: "Upload Foto dan Caption",
    uploads: result.rows,
  });
});

// Proses Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const query = "SELECT * FROM users WHERE email = $1";
  const values = [email];

  try {
    const result = await pool.query(query, values);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.userId = user.id; // Menyimpan ID user di session
      res.redirect("/upload"); // Setelah login berhasil, arahkan ke halaman upload
    } else {
      res.send("Email atau password salah.");
    }
  } catch (error) {
    console.error("Error logging in:", error);
    res.send("Terjadi kesalahan saat login.");
  }
});

// Halaman Upload (hanya dapat diakses jika login)
app.get("/upload", async (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login"); // Jika tidak login, redirect ke halaman login
  }

  const result = await pool.query("SELECT * FROM uploads");
  res.render("upload", {
    title: "Upload Foto dan Caption",
    uploads: result.rows,
  });
});

// Menangani unggahan foto dan caption
app.post("/upload", upload.single("photo"), async (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login"); // Jika tidak login, redirect ke halaman login
  }

  const { caption } = req.body;
  const photo = req.file ? req.file.filename : null;

  if (photo) {
    const query = "INSERT INTO uploads(caption, photo_url) VALUES($1, $2)";
    const values = [caption, `uploads/${photo}`];

    try {
      await pool.query(query, values);
    } catch (error) {
      console.error("Error inserting data into database:", error);
    }
  }

  res.redirect("/upload");
});

// 404 route for unmatched paths
app.use("/", (req, res) => {
  res.send("<h1>404</h1>");
});

// Start server
app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
