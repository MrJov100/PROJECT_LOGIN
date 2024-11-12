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
  const loggedIn = req.session.userId ? true : false; // Mengecek session user
  const namaLengkap = req.session.namaLengkap || ""; // Menyediakan nama lengkap jika ada
  res.render("index", {
    title: "Halaman Utama",
    loggedIn: loggedIn,
    namaLengkap: namaLengkap,
  });
});

// Halaman Signup
app.get("/signup", (req, res) => {
  res.render("signup", { title: "Halaman Signup" });
});

// Halaman Login
app.get("/login", (req, res) => {
  res.render("login", { title: "Halaman Login" });
});

app.get("/profile", checkAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    // Ambil data pengguna dari database
    const result = await pool.query(
      "SELECT nama_lengkap, email FROM users WHERE id = $1",
      [userId]
    );
    const user = result.rows[0];

    if (user) {
      res.render("profile", {
        title: "Halaman Profil",
        namaLengkap: user.nama_lengkap,
        email: user.email,
      });
    } else {
      res.status(404).send("User not found.");
    }
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).send("Error fetching user profile.");
  }
});

// Halaman untuk ganti password
app.get("/change-password", checkAuth, (req, res) => {
  res.render("change-password", { title: "Ganti Password" });
});

// Route untuk menangani POST request ganti password
app.post("/change-password", checkAuth, async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;
  const userId = req.session.userId;

  try {
    // Validasi apakah password baru dan konfirmasinya cocok
    if (newPassword !== confirmPassword) {
      return res.send("Password baru dan konfirmasi password tidak cocok.");
    }

    // Ambil password lama dari database
    const result = await pool.query(
      "SELECT password FROM users WHERE id = $1",
      [userId]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(404).send("Pengguna tidak ditemukan.");
    }

    // Bandingkan password lama dengan yang ada di database
    const isOldPasswordCorrect = await bcrypt.compare(
      oldPassword,
      user.password
    );
    if (!isOldPasswordCorrect) {
      return res.send("Password lama salah.");
    }

    // Hash password baru
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update password baru di database
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [
      hashedNewPassword,
      userId,
    ]);

    res.send("Password berhasil diganti.");
  } catch (error) {
    console.error("Error ganti password:", error);
    res.status(500).send("Terjadi kesalahan saat mengganti password.");
  }
});

// Proses Signup
app.post("/signup", async (req, res) => {
  const { nama_lengkap, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const query =
    "INSERT INTO users(nama_lengkap, email, password) VALUES($1, $2, $3)";
  const values = [nama_lengkap, email, hashedPassword];

  try {
    await pool.query(query, values);
    res.redirect("/login"); // Setelah signup, arahkan ke halaman login
  } catch (error) {
    console.error("Error signing up:", error);
    res.send("Terjadi kesalahan saat signup.");
  }
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
  try {
    // Check for user session ID
    const userId = req.session.userId;
    if (!userId) {
      console.error("User ID not found in session.");
      return res.redirect("/login");
    }

    // Fetch the user's full name
    const userResult = await pool.query(
      "SELECT nama_lengkap FROM users WHERE id = $1",
      [userId]
    );
    if (userResult.rows.length === 0) {
      console.error(`No user found with ID: ${userId}`);
      return res.status(404).send("User not found.");
    }

    const user = userResult.rows[0];

    // Fetch the uploads associated with the user
    const uploadsResult = await pool.query(
      "SELECT * FROM uploads WHERE id_user = $1",
      [userId]
    );

    // Render the upload page with user details and uploads
    res.render("upload", {
      title: "Upload Foto dan Caption",
      uploads: uploadsResult.rows,
      namaLengkap: user.nama_lengkap, // Pass the user's full name
    });
  } catch (error) {
    console.error("Error details:", error.message);
    res.status(500).send("Error loading the upload page.");
  }
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
      req.session.namaLengkap = user.nama_lengkap; // Menyimpan Nama Lengkap di session
      res.redirect("/upload"); // Setelah login berhasil, arahkan ke halaman upload
    } else {
      res.send("Email atau password salah.");
    }
  } catch (error) {
    console.error("Error logging in:", error);
    res.send("Terjadi kesalahan saat login.");
  }
});

// Menangani unggahan foto dan caption
app.post("/upload", upload.single("photo"), async (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login"); // Jika tidak login, redirect ke halaman login
  }

  const { caption } = req.body;
  const photo = req.file ? req.file.filename : null;

  if (photo) {
    const query =
      "INSERT INTO uploads(id_user, caption, photo_url) VALUES($1, $2, $3)";
    const values = [req.session.userId, caption, `uploads/${photo}`];

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
