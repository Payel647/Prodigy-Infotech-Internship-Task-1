const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const flash = require("connect-flash");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const User = require("./models/User");

dotenv.config();
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

app.use(flash());

app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  next();
});

// Routes
app.get("/", (req, res) => res.redirect("/login"));

app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const existing = await User.findOne({ email });
  if (existing) {
    req.flash("error", "User already exists");
    return res.redirect("/register");
  }
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed });
  req.flash("success", "Registration successful. Please log in.");
  res.redirect("/login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    req.flash("error", "Email not found");
    return res.redirect("/login");
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    req.flash("error", "Invalid password");
    return res.redirect("/login");
  }
  req.session.userId = user._id;
  res.redirect("/dashboard");
});

app.get("/dashboard", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login");
  const user = await User.findById(req.session.userId);
  res.render("dashboard", { user });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => app.listen(5000, () => console.log("Server running on port 5000")))
  .catch(console.error);
