require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection string built from .env variables
const dbUser = process.env.MONGODB_USER;
const dbPass = process.env.MONGODB_PASSWORD;
const dbHost = process.env.MONGODB_HOST;
const dbName = process.env.MONGODB_DATABASE;

const dbUri = `mongodb+srv://${dbUser}:${dbPass}@${dbHost}/${dbName}?retryWrites=true&w=majority`;


// Connect to MongoDB
mongoose.connect(dbUri);

// Define User schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Session Setup
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: dbUri,
    ttl: 60 * 60 
  })
}));

// Home Page
app.get('/', (req, res) => {
  const user = req.session.user;
  res.render('home', { user });
});

// Sign Up GET
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

// Sign Up POST
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  
  if (!name || !email || !password) {
    return res.render('signup', { error: "Please fill in all fields." });
  }

  // Joi Validation
  const schema = Joi.object({
    name: Joi.string().alphanum().min(2).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(5).max(50).required()
  });

  const { error } = schema.validate({ name, email, password });

  if (error) {
    return res.render('signup', { error: error.details[0].message });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();

  req.session.user = { name };
  res.redirect('/members');
});

// Log In GET
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Log In POST
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', { error: "Please enter both email and password." });
  }

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(5).max(50).required()
  });

  const { error } = schema.validate({ email, password });

  if (error) {
    return res.render('login', { error: error.details[0].message });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.render('login', { error: "User and password not found." });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.render('login', { error: "User and password not found." });
  }

  req.session.user = { name: user.name };
  res.redirect('/members');
});

// Members Page
app.get('/members', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }

  const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];
  const name = req.session.user.name;

  res.render('members', { name, image: randomImage });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err); 
    }
    res.redirect('/');
  });
});

// 404 Page
app.use((req, res) => {
  res.status(404).render('404');
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});