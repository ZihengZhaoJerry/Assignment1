const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String // this will be a hashed password
});

module.exports = mongoose.model('User', userSchema);