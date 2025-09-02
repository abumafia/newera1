const mongoose = require("mongoose");

const replySchema = new mongoose.Schema({
  text: String,
  author: String,
  createdAt: { type: Date, default: Date.now },
});

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: String,
  replies: [replySchema],
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Post", postSchema);
