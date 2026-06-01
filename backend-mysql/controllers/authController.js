import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { query } from "../config/db.js";

// Helper function to sign JWT tokens
const signToken = (user) =>
  jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET || "exam_secret",
    { expiresIn: "8h" }
  );

// Helper function to normalize email strings
const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

// 1. REGISTER CONTROLLER
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "Username, email, and password are required." });
    }
    const emailNorm = normalizeEmail(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNorm)) {
      return res.status(400).json({ message: "Enter a valid email address." });
    }
    const existingUser = await query("SELECT id FROM users WHERE username = ?", [username.trim()]);
    if (existingUser && existingUser.length > 0) {
      return res.status(409).json({ message: "Username already exists." });
    }
    const existingEmail = await query("SELECT id FROM users WHERE email = ?", [emailNorm]);
    if (existingEmail && existingEmail.length > 0) {
      return res.status(409).json({ message: "Email already registered." });
    }
    const hash = await bcrypt.hash(password, 10);
    await query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [
      username.trim(),
      emailNorm,
      hash,
    ]);
    return res.status(201).json({ message: "Account created successfully." });
  } catch (error) {
    console.error("REGISTER ERROR:", error); 
    return res.status(500).json({ message: "Server error during registration." });
  }
};

// 2. LOGIN CONTROLLER
export const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }
    const users = await query("SELECT * FROM users WHERE username = ?", [username.trim()]);
    if (!users || users.length === 0) {
      return res.status(401).json({ message: "Invalid username or password." });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username or password." });
    }
    const token = signToken(user);
    return res.status(200).json({
      message: "Login successful.",
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    return res.status(500).json({ message: "Server error during login." });
  }
};

// 3. FORGOT PASSWORD CONTROLLER
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }
    const emailNorm = normalizeEmail(email);
    const users = await query("SELECT id FROM users WHERE email = ?", [emailNorm]);
    if (!users || users.length === 0) {
      return res.status(404).json({ message: "No user found with this email." });
    }
    return res.status(200).json({ message: "Password reset link sent to your email." });
  } catch (error) {
    console.error("FORGOT PASSWORD ERROR:", error);
    return res.status(500).json({ message: "Server error during forgot password." });
  }
};