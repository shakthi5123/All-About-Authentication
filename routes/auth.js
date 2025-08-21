// routes/auth.js (register, login, refresh, logout)
import express from "express"
import bcrypt from "bcrypt"
import crypto from "crypto"
import { User } from "../models/User"
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../utils/jwt"

const router = express.Router()

const COOKIE_OPTIONS = {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
}

// Register
router.post("/register", async(req, res) => {
    try {
        const { email, password } = req.body
        if(!email || !password) return res.status(400).json({ message: "Email and password required"})

        const existing = await User.findOne({ email })    
        if(existing) return res.status(409).json({ message: "Email already in use "})
        
        const hashed = await bcrypt.hash(password, 12)
        const user = await User.create({ email, password: hashed })

        // Create tokens
        const accessToken = signAccessToken({sub: user._id, roles: user.roles })
        const refreshToken = signRefreshToken({ sub: user._id });

        // store refresh token (simple approach)
        user.refreshTokens.push(refreshToken)
        await user.save();

        // Set HttpOnly cookie for refresh token
        res.cookie("refreshToken", refreshToken, COOKIE_OPTIONS)

        // Return access token (client stores temporarily, e.g. in memory)
    return res.status(201).json({ accessToken, user: { id: user._id, email: user.email } });
        
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
})

//Login
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body
        const user = await User.findOne({ email })
        if (!user) return res.status(401).json({ message: "Invalid credentials" });

        const ok = await bcrypt.compare(password, user.password)
        if (!ok) return res.status(401).json({ message: "Invalid credentials" });

        const accessToken = signAccessToken({ sub: user._id, roles: user.roles });
        const refreshToken = signRefreshToken({ sub: user._id });

        user.refreshTokens.push(refreshToken);
        await user.save();

        res.cookie("refreshToken", refreshToken, COOKIE_OPTIONS);
    return res.json({ accessToken, user: { id: user._id, email: user.email } });
    } catch (error) {
        return res.status(500).json({ message: err.message });
    }

});

// Refresh access token
router.post("/refresh", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ message: "Missing refresh token" });

    // verify signature & decode
    const payload = verifyRefreshToken(token);
    const userId = payload.sub;
    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ message: "Invalid refresh token (user not found)" });

    // check token exists in DB
    if (!user.refreshTokens.includes(token)) {
      // token reuse detected or token previously revoked
      user.refreshTokens = []; // revoke all as precaution
      await user.save();
      return res.status(401).json({ message: "Refresh token not recognized. Please login again." });
    }

    // Optionally: rotate refresh tokens — issue new refresh token and replace the old one
    const newRefreshToken = signRefreshToken({ sub: user._id });
    // replace token in DB (remove old, add new)
    user.refreshTokens = user.refreshTokens.filter(t => t !== token);
    user.refreshTokens.push(newRefreshToken);
    await user.save();

    // new access token
    const accessToken = signAccessToken({ sub: user._id, roles: user.roles });
    // set cookie
    res.cookie("refreshToken", newRefreshToken, COOKIE_OPTIONS);
    return res.json({ accessToken });

  } catch (err) {
    return res.status(401).json({ message: "Invalid token", error: err.message });
  }
});

// Logout
router.post("/logout", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (token) {
      // find user and remove token
      const payload = (() => {
        try { return verifyRefreshToken(token); } catch { return null; }
      })();
      if (payload) {
        const user = await User.findById(payload.sub);
        if (user) {
          user.refreshTokens = user.refreshTokens.filter(t => t !== token);
          await user.save();
        }
      }
    }
    res.clearCookie("refreshToken", COOKIE_OPTIONS);
    return res.json({ message: "Logged out" });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

export default router;