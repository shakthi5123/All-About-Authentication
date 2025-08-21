import "dotenv/config"
import express from "express"
import mongoose from "mongoose"
import cookieParser from "cookie-parser"
import helmet from "helmet"
import rateLimit from "express-rate-limit"

import authRoutes from "./routes/auth.js"
import { requireAuth } from "./middleware/auth.js";

const app = express()
app.use(helmet())
app.use(express.json());
app.use(cookieParser());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

await mongoose.connect(process.env.MONGO_URI);
console.log("Mongo connected");

app.use("/auth", authRoutes);

// protected example
app.get("/protected", requireAuth, (req, res) => {
  res.json({ message: `Hello ${req.user.sub}`, user: req.user });
});

app.listen(process.env.PORT || 3000, () => console.log("Server running"));