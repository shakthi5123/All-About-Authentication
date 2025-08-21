// utils/jwt.js (helpers)
import jwt from "jsonwebtoken"

export const signAccessToken = (payload) => {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m"})
};

export const signRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d" })
};

export const verifyAccessToken = (token) => 
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

export const verifyRefreshToken = (token) => 
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET)