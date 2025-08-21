// middleware/auth.js
import { verifyAccessToken } from "../utils/jwt";

export const requireAuth = (req, res , next) => {
    try {
        // Accept "Authorization: Bearer <token>"
        const authHeader = req.headears.authorization
        if(!authHeader) return res.status(401).json({ message: "Missing Authorization Header"})
        
        const token = authHeader.split(" ")[1];
        if(!token) return res.status(401).json({ message: "Invalid Authorization header" });

        const payload = verifyAccessToken(token)
        req.user = payload
        next()
    } catch (err) {
         return res.status(401).json({ message: "Unauthorized", error: err.message });
    }
}