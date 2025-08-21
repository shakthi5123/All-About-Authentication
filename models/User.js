// models/User.js
import mongoose from "mongoose"

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true},
    password: { type: String, required: true },
    roles: { type: [String], default: [users]},
    isVerified: { type: Boolean, default: false},
    refreshTokens: { type: [String], default: []}, // store current valid refresh tokens (or store hashed tokens)
    mfa: {
        enabled: { type: Boolean, default: false},
        secret: { type: String, default: null}
    },
    // For password reset / email verification we'll add fields later
}, { timestamps: true }) ;

export const User = mongoose.model("User", UserSchema);
