import mongoose, { Schema } from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const userSchema = new Schema({
    avatar: {
        type: { url: String, localPath: String }, default: {
            url: 'https://placehold.co/100x100', localPath: ''
        }
    },
    username: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    fullName: { type: String, trim: true },
    password: { type: String, required: [true, 'Password is required'] },
    isEmailVerified: { type: Boolean, default: false },
    refreshToken: { type: String },
    forgotPasswordToken: { type: String },
    forgotPasswordExpiry: { type: Date },
    emailVerificationToken: { type: String },
    emailVerificationExpiry: { type: Date }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Check if password is valid
userSchema.methods.isValidPassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

// Generate Access token
userSchema.methods.generateAccessToken = function () {
    return jwt.sign({ _id: this._id, email: this.email, username: this.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });
}

// Generate Refresh token
userSchema.methods.generateRefreshToken = function () {
    return jwt.sign({ _id: this._id, email: this.email, username: this.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY });
}

// Generate temporary token for email verification and password reset
userSchema.methods.generateTemporaryToken = function () {
    const unhashedToken = crypto.randomeBytes(20).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(unhashedToken).digest('hex');

    const tokenExpiry= Date.now() + 20 * 60 * 1000; // 20 minutes

   return { unhashedToken, hashedToken, tokenExpiry };
}

const User = new mongoose.Model('User', userSchema);
export default User;