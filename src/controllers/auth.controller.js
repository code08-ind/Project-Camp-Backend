import { User } from '../models/user.model.js';
import { ApiResponse } from "../utils/api-response.js";
import { asynHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import jwt from 'jsonwebtoken';
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";

export const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch (error) {
        console.error('Error generating tokens:', error);
        throw new ApiError(500, 'Internal Server Error');
    }
}

export const registerUser = asynHandler(async (req, res) => {
    const { username, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });

    if (existingUser) {
        throw new ApiError(409, 'User already exists');
    }

    const user = await User.create({ email, password, username, isEmailVerified: false });

    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;

    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: 'Please verify your email',
        mailgenContent: emailVerificationMailgenContent(user?.username,
            `${req.protocol}://${req.get('host')}/api/v1/users/verify-email?token=${unhashedToken}`
        )
    });

    const createdUser = await User.findById(user._id).select('-password -emailVerificationToken -emailVerificationExpiry -refreshToken');

    if (!createdUser) {
        throw new ApiError(500, 'Something went wrong while creating user');
    }

    return res.status(201).json(new ApiResponse(201, { user: createdUser }, 'User registered successfully and verification email sent on your email.'));
});

export const loginUser = asynHandler(async (req, res) => {
    const { username, password, email } = req.body;

    if (!email || !username) {
        throw new ApiError(400, 'Username or Email is required');
    }

    if (!password) {
        throw new ApiError(400, 'Password is required');
    }

    const user = await User.findOne({ $or: [{ email }, { username }] });

    if (!user) {
        throw new ApiError(404, 'User not found');
    }

    const isPasswordMatched = await user.isValidPassword(password);

    if (!isPasswordMatched) {
        throw new ApiError(401, 'Invalid credentials');
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    const loggedInUser = await User.findById(user._id).select('-password -emailVerificationToken -emailVerificationExpiry -refreshToken');

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    }

    res.status(200).
        cookie('refreshToken', refreshToken, options).
        cookie('accessToken', accessToken, options).
        json(new ApiResponse(200, { user: loggedInUser }, 'User logged in successfully'));
});

// User Logout: Give me new object after the refresh token is nulled.
export const logoutUser = asynHandler(async (req, res) => {
    const userId = req.user?._id;
    const user = await User.findByIdAndUpdate(userId, {
        $set: { refreshToken: null }
    }, { new: true });

    const options = {
        httpOnly: true,
        secure: true
    };

    return res.status(200).
        clearCookie('refreshToken', options).
        clearCookie('accessToken', options).
        json(new ApiResponse(200, {}, 'User logged out successfully'));
});

export const getCurrentUser = asynHandler(async (req, res) => {
    const userId = req.user?._id;
    const user = await User.findById(userId).select('-password -emailVerificationToken -emailVerificationExpiry -refreshToken');

    if (!user) {
        throw new ApiError(404, 'User not found');
    }

    return res.status(200).json(new ApiResponse(200, { user }, 'Current user fetched successfully'));
});

export const verifyEmail = asynHandler(async (req, res) => {
    const { token } = req.params;

    if (!token) {
        throw new ApiError(400, 'Token is required');
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ emailVerificationToken: hashedToken, emailVerificationExpiry: { $gt: Date.now() } });

    if (!user) {
        throw new ApiError(404, 'Invalid or expired token');
    }

    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;
    user.isEmailVerified = true;

    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, { user }, 'Email verified successfully'));
});

export const resendVerificationEmail = asynHandler(async (req, res) => {
    const user = await User.findById(req.user?._id);

    if (!user) {
        throw new ApiError(404, 'User not found');
    }

    if (user.isEmailVerified) {
        throw new ApiError(400, 'Email is already verified');
    }

    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: 'Please verify your email',
        mailgenContent: emailVerificationMailgenContent(user?.username,
            `${req.protocol}://${req.get('host')}/api/v1/users/verify-email?token=${unhashedToken}`
        )
    });

    return res.status(200).json(new ApiResponse(200, {}, 'Verification email resent successfully'));
});

export const refreshAccessToken = asynHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, 'Unauthorized, please login again');
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findOne(decodedToken?._id);

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, 'Refresh token is expired');
        }

        const options = {
            httpOnly: true,
            secure: true,
        };

        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshTokens(user._id);

        user.refreshToken = newRefreshToken;

        await user.save({ validateBeforeSave: false });

        return res.status(200).cookie('accessToken', accessToken, options).cookie('refreshToken', newRefreshToken, options).json(new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, 'Access token refreshed successfully'));
    } catch (error) {
        console.error('Error verifying refresh token:', error);
        throw new ApiError(401, 'Invalid refresh token, please login again');
    }
});

export const forgotPassword = asynHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
        throw new ApiError(400, 'Email is required');
    }

    const user = await User.findOne({ email });

    if (!user) {
        throw new ApiError(404, 'User not found');
    }

    const { unhashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = tokenExpiry;

    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: 'Forgot Password Request',
        mailgenContent: forgotPasswordMailgenContent(user?.username,
            `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unhashedToken}`
        )
    });

    return res.status(200).json(new ApiResponse(200, {}, 'Password reset email sent successfully'));
});

export const resetForgotPassword = asynHandler(async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!token) {
        throw new ApiError(400, 'Token is required');
    }

    if (!newPassword) {
        throw new ApiError(400, 'New password is required');
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({ forgotPasswordToken: hashedToken, forgotPasswordExpiry: { $gt: Date.now() } });

    if (!user) {
        throw new ApiError(404, 'Invalid or expired token');
    }

    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    user.password = newPassword;

    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, {}, 'Password reset successfully'));
});

export const changeCurrentPassword = asynHandler(async (req, res) => {
    const userId = req.user?._id;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        throw new ApiError(400, 'Current password and new password are required');
    }

    const user = await User.findById(userId);

    if (!user) {
        throw new ApiError(404, 'User not found');
    }

    const isPasswordValid = await user.isValidPassword(currentPassword);

    if (!isPasswordValid) {
        throw new ApiError(401, 'Invalid current password');
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(new ApiResponse(200, {}, 'Password changed successfully'))
});