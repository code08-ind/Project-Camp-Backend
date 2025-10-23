import { body } from "express-validator";

const userRegisterValidator = () => {
    return [
        body('email').trim().notEmpty().withMessage('Email is required').isEmail().withMessage('Email must be a valid email address'),
        body('username').trim().notEmpty().withMessage('Username is required').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long').isLowercase().withMessage('Username must be in lowercase'),
        body('password').trim().notEmpty().withMessage('Password is required').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
        b
    ];
}

const userLoginValidator = () => {
    return [
        body('email').optional().trim().isEmail().withMessage('Email must be a valid email address'),
        body('password').trim().notEmpty().withMessage('Password is required').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    ];
}

const userChangeCurrentPasswordValidator = () => {
    return [
        body('oldPassword').trim().notEmpty().withMessage('Old Password is required').isLength({ min: 6 }).withMessage('Old Password must be at least 6 characters long'),
        body('newPassword').trim().notEmpty().withMessage('New Password is required').isLength({ min: 6 }).withMessage('New Password must be at least 6 characters long'),
    ];
}

const userForgotPasswordValidator = () => {
    return [
        body('email').trim().notEmpty().withMessage('Email is required').isEmail().withMessage('Email must be a valid email address'),
    ];
}

const userResetForgotPasswordValidator = () => {
    return [
        body('newPassword').trim().notEmpty().withMessage('New Password is required').isLength({ min: 6 }).withMessage('New Password must be at least 6 characters long'),
    ];
}

export { userRegisterValidator, userLoginValidator, userChangeCurrentPasswordValidator, userForgotPasswordValidator, userResetForgotPasswordValidator };