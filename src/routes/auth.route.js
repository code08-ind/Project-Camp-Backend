import { Router } from "express";
import { changeCurrentPassword, forgotPassword, getCurrentUser, loginUser, logoutUser, refreshAccessToken, registerUser, resendVerificationEmail, resetForgotPassword, verifyEmail } from "../controllers/auth.controller";
import { validate } from "../middlewares/validator.middleware";
import { userForgotPasswordValidator, userLoginValidator, userRegisterValidator, userResetForgotPasswordValidator } from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const authRouter = Router();

// User Registration when we capture user details and validate the data.
// unsecured routes
authRouter.route("/register").post(userRegisterValidator(), validate, registerUser);
authRouter.route("/login").post(userLoginValidator(), validate, loginUser);
authRouter.route("/verify-email/:verificationToken").get(verifyEmail);
authRouter.route("/refresh-token").post(refreshAccessToken);
authRouter.route("/forgot-password").post(userForgotPasswordValidator(), validate, forgotPassword);
authRouter.route("/reset-password/:resetToken").post(userResetForgotPasswordValidator(), validate, resetForgotPassword);


// secured routes
authRouter.route("/logout").post(verifyJWT, logoutUser);
authRouter.route("/current-user").get(verifyJWT, getCurrentUser);
authRouter.route("/change-password").post(verifyJWT, userResetForgotPasswordValidator(), validate, changeCurrentPassword);
authRouter.route("/resend-verification-email").post(verifyJWT, resendVerificationEmail);

export default authRouter;