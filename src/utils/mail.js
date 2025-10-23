import Mailgen from 'mailgen';
import nodemailer from 'nodemailer';

// Configure mailgen
const emailVerificationMailgenContent = (username, verificationUrl) => {
    return {
        body: {
            name: username,
            intro: 'Welcome to Project Camp! We\'re very excited to have you on board.',
            action: {
                instructions: 'Please click the button below to verify your email address.',
                button: {
                    color: '#22BC66',
                    text: 'Verify Email',
                    link: verificationUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
}

const forgotPasswordMailgenContent = (username, resetUrl) => {
    return {
        body: {
            name: username,
            intro: 'We received a request to reset your password.',
            action: {
                instructions: 'Please click the button below to reset your password.',
                button: {
                    color: '#22BC66',
                    text: 'Reset Password',
                    link: resetUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
}

// Send email
const sendEmail = async (options) => {
    // branding of mailgen
    const mailgenerator = new Mailgen({
        theme: 'default',
        product: {
            name: 'Project Camp',
            link: 'https://project-camp.com/'
        }
    });

    const emailTextual = mailgenerator.generatePlaintext(options.mailgenContent);
    const emailHTML = mailgenerator.generate(options.mailgenContent);

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user: process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASS
        }
    });

    const mailOptions = {
        from: 'mail@project-camp.com',
        to: options.email,
        subject: options.subject,
        text: emailTextual,
        html: emailHTML
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

export { emailVerificationMailgenContent, forgotPasswordMailgenContent, sendEmail };