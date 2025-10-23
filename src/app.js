import express from 'express';
import dotenv from 'dotenv';
import connectDB from './db/index.js';
import cors from 'cors';
import healthCheckRouter from './routes/healthcheck.route.js';
import authRouter from './routes/auth.route.js';
import cookieParser from 'cookie-parser';

dotenv.config({
  path: './.env'
});

connectDB();

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware setup
app.use(cors({ 
  origin: process.env.CORS_ORIGIN.split(',') || "http://localhost:5173", 
  credentials: true, 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(cookieParser());
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));

app.use('/api/v1/healthcheck', healthCheckRouter);
app.use('/api/v1/auth', authRouter);

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
}).then(() => {
  console.log('Database connected and server started successfully');
  process.exit(1);
}).catch((error) => {
  console.error('Error starting server:', error);
});
