import express, { Express } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import authRoutes from './routes/authRoutes';
import podcastRoutes from './routes/podcastRoutes';
import blogRoutes from './routes/blogRoutes';

dotenv.config();

const app: Express = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Routes
app.use('/', authRoutes);
app.use('/', podcastRoutes);
app.use('/blog', blogRoutes);

export default app;