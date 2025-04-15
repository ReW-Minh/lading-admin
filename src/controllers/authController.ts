import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { success, error } from '../utils';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || '030c9d0d-0158-4de9-a50a-8cb7df06a32e';

export const register = async (req: Request, res: Response) => {
    try {
        const { username, password, confirm } = req.body;

        // Ensure username was submitted
        if (!username) {
            return error(res, 'Must provide username', 400);
        }

        // Ensure password was submitted
        if (!password) {
            return error(res, 'Must provide password', 400);
        }

        // Ensure confirmation password was submitted
        if (!confirm) {
            return error(res, 'Must provide confirmation password', 400);
        }

        // Ensure password and confirmation password are matched
        if (confirm !== password) {
            return error(res, 'Passwords do not match', 400);
        }

        // Check if user exists
        const existingUser = await prisma.user.findUnique({
            where: { username },
        });

        if (existingUser) {
            return error(res, 'Username already exists', 400);
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        await prisma.user.create({
            data: {
                username,
                password: hashedPassword,
            },
        });

        return success(res, 'Registered successfully');
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const login = async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;

        // Ensure username was submitted
        if (!username) {
            return error(res, 'Must provide username', 400);
        }

        // Ensure password was submitted
        if (!password) {
            return error(res, 'Must provide password', 400);
        }

        // Find user
        const user = await prisma.user.findUnique({
            where: { username },
        });

        // Check if user exists and password is correct
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return error(res, 'Invalid username and/or password', 400);
        }

        // Generate token
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);

        return success(res, 'Logged in successfully', {
            username: user.username,
            token,
        });
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const changePassword = async (req: Request, res: Response) => {
    try {
        const { currentPassword, newPassword, confirm } = req.body;
        const userId = req.user.id;

        // Ensure current password was submitted
        if (!currentPassword) {
            return error(res, 'Must provide old password', 400);
        }

        // Ensure new password was submitted
        if (!newPassword) {
            return error(res, 'Must provide password', 400);
        }

        // Ensure confirmation password was submitted
        if (!confirm) {
            return error(res, 'Must provide confirmation password', 400);
        }

        // Ensure password and confirmation password are matched
        if (confirm !== newPassword) {
            return error(res, 'Passwords do not match', 400);
        }

        // Find user
        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        // Check if current password is correct
        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            return error(res, 'Incorrect current password', 400);
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword },
        });

        return success(res, 'Updated successfully');
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};