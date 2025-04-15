import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { success, error, getCurrentMs } from '../utils';

const prisma = new PrismaClient();

export const addBlog = async (req: Request, res: Response) => {
    try {
        const { title, author, route, content } = req.body;

        if (!title || !author || !route || !content) {
            return error(res, 'You have not filled in the required field(s)', 400);
        }

        // Check if route exists
        const existingBlog = await prisma.blog.findUnique({
            where: { route }
        });

        if (existingBlog) {
            return error(res, 'Route already exists', 400);
        }

        // Create blog
        await prisma.blog.create({
            data: {
                title,
                author,
                route,
                content,
                is_published: false,
                created_time: getCurrentMs()
            }
        });

        return success(res, 'OK');
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const getBlogByRoute = async (req: Request, res: Response) => {
    try {
        const route = req.query.route as string;

        const blog = await prisma.blog.findUnique({
            where: { route }
        });

        if (!blog) {
            return error(res, 'Blog not found', 404);
        }

        return success(res, 'OK', blog);
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const getAllBlogs = async (req: Request, res: Response) => {
    try {
        const page = Number(req.query.page);
        const per_page = Number(req.query.per_page);

        if (!page || !per_page) {
            return error(res, 'Missing required parameters', 400);
        }

        const skip = (page - 1) * per_page;

        // Get total count
        const total = await prisma.blog.count();

        // Get blogs for page
        const blogs = await prisma.blog.findMany({
            orderBy: {
                created_time: 'desc'
            },
            skip,
            take: per_page
        });

        return success(res, 'OK', { blogs, total });
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const getPublishedBlogs = async (req: Request, res: Response) => {
    try {
        const page = Number(req.query.page);
        const per_page = Number(req.query.per_page);

        if (!page || !per_page) {
            return error(res, 'Missing required parameters', 400);
        }

        const skip = (page - 1) * per_page;

        // Get total count
        const total = await prisma.blog.count({
            where: { is_published: true }
        });

        // Get blogs for page
        const blogs = await prisma.blog.findMany({
            where: { is_published: true },
            orderBy: {
                publish_time: 'desc'
            },
            skip,
            take: per_page
        });

        return success(res, 'OK', { blogs, total });
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const publishBlog = async (req: Request, res: Response) => {
    try {
        const { id } = req.body;

        if (!id) {
            return error(res, 'Missing blog ID', 400);
        }

        // Find blog
        const blog = await prisma.blog.findUnique({
            where: { id: Number(id) }
        });

        if (!blog) {
            return error(res, 'Blog not found', 404);
        }

        // Update blog
        await prisma.blog.update({
            where: { id: Number(id) },
            data: {
                is_published: true,
                publish_time: getCurrentMs()
            }
        });

        return success(res, 'OK');
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const updateBlog = async (req: Request, res: Response) => {
    try {
        const { id, title, author, route, content } = req.body;

        if (!id) {
            return error(res, 'Missing blog ID', 400);
        }

        if (!title || !author || !route || !content) {
            return error(res, 'You have not filled in the required field(s)', 400);
        }

        // Find blog
        const blog = await prisma.blog.findUnique({
            where: { id: Number(id) }
        });

        if (!blog) {
            return error(res, 'Blog not found', 404);
        }

        // Check if route exists and belongs to another blog
        if (blog.route !== route) {
            const existingBlog = await prisma.blog.findUnique({
                where: { route }
            });

            if (existingBlog) {
                return error(res, 'Route already exists', 400);
            }
        }

        // Update blog
        await prisma.blog.update({
            where: { id: Number(id) },
            data: {
                title,
                author,
                route,
                content
            }
        });

        return success(res, 'OK');
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};

export const deleteBlog = async (req: Request, res: Response) => {
    try {
        const { id } = req.body;

        if (!id) {
            return error(res, 'Missing blog ID', 400);
        }

        // Find blog
        const blog = await prisma.blog.findUnique({
            where: { id: Number(id) }
        });

        if (!blog) {
            return error(res, 'Blog not found', 404);
        }

        // Delete blog
        await prisma.blog.delete({
            where: { id: Number(id) }
        });

        return success(res, 'OK');
    } catch (err) {
        console.error(err);
        return error(res, 'Server error', 500);
    }
};