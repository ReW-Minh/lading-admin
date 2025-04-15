import { Router } from 'express';
import { addBlog, deleteBlog, getAllBlogs, getBlogByRoute, getPublishedBlogs, publishBlog, updateBlog } from '../controllers/blogController';
import { authenticateToken } from '../middleware/auth'

const router = Router();

router.post('/add', authenticateToken, addBlog);
router.get('/get', getBlogByRoute);
router.get('/getAll', authenticateToken, getAllBlogs);
router.get('/getPublished', getPublishedBlogs);
router.post('/publish', authenticateToken, publishBlog);
router.post('/update', authenticateToken, updateBlog);
router.post('/delete', authenticateToken, deleteBlog);

export default router;