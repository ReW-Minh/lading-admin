import { Router } from 'express';
import { register, login, changePassword } from '../controllers/authController';
import { authenticateToken } from '../middleware/auth';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/changePassword', authenticateToken, changePassword);

export default router;