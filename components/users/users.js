import express from 'express';
import {
  users_get_all,
  users_post_register,
  users_post_login,
  users_get_one,
  users_post_patch,
  users_post_reset,
  users_post_reset_link,
} from './userController.js';
import { authenticate, authorize } from '../middlewares/auth.js';

const router = express.Router();

router
  .get('/', authenticate, authorize('admin'), users_get_all)
  .post('/register', users_post_register)
  .post('/login', users_post_login)
  .get('/:id', authenticate, users_get_one)
  .patch('/:id', authenticate, users_post_patch)
  .post('/reset', users_post_reset)
  .post('/reset/:id/', users_post_reset_link);

export default router;
