import express from 'express';
import {
  users_get_all,
  users_post_register,
  users_post_login,
  users_post_reset,
  users_post_reset_link,
  users_get_one,
  users_post_patch,
  users_delete,
} from './userController.js';
import { authenticate, authorize } from '../middlewares/auth.js';

const router = express.Router();

router
  .get('/', authenticate, authorize('admin'), users_get_all)
  .post('/register', users_post_register)
  .post('/login', users_post_login)
  .post('/reset', users_post_reset)
  .post('/reset/:id/', users_post_reset_link)
  .get('/:id', authenticate, users_get_one)
  .patch('/:id', authenticate, users_post_patch)
  .delete('/:id', authenticate, users_delete);

export default router;
