import express from 'express';

import {
  users_post_register,
  users_post_confirm_link,
  users_post_confirm,
  users_post_login,
  users_post_reset,
  users_post_reset_link,
} from './authController.js';

import {
  users_get_all,
  users_get_one,
  users_post_patch,
  users_delete,
} from './userController.js';
import { authenticate, authorize } from '../middlewares/auth.js';

const router = express.Router();

router
  .post('/auth/register', users_post_register)
  .post('/auth/register/confirm/:id', users_post_confirm_link)
  .post('/auth/confirm/:id', users_post_confirm)
  .post('/auth/login', users_post_login)
  .post('/auth/reset', users_post_reset_link)
  .post('/auth/reset/:id', users_post_reset);

router
  .get('/', authenticate, authorize('admin'), users_get_all)
  .get('/:id', authenticate, users_get_one)
  .patch('/:id', authenticate, users_post_patch)
  .delete('/:id', authenticate, users_delete);

export default router;
