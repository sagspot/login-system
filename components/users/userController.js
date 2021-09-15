import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import User from './userModel.js';
import Token from './tokenModel.js';
import {
  registerValidation,
  loginValidation,
  updateUserValidation,
  resetPassValidation,
} from '../middlewares/validation.js';
import sendEmail from '../utils/mailer.js';

export const users_get_all = async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    if (users.length === 0)
      return res.status(404).json({ message: 'No users found' });

    return res.status(200).json({ users });
  } catch (err) {
    return res.status(500).json({ err });
  }
};

export const users_post_register = async (req, res) => {
  const { error } = registerValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const useremail = await User.findOne({ email: req.body.email.trim() });
  if (useremail && !isDeleted)
    return res.status(409).send('User already exist. Login Instead.');

  const username = await User.findOne({ username: req.body.username.trim() });
  if (username && !isDeleted)
    return res.status(409).send('User already exist. Login Instead.');

  const hash = await bcrypt.hashSync(req.body.password, 10);

  const newUser = new User({
    name: req.body.name,
    username: req.body.username,
    email: req.body.email,
    password: hash,
  });

  try {
    const savedUser = await newUser.save();

    const loggedUser = {
      id: savedUser._id,
      name: savedUser.name,
      username: savedUser.username,
      email: savedUser.email,
      role: savedUser.role,
    };

    const token = jwt.sign(loggedUser, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });

    const recipient = loggedUser.email;
    const subject = 'Confirm your email';
    const email = `<p>Howdy ${loggedUser.name},</p>
  
    <p>Thanks for creating your account. Confirm your email by clicking the link below.</p>
    <a href="https://sagspot.co.ke"><button>Link</button></a>`;

    return res.status(200).json({ user: loggedUser, token });
    // return sendEmail(recipient, subject, email);
  } catch (err) {
    return res.status(400).json({ err });
  }
};

export const users_post_login = async (req, res) => {
  const { error } = loginValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const user = await User.find({
    $or: [{ email: req.body.email }, { username: req.body.username }],
  });

  if (!user || user.length == 0) return res.status(401).send('Auth failed');
  const [currentUser] = user;

  const validPassword = await bcrypt.compareSync(
    req.body.password,
    currentUser.password
  );

  if (!validPassword) return res.status(401).send('Authentication failed');

  try {
    const { id, name, username, email, role, isActive } = currentUser;
    const userDetails = { id, name, username, email, role };

    const token = jwt.sign(
      { id, name, username, email, role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION }
    );

    if (!isActive) {
      user[0].isActive = true;
      user[0].dateDeactivated = undefined;
      await user.save();
      console.log('Account restored');
    }

    return res
      .status(200)
      .json({ message: 'Authentication successful', userDetails, token });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

export const users_post_reset = async (req, res) => {
  const { error } = resetPassValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  try {
    const user = await User.find({
      $or: [{ email: req.body.email }, { username: req.body.username }],
    });

    if (!user || user.length == 0)
      return res.status(401).send('Account not found.');
    const [currentUser] = user;

    const resetToken = await new Token({
      userId: currentUser.id,
      token: crypto.randomBytes(32).toString('hex'),
    }).save();

    const link = `/api/v1/users/reset/${currentUser._id}?token=${resetToken.token}`;

    const recipient = loggedUser.email;
    const subject = 'Reset password';
    const email = `<p>Howdy ${loggedUser.name},</p>
  
    <p>You requested to change your password. Click the link below to change your password.</p>
    <a href="${link}"><button>Link</button></a>`;

    // sendEmail(recipient, subject, email);

    return res.status(200).json({ message: 'Password reset link sent.', link });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};

export const users_post_reset_link = async (req, res) => {
  const userId = req.params.id;
  const resetToken = req.query.token;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid or expired link' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user)
      return res.status(404).json({ message: 'Invalid or expired link' });

    const token = await Token.findOne({
      userId: user._id,
      token: resetToken,
    });

    if (!token)
      return res.status(404).json({ message: 'Invalid or expired link' });

    const hash = await bcrypt.hashSync(req.body.password, 10);
    user.password = hash;
    await user.save();
    await token.delete();

    return res.status(200).json({ message: 'Password reset sucessfully' });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};

export const users_get_one = async (req, res) => {
  const id = req.params.id;

  const validateObjectId = await mongoose.isValidObjectId(id);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid user ID' });

  try {
    const user = await User.findById(id, { password: 0 });

    if (!user) return res.status(404).json({ message: 'User not found' });

    if (req.userData.role === 'user' && req.userData.id !== user.id)
      return res
        .status(403)
        .json({ message: 'Not authorized to view this resource' });

    return res.status(200).json({ user });
  } catch (err) {
    return res.status(500).json({ err });
  }
};

export const users_post_patch = async (req, res) => {
  const { error } = updateUserValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const id = req.params.id;
  const validateObjectId = await mongoose.isValidObjectId(id);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid user ID' });

  try {
    const user = await User.findById(id, { password: 0 });

    if (!user) return res.status(404).json({ message: 'User not found' });

    if (req.userData.role === 'user' && req.userData.id !== user.id)
      return res
        .status(403)
        .json({ message: 'Not authorized to update this resource' });

    const updateUser = await User.update(
      { _id: id },
      {
        $set: {
          name: req.body.name ? req.body.name : user.name,
          username: req.body.username ? req.body.username : user.username,
          email: req.body.email ? req.body.email : user.email,
        },
      }
    );

    return res.status(200).json({ message: 'user updated', updateUser });
  } catch (err) {
    return res.status(500).json({ err });
  }
};

export const users_delete = async (req, res) => {
  const id = req.params.id;

  const validateObjectId = await mongoose.isValidObjectId(id);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid user ID' });

  try {
    const user = await User.findById(id, { password: 0 });

    if (!user) return res.status(404).json({ message: 'User not found' });

    if (req.userData.role === 'user' && req.userData.id !== user.id)
      return res
        .status(403)
        .json({ message: 'Not authorized to delete account' });

    user.isActive = false;
    user.dateDeactivated = Date.now();
    await user.save();

    return res.status(200).json({
      message:
        'Account temporarily deleted. If you wish to recover your account, please login within 30 days. Your account will be permanently deleted after 30 days and you cannot recover your data',
    });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};
