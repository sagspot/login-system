import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import sendEmail from '../utils/mailer.js';
import User from './userModel.js';
import { ConfirmToken, ResetToken } from './tokenModel.js';
import {
  registerValidation,
  loginValidation,
  resetPassValidationLink,
  resetPassValidation,
} from '../middlewares/validation.js';

export const users_post_register = async (req, res) => {
  const { error } = registerValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const useremail = await User.findOne({ email: req.body.email.trim() });
  if (useremail && !useremail.isDeleted)
    return res.status(409).send('User already exist. Login Instead.');

  const username = await User.findOne({ username: req.body.username.trim() });
  if (username && !username.isDeleted)
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
      id: savedUser.id,
      name: savedUser.name,
      username: savedUser.username,
      email: savedUser.email,
      role: savedUser.role,
    };

    const token = jwt.sign(loggedUser, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });

    // Activate account
    const activateToken = await new ConfirmToken({
      userId: savedUser.id,
      token: crypto.randomBytes(32).toString('hex'),
    }).save();

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/auth/confirm/${savedUser.id}?token=${activateToken.token}`;

    const recipient = loggedUser.email;
    const subject = 'Confirm your email';
    const email = `<p>Howdy ${loggedUser.name},</p>
  
    <p>Thanks for creating your account. Confirm your email by clicking the link below.</p>
    <a href="${link}"><button>Confirm Account</button></a>`;

    sendEmail(recipient, subject, email);

    return res
      .status(200)
      .json({ user: loggedUser, token, confirmAccount: link });
  } catch (err) {
    return res.status(400).json({ err });
  }
};

export const users_post_confirm_link = async (req, res) => {
  const userId = req.params.id;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid User ID' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.isConfirmed)
      return res.status(400).json({ message: 'Account already confirmed' });

    const token = await ConfirmToken.findOne({ userId: user._id });

    if (token) await token.delete();

    const activateToken = await new ConfirmToken({
      userId: user.id,
      token: crypto.randomBytes(32).toString('hex'),
    }).save();

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/auth/confirm/${user.id}?token=${activateToken.token}`;

    const recipient = user.email;
    const subject = 'Account Confirmed';
    const email = `<p>Howdy ${user.name},</p>    
    <p>Use this link to confirm your account.</p>
    <a href="${link}"><button>Confirm Account</button></a>`;

    sendEmail(recipient, subject, email);

    return res.status(200).json({ message: 'Confirm account', link });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};

export const users_post_confirm = async (req, res) => {
  const userId = req.params.id;
  const confirmAcc = req.query.token;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid or expired link' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user)
      return res.status(404).json({ message: 'Invalid or expired link' });

    const token = await ConfirmToken.findOne({
      userId: user._id,
      token: confirmAcc,
    });

    if (!token)
      return res.status(404).json({ message: 'Invalid or expired link' });

    user.isConfirmed = true;
    await user.save();
    await token.delete();

    const recipient = user.email;
    const subject = 'Account Confirmed';
    const email = `<p>Howdy ${user.name},</p>    
    <p>Account confirmation successfull.</p>`;

    sendEmail(recipient, subject, email);

    return res
      .status(200)
      .json({ message: 'Account confirmation successfull' });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
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
      currentUser.isActive = true;
      currentUser.dateDeactivated = undefined;
      await currentUser.save();

      // Send Email
      const recipient = currentUser.email;
      const subject = 'Account recovered';
      const email = `<p>Howdy ${currentUser.name},</p>  
    <p>Your account has been recovered. Welcome back`;

      sendEmail(recipient, subject, email);
    }

    return res
      .status(200)
      .json({ message: 'Authentication successful', userDetails, token });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

export const users_post_reset_link = async (req, res) => {
  const { error } = resetPassValidationLink(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  try {
    const user = await User.find({
      $or: [{ email: req.body.email }, { username: req.body.username }],
    });

    if (!user || user.length == 0)
      return res.status(401).send('Account not found.');
    const [currentUser] = user;

    const resetUser = await new ResetToken({
      userId: currentUser.id,
      token: crypto.randomBytes(32).toString('hex'),
    }).save();

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/auth/reset/${currentUser.id}?token=${resetUser.token}`;

    const recipient = currentUser.email;
    const subject = 'Reset password';
    const email = `<p>Howdy ${currentUser.name},</p>
    
    <p>You requested to change your password. Click the link below to change your password.</p>
    <a href="${link}"><button>Reset Password</button></a>`;

    sendEmail(recipient, subject, email);

    return res
      .status(200)
      .json({ message: 'Password reset initiated', resetPassword: link });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};

export const users_post_reset = async (req, res) => {
  const userId = req.params.id;
  const resetPass = req.query.token;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid or expired link' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user)
      return res.status(404).json({ message: 'Invalid or expired link' });

    const token = await ResetToken.findOne({
      userId: user._id,
      token: resetPass,
    });

    if (!token)
      return res.status(404).json({ message: 'Invalid or expired link' });

    const { error } = resetPassValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const hash = await bcrypt.hashSync(req.body.password, 10);
    user.password = hash;
    await user.save();
    await token.delete();

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/auth/reset`;

    const recipient = user.email;
    const subject = 'Password changed';
    const email = `<p>Howdy ${user.name},</p>
    
    <p>Your password has been successfully reset.</p>
    <p>If you did not perform this action, your account might be compromised. Please change your password by clicking on the link below</p>
    
    <a href="${link}"><button>Change Password</button></a>`;

    sendEmail(recipient, subject, email);

    return res.status(200).json({ message: 'Password reset sucessfully' });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};
