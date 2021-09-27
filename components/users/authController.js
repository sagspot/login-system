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
    const subject = 'Confirm your Sagspot account';
    const email = {
      text: `${loggedUser.name},
      Thanks for creating your Sagspot account. To get the most of Sagpot, please confirm your account by clicking the link below, 
      or copr and paste it in your favorite browser.
      <a href="${link}">${link}</a>
      - Team Sagspot`,

      html: `<p>${loggedUser.name},</p>
      <p>Thanks for creating your Sagspot account. To get the most of Sagpot, please confirm your account by clicking the link below, 
      or copr and paste it in your favorite browser.</p>
      <a href="${link}">${link}</a>
      <p>- Team Sagspot</p>`,
    };

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
    const subject = 'Confirm your Sagspot account';

    const email = {
      text: `${user.name},
      Use the link below to confirm your account.
      <a href="${link}">${link}</a>
      - Team Sagspot`,

      html: `<p>${user.name},</p>
      <p>Use the link below to confirm your account.</p>
      <a href="${link}">${link}</a>
      <p>- Team Sagspot</p>`,
    };

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
    const subject = 'Your Sagspot account confirmed';
    const email = {
      text: `${user.name},
      Your account confirmation was successfull. Welcome to Sagspot
      - Team Sagspot`,

      html: `<p>Howdy ${er.name},</p>
      <p>Your account confirmation was successfull. Welcome to Sagspot</p>
      <p>- Team Sagspot</p>`,
    };

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
      const subject = 'Your Sagspot account has been recovered';
      const email = {
        text: `${currentUser.name},
        Your account has been recovered. Welcome back
        - Team Sagspot`,

        html: `<p>Howdy ${currentUser.name},</p>
        <p>Your account has been recovered. Welcome back</p>
        <p>- Team Sagspot</p>`,
      };

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
      otp: Math.floor(Math.random() * 999999),
    }).save();

    const recipient = currentUser.email;
    const subject = 'Reset your Sagspot password';
    const email = {
      text: `${currentUser.name},
      We have received a request to reset your password.
      Use the otp below within the next 10 minutes to reset your password. If you ignore this message, your password won’t be changed.
      ${resetUser.otp}
      - Team Sagspot`,

      html: `<p>${currentUser.name},</p>
      <p>We have received a request to reset your password.</p>
      <p>Use the otp below within the next 10 minutes to reset your password. If you ignore this message, your password won’t be changed.</p>
      ${resetUser.otp}
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    return res
      .status(200)
      .json({ message: 'Password reset initiated', resetUser });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};

export const users_post_reset = async (req, res) => {
  const userId = req.params.id;
  const OTP = req.body.otp;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid or expired OTP' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user)
      return res.status(404).json({ message: 'Invalid or expired OTP' });

    const resetUserOTP = await ResetToken.findOne({
      userId: user._id,
      OTP,
    });

    if (!resetUserOTP)
      return res.status(404).json({ message: 'Invalid or expired OTP' });

    const { error } = resetPassValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const hash = await bcrypt.hashSync(req.body.password, 10);
    user.password = hash;
    await user.save();
    await resetUserOTP.delete();

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/auth/reset`;

    const recipient = user.email;
    const subject = 'Your Sagspot password was reset';
    const email = {
      text: `${user.name},
      The password for your account has just been reset.
      Your password has been successfully reset.
      If you did not perform password reset, your account may have been compromised. 
      Please change your password by clicking on the link below or copy and paste it in your favorite browser
      <a href="${link}">${link}</a>
      - Team Sagspot`,

      html: `<p>${user.name},</p>
      <p>The password for your account has just been reset.</p>
      <p>Your password has been successfully reset.</p>
      <p>If you did not perform password reset, your account may have been compromised. 
      Please change your password by clicking on the link below or copy and paste it in your favorite browser</p>
      <a href="${link}">${link}</a>
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    return res.status(200).json({ message: 'Password reset sucessfully' });
  } catch (err) {
    return res.status(500).json({ message: 'An error occurred', err });
  }
};
