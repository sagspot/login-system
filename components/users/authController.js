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

/**
 * @desc Register a new user
 * @route POST /api/v1/users/auth/register
 * @access Public
 */
export const users_post_register = async (req, res) => {
  const { error } = registerValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const useremail = await User.findOne({
    email: req.body.email.trim().toLowerCase(),
  });
  if (useremail && !useremail.isDeleted)
    return res.status(409).send('User already exists. Login Instead.');

  const username = await User.findOne({
    username: req.body.username.trim().toLowerCase(),
  });
  if (username && !username.isDeleted)
    return res.status(409).send('User already exists. Login Instead.');

  const hash = await bcrypt.hashSync(req.body.password, 10);

  const newUser = new User({
    name: req.body.name,
    username: req.body.username.toLowerCase(),
    email: req.body.email.toLowerCase(),
    password: hash,
  });

  try {
    const savedUser = await newUser.save();

    const token = jwt.sign(
      { id: savedUser.id, role: savedUser.role },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRATION,
      }
    );

    const user = {
      id: savedUser.id,
      name: savedUser.name,
      username: savedUser.username,
      email: savedUser.email,
      role: savedUser.role,
      isConfirmed: savedUser.isConfirmed,
    };

    // Account activation link
    const activateToken = await new ConfirmToken({
      userId: user.id,
      token: crypto.randomBytes(32).toString('hex'),
      referrer: req.header('Referer'),
    }).save();

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/auth/confirm/${user.id}?token=${activateToken.token}`;

    const recipient = user.email;
    const subject = 'Confirm your Sagspot account';
    const email = {
      text: `${user.name},
      Thanks for creating your Sagspot account. To get the most of Sagpot, please confirm your account by clicking the link below, 
      or copy and paste it in your favorite browser.
      <a href="${link}">${link}</a>
      - Team Sagspot`,

      html: `<p>${user.name},</p>
      <p>Thanks for creating your Sagspot account. To get the most of Sagpot, please confirm your account by clicking the link below, 
      or copr and paste it in your favorite browser.</p>
      <a href="${link}">${link}</a>
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    return res
      .status(200)
      .json({ message: 'Registration successful', user, AuthToken: token });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

/**
 * @desc Generate account confirmation link
 * @route GET /auth/register/confirm/:id
 * @access Private
 */
export const users_post_confirm_link = async (req, res) => {
  const userId = req.params.id;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid User ID' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user) return res.status(404).json({ message: 'Account not found' });

    if (req.userData.role === 'user' && req.userData.id !== user.id)
      return res
        .status(403)
        .json({ message: 'Not authorized to perform this action' });

    if (user.isConfirmed)
      return res.status(400).json({ message: 'Account already confirmed' });

    const token = await ConfirmToken.findOne({ userId: user._id });

    if (token) await token.delete();

    const activateToken = await new ConfirmToken({
      userId: user.id,
      token: crypto.randomBytes(32).toString('hex'),
      referrer: req.header('Referer'),
    }).save();

    const baseUrl = `${req.protocol}://${req.get('host')}`;

    const link = `${baseUrl}/api/v1/users/auth/confirm/${user.id}?token=${activateToken.token}`;

    const recipient = user.email;
    const subject = 'Confirm your Sagspot account';

    const email = {
      text: `${user.name},
      Use the link below to confirm your Sagspot account.
      <a href="${link}">${link}</a>
      - Team Sagspot`,

      html: `<p>${user.name},</p>
      <p>Use the link below to confirm your Sagspot account.</p>
      <a href="${link}">${link}</a>
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    return res.status(200).json({ message: 'Account confirmation link sent' });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

/**
 * @desc Account confirmation link
 * @route GET /auth/confirm/:id
 * @access Public
 */
export const users_post_confirm = async (req, res, done) => {
  const userId = req.params.id;
  const confirmationToken = req.query.token;

  const validateObjectId = await mongoose.isValidObjectId(userId);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid or expired otp' });

  try {
    const user = await User.findById(userId, { password: 0 });
    if (!user)
      return res.status(404).json({ message: 'Invalid or expired otp' });

    const token = await ConfirmToken.findOne({
      userId: user._id,
      token: confirmationToken,
    });

    if (!token)
      return res.status(404).json({ message: 'Invalid or expired otp' });

    const referrer = token.referrer;

    user.isConfirmed = true;
    await user.save();
    await token.delete();

    const recipient = user.email;
    const subject = 'Your Sagspot account confirmed';
    const email = {
      text: `${user.name},
      Your account confirmation was successfull. Welcome to Sagspot
      - Team Sagspot`,

      html: `<p>${user.name},</p>
      <p>Your account confirmation was successfull. Welcome to Sagspot</p>
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    if (referrer !== undefined) return done(res.redirect(referrer));

    return res.status(200).json({ message: 'Account confirmation successful' });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

/**
 * @desc Login a user
 * @route POST /api/v1/users/auth/login
 * @access Public
 */
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
    const { id, name, username, email, role, isActive, isConfirmed } =
      currentUser;
    const token = jwt.sign({ id, role }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });

    const userInfo = { id, name, username, email, role, isConfirmed };

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
      .json({
        message: 'Authentication successful',
        user: userInfo,
        AuthToken: token,
      });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

/**
 * @desc Password reset otp
 * @route POST /api/v1/users/auth/reset
 * @access Public
 */
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

    const OTPExists = await ResetToken.findOne({ userId: currentUser._id });

    if (OTPExists) await OTPExists.delete();

    const resetUser = await new ResetToken({
      userId: currentUser.id,
      otp: Math.floor(Math.random() * 999999),
    }).save();

    const recipient = currentUser.email;
    const subject = 'Reset your Sagspot password';
    const email = {
      text: `${currentUser.name},
      We have received a request to reset your password.
      Use the otp below within the next 10 minutes to reset your password. If you did not perform this action, disregard this email and don't do anything.
      Do not share this otp with anyone as it can be used to reset your password and grant access to your account.
      ${resetUser.otp}
      - Team Sagspot`,

      html: `<p>${currentUser.name},</p>
      <p>We have received a request to reset your password.</p>
      <p>Use the otp below within the next 10 minutes to reset your password. If you did not perform this action, disregard this email and don't do anything.</p>
      <p>Do not share this otp with anyone as it can be used to reset your password and grant access to your account.</p>
      ${resetUser.otp}
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    return res
      .status(200)
      .json({ message: 'Password reset initiated', userId: currentUser.id });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};

/**
 * @desc Reset password
 * @route POST /api/v1/users/auth/reset/:id
 * @access Public
 */
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
      Your password has been successfully reset.
      If you did not perform password reset, your account may have been compromised. 
      Please change your password by clicking on the link below or copy and paste it in your favorite browser
      <a href="${link}">${link}</a>
      - Team Sagspot`,

      html: `<p>${user.name},</p>
      <p>Your password has been successfully reset.</p>
      <p>If you did not perform password reset, your account may have been compromised. 
      Please change your password by clicking on the link below or copy and paste it in your favorite browser</p>
      <a href="${link}">${link}</a>
      <p>- Team Sagspot</p>`,
    };

    sendEmail(recipient, subject, email);

    return res.status(200).json({ message: 'Password reset sucessfully' });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};
