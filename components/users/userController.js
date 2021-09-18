import mongoose from 'mongoose';

import sendEmail from '../utils/mailer.js';
import User from './userModel.js';
import { updateUserValidation } from '../middlewares/validation.js';

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

export const users_get_one = async (req, res) => {
  const id = req.params.id;

  const validateObjectId = await mongoose.isValidObjectId(id);
  if (!validateObjectId)
    return res.status(400).json({ message: 'Invalid user ID' });

  try {
    const user = await User.findById(id, { password: 0 });
    console.log(user.isDeleted);
    if (!user || user.isDeleted)
      return res.status(404).json({ message: 'User not found' });

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

    const updateUser = await User.findByIdAndUpdate(
      { _id: id },
      {
        $set: {
          name: req.body.name ? req.body.name : user.name,
          username: req.body.username ? req.body.username : user.username,
          email: req.body.email ? req.body.email : user.email,
        },
      },
      { new: true }
    );

    const recipient = updateUser.email;
    const subject = 'Account updated';
    const email = {
      text: `Howdy ${updateUser.name},
      Account details updated.`,

      html: `<p>Howdy ${updateUser.name},</p>
      <p>Account details updated</p>.`,
    };

    sendEmail(recipient, subject, email);

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

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link = `${baseUrl}/api/v1/users/reset`;

    const recipient = user.email;
    const subject = 'Account Deactivated';
    const email = {
      text: `Howdy ${user.name},
      Your account has been temporarily deactivated. If you wish to recover your account, please login within 30 days.
      If not recovered within 30 days, your account will permanently be deactivated and you cannot recover your data.
      If you did not perform this action, your account might be compromised. Please change your password by clicking on the link below.
      <a href="${link}">${link}</a>`,

      html: `<p>Howdy ${user.name},</p>
      <p>Your account has been temporarily deactivated. If you wish to recover your account, please login within 30 days.
      If not recovered within 30 days, your account will permanently be deactivated and you cannot recover your data</p>
      <p>If you did not perform this action, your account might be compromised. Please change your password by clicking on the link below</p>
      <a href="${link}"><button>Change Password</button></a>`,
    };

    sendEmail(recipient, subject, email);

    return res.status(200).json({
      message:
        'Account temporarily deactivated. Will be permanently deactivated after 30 days if not recovered',
    });
  } catch (err) {
    return res.status(500).json({ message: 'Something went wrong', err });
  }
};
