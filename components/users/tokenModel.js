import mongoose from 'mongoose';

const resetSchema = new mongoose.Schema({
  userId: { type: 'ObjectId', required: true, ref: 'User' },
  otp: { type: String, required: true },
  expiry: { type: Date, default: Date.now, expires: '10m' },
});

export const ResetToken = mongoose.model('ResetOTP', resetSchema);

const confirmSchema = new mongoose.Schema({
  userId: { type: 'ObjectId', required: true, ref: 'User' },
  token: { type: String, required: true },
  referrer: { type: String },
  expiry: { type: Date, default: Date.now, expires: '24h' },
});

export const ConfirmToken = mongoose.model('ConfirmToken', confirmSchema);
