import mongoose from 'mongoose';

const tokenSchema = new mongoose.Schema({
  userId: { type: 'ObjectId', required: true, ref: 'User' },
  token: { type: String, required: true },
  expiry: { type: Date, default: Date.now, expires: '10m' },
});

export default mongoose.model('Token', tokenSchema);
