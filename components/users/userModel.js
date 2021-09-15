import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, min: 3, max: 255, trim: true },
    username: {
      type: String,
      unique: true,
      required: true,
      min: 4,
      max: 16,
      trim: true,
    },
    email: { type: String, unique: true, required: true, trim: true },
    password: { type: String, required: true, min: 6, max: 1024 },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    isConfirmed: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    dateDeactivated: { type: Date },
    isDeleted: { type: Boolean, default: false },
    dateDeleted: { type: Date },
  },
  { timestamps: true }
);

export default mongoose.model('User', userSchema);
