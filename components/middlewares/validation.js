import Joi from 'joi';

export const registerValidation = (data) => {
  const schema = Joi.object({
    name: Joi.string().min(3).max(255).required(),
    username: Joi.string().alphanum().min(4).max(16),
    email: Joi.string().email().required(),
    password: Joi.string().min(4).required(),
  });

  return schema.validate(data);
};

export const loginValidation = (data) => {
  const schema = Joi.object({
    username: Joi.string(),
    email: Joi.string().email(),
    password: Joi.string().required(),
  }).xor('username', 'email');

  return schema.validate(data);
};

export const updateUserValidation = (data) => {
  const schema = Joi.object({
    name: Joi.string().min(3).max(255),
    username: Joi.string().alphanum().min(4).max(16),
    email: Joi.string().email(),
    password: Joi.string().min(4),
  });

  return schema.validate(data);
};

export const resetPassValidationLink = (data) => {
  const schema = Joi.object({
    username: Joi.string(),
    email: Joi.string().email(),
  }).xor('username', 'email');

  return schema.validate(data);
};

export const resetPassValidation = (data) => {
  const schema = Joi.object({
    otp: Joi.string().required(),
    password: Joi.string().min(4).required(),
  });

  return schema.validate(data);
};
