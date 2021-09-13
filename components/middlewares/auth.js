import jwt from 'jsonwebtoken';

export const authenticate = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userData = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Authentication failed' });
  }
};

export const authorize = (...roles) => {
  return (req, res, next) => {
    console.log(req.userData);
    if (!roles.includes(req.userData.role))
      return next(res.status(403).send('Access denied'));
    next();
  };
};
