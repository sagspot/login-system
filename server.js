import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import boxen from 'boxen';
import chalk from 'chalk';

import database from './db.js';
import users from './components/users/users.js';
import sendEmail from './components/utils/mailer.js';

dotenv.config();

const app = express();

app.use(cors());

app.use(morgan('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use('/api/v1/users', users);

app.use((req, res, next) => {
  const error = new Error('Not found');
  error.status = 404;
  next(error);
});

app.use((error, req, res, next) => {
  res.status(error.status || 500).json({
    error: { message: error.message },
  });
});

const PORT = process.env.port || 4000;

const server = async () => {
  try {
    await database();

    await app.listen(PORT);
    console.log(
      boxen(chalk.cyan.bold(`Server listening on port ${PORT}...`), {
        padding: 1,
      })
    );
  } catch (err) {
    console.log(
      boxen(chalk.red(`Server connection failed! \n\n ${err.message}`), {
        padding: 1,
      })
    );
    process.exit(1);
  }
};

server();
