import mongoose from 'mongoose';
import boxen from 'boxen';
import chalk from 'chalk';

const database = async () => {
  try {
    const dbParams = {
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
      // useCreateIndex: true,
    };

    await mongoose.connect(process.env.DB, dbParams);
    console.log(
      boxen(chalk.cyan(`Connection to database successful`), { padding: 1 })
    );
  } catch (err) {
    console.log(
      boxen(chalk.red(`Connection to database failed! \n\n ${err}`), {
        padding: 1,
      })
    );
    process.exit(1);
  }
};

export default database;
