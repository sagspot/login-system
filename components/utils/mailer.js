import nodemailer from 'nodemailer';

const sendEmail = async (recipient, subject, email) => {
  try {
    const transporter = nodemailer.createTransport({
      pool: true,
      host: process.env.SMTP_HOST,
      port: 465,
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    });

    const mailOptions = {
      from: {
        name: 'Advanced Login System',
        address: process.env.SMTP_USER,
      },
      to: recipient,
      subject,
      // text,
      html: email,
    };

    await transporter.sendMail(mailOptions, (err, info) => {
      if (err) return console.log('Could not send email \n', err);

      console.log('Email sent successfully \n', info);
    });
  } catch (err) {
    console.log(err);
  }
};

export default sendEmail;
