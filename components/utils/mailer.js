import nodemailer from 'nodemailer';

const sendEmail = async (recipient, subject, email) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: 465,
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: recipient,
      subject,
      html: email,
    });

    console.log('/t Email sent successfully');
  } catch (err) {
    console.log('/t Could not send email /n', err);
  }
};

export default sendEmail;
