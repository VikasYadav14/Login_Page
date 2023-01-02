const jwt = require('jsonwebtoken');
const userModel = require('./userModel');
const bcrypt = require('bcryptjs');

async function registration(req, res) {
    try {
        const { firstName, lastName, email, password } = req.body;
        if (req.file) {
            const { path } = req.file;
            req.body.avatar = path
        }

        if (!isValidName(firstName))
            return res.status(400).send({ error: "Name isn't in correct format" });
        if (!isValidName(lastName))
            return res.status(400).send({ error: "Name isn't in correct format" });

        if (!isValidEmail(email))
            return res.status(400).send({ error: 'email is not in correct format' });
        if (!isValidPassword(password))
            return res.status(400).send({
                error:
                    'password is weak. use uppercase, lowercase, number and special character and minimum size 8',
            });

        const hashPaswword = await bcrypt.hash(password, 10);

        req.body.password = hashPaswword;

        const user = await userModel.create(req.body);

        return res.status(201).json(user);
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

async function login(req, res) {
    try {
        const { email, password } = req.body;

        if (!isValidEmail(email))
            return res.status(400).send({ error: 'email is not in correct format' });

        const user = await userModel.findOne({ email });
        if (!user)
            return res.status(400).send({ error: 'Credentials are incorrect' });

        let varifyPassword = await bcrypt.compare(password, user.password);
        if (!varifyPassword)
            return res.status(400).send({ error: 'Credentials are incorrect' });
        const token = jwt.sign({ email, password }, 'my secret key', {
            expiresIn: '1h',
        });
        return res.status(200).send({ token });
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

async function authentication(req, res, next) {
    try {
        let token = req.headers['authorization'];
        token = token.split(' ');

        const credentials = jwt.verify(token[1], 'my secret key');
        req.body.email = credentials.email;
        req.body.password = credentials.password
        next();
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

async function userDetails(req, res) {
    try {
        const { email, password } = req.body;
        const users = await userModel.find({ email, password });
        return res.status(200).send(users);
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

async function updateDetails(req, res) {
    try {
        const {
            email,
            password,
            firstName,
            lastName,
            oldPassword,
            newPassword,
            confirmPassword,
        } = req.body;

        if (req.file) {
            const { path } = req.file;
            req.body.avatar = path
        }

        if(firstName)
            if (!isValidName(firstName))
                return res.status(400).send({ error: "Name isn't in correct format" });
        if(lastName)
            if (!isValidName(lastName))
                return res.status(400).send({ error: "Name isn't in correct format" });
        if (oldPassword) {
            if (password != oldPassword)
                return res
                    .status(500)
                    .send({ error: 'Your old password did not match' });
            if (newPassword != confirmPassword)
                return res.status(500).send({ error: 'confirm password is not same' });
            if (!isValidPassword(newPassword))
                return res.status(400).send({
                    error:
                        'password is weak. use uppercase, lowercase, number and special character and minimum size 8',
                });
            const hashPaswword = await bcrypt.hash(newPassword, 10);
            req.body.password = hashPaswword;
        }

        await userModel.updateOne({ email, password }, req.body);
        return res.status(200).send('Your details has been updated 😊');
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

async function sendotp(req, res) {
    try {
        const { email } = req.body;
        const otp = Math.floor(Math.random() * (999999 - 100000) + 100000);
        const user = await userModel.findOne({ email });
        if (!user)
            return res.status(404).send({ error: `user not found at ${email}` });
        const mailOptions = {
            from: 'vikas14nov2001@gmail.com',
            to: 'pravinpatekar1999@gmail.com',
            subject: 'Your One Time Password',
            html: `<p>Enter <b>${otp}</b> in the app to reset Password</p>
            <p>This code <b>expires in 1 hour</b></p>`,
        };
        transporter.sendMail(mailOptions, (error, done) => {
            if (error) return res.status(500).send(error.message);
            else return done;
        });
        const obj = {};
        obj.otp = otp;
        obj.exTime = Date.now() + 3600000;
        await userModel.updateOne({ email }, obj);
        return res.status(200).send('OTP successfully send to your register Email');
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

async function verifyotp(req, res) {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await userModel.findOne({ email, otp });
        if (!user) return res.status(500).send({ error: 'otp is incorrect' });
        if (!isValidPassword(newPassword))
            return res.status(400).send({
                error:
                    'password is weak. use uppercase, lowercase, number and special character and minimum size 8',
            });
        const password = await bcrypt.hash(newPassword, 10);
        const { exTime } = user;
        if (exTime < Date.now())
            return res.status(400).send('OTP expires please resend');
        await userModel.updateOne(
            { email },
            {
                $set: { password },
                $unset: { otp, exTime },
            }
        );
        return res.status(200).send('Password has been reset succesfully');
    } catch (error) {
        return res.status(500).send(error.message);
    }
}

module.exports = {
    registration,
    login,
    authentication,
    userDetails,
    updateDetails,
    sendotp,
    verifyotp,
};

// ----------validations----------//

const isValidName = function (name) {
    const nameRegex = /^[a-zA-Z ]{2,30}$/;
    return nameRegex.test(name);
};

const isValidEmail = function (email) {
    const emailRegex =
        /^[a-z0-9][a-z0-9-_\.]+@([a-z]|[a-z0-9]?[a-z0-9-]+[a-z0-9])\.[a-z0-9]{2,10}(?:\.[a-z]{2,10})?$/;
    return emailRegex.test(email);
};

const isValidPassword = function (password) {
    var passRegex = new RegExp(
        '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,15})'
    );
    return passRegex.test(password);
};

// ---------Using Nodemailer--------//

require('dotenv').config()

const Nodemailer = require('nodemailer');
const transporter = Nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.USER,
        pass: process.env.PASS,
    },
});
