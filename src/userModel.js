const mongoose = require("mongoose")

const userSchema = new mongoose.Schema({
    avatar: {
        type: String,
        default:'src/uploads/default_avatar.png'
    },
    firstName: {
        type: String,
        lowercase: true,
        required: true,
        trim: true,
    },
    lastName: {
        type: String,
        lowercase: true,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
    },
    otp: {
        type: Number
    },
    exTime: {
        type: Number
    }
}, { timestamps: true })


module.exports = mongoose.model("user", userSchema)