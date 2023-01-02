const express = require("express")
const mongoose = require("mongoose")
require('dotenv').config()
const uploadAvatar = require("./src/multer")
const route = require("./src/route")

const app = express()
app.use(express.json())
app.use(uploadAvatar)

mongoose.set('strictQuery', false)
mongoose.connect(process.env.DATABASE, {
    useNewUrlParser: true
})
    .then(() => console.log("MongoDb is connected"))
    .catch(err => console.log(err))

app.use("/user", route)

app.use('/', (req, res) => {
    console.log(process.env)
    return res.status(404).send("Sorry page not found 😥")
})


const port = process.env.PORT || 3000
app.listen(port, () => {
    console.log(`server is connected to port => ${port}`)
})