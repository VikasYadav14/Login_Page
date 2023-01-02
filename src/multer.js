const multer = require('multer')

const uploadAvatar = multer({
    storage: multer.diskStorage({
        destination: './src/uploads',
        filename: function (req, file, cb) {
            const imageType = file.originalname.split(".")[1]
            cb(null, `avatar${Date.now()}.${imageType}`)
        }
    })
}).single('avatar')

module.exports = uploadAvatar