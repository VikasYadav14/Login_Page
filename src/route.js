const express = require("express")

const router = express.Router()

const { registration, login, userDetails, authentication, sendotp, verifyotp, updateDetails } = require("./user")


router.post("/register", registration)
router.get("/login", login)
router.get("/profile", authentication, userDetails)
router.put("/updatedetails", authentication, updateDetails)

router.get('/forgot_password/sendotp', sendotp)
router.post('/forgot_password/verifyotp', verifyotp)


module.exports = router
