const router = require('express').Router();
const bcrypt = require('bcrypt');
const User = require('../models/user')

const jwt = require('jsonwebtoken');
const checkAuth = require('../middleware/check-auth');

router.post('/signup', (req, res) => {
    bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) {
            return res.json({ success: false, message: "Password Hash Error" })
        } else {
            const user = new User({
                name: req.body.name,
                email: req.body.email,
                password: hash
            })
            user.save()
                .then((_) => {
                    res.json({ success: true, message: "account has been created" })
                }).catch((err) => {
                    if (err.code === 11000) {
                        return res.json({ success: false, message: "Email is already exist" })
                    }
                    res.json({ success: false, message: "Authentication failed" })
                })
        }
    });

})

router.post('/login', (req, res) => {
    User.find({ email: req.body.email }).exec().then((result) => {
        if (result.length < 1) {
            return res.json({ success: false, message: "User not found" })
        }
        const user = result[0]
        bcrypt.compare(req.body.password, user.password, (err, ret) => {
            if (ret) {
                const payload = {
                    userId: user._id,
                }
                const token = jwt.sign(payload, "webBatch")
                return res.json({ success: true, token: token, message: "Login success" })
            } else {
                return res.json({ success: false, message: "Password doesnt match" })
            }
        })
    }).catch(err => {
        res.json({ success: false, message: "Authenication failed" })
    })
})

router.get('/profile', checkAuth, (req, res) => {
    const userId = req.userData.userId;
    User.findById(userId).exec().then((result) => {
        res.json({ success: true, data: result })
    }).catch(err => {
        res.json({ success: false, message: "Server while getting profile Error" })
    })
})



//UPDATE
router.put("/:id", (request, response) => {
    if (request.body.userId === request.params.id) {
        if (request.body.password) {
            const salt = bcrypt.genSalt(10);
            request.body.password = bcrypt.hash(request.body.password, salt);
        }
        try {
            const updatedUser = User.findByIdAndUpdate(request.params.id, {
                $set: request.body,
            }, { new: true }
            );
            response.status(200).json(updatedUser);
        } catch (error) {
            response.status(500).json({ message: error.message });
        }
    } else {
        response.status(401).json("You update only your account")
    }
})

module.exports = router