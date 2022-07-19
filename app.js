require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const salt = bcrypt.genSaltSync(10);
const port = process.env.PORT || 3000;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Setup DB
mongoose.connect(process.env.DB_URL);

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    password: String
});

const User = mongoose.model('User', userSchema);

// Routes

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    bcrypt.hash(req.body.password, salt, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
        newUser.save((err) => {
            if(err){
                console.log(err);
            }else{
                res.render('secrets');
            }
        });
    });
});

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    User.findOne({ email: username }, (err, user) => {
        if(err){
            console.log(err);
        }else{
            if(user){
                bcrypt.compare(password, user.password, function(err, result) {
                    if(result){
                        res.render('secrets');
                    }
                });
            }
        }
    });
});

// Start Server
app.listen(port, () => {
    console.log(`App running on port ${port}`);
});