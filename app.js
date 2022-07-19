require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const port = process.env.PORT || 3000;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Setup DB
mongoose.connect(`mongodb://localhost:27017/${process.env.DB_NAME}`);

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    password: String
});

userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

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
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });
    newUser.save((err) => {
        if(err){
            console.log(err);
        }else{
            res.render('secrets');
        }
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
                if(user.password === password){
                    res.render('secrets');
                }
            }
        }
    });
});

// Start Server
app.listen(port, () => {
    console.log(`App running on port ${port}`);
});