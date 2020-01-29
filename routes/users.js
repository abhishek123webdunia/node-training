const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const jwt = require("jsonwebtoken");
// Load User model
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');
const config = require('../config/config');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

router.get("/edit/:id", function(req, res){
  User.findById(req.params.id,function(err,results){
    res.render('edit',{
      results:results
    });
  });
});

router.post("/edit/:id", function(req, res){
  let info = {};
   
   info.name = req.body.name;
   info.email = req.body.email;

   let query = {_id:req.params.id}

   User.findByIdAndUpdate(query,info, function (err, result) {
    if (err) {
    console.log(err);
    } else {
   console.log("User Updated successfully");
   res.redirect('/dashboard');
    }
  }); 
  });
  
// Register
router.post('/register', (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      } else {
        const newUser = new User({
          name,
          email,
          password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                res.redirect('/users/login');
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});


// Login
router.post('/login', (req, res, next) => {
  User.findOne({ email: req.body.email }, function (err, user) {
  
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user found.');
    
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
    
    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
    res.status(200).send({ auth: true, token: token });
   });
  
});

//passport.authenticate('local', {
  //successRedirect: '/dashboard',
  //failureRedirect: '/users/login',
  //failureFlash: true
//})(req, res, next);

router.get('/delete/:id', (req, res) => {
  let query = {_id:req.params.id};
  User.deleteOne(query,function(err){
    if(err){
      console.log(err);
    }else{
      return res.redirect('/dashboard');
    }
  })
});

router.get('/status/:id', (req, res) => {
  User.findByIdAndUpdate(req.params.id,function(err,results){
    res.render('dashboard',{
      results:results
    });
  });
});

router.post("/status/:id", function(req, res){
  let infos = {};
   
   info.status = 'inactive';

   let querys = {_id:req.params.id}
     console/log(querys);

   User.updateOne(querys,infos, function (err, results) {
    if (err) {
    console.log(err);
    } else {
   console.log("status Updated successfully");
   res.redirect('/dashboard');
    }
  }); 
  });

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
