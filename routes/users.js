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
    var token = jwt.sign({ query}, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
      var decoded = jwt.verify(token,config.secret);
      if(decoded){
        console.log("User Updated successfully");
        res.redirect(`/dashboard/${decoded.id}`);
      }else{
        console.log(err);
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
    
    var token = jwt.sign({ id: user._id, role:user.role }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
      var decoded = jwt.verify(token,config.secret);
       if(decoded.role== "admin"){
          res.redirect(`/dashboard/${token}`);
       }else if(decoded.role == "user"){
          res.redirect(`/users/edit/${decoded.id}`);
       }else{
         res.send({status:400});
       }
   });
  
});


router.get('/delete/:id', (req, res) => {

  User.deleteOne({ _id:req.params.id }, function (err, user) {
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user delete.');
    
    var token = jwt.sign({ id: req.params.id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
   
      var decoded = jwt.verify(token,config.secret);
      console.log(decoded);
       if(decoded){
        return res.redirect(`/dashboard/${decoded.id}`);
       }else{
         res.send({status:400});
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
