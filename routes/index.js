const express = require('express');
const router = express.Router();
const { ensureAuthenticated, forwardAuthenticated } = require('../config/auth');
const User = require('../models/User');
const jwt = require("jsonwebtoken");
const config = require('../config/config');
// Welcome Page
router.get('/', forwardAuthenticated, (req, res) => res.render('welcome'));

// Dashboard
router.get('/dashboard/:token', (req, res) => {
    decoded = jwt.verify(req.params.token,config.secret);
     if(decoded.role == "admin"){
    var users = User.find({});
	users.exec(function(err,decoded){
	if(err) throw err
		res.render('dashboard', { results:decoded })
		  });
   	}else{
        res.send({Status:"FALSE"});
	}

 });

module.exports = router;
