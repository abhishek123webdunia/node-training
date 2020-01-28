const express = require('express');
const router = express.Router();
const { ensureAuthenticated, forwardAuthenticated } = require('../config/auth');
const User = require('../models/User');
// Welcome Page
router.get('/', forwardAuthenticated, (req, res) => res.render('welcome'));

// Dashboard
router.get('/dashboard', (req, res) => {
  var users = User.find({});
	users.exec(function(err,data){
	if(err) throw err
		res.render('dashboard', { results:data })
		  });
    });

	
module.exports = router;
