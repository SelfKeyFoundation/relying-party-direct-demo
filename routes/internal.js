const express = require('express');
const router = express.Router();
const Users = require('../models/users');

router.get('/info', (req, res, next) => {
	if (!req.session.userID) {
		return res.redirect('/');
	}
	const user = Users.findById(req.session.userID);
	if (!user) {
		return res.redirect('/logout');
	}
	res.render('user-info', {user});
});

module.exports = router;
