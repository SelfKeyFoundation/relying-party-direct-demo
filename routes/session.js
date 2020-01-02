var express = require('express');
var router = express.Router();

router.get('/login', (req, res, next) => {
	if (req.session.userID) {
		return res.redirect('/me/info');
	}
	res.render('login', {
		title: 'Login'
	});
});

router.get('/logout', (req, res, next) => {
	req.session.destroy();
	res.redirect('/');
});

router.get('/login-error', (req, res, next) => {
	res.redirect('/login');
});

module.exports = router;
