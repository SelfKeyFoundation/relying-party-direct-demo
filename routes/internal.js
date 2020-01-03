const express = require('express');
const router = express.Router();
const Users = require('../models/users');

const Documents = require('../models/documents');

router.get('/files/:id', (req, res) => {
	if (!req.session.userID) {
		return res.status(401).send();
	}
	let doc = Documents.findById(+req.params.id);
	if (!doc) return res.status(404).send();
	res.setHeader('Content-Transfer-Encoding', 'binary');
	res.setHeader('Content-Type', doc.mimeType || 'application/octet-stream');
	res.send(doc.content);
});

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
