const express = require('express');
const router = express.Router();
const sk = require('@selfkey/node-lib');
const multer = require('multer');
const upload = multer();
const Users = require('../models/users');
const Documents = require('../models/documents');

const JWT_SECRET = 'lws-direct-example-secret';
const JWT_ALGORITHM = 'hmac';

const LWS_TEMPLATE = [
	{
		id: 'first_name',
		label: 'First Name',
		schemaId: 'http://platform.selfkey.org/schema/attribute/first-name.json'
	},
	{
		label: 'Last Name',
		attribute: 'http://platform.selfkey.org/schema/attribute/last-name.json'
	},
	{
		id: 'email',
		schemaId: 'http://platform.selfkey.org/schema/attribute/email.json'
	},
	'http://platform.selfkey.org/schema/attribute/passport.json'
];

const jwtAuthMiddleware = tokenType => async (req, res, next) => {
	// Fetch authorization header
	const auth = req.headers.authorization;

	// Checkout it actually exists, fail the request otherwise
	if (!auth) {
		return res
			.status(400)
			.json({code: 'token_missing', message: 'Missing authorization header'});
	}

	// verify that the authorization header is a Bearer token, fail otherwise
	if (!auth.startsWith('Bearer ')) {
		return res.status(400).json({
			code: 'token_invalid',
			message: 'Malformed authorization header'
		});
	}
	// parse the authorization header and fetch the actual jwt token string
	const tokenString = auth.replace(/^Bearer /, '');
	try {
		req.decodedAuth = await (tokenType === 'challenge'
			? sk.auth.validateChallengeToken(tokenString, JWT_ALGORITHM, JWT_SECRET)
			: sk.auth.validateAccessToken(tokenString, JWT_ALGORITHM, JWT_SECRET));

		next();
	} catch (error) {
		// fail with 401, token was invalid or expired or forged.
		return res
			.status(401)
			.json({code: 'token_invalid', message: 'Invalid authentication token'});
	}
};

let attributeManager;

router.use(async (req, res, next) => {
	if (!attributeManager) {
		attributeManager = await sk.identity.AttributeManager.createWithSelfkeyRepository();
	}
	req.attributeManager = attributeManager;
	next();
});

router.get('/auth/challenge/:did', async (req, res, next) => {
	const did = req.params.did;
	try {
		const challengeToken = await sk.auth.generateChallengeToken(did, JWT_ALGORITHM, JWT_SECRET);
		return res.json({jwt: challengeToken});
	} catch (error) {
		return res.status(422).json({
			code: 'invalid_did',
			message: 'Invalid DID'
		});
	}
});

router.post('/auth/challenge', jwtAuthMiddleware('challenge'), async (req, res, next) => {
	const signature = req.body.signature;

	if (!signature || !signature.value || !signature.keyId) {
		return res.status(422).json({
			code: 'invalid_signature',
			message: 'Bad Payload: invalid signature object provided'
		});
	}

	const {nonce, sub: did} = req.decodedAuth;

	try {
		const isValid = await sk.auth.verifyChallengeSignature(nonce, signature, did);
		if (!isValid) {
			throw new Error('invalid signature');
		}
		const accessToken = await sk.auth.generateAccessToken(did, JWT_ALGORITHM, JWT_SECRET);
		return res.json({jwt: accessToken});
	} catch (error) {
		return res.status(422).json({
			code: 'signature_invalid',
			message: 'Bad Payload: invalid signature'
		});
	}
});

router.post('/users/files', jwtAuthMiddleware(), upload.single('document'), (req, res) => {
	// fetch file from request
	const f = req.file;

	if (!f) return res.status(400).json({code: 'no_file', message: 'no file uploaded'});

	// parse file info
	let doc = {
		mimeType: f.mimetype,
		size: f.size,
		content: f.buffer
	};

	// save the document to storage
	doc = Documents.create(doc);

	// respond with document id
	return res.json({id: doc.id});
});

router.post('/users', jwtAuthMiddleware(), async (req, res) => {
	// fetch attributes from body
	const attributes = req.body;

	if (!attributes || !attributes.length) {
		return res.status(422).json({code: 'no_attributes', message: 'No attributes provided'});
	}

	const {attributes: validated, errors, valid} = req.attributeManager.validateAttributes(
		attributes,
		LWS_TEMPLATE
	);

	if (!valid) {
		return res.status(422).json({
			code: 'invalid_attributes',
			message: 'Validation errors occurred',
			errors
		});
	}

	// fetch public key from token
	const did = req.decodedAuth.sub;

	// update or create user by public key
	let user = Users.findByDID(did);

	if (user) {
		console.log('updating user');
		user = Users.update(user.id, {attributes: validated});
	} else {
		user = Users.create({attributes: validated}, did);
	}

	if (!user) {
		return res.status(400).json({
			code: 'could_not_create',
			message: 'Could not create user'
		});
	}

	// send success empty respone
	return res.status(201).send();
});

router.get('/users/token', jwtAuthMiddleware(), (req, res, next) => {
	const {sub: did} = req.decodedAuth;

	const user = Users.findByDID(did);

	if (!user) {
		return res.status(404).json({
			code: 'user_does_not_exist',
			message: 'User with provided public key does not exist'
		});
	}

	const jwt = sk.jwt.issueJWT(did, JWT_ALGORITHM, JWT_SECRET);
	return res.json(jwt);
});

router.post('/login', async (req, res, next) => {
	const token = req.body.token || req.body.jwt;
	if (!token) {
		return next(new Error('Not token provided'));
	}
	try {
		const decoded = sk.jwt.validate(token);
		let user = Users.findByDID(decoded.sub);
		req.session.userID = user.id;
		return res.json({redirectTo: '/me/info'});
	} catch (error) {
		console.error('LWS LOGIN ERROR', error);
		return next(new Error('Could not login with provided token'));
	}
});

module.exports = router;
