const express = require('express');
const router = express.Router();
const sk = require('@selfkey/node-lib');
const multer = require('multer');
const upload = multer();
const Users = require('../models/users');
const Documents = require('../models/documents');

const JWT_SECRET =
	'lws-direct-example-secret-lws-direct-example-secret-lws-direct-example-secret-lws-direct-example-secret-lws-direct-example-secret';
const JWT_ALGORITHM = 'hmac';

const LWS_TEMPLATE = [
	{
		id: 'first_name',
		label: 'First Name',
		schemaId: 'http://platform.selfkey.org/schema/attribute/first-name.json'
	},
	{
		label: 'Last Name',
		schemaId: 'http://platform.selfkey.org/schema/attribute/last-name.json'
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
		// validate jwt token as challenge or access token
		const decoded = await (tokenType === 'challenge'
			? sk.auth.validateChallengeToken(tokenString, JWT_ALGORITHM, JWT_SECRET)
			: sk.auth.validateAccessToken(tokenString, JWT_ALGORITHM, JWT_SECRET));

		req.decodedAuth = decoded.payload;

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
	// initialize selfkey attributes manager
	// it is needed for attribute validation
	// based on requirements and json schemas
	// located at http://platform.selfkey.org/repository.json
	if (!attributeManager) {
		attributeManager = await sk.identity.AttributeManager.createWithSelfkeyRepository();
	}
	req.attributeManager = attributeManager;
	next();
});

// Get challenge endpoint --> returns challenge jwt token
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

// Challenge response endpoint
// Gets challenge jwt token and signature object
// if signature is valid, return an "access" jwt token
router.post('/auth/challenge', jwtAuthMiddleware('challenge'), async (req, res, next) => {
	const signature = req.body.signature;

	if (!signature || !signature.value || !signature.keyId) {
		return res.status(422).json({
			code: 'invalid_signature',
			message: 'Bad Payload: invalid signature object provided'
		});
	}

	// get nonce and did from decoded challenge token
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

// Example user file upload endpoint. For real life use-cases files should not be stored in memory
router.post('/users/file', jwtAuthMiddleware(), upload.single('document'), (req, res) => {
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
	return res.json({id: '' + doc.id});
});

// Create user endpoint
// Receives a list of attributes
router.post('/users', jwtAuthMiddleware(), async (req, res) => {
	// fetch attributes from body
	let {attributes} = req.body;

	if (!attributes || !attributes.length) {
		return res.status(422).json({code: 'no_attributes', message: 'No attributes provided'});
	}
	try {
		// Validate attributes based on requirements (LWS_TEMPLATE)
		const {
			attributes: validated,
			errors,
			valid
		} = await req.attributeManager.validateAttributes(attributes, LWS_TEMPLATE);

		if (!valid) {
			return res.status(422).json({
				code: 'invalid_attributes',
				message: 'Validation errors occurred',
				errors
			});
		}

		// create a human readable attribute map
		// [{schemaId: 'http://platform.selfkey.org/schema/attribute/first-name.json', data: 'first name'}]
		// Becomes
		// { firstName: {schemaId: 'http://platform.selfkey.org/schema/attribute/first-name.json', data: 'first name'}}
		attributes = sk.identity.utils.attributeMapBySchema(validated);

		// create user object based on attributes
		const userData = {
			firstName: attributes.firstName.data,
			lastName: attributes.lastName.data,
			email: attributes.email.data,
			passport: attributes.passport.data
		};

		// fetch public key from token
		const did = req.decodedAuth.sub;

		// update or create user by public key
		let user = Users.findByDID(did);
		if (user) {
			user = Users.update(user.id, userData);
		} else {
			user = Users.create(userData, did);
		}

		if (!user) {
			return res.status(400).json({
				code: 'could_not_create',
				message: 'Could not create user'
			});
		}

		// send success empty respone
		return res.status(201).send();
	} catch (error) {
		console.error(error);
		return res
			.status(422)
			.json({code: 'invalid_attributes', message: 'Validation errors occurred'});
	}
});

// GET User token endpoint
// returns a json object that is passed back to the web page
// this payload should allow user to authenticate with the web page
// in that case, a new jwt token is generated
router.get('/users/token', jwtAuthMiddleware(), async (req, res, next) => {
	const {sub: did} = req.decodedAuth;

	const user = Users.findByDID(did);

	if (!user) {
		return res.status(404).json({
			code: 'user_does_not_exist',
			message: 'User with provided public key does not exist'
		});
	}

	const jwt = await sk.jwt.issueJWT(did, JWT_ALGORITHM, JWT_SECRET);
	return res.json({jwt});
});

// Login endpoint
// Optionally called from the web page with the payload provided by '/user/token' endpoint
// Returns a json object with "redirectTo" key indicating a page to redirect to.
router.post('/login', async (req, res, next) => {
	const token = req.body.token || req.body.jwt;
	if (!token) {
		return next(new Error('Not token provided'));
	}
	try {
		const decoded = await sk.jwt.validateJWT(token, JWT_ALGORITHM, JWT_SECRET);
		let user = Users.findByDID(decoded.payload.sub);
		req.session.userID = user.id;
		return res.json({redirectTo: '/me/info'});
	} catch (error) {
		console.error('LWS LOGIN ERROR', error);
		return next(new Error('Could not login with provided token'));
	}
});

module.exports = router;
