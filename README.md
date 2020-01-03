# Login With Selfkey Demo for direct integrations

## Contents

- [Usage](#usage)
- [License](#license)

<a name="usage"></a>

## Usage

### Install
```sh
git clone https://github.com/SelfKeyFoundation/relying-party-direct-demo.git
cd relying-party-direct-demo
npm install
```

### Run
```sh
npm start
```

### Run dev
```sh
npm run start-dev
```

### SDK code examples

From [routes/lws.js](https://github.com/SelfKeyFoundation/relying-party-kycc-demo/blob/master/routes/lws.js)

```js
// validate jwt token as challenge or access token
const decoded = await (tokenType === 'challenge'
	? sk.auth.validateChallengeToken(tokenString, JWT_ALGORITHM, JWT_SECRET)
	: sk.auth.validateAccessToken(tokenString, JWT_ALGORITHM, JWT_SECRET));
```

```js
attributeManager = await sk.identity.AttributeManager.createWithSelfkeyRepository();
```

```js
const challengeToken = await sk.auth.generateChallengeToken(did, JWT_ALGORITHM, JWT_SECRET)
```

```js
const isValid = await sk.auth.verifyChallengeSignature(nonce, signature, did);
```

```js
const accessToken = await sk.auth.generateAccessToken(did, JWT_ALGORITHM, JWT_SECRET);
```

```js
// Validate attributes based on requirements (LWS_TEMPLATE)
const {
	attributes: validated,
	errors,
	valid
} = await req.attributeManager.validateAttributes(attributes, LWS_TEMPLATE);
```

```js
// create a human readable attribute map
// [{schemaId: 'http://platform.selfkey.org/schema/attribute/first-name.json', data: 'first name'}]
// Becomes
// { firstName: {schemaId: 'http://platform.selfkey.org/schema/attribute/first-name.json', data: 'first name'}}
attributes = sk.identity.utils.attributeMapBySchema(validated);
```

```js
const jwt = await sk.jwt.issueJWT(did, JWT_ALGORITHM, JWT_SECRET);
```

```js
const decoded = await sk.jwt.validateJWT(token, JWT_ALGORITHM, JWT_SECRET);
```

<a name="license"></a>
## License

[The GPL-3.0 License](http://opensource.org/licenses/GPL-3.0)

Copyright (c) 2018 SelfKey Foundation <https://selfkey.org/>
