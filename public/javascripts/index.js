/* global lws */

const config = {
	ui: {
		el: '#lws'
	},
	website: {
		name: 'LWS Example',
		url: 'http://localhost:3000/',
		termsUrl: 'http://localhost:3000/terms.html',
		policyUrl: 'http://localhost:3000/policy.html'
	},
	rootEndpoint: 'http://localhost:3000/lws',
	endpoints: {},
	attributes: [
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
	],
	did: true
};

lws.init(config);
