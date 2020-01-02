const Documents = require('./documents');
const allIds = [];
const byId = {};
let runningId = 0;
const HOST = `http://localhost:${process.env.PORT}`;

exports.findByDID = did => {
	let found = allIds.map(id => byId[id]).filter(usr => usr.dids && usr.dids.includes(did));
	if (!found.length) return null;
	return found[0];
};

exports.findById = id => {
	return byId[id];
};

exports.create = (data, did) => {
	let user = Object.assign({}, data, {id: ++runningId});
	user.dids = [did];
	allIds.push(user.id);
	byId[user.id] = user;
	return user;
};

exports.update = (id, data) => {
	if (!byId[id]) return null;
	if (data.attributes) {
		data.attributes = data.attributes.map(attr => {
			if (!attr.documents) return attr;
			attr.documents = attr.documents.map(doc => {
				let newDoc = Documents.create(doc);
				let link = `${HOST}/documents/${newDoc.id}`;
				doc.localId = newDoc.id;
				doc.content = link;
				return doc;
			});
			return attr;
		});
	}
	byId[id] = Object.assign({}, byId[id], data, {id});
	return byId[id];
};

exports.findAll = () => {
	return allIds.map(id => byId[id]);
};
