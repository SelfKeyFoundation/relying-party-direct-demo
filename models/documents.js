const allIds = [];
const byId = {};
let runningId = 0;

exports.findById = id => {
	return byId[id];
};

exports.create = data => {
	let id = ++runningId;
	let doc = {...data, id};
	byId[id] = doc;
	allIds.push(id);
	return doc;
};

exports.delete = id => {
	let doc = byId[id];
	if (!doc) return false;
	let indx = allIds.indexOf(id);
	allIds.splice(indx, 1);
	delete byId[id];
	return doc;
};

exports.findAll = () => {
	return allIds.map(id => byId[id]);
};
