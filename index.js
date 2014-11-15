

var addon = require('./build/Release/natlookup.node');

var nlp =  new addon.NatLookup();


function getOrginalDst(socket,cb){
	if(!socket || !socket._handle ||  !socket._handle.fd) return cb("no socket");
	nlp.natLookup(socket._handle.fd, socket.localPort , socket.localAddress ,cb);
}

module.exports.getOrginalDst = getOrginalDst;
