

var addon = require('./build/Release/natlookup.node');

var nlp =  new addon.NatLookup();


function getOrginalDst(socket,cb){
	nlp.natLookup(socket._handle.fd, socket.localPort , socket.localAddress ,cb);
}

module.exports.getOrginalDst = getOrginalDst;
