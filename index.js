

var nlp = require('./build/Release/natlookup.node');


function getOrginalDst(socket,cb){
	if(!socket || !socket._handle ||  !socket._handle.fd) return cb("no socket");
	nlp.natLookup( socket._handle.fd , cb );
}

module.exports.getOrginalDst = getOrginalDst;
