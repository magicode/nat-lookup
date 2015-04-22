

var nlp = require('./build/Release/natlookup.node');


function getOrginalDst(socket,cb){
	if(!socket || !socket._handle ||  !socket._handle.fd) return cb("no socket");
	console.log('nlp 1 :: %d' , socket._handle.fd);
	nlp.natLookup( socket._handle.fd , cb );
}

module.exports.getOrginalDst = getOrginalDst;
