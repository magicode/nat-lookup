

var nlp = require('./build/Release/natlookup.node');


function getOrginalDst(socket,cb){
	if(!socket || !socket._handle ||  !socket._handle.fd) return cb("no socket");
	
	var idDebug = Date.now();
	
	console.log('nlp-'+ idDebug +'-1-' + socket._handle.fd);
	nlp.natLookup( socket._handle.fd , cb  , idDebug );
	
	return idDebug;
}

module.exports.getOrginalDst = getOrginalDst;
