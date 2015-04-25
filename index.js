

var nlp = require('./build/Release/natlookup.node');


module.exports.getOrginalDst = function getOrginalDst(socket,cb){
	if(!socket || !socket._handle ||  !socket._handle.fd) return cb("no socket");
	
	var idDebug = Date.now();
	
	console.log('nlp-'+ idDebug +'-1-' + socket._handle.fd);
	nlp.natLookup( socket._handle.fd , cb  , idDebug );
	
	return idDebug;
};

module.exports.getOrginalDstSync = function getOrginalDstSync(socket ){
	if(!socket || !socket._handle ||  !socket._handle.fd) return  { error: "no socket"} ;
	return nlp.natLookupSync( socket._handle.fd );
}

