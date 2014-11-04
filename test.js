

var nlp = require('./');

var net = require('net');

var server = net.createServer().on('connection',function(socket){
	console.log(socket._handle.fd);

	nlp.getOrginalDst(socket,function(err,ip,port){
		console.log(err,ip,port);
	})
	
	
}).listen(6789);

net.connect(6789, function(){
	
});
net.connect(5555,"200.56.45.23", function(){
	
});