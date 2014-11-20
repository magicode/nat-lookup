

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

// iptables -t nat -A OUTPUT -d 6.13.6.13 -p tcp -j REDIRECT --to-ports 6789
net.connect(5555,"6.13.6.13", function(){
	
});