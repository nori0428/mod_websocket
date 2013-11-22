var io = require('socket.io').listen(8081);

io.sockets.on('connection', function (socket) {
	socket.on('echo', function (msg) {
		socket.emit('echo-back', msg);
	});
});
