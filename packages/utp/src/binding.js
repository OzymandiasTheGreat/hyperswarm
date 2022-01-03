const binding = {...global};


binding.sizeof_utp_rn_t = global.sizeof_utp_rn_t();
binding.sizeof_utp_rn_send_request_t = global.sizeof_utp_rn_send_request_t();
binding.sizeof_utp_rn_connection_t = global.sizeof_utp_rn_connection_t();
binding.offsetof_utp_rn_t_accept_connections = global.offsetof_utp_rn_t_accept_connections();

const requests = [];
binding.lookup = function(host, callback) {
	const req = new Uint8Array(global.sizeof_utp_rn_dns_request_t());
	requests.push(req);
	global.utp_rn_dns_lookup(req, host, (err, ip) => {
		requests.splice(requests.indexOf(req), 1);
		callback(err, ip);
	});
}


setInterval(() => {
	binding.utp_rn_run();
}, 3);


module.exports = binding;
