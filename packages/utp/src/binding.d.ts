namespace binding {
	function utp_rn_init(
		utp: Uint8Array,
		ctx: Uint8Array,
		conn: Uint8Array,
		buf: Uint8Array,
		on_message: (nread: number, port: number, ip: string) => Uint8Array,
		on_send: (buf: Uint8Array, status: number) => void,
		on_connection: (port: number, ip: string) => Uint8Array,
		on_close: () => void,
		realloc: () => Uint8Array,
	): void;
	function utp_rn_close(utp: Uint8Array): void;
	function utp_rn_destroy(utp: Uint8Array, send_reqs: Uint8Array[]): void;
	function utp_rn_bind(utp: Uint8Array, port: number, ip: string): void;
	function utp_rn_local_port(utp: Uint8Array): number;
	function utp_rn_send_request_init(send_req: Uint8Array, ctx: Uint8Array): void;
	function utp_rn_send(
		utp: Uint8Array,
		send_req: Uint8Array,
		buf: Uint8Array,
		offset: number,
		len: number,
		port: number,
		ip: string,
	): void;
	function utp_rn_ref(utp: Uint8Array): void;
	function utp_rn_unref(utp: Uint8Array): void;
	function utp_rn_recv_buffer(utp: Uint8Array, size: number): number;
	function utp_rn_send_buffer(utp: Uint8Array, size: number): number;
	function utp_rn_set_ttl(utp: Uint8Array, ttl: number): void;
	function utp_rn_connection_init(
		conn: Uint8Array,
		ctx: Uint8Array,
		buf: Uint8Array,
		on_read: (recv_packet_size: number) => Uint8Array,
		on_drain: () => void,
		on_end: () => void,
		on_error: (error_code: number) => void,
		on_close: () => void,
		on_connect: () => void,
		realloc: () => Uint8Array,
	): void;
	function utp_rn_connection_on_close(conn: Uint8Array): void;
	function utp_rn_connection_write(conn: Uint8Array, buf: Uint8Array): number;
	function utp_rn_connection_writev(conn: Uint8Array, bufs: Uint8Array[]): number;
	function utp_rn_connection_shutdown(conn: Uint8Array): void;
	function utp_rn_connect(utp: Uint8Array, conn: Uint8Array, port: number, ip: string): void;
	const sizeof_utp_rn_t: number;
	const sizeof_utp_rn_send_request_t: number;
	const sizeof_utp_rn_connection_t: number;
	const accept_connections: number;
};


module "binding" {
	export default binding;
}
