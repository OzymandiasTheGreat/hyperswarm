const sodium = {...global};


sodium.sodium_malloc = function(n) { return new Uint8Array(n); }
sodium.sodium_memzero = function(arr) { arr.fill(0); }
sodium.sodium_free = function(arr) { sodium.sodium_memzero(arr); }


sodium.randombytes_SEEDBYTES = global.get_randombytes_SEEDBYTES();


sodium.crypto_sign_PUBLICKEYBYTES = global.get_crypto_sign_PUBLICKEYBYTES();
sodium.crypto_sign_SECRETKEYBYTES = global.get_crypto_sign_SECRETKEYBYTES();
sodium.crypto_sign_SEEDBYTES = global.get_crypto_sign_SEEDBYTES();
sodium.crypto_sign_BYTES = global.get_crypto_sign_BYTES();
sodium.crypto_box_PUBLICKEYBYTES = global.get_crypto_box_PUBLICKEYBYTES();
sodium.crypto_box_SECRETKEYBYTES = global.get_crypto_box_SECRETKEYBYTES();


sodium.crypto_generichash_PRIMITIVE = "blake2b";
sodium.crypto_generichash_BYTES = global.get_crypto_generichash_BYTES();
sodium.crypto_generichash_BYTES_MIN = global.get_crypto_generichash_BYTES_MIN();
sodium.crypto_generichash_BYTES_MAX = global.get_crypto_generichash_BYTES_MAX();
sodium.crypto_generichash_KEYBYTES = global.get_crypto_generichash_KEYBYTES();
sodium.crypto_generichash_KEYBYTES_MIN = global.get_crypto_generichash_KEYBYTES_MIN();
sodium.crypto_generichash_KEYBYTES_MAX = global.get_crypto_generichash_KEYBYTES_MAX();
sodium.crypto_generichash_STATEBYTES = global.get_crypto_generichash_STATEBYTES();
sodium.crypto_generichash_batch = function(out, inArray, key) {
	const state = new Uint8Array(sodium.crypto_generichash_STATEBYTES);
	if (key) {
		sodium.crypto_generichash_init(state, key, out.length);
	} else {
		sodium.crypto_generichash_init(state, out.length);
	}
	for (let ui8 of inArray) {
		sodium.crypto_generichash_update(state, ui8);
	}
	return sodium.crypto_generichash_final(state, out);
}
sodium.crypto_generichash_instance = function(key, outlen) {
	return new CryptoGenericHashInstance(key, outlen);
}


sodium.crypto_box_SEEDBYTES = global.get_crypto_box_SEEDBYTES();
sodium.crypto_box_MACBYTES = global.get_crypto_box_MACBYTES();
sodium.crypto_box_NONCEBYTES = global.get_crypto_box_NONCEBYTES();


sodium.crypto_box_SEALBYTES = global.get_crypto_box_SEALBYTES();


sodium.crypto_secretbox_MACBYTES = global.get_crypto_secretbox_MACBYTES();
sodium.crypto_secretbox_NONCEBYTES = global.get_crypto_secretbox_NONCEBYTES();
sodium.crypto_secretbox_KEYBYTES = global.get_crypto_secretbox_KEYBYTES();


sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES = global.get_crypto_aead_xchacha20poly1305_ietf_ABYTES();
sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES = global.get_crypto_aead_xchacha20poly1305_ietf_KEYBYTES();
sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = global.get_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES();
sodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES = global.get_crypto_aead_xchacha20poly1305_ietf_NSECBYTES();
sodium.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = global.get_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX();
sodium.crypto_aead_chacha20poly1305_ietf_ABYTES = global.get_crypto_aead_chacha20poly1305_ietf_ABYTES();
sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES = global.get_crypto_aead_chacha20poly1305_ietf_KEYBYTES();
sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES = global.get_crypto_aead_chacha20poly1305_ietf_NPUBBYTES();
sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES = global.get_crypto_aead_chacha20poly1305_ietf_NSECBYTES();
sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = global.get_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX();


sodium.crypto_stream_PRIMITIVE = xsalsa20crypto_stream_NONCEBYTES = global.get_crypto_stream_NONCEBYTES();
sodium.crypto_stream_KEYBYTES = global.get_crypto_stream_KEYBYTES();
sodium.crypto_stream_chacha20_NONCEBYTES = global.get_crypto_stream_chacha20_NONCEBYTES();
sodium.crypto_stream_chacha20_ietf_NONCEBYTES = global.get_crypto_stream_chacha20_ietf_NONCEBYTES();
sodium.crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = global.get_crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX();
sodium.crypto_stream_chacha20_KEYBYTES = global.get_crypto_stream_chacha20_KEYBYTES();
sodium.crypto_stream_chacha20_ietf_KEYBYTES = global.get_crypto_stream_chacha20_ietf_KEYBYTES();
sodium.crypto_stream_xor_init = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_xor_update = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_xor_final = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_chacha20_xor_init = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_chacha20_xor_update = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_chacha20_xor_final = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_chacha20_ietf_xor_init = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_chacha20_ietf_xor_update = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_chacha20_ietf_xor_final = () => console.warn("NOT IMPLEMENTED");
sodium.crypto_stream_xor_instance = (n, k) => new CryptoStreamChaCha20XorInstance(n, k);
sodium.crypto_stream_chacha20_xor_instance = (n, k) => new CryptoStreamChaCha20XorInstance(n, k);
sodium.crypto_stream_chacha20_ietf_xor_instance = (n, k) => new CryptoStreamChaCha20IETFXorInstance(n, k);


sodium.crypto_auth_BYTES = global.get_crypto_auth_BYTES();
sodium.crypto_auth_KEYBYTES = global.get_crypto_auth_KEYBYTES();


sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = new Uint8Array(1);
global.get_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE(sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH = new Uint8Array(1);
global.get_crypto_secretstream_xchacha20poly1305_TAG_PUSH(sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH);
sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY = new Uint8Array(1);
global.get_crypto_secretstream_xchacha20poly1305_TAG_REKEY(sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY);
sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL = new Uint8Array(1);
global.get_crypto_secretstream_xchacha20poly1305_TAG_FINAL(sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
sodium.crypto_secretstream_xchacha20poly1305_ABYTES = global.get_crypto_secretstream_xchacha20poly1305_ABYTES();
sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES = global.get_crypto_secretstream_xchacha20poly1305_HEADERBYTES();
sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES = global.get_crypto_secretstream_xchacha20poly1305_KEYBYTES();
sodium.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = global.get_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX();
sodium.crypto_secretstream_xchacha20poly1305_TAGBYTES = 1;
sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES = global.get_crypto_secretstream_xchacha20poly1305_STATEBYTES();
sodium.crypto_secretstream_xchacha20poly1305_state_new = function() { return new Uint8Array(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES); }


sodium.crypto_onetimeauth_BYTES = global.get_crypto_onetimeauth_BYTES();
sodium.crypto_onetimeauth_KEYBYTES = global.get_crypto_onetimeauth_KEYBYTES();
sodium.crypto_onetimeauth_STATEBYTES = global.get_crypto_onetimeauth_STATEBYTES();
sodium.crypto_onetimeauth_instance = (k) => new CryptoOneTimeAuthInstance(k);


sodium.crypto_pwhash_BYTES_MIN = global.get_crypto_pwhash_BYTES_MIN();
sodium.crypto_pwhash_BYTES_MAX = global.get_crypto_pwhash_BYTES_MAX();
sodium.crypto_pwhash_SALTBYTES = global.get_crypto_pwhash_SALTBYTES();
sodium.crypto_pwhash_STRBYTES = global.get_crypto_pwhash_STRBYTES();
sodium.crypto_pwhash_OPSLIMIT_MIN = global.get_crypto_pwhash_OPSLIMIT_MIN();
sodium.crypto_pwhash_OPSLIMIT_MAX = global.get_crypto_pwhash_OPSLIMIT_MAX();
sodium.crypto_pwhash_MEMLIMIT_MIN = global.get_crypto_pwhash_MEMLIMIT_MIN();
sodium.crypto_pwhash_MEMLIMIT_MAX = global.get_crypto_pwhash_MEMLIMIT_MAX();
sodium.crypto_pwhash_STRPREFIX = global.get_crypto_pwhash_STRPREFIX();
sodium.crypto_pwhash_ALG_ARGON2I13 = global.get_crypto_pwhash_ALG_ARGON2I13();
sodium.crypto_pwhash_ALG_ARGON2ID13 = global.get_crypto_pwhash_ALG_ARGON2ID13();
sodium.crypto_pwhash_ALG_DEFAULT = global.get_crypto_pwhash_ALG_DEFAULT();
sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE = global.get_crypto_pwhash_MEMLIMIT_INTERACTIVE();
sodium.crypto_pwhash_MEMLIMIT_MODERATE = global.get_crypto_pwhash_MEMLIMIT_MODERATE();
sodium.crypto_pwhash_MEMLIMIT_SENSITIVE = global.get_crypto_pwhash_MEMLIMIT_SENSITIVE();
sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE = global.get_crypto_pwhash_OPSLIMIT_INTERACTIVE();
sodium.crypto_pwhash_OPSLIMIT_MODERATE = global.get_crypto_pwhash_OPSLIMIT_MODERATE();
sodium.crypto_pwhash_OPSLIMIT_SENSITIVE = global.get_crypto_pwhash_OPSLIMIT_SENSITIVE();
sodium.crypto_pwhash_PASSWD_MIN = global.get_crypto_pwhash_PASSWD_MIN();
sodium.crypto_pwhash_PASSWD_MAX = global.get_crypto_pwhash_PASSWD_MAX();
sodium.crypto_pwhash_async = function(out, passwd, salt, opslimit, memlimit, alg, callback) {
	setImmediate(() => {
		const r = sodium.crypto_pwhash(out, passwd, salt, opslimit, memlimit, alg);
		if (r) {
			callback();
		} else {
			callback(new Error("Hashing failed"));
		}
	});
}
sodium.crypto_pwhash_str_async = function(out, passwd, opslimit, memlimit, callback) {
	setImmediate(() => {
		const r = sodium.crypto_pwhash_str(out, passwd, opslimit, memlimit);
		if (r) {
			callback();
		} else {
			callback(new Error("Hashing failed"));
		}
	});
}
sodium.crypto_pwhash_str_verify_async = function(str, passwd, callback) {
	setImmediate(() => {
		const r = sodium.crypto_pwhash_str_verify(str, passwd);
		callback(undefined, r);
	});
}


sodium.crypto_kx_PUBLICKEYBYTES = global.get_crypto_kx_PUBLICKEYBYTES();
sodium.crypto_kx_SECRETKEYBYTES = global.get_crypto_kx_SECRETKEYBYTES();
sodium.crypto_kx_SEEDBYTES = global.get_crypto_kx_SEEDBYTES();
sodium.crypto_kx_SESSIONKEYBYTES = global.get_crypto_kx_SESSIONKEYBYTES();
sodium.crypto_kx_PRIMITIVE = global.get_crypto_kx_PRIMITIVE();


sodium.crypto_scalarmult_BYTES = global.get_crypto_scalarmult_BYTES();
sodium.crypto_scalarmult_SCALARBYTES = global.get_crypto_scalarmult_SCALARBYTES();


sodium.crypto_scalarmult_ed25519_BYTES = global.get_crypto_scalarmult_ed25519_BYTES();
sodium.crypto_scalarmult_ed25519_SCALARBYTES = global.get_crypto_scalarmult_ed25519_SCALARBYTES();
sodium.crypto_core_ed25519_BYTES = global.get_crypto_core_ed25519_BYTES();
sodium.crypto_core_ed25519_UNIFORMBYTES = global.get_crypto_core_ed25519_UNIFORMBYTES();
sodium.crypto_core_ed25519_SCALARBYTES = global.get_crypto_core_ed25519_SCALARBYTES();
sodium.crypto_core_ed25519_NONREDUCEDSCALARBYTES = global.get_crypto_core_ed25519_NONREDUCEDSCALARBYTES();
sodium.crypto_scalarmult_PRIMITIVE = global.get_crypto_scalarmult_PRIMITIVE();


sodium.crypto_shorthash_BYTES = global.get_crypto_shorthash_BYTES();
sodium.crypto_shorthash_KEYBYTES = global.get_crypto_shorthash_KEYBYTES();
sodium.crypto_shorthash_PRIMITIVE = global.get_crypto_shorthash_PRIMITIVE();


sodium.crypto_kdf_KEYBYTES = global.get_crypto_kdf_KEYBYTES();
sodium.crypto_kdf_BYTES_MIN = global.get_crypto_kdf_BYTES_MIN();
sodium.crypto_kdf_BYTES_MAX = global.get_crypto_kdf_BYTES_MAX();
sodium.crypto_kdf_CONTEXTBYTES = global.get_crypto_kdf_CONTEXTBYTES();
sodium.crypto_kdf_PRIMITIVE = global.get_crypto_kdf_PRIMITIVE();


sodium.crypto_hash_BYTES = global.get_crypto_hash_BYTES();
sodium.crypto_hash_sha256_BYTES = global.get_crypto_hash_sha256_BYTES();
sodium.crypto_hash_sha512_BYTES = global.get_crypto_hash_sha512_BYTES();
sodium.crypto_hash_sha256_STATEBYTES = global.get_crypto_hash_sha256_STATEBYTES();
sodium.crypto_hash_sha512_STATEBYTES = global.get_crypto_hash_sha512_STATEBYTES();
sodium.crypto_hash_PRIMITIVE = global.get_crypto_hash_PRIMITIVE();
sodium.crypto_hash_sha256_instance = function() { return new CryptoHashSha256Instance(); }
sodium.crypto_hash_sha512_instance = function() { return new CryptoHashSha512Instance(); }


class CryptoGenericHashInstance {
	state = new Uint8Array(sodium.crypto_generichash_STATEBYTES);

	constructor(key, outlen) {
		if (typeof key === "undefined" || key === null) {
			sodium.crypto_generichash_init(this.state, outlen || sodium.crypto_generichash_BYTES);
		} else if (typeof key === "number") {
			sodium.crypto_generichash_init(this.state, key);
		} else if (key instanceof Uint8Array) {
			sodium.crypto_generichash_init(this.state, key, typeof outlen === "number" ? outlen : sodium.crypto_generichash_BYTES);
		} else {
			throw new Error("Invalid arguments");
		}
	}

	update(inp) {
		sodium.crypto_generichash_update(this.state, inp);
	}

	final(out) {
		sodium.crypto_generichash_final(this.state, out);
	}
}


class CryptoStreamXorInstance {
	state = new Uint8Array();

	constructor(n, k) {
		sodium.crypto_stream_xor_init(this.state, n, k);
	}

	update(c, m) {
		// sodium.crypto_stream_xor_update(this.state, c, m);
	}

	final() {
		// sodium.crypto_stream_xor_final(this.state, new Uint8Array());
	}
}


class CryptoStreamChaCha20XorInstance {
	state = new Uint8Array();

	constructor(n, k) {
		sodium.crypto_stream_chacha20_xor_init(this.state, n, k);
	}

	update(c, m) {
		// sodium.crypto_stream_chacha20_xor_update(this.state, c, m);
	}

	final() {
		// sodium.crypto_stream_chacha20_xor_final(this.state, new Uint8Array());
	}
}


class CryptoStreamChaCha20IETFXorInstance {
	state = new Uint8Array();

	constructor(n, k) {
		sodium.crypto_stream_chacha20_ietf_xor_init(this.state, n, k);
	}

	update(c, m) {
		// sodium.crypto_stream_chacha20_ietf_xor_update(this.state, c, m);
	}

	final() {
		// sodium.crypto_stream_chacha20_ietf_xor_final(this.state, new Uint8Array());
	}
}


class CryptoOneTimeAuthInstance {
	state = new Uint8Array(sodium.crypto_onetimeauth_STATEBYTES);

	constructor(k) {
		sodium.crypto_onetimeauth_init(this.state, k);
	}

	update(inp) {
		sodium.crypto_onetimeauth_update(this.state, inp);
	}

	final(out) {
		sodium.crypto_onetimeauth_final(this.state, out);
	}
}


class CryptoHashSha256Instance {
	state = new Uint8Array(sodium.crypto_hash_sha256_STATEBYTES);

	constructor() {
		sodium.crypto_hash_sha256_init(this.state, 0);
	}

	update(inp) {
		sodium.crypto_hash_sha256_update(this.state, inp);
	}

	final(out) {
		sodium.crypto_hash_sha256_final(this.state, out);
	}
}


class CryptoHashSha512Instance {
	state = new Uint8Array(sodium.crypto_hash_sha512_STATEBYTES);

	constructor() {
		sodium.crypto_hash_sha512_init(this.state, 0);
	}

	update(inp) {
		sodium.crypto_hash_sha512_update(this.state, inp);
	}

	final(out) {
		sodium.crypto_hash_sha512_final(this.state, out);
	}
}


module.exports = sodium;
