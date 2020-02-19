
## `local tls = require'libtls'`

## API

------------------------------------------------- ----------------------------
__configuration__
`tls.config() -> conf`                            create a shared config object
`conf:free()`                                     free the config object
`conf:set{opt->val}`                              set options in bulk

	alpn = '123',
	--ca_file = 'xx',
	--ca_path = 'x:/',
	ca = 'x',
	--ciphers = 'P-256',
	--crl_file = 'x',
	--crl = 'x',
	--dheparams = 'a',
	--ecdhecurve = 'x',
	--ecdhecurves = 'z,y',
	ocsp_staple = 'x',
	ocsp_staple_file = 'x',
	--protocols = 'x',
	verify_depth = true,

	--sessions are not supported by BearSSL
	--session_fd = 1,
	--session_id = '1',
	--session_lifetime = 1,

	prefer_ciphers_client  = true,
	prefer_ciphers_server  = true,
	insecure_noverifycert  = true,
	insecure_noverifyname  = true,
	insecure_noverifytime  = true,
	ocsp_require_stapling  = true,
	verify                 = true,
	verify_client          = true,
	verify_client_optional = true,


`conf:add_keypair_file(cert_file, key_file, [staple_file])`
`conf:add_keypair(cert, [cert_size], key, [key_size], [staple], [staple_size])`
`conf:add_ticket_key(keyrev, key, [key_size])`
`conf:clear_keys()`
`conf:set_alpn(alpn)`
`conf:set_ca_file(ca_file)`
`conf:set_ca_path(ca_path)`
`conf:set_ca(ca, [ca_size])`
`conf:set_ciphers(ciphers)`
`conf:set_crl_file(file)`
`conf:set_crl(crl, sz)`
`conf:set_dheparams(params)`
`conf:set_ecdhecurve(curve)`
`conf:set_ecdhecurves(curves)`
`conf:set_key_file(key_file)`
`conf:set_protocols(protocols)`
`conf:set_verify_depth(verify_depth)`
`conf:prefer_ciphers_client()`
`conf:prefer_ciphers_server()`
`conf:insecure_noverifycert()`
`conf:insecure_noverifyname()`
`conf:insecure_noverifytime()`
`conf:verify()`
`conf:ocsp_require_stapling()`
`conf:verify_client()`
`conf:verify_client_optional()`
`conf:parse_protocols(protostr)`
`conf:set_session_fd(session_fd)`                 NYI:
`conf:set_session_id(session_id, sz)`             NYI:
`conf:set_session_lifetime(lifetime)`             NYI:
__operation__

------------------------------------------------- ----------------------------
