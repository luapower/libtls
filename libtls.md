
## `local tls = require'libtls'`

libtls ffi binding. Use it with luapower's [libtls_bearssl] and [bearssl]
or with your own libressl binary.

## Rationale

libtls has a sane API as opposed to OpenSSL which was written by monkeys.
libtls doesn't force us to do I/O in its callbacks which we can't do
anyway because we can't yield from C callbacks.

## Status

<warn>Work in progress</warn>

## API

------------------------------------------------- ----------------------------
__configuration__
`tls.config() -> conf`                            create a shared config object
`conf:free()`                                     free the config object
`conf:set{opt->val,{opt->val},...}`               set options in bulk
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
`conf:set_session_fd(session_fd)`                 NYI
`conf:set_session_id(session_id, sz)`             NYI
`conf:set_session_lifetime(lifetime)`             NYI
__operation__
`tls.client(conf) -> ts`
`tls.server(conf) -> ts`
`ts:configure(conf)`
`ts:reset(conf)`
`ts:free()`
`ts:accept(cctx, read_cb, write_cb, cb_arg)`
`ts:connect(vhost, read_cb, write_cb, cb_arg)`
`ts:recv(buf, sz)`
`ts:send(buf, sz)`
`ts:close()`
------------------------------------------------- ----------------------------
