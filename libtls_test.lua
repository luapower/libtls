local tls = require'libtls'
local ffi = require'ffi'

local conf = tls.config()
assert(conf:set{

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

})

local c = tls.client()

assert(c:configure(conf))

local function checkio(self, ret)
	if ret == C.TLS_WANT_POLLIN then
		--
	elseif ret == C.TLS_WANT_POLLOUT then
		--
	end
end

local read_cb = ffi.cast('tls_read_cb', function(self, buf, buf_sz, cb_arg)
	return C.TLS_WANT_POLLIN
end)

local write_cb = ffi.cast('tls_write_cb', function(self, buf, buf_sz, cb_arg)
	return C.TLS_WANT_POLLOUT
end)

conf:free()

