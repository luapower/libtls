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

		--{'prefer_ciphers_client' , barg(config.prefer_ciphers_client)},
		--{'prefer_ciphers_server' , barg(config.prefer_ciphers_server)},
		--{'insecure_noverifycert' , barg(config.insecure_noverifycert)},
		--{'insecure_noverifyname' , barg(config.insecure_noverifyname)},
		--{'insecure_noverifytime' , barg(config.insecure_noverifytime)},
		--{'ocsp_require_stapling' , barg(config.ocsp_require_stapling)},
		--{'verify'                , barg(config.verify)},
		--{'verify_client'         , barg(config.verify_client)},
		--{'verify_client_optional', barg(config.verify_client_optional)},

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

