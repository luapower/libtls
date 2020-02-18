local tls = require'libtls'
local ffi = require'ffi'

local conf = tls.config()
assert(conf:set{
	--cert = 'xx',
	--cert_file = 'file',
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

