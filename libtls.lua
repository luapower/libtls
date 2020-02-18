local ffi = require'ffi'
require'libtls_h'
local C = ffi.load'tls_bearssl'
local M = {C = C}

local function ptr(p) return p ~= nil and p or nil end
local function str(s) return s ~= nil and ffi.string(s) or nil end

local config = {}

function M.config()
	return assert(ptr(C.tls_config_new()))
end

config.free = C.tls_config_free

local function check(c, ret)
	if ret == 0 then return true end
	return nil, str(C.tls_config_error(c))
end

function config:add_keypair_file(cert_file, key_file)
	return check(self, C.tls_config_add_keypair_file(self, cert_file, key_file))
end

function config:add_keypair(cert_buf, cert_len, key_buf, key_len)
	return check(self, C.tls_config_add_keypair_mem(self,
		cert_buf, cert_len or #cert_buf,
		key_buf, key_len or #key_buf))
end

function config:add_keypair_ocsp_file(cert_file, key_file, ocsp_staple_file)
	return check(self, C.tls_config_add_keypair_ocsp_file(self,
		cert_file, key_file, ocsp_staple_file))
end

function config:add_keypair_ocsp_file(cert_file, key_file, ocsp_staple_file)
	return check(self, C.tls_config_add_keypair_ocsp_file(self,
		cert_file, key_file, ocsp_staple_file))
end

function config:add_keypair_ocsp(cert_len, key, key_len, staple, staple_len)
	return check(self, C.tls_config_add_keypair_ocsp_mem(self,
		cert, cert_len or #cert,
		key, key_len or #key,
		staple, staple_len or #staple))
end

function config:set_alpn(alpn)
	return check(self, C.tls_config_set_alpn(self, alpn))
end

function config:set_ca_file(ca_file)
	return check(self, C.tls_config_set_ca_file(self, ca_file))
end

function config:set_ca_path(ca_path)
	return check(self, C.tls_config_set_ca_path(self, ca_path))
end

function config:set_ca(ca, ca_len)
	return check(self, C.tls_config_set_ca_mem(self, ca, ca_len or #ca))
end

function config:set_cert_file(cert_file)
	return check(self, C.tls_config_set_cert_file(self, cert_file))
end

function config:set_cert(cert, cert_len)
	return check(self, C.tls_config_set_cert_mem(self, cert, cert_len or #cert))
end

function config:add_ticket_key(keyrev, key, keylen)
	return check(self, C.tls_config_add_ticket_key(self, keyrev, key, keylen or #key))
end

function config:set_ciphers(ciphers)
	return check(self, C.tls_config_set_ciphers(self, ciphers))
end

function config:set_crl_file(crl_file)
	return check(self, C.tls_config_set_crl_file(self, crl_file))
end

function config:set_crl(crl, len)
	return check(self, C.tls_config_set_crl_mem(self, crl, len or #crl))
end

function config:set_dheparams(params)
	return check(self, C.tls_config_set_dheparams(self, params))
end

function config:set_ecdhecurve(curve)
	return check(self, C.tls_config_set_ecdhecurve(self, curve))
end

function config:set_ecdhecurves(curves)
	return check(self, C.tls_config_set_ecdhecurves(self, curves))
end

function config:set_key_file(key_file)
	return check(self, C.tls_config_set_key_file(self, key_file))
end

function config:set_key(key, len)
	return check(self, C.tls_config_set_key_mem(self, key, len or #key))
end

function config:set_keypair_file(cert_file, key_file)
	return check(self, C.tls_config_set_keypair_file(self, cert_file, key_file))
end

function config:set_keypair(cert, cert_len, key, key_len)
	return check(self, C.tls_config_set_keypair_mem(self,
		cert, cert_len or #cert,
		key, key_len or #key))
end

function config:set_keypair_ocsp_file(cert_file, key_file, staple_file)
	return check(self, C.tls_config_set_keypair_ocsp_file(self, cert_file, key_file, staple_file))
end

function config:set_keypair_ocsp(cert, cert_len, key, key_len, staple, staple_len)
	return check(self, C.tls_config_set_keypair_ocsp_mem(self, cert,
		 cert_len or #cert,
		 key, key_len or #key,
		 staple, staple_len or #staple))
end

function config:set_ocsp_staple(staple, len)
	return check(self, C.tls_config_set_ocsp_staple_mem(self, staple, len or #staple))
end

function config:set_ocsp_staple_file(staple_file)
	return check(self, C.tls_config_set_ocsp_staple_file(self, staple_file))
end

function config:set_protocols(protocols)
	local err
	if type(protocols) == 'string' then
		protocols, err = self:parse_protocols(protocols)
		if not protocols then return nil, err end
	end
	return check(self, C.tls_config_set_protocols(self, protocols))
end

function config:set_session_fd(session_fd)
	return check(self, C.tls_config_set_session_fd(self, session_fd))
end

function config:set_verify_depth(verify_depth)
	return check(self, C.tls_config_set_verify_depth(self, verify_depth))
end

config.prefer_ciphers_client  = C.tls_config_prefer_ciphers_client
config.prefer_ciphers_server  = C.tls_config_prefer_ciphers_server
config.insecure_noverifycert  = C.tls_config_insecure_noverifycert
config.insecure_noverifyname  = C.tls_config_insecure_noverifyname
config.insecure_noverifytime  = C.tls_config_insecure_noverifytime
config.verify                 = C.tls_config_verify
config.ocsp_require_stapling  = C.tls_config_ocsp_require_stapling
config.verify_client          = C.tls_config_verify_client
config.verify_client_optional = C.tls_config_verify_client_optional
config.clear_keys             = C.tls_config_clear_keys

local proto_buf = ffi.new'uint32_t[1]'
function config:parse_protocols(protostr)
	local ok, err = check(self, C.tls_config_parse_protocols(proto_buf, protostr))
	if not ok then return nil, err end
	return proto_buf[0]
end

function config:set_session_id(session_id, len)
	return check(self, C.tls_config_set_session_id(self, session_id, len or #session_id))
end

function config:set_session_lifetime(lifetime)
	return check(self, C.tls_config_set_session_lifetime(self, lifetime))
end

do
	local function set(self, t, fields, set_method)
		if not t then return true end
		local args
		if type(t) == 'table' then
			if #t > 0 then
				args = t
			else
				args = {}
				for i,field in ipairs(fields) do
					args[i] = t[field]
				end
			end
		else
			args = {t}
		end
		return set_method(self, unpack(args))
	end

	local function add(self, t, fields, add_method)
		if not t then return true end
		for i,t in ipairs(t) do
			local ok, err = set(t, fields, add_method)
			if not ok then return nil, err end
		end
		return true
	end

	local args = {
		{add, 'keypair_files', {'cert_file', 'key_file'}, config.add_keypair},
		{add, 'keypairs', {'cert', 'cert_size', 'key', 'key_size'}, config.add_keypair},
		{set, 'ca_file', {'file'}, config.set_ca_file},
		{set, 'ca_path', {'path'}, config.set_ca_path},
		{set, 'ca', {'data', 'size'}, config.set_ca},
		{set, 'cert_file', {'file'}, config.set_cert_file},
		{set, 'cert', {'data', 'size'}, config.set_cert},
	}

	function config:set(t)
		for i,a in ipairs(args) do
			local set, k, fields, set_method = unpack(a)
			local ok, err = set(self, t[k], fields, set_method)
			if not ok then return nil, err end
		end
		return true
	end
end

ffi.metatype('struct tls_config', {__index = config})

local function check(c, ret)
	if ret == 0 then return true end
	return nil, str(C.tls_error(c))
end

local tls = {}

function tls:configure(conf)
	return check(self, C.tls_configure(self, conf))
end

function M.client()
	return assert(ptr(C.tls_client()))
end

function M.server(config)
	return assert(ptr(C.tls_server()))
end

function tls:reset()
	return check(self, C.tls_reset(self))
end

function tls:free()
	return check(self, C.tls_free(self))
end

function tls:accept(cctx, read_cb, write_cb, cb_arg)
	return check(self, C.tls_accept_cbs(self, cctx, read_cb, write_cb, cb_arg))
end

function tls:connect(servername, read_cb, write_cb, cb_arg)
	return check(self, C.tls_connect_cbs(self, read_cb, write_cb, cb_arg, servername))
end

function tls:handshake()
	return check(self, C.tls_handshake(self))
end

function tls:read(buf, sz)
	return check(self, C.tls_read(self, buf, sz))
end

function tls:write(buf, sz)
	return check(self, C.tls_write(self, buf, sz or #buf))
end

function tls:close()
	return check(self, C.tls_close(self))
end


ffi.metatype('struct tls', {__index = tls})


if not ... then
	local tls = M

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

end

return M
