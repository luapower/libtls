
--libtls binding.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'libtls_test'; return end

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
	return nil, str(C.tls_config_error(c)) or 'unknown error'
end

function config:add_keypair_file(cert_file, key_file, staple_file)
	return check(self, C.tls_config_add_keypair_ocsp_file(self,
		cert_file, key_file, staple_file))
end

function config:add_keypair(cert, cert_size, key, key_size, staple, staple_size)
	return check(self, C.tls_config_add_keypair_ocsp_mem(self,
		cert, cert_size or #cert,
		key, key_size or #key,
		staple, staple_size or #staple))
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

function config:set_ca(ca, ca_size)
	return check(self, C.tls_config_set_ca_mem(self, ca, ca_size or #ca))
end

function config:add_ticket_key(keyrev, key, key_size)
	return check(self, C.tls_config_add_ticket_key(self, keyrev, key, key_size or #key))
end

function config:set_ciphers(ciphers)
	return check(self, C.tls_config_set_ciphers(self, ciphers))
end

function config:set_crl_file(file)
	return check(self, C.tls_config_set_crl_file(self, file))
end

function config:set_crl(crl, sz)
	return check(self, C.tls_config_set_crl_mem(self, crl, sz or #crl))
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

function config:set_session_id(session_id, sz)
	return check(self, C.tls_config_set_session_id(self, session_id, sz or #session_id))
end

function config:set_session_lifetime(lifetime)
	return check(self, C.tls_config_set_session_lifetime(self, lifetime))
end

do
	local function barg(set_method)
		return function(self, arg)
			if not arg then return true end
			return set_method(self)
		end
	end

	local keys = {
		{'alpn'                  , config.set_alpn},
		{'ca_file'               , config.set_ca_file},
		{'ca_path'               , config.set_ca_path},
		{'ca'                    , config.set_ca, true},
		{'ciphers'               , config.set_ciphers},
		{'crl_file'              , config.set_crl_file},
		{'crl'                   , config.set_crl, true},
		{'dheparams'             , config.set_dheparams},
		{'ecdhecurve'            , config.set_ecdhecurve},
		{'ecdhecurves'           , config.set_ecdhecurves},
		{'protocols'             , config.set_protocols},
		{'session_fd'            , config.set_session_fd},
		{'verify_depth'          , config.set_verify_depth},
		{'session_id'            , config.set_session_id, true},
		{'session_lifetime'      , config.set_session_lifetime},
		{'prefer_ciphers_client' , barg(config.prefer_ciphers_client)},
		{'prefer_ciphers_server' , barg(config.prefer_ciphers_server)},
		{'insecure_noverifycert' , barg(config.insecure_noverifycert)},
		{'insecure_noverifyname' , barg(config.insecure_noverifyname)},
		{'insecure_noverifytime' , barg(config.insecure_noverifytime)},
		{'ocsp_require_stapling' , barg(config.ocsp_require_stapling)},
		{'verify'                , barg(config.verify)},
		{'verify_client'         , barg(config.verify_client)},
		{'verify_client_optional', barg(config.verify_client_optional)},
	}

	function config:set(t)
		if #t > 0 then
			for _,t in ipairs(t) do
				local ok, err = self:set(t)
				if not ok then return nil, err end
			end
			return true
		end
		if t.cert_file then
			local ok, err = self:add_keypair_file(t.cert_file, t.key_file, t.ocsp_staple_file)
			if not ok then return nil, err end
		end
		if t.cert then
			local ok, err = self:add_keypair(t.cert, t.cert_size, t.key, t.key_size, t.ocsp_staple, t.ocsp_staple_size)
			if not ok then return nil, err end
		end
		if t.ticket_key then
			local ok, err = self:add_ticket_key(t.ticket_key_rev, t.ticket_key, t.ticket_key_size)
			if not ok then return nil, err end
		end
		for i,kt in ipairs(keys) do
			local k, set_method, is_str = unpack(kt)
			local v = t[k]
			if v ~= nil then
				local sz = is_str and (t[k..'_size'] or #k) or nil
				local ok, err = set_method(self, v, sz)
				if not ok then return nil, err end
			end
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

return M
