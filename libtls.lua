local ffi = require'ffi'
require'libtls_h'
local C = ffi.load'tls_bearssl'
local M = {C = C}

local config = {}
function M.config(t)
	local self = C.tls_config_new()
	if t then self:set(t) end
	return self
end

config.free = C.tls_config_free

local function check(ret)
	assert(ret == 0)
end

function config:add_keypair_file(cert_file, key_file)
	check(C.tls_config_add_keypair_file(self, cert_file, key_file))
end

function config:add_keypair(cert_buf, cert_sz, key_buf, key_sz)
	check(C.tls_config_add_keypair_mem(self,
		cert_buf, cert_sz or #cert_buf,
		key_buf, key_sz or #key_buf))
end

function config:set_ca_file(ca_file)
	check(C.tls_config_set_ca_file(self, ca_file))
end

function config:set_ca_path(ca_path)
	check(C.tls_config_set_ca_path(self, ca_path))
end

function config:set_ca(ca, ca_sz)
	check(C.tls_config_set_ca_mem(self, ca, ca_sz or #ca))
end

function config:set_cert_file(cert_file)
	check(C.tls_config_set_cert_file(self, cert_file))
end

function config:set_cert(cert, cert_sz)
	check(C.tls_config_set_cert_mem(self, cert, cert_sz))
end

--[[
int tls_config_add_keypair_ocsp_file(struct tls_config *_config,
    const char *_cert_file, const char *_key_file,
    const char *_ocsp_staple_file);
int tls_config_add_keypair_ocsp_mem(struct tls_config *_config, const uint8_t *_cert,
    size_t _cert_len, const uint8_t *_key, size_t _key_len,
    const uint8_t *_staple, size_t _staple_len);
int tls_config_add_ticket_key(struct tls_config *_config, uint32_t _keyrev,
    unsigned char *_key, size_t _keylen);

int tls_config_set_alpn(struct tls_config *_config, const char *_alpn);
int tls_config_set_ciphers(struct tls_config *_config, const char *_ciphers);
int tls_config_set_crl_file(struct tls_config *_config, const char *_crl_file);
int tls_config_set_crl_mem(struct tls_config *_config, const uint8_t *_crl,
    size_t _len);
int tls_config_set_dheparams(struct tls_config *_config, const char *_params);
int tls_config_set_ecdhecurve(struct tls_config *_config, const char *_curve);
int tls_config_set_ecdhecurves(struct tls_config *_config, const char *_curves);
int tls_config_set_key_file(struct tls_config *_config, const char *_key_file);
int tls_config_set_key_mem(struct tls_config *_config, const uint8_t *_key,
    size_t _len);
int tls_config_set_keypair_file(struct tls_config *_config,
    const char *_cert_file, const char *_key_file);
int tls_config_set_keypair_mem(struct tls_config *_config, const uint8_t *_cert,
    size_t _cert_len, const uint8_t *_key, size_t _key_len);
int tls_config_set_keypair_ocsp_file(struct tls_config *_config,
    const char *_cert_file, const char *_key_file, const char *_staple_file);
int tls_config_set_keypair_ocsp_mem(struct tls_config *_config, const uint8_t *_cert,
    size_t _cert_len, const uint8_t *_key, size_t _key_len,
    const uint8_t *_staple, size_t staple_len);
int tls_config_set_ocsp_staple_mem(struct tls_config *_config,
    const uint8_t *_staple, size_t _len);
int tls_config_set_ocsp_staple_file(struct tls_config *_config,
    const char *_staple_file);
int tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols);
int tls_config_set_session_fd(struct tls_config *_config, int _session_fd);
int tls_config_set_verify_depth(struct tls_config *_config, int _verify_depth);

void tls_config_prefer_ciphers_client(struct tls_config *_config);
void tls_config_prefer_ciphers_server(struct tls_config *_config);

void tls_config_insecure_noverifycert(struct tls_config *_config);
void tls_config_insecure_noverifyname(struct tls_config *_config);
void tls_config_insecure_noverifytime(struct tls_config *_config);
void tls_config_verify(struct tls_config *_config);

void tls_config_ocsp_require_stapling(struct tls_config *_config);
void tls_config_verify_client(struct tls_config *_config);
void tls_config_verify_client_optional(struct tls_config *_config);

void tls_config_clear_keys(struct tls_config *_config);
int tls_config_parse_protocols(uint32_t *_protocols, const char *_protostr);

int tls_config_set_session_id(struct tls_config *_config,
    const unsigned char *_session_id, size_t _len);
int tls_config_set_session_lifetime(struct tls_config *_config, int _lifetime);
]]

local function set_t(t, fields, set_method)
	if not t then return end
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
	set_method(self, unpack(args))
end

local function add_t(t, fields, add_method)
	if not t then return end
	for i,t in ipairs(t) do
		set(t, fields, add_method)
	end
end

function config:set(t)
	add_t(t.keypair_files, {'cert_file', 'key_file'}, config.add_keypair)
	add_t(t.keypairs, {'cert', 'cert_size', 'key', 'key_size'}, config.add_keypair)
	set_t(t.ca_file, {'file'}, config.set_ca_file)
	set_t(t.ca_path, {'path'}, config.set_ca_path)
	set_t(t.ca, {'data', 'size'}, config.set_ca)
	set_t(t.cert_file, {'file'}, config.set_cert_file)
	set_t(t.cert, {'data', 'size'}, config.set_cert)
end

ffi.metatype('struct tls_config', {__index = config})

if not ... then
	local tls = M

	local c = tls.config{
		cert_file = 'file',
	}

	c:free()

end

return M
