--
-- secureunionid 库封装
--
-- 原则:
--   1. c string 对外不可见
--     1.1 出库的buf内容使用base64编码, 结果转换为lua string
--     1.2 入库内容为lua string
--
-- NOTE:
--   1. dspid, did均无长度限制, 一般选择用uuid

--
-- cache common function
--
local ffi               = require("ffi")
local ffi_new           = ffi.new
local ffi_str           = ffi.string
local ffi_copy          = ffi.copy
local ffi_cdef          = ffi.cdef
local char_arr_t        = ffi.typeof("char[?]")
local u_int8_arr_t      = ffi.typeof("uint8_t[?]")
local char_arr2d1_t     = ffi.typeof("char *[1]")
-- local char_arr2d2_t     = ffi.typeof("char *[2]")
-- local str_fmt           = string.format

--
-- load libsecureunionid lib
-- ref: lua-resty-radixtree/lib/resty/radixtree.lua
--
local lib_name = "libsecureunionid.so"

local function load_shared_lib(so_name)
    local string_gmatch = string.gmatch
    local string_match  = string.match
    local io_open       = io.open
    local io_close      = io.close

    local cpath = package.cpath
    local tried_paths = {}
    local i = 1
    for k, _ in string_gmatch(cpath, "[^;]+") do
        local fpath = string_match(k, "(.*/)")
        fpath = fpath .. so_name
        -- Don't get me wrong, the only way to know if a file exist is trying
        -- to open it.
        local f = io_open(fpath)
        if f ~= nil then
            io_close(f)
            return ffi.load(fpath)
        end
        tried_paths[i] = fpath
        i = i + 1
    end

    return nil, tried_paths
end

local mylib, tried_paths = load_shared_lib(lib_name)
if not mylib then
    tried_paths[#tried_paths + 1] = 'tried above paths but can not load '
                                    .. lib_name
    error(table.concat(tried_paths, '\r\n', 1, #tried_paths))
end

ffi_cdef[[
    typedef unsigned char u_char;

    unsigned long randomSeed();
    int genRandSeed(char *rnd);
    int MasterKeygen(unsigned long ran, char *masterkey);
    int genMasterKey(char *ran, char *masterkey);
    int Keygen(char *masterkey,
               char *dspid,
               char *pkg1string,
               char *pkg2string,
               char *skstring);
    int System_Keygen(char **pkig1string,
                      char **pkig2string,
                      int numofmedia,
                      char *sysg1string,
                      char *sysg2string);
    int Blinding(char *did,
                 unsigned long seed,
                 char *betastring,
                 char *Mstring);
    int Blind(char *did,
              char *seed,
              char *betastring,
              char *Mstring);
    int Enc(char *skstring, char *Mstring, char *btistring);
    int Unblinding(char **btistring,
                   int numofmedia,
                   char *betastring,
                   char *sysg1string,
                   char *btstring);
    int verify_individual(char **btistring,
                          char **pkig1string,
                          char **pkig2string,
                          char *did,
                          int numofmedia,
                          char *betastring);
    int batch_verify(char **btstring, char **did, char *sysg2string, int numofdid);

    int encode_base64url(u_char *dst, u_char *src, int len);
    int decode_base64url(u_char *dst, u_char *src, int len);
]]

--
-- convert lua string to c string
--
local function to_cstr(s)
    local buf = ffi_new(char_arr_t, #s + 1)
    ffi_copy(buf, s)
    return buf
end

local function base64_encoded_length(len)
    return math.floor(((len + 2) / 3) * 4)
end

local function base64_decoded_length(len)
    return math.floor(((len + 3) / 4) * 3)
end

local BUF_MAX_LEN   = 1024
local buf_base64    = ffi_new(u_int8_arr_t, BUF_MAX_LEN)

--
-- common const
--
local MASTER_KEY_LEN        = 64
local PRIVATE_KEY_LEN       = 32
local G1_LEN                = 33
local G2_LEN                = 128
local PUBKEY_G1_LEN         = G1_LEN * 2 + 1
local PUBKEY_G2_LEN         = G2_LEN * 2 + 1
local SUCCESS               = 0
local FAIL                  = -1
local C_NULL_POINTER_ERROR  = -3
local C_MALLOC_ERROR        = -4

local function my_malloc(len)
    if len == nil or len <= 0 then
        return FAIL, "len is nil or <= 0"
    end

    local dst
    if len <= BUF_MAX_LEN then
        dst = buf_base64
    else
        dst = ffi_new(u_int8_arr_t, len)
    end

    return SUCCESS, dst
end

--
-- convert c string to base64
-- and return the result in lua string
--
-- src      : pointer to c string
-- src_len  : integer
--
local function encode_base64(src, src_len)
    if src == nil or src_len <= 0 then
        return FAIL, "src is nil or len <= 0"
    end

    local dst_len = base64_encoded_length(src_len)
    local r, dst = my_malloc(dst_len)
    if r ~= SUCCESS then
        return FAIL, "dst buf not avaliable"
    end

    -- return len
    dst_len = mylib.encode_base64url(dst, src, src_len)
    return SUCCESS, ffi_str(dst, dst_len)
end

local function decode_base64(dst_result, s)
    local src_len = #s

    local dst_len = base64_decoded_length(src_len)
    local r, dst = my_malloc(dst_len)
    if r ~= SUCCESS then
        return FAIL, "dst buf not avaliable"
    end

    local len = mylib.decode_base64url(dst, to_cstr(s), src_len)
    if len > 0 then
        if dst_result == nil then
            dst_result = ffi_new(u_int8_arr_t, len)
        end
        ffi_copy(dst_result, dst, len)
        return SUCCESS, dst_result
    end

    return FAIL, "decode base64 error"
end

local _M = {
    _VERSION                = '0.1',
    MASTER_KEY_LEN          = MASTER_KEY_LEN,
    PRIVATE_KEY_LEN         = PRIVATE_KEY_LEN,
    G1_LEN                  = G1_LEN,
    G2_LEN                  = G2_LEN,
    PUBKEY_G1_LEN           = PUBKEY_G1_LEN,
    PUBKEY_G2_LEN           = PUBKEY_G2_LEN,
    SUCCESS                 = SUCCESS,
    FAIL                    = FAIL,
    C_NULL_POINTER_ERROR    = C_NULL_POINTER_ERROR,
    C_MALLOC_ERROR          = C_MALLOC_ERROR
}
local mt = { __index = _M }

function _M.new()
    local buf_randseed  = ffi_new(char_arr_t, MASTER_KEY_LEN)
    local buf_masterkey = ffi_new(char_arr_t, MASTER_KEY_LEN)

    local self = setmetatable({
        _buf_randseed    = buf_randseed,
        _buf_masterkey   = buf_masterkey,
    }, mt)

    return self
end

--
-- generate rand seed, save the result in inner _buf_randseed
--
function _M.gen_randseed(self)
    local randseed = self._buf_randseed
    local r = mylib.genRandSeed(randseed)
    if r == MASTER_KEY_LEN then
        return SUCCESS
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    elseif r == 3 then
        return FAIL, "gen rand seed error"
    end
    return r
end

function _M.get_randseed(self)
    local randseed = self._buf_randseed
    return encode_base64(randseed, MASTER_KEY_LEN)
end

--
-- set randseed buf
-- key: lua string, encode in base64 string
-- return: SUCCESS or FAIL
--
function _M.set_randseed(self, seed)
    if seed == nil or #seed == 0 then
        return FAIL, "illegal rand seed"
    end

    local dst = self._buf_randseed
    local r, err = decode_base64(dst, seed)
    if r ~= SUCCESS then
        return FAIL, err
    else
        return SUCCESS
    end
end

--
-- get master key, the result encode in base64 lua string
--
function _M.get_masterkey(self)
    local masterkey = self._buf_masterkey
    return encode_base64(masterkey, MASTER_KEY_LEN)
end

--
-- set master key buf
-- key: lua string, encode in base64 string
-- return: SUCCESS or FAIL
--
function _M.set_masterkey(self, key)
    if key == nil then
        return FAIL, "illegal master key"
    end

    local dst = self._buf_masterkey
    local r, err = decode_base64(dst, key)
    if r ~= SUCCESS then
        return FAIL, err
    else
        return SUCCESS
    end
end

--
-- regen master key
--
function _M.gen_masterkey(self)
    local randseed = self._buf_randseed
    local masterkey = self._buf_masterkey
    local r = mylib.genMasterKey(randseed, masterkey)
    if r == 2 then
        return SUCCESS
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    end
    return r
end

--
-- generate key
-- dspid: demand side platform id, lua string
--     dspid 一般使用uuid
--
function _M.gen_key(self, dspid)
    if not dspid or #dspid == 0 then
        return FAIL, "illegal dsp id"
    end

    local masterkey = self._buf_masterkey
    local pubkey_g1_cstr = ffi_new(char_arr_t, PUBKEY_G1_LEN)
    local pubkey_g2_cstr = ffi_new(char_arr_t, PUBKEY_G2_LEN)
    local privatekey_cstr = ffi_new(char_arr_t, PRIVATE_KEY_LEN)
    local dspid_cstr = to_cstr(dspid)

    local r = mylib.Keygen(masterkey, dspid_cstr, pubkey_g1_cstr, pubkey_g2_cstr, privatekey_cstr)
    if r == 2 then
        local _, pubkey_g1 = encode_base64(pubkey_g1_cstr, PUBKEY_G1_LEN)
        local _, pubkey_g2 = encode_base64(pubkey_g2_cstr, PUBKEY_G2_LEN)
        local _, privatekey = encode_base64(privatekey_cstr, PRIVATE_KEY_LEN)
        local key = {
            pubkey_g1 = pubkey_g1,
            pubkey_g2 = pubkey_g2,
            privatekey = privatekey
        }
        return SUCCESS, key
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    end
    return r
end

--
-- generate system key
--
function _M.gen_systemkey(pubkey_g1, pubkey_g2)
    if pubkey_g1 == nil or pubkey_g2 == nil then
        return FAIL, "illegal pubkey_g1 or pubkey_g2"
    end

    local _, pubkey_g1_cstr = decode_base64(nil, pubkey_g1)
    local _, pubkey_g2_cstr = decode_base64(nil, pubkey_g2)
    local pubkey_g1_ary = ffi_new(char_arr2d1_t, pubkey_g1_cstr)
    local pubkey_g2_ary = ffi_new(char_arr2d1_t, pubkey_g2_cstr)
    local syskey_g1_cstr = ffi_new(char_arr_t, PUBKEY_G1_LEN)
    local syskey_g2_cstr = ffi_new(char_arr_t, PUBKEY_G2_LEN)

    local r = mylib.System_Keygen(pubkey_g1_ary, pubkey_g2_ary, 1, syskey_g1_cstr, syskey_g2_cstr)
    if r == 2 then
        local _, syskey_g1 = encode_base64(syskey_g1_cstr, PUBKEY_G1_LEN)
        local _, syskey_g2 = encode_base64(syskey_g2_cstr, PUBKEY_G2_LEN)
        local key = {
            syskey_g1 = syskey_g1,
            syskey_g2 = syskey_g2
        }
        return SUCCESS, key
    elseif r == 3 then
        return FAIL
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c  null pointer error"
    elseif r == 1 then
        return C_MALLOC_ERROR, "c malloc error"
    end
    return r
end

--
-- blind
-- did: device id
--
function _M.blind(self, did)
    if not did or #did == 0 then
        return FAIL, "illegal device id"
    end

    local did_cstr = to_cstr(did)
    local randseed = self._buf_randseed
    local beta_cstr = ffi_new(char_arr_t, 2 * PRIVATE_KEY_LEN + 1)
    local blind_cstr = ffi_new(char_arr_t, PUBKEY_G1_LEN)

    local r = mylib.Blind(did_cstr, randseed, beta_cstr, blind_cstr)
    if r == 2 then
        local _, beta = encode_base64(beta_cstr, 2 * PRIVATE_KEY_LEN + 1)
        local _, blind = encode_base64(blind_cstr, PUBKEY_G1_LEN)
        return SUCCESS, { beta = beta, blind = blind }
    elseif r == 3 then
        return FAIL, "unkown"
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    end
    return r
end

--
-- encrypt
--
function _M.encrypt(privatekey, blind)
    local _, privatekey_cstr = decode_base64(nil, privatekey)
    local _, blind_cstr = decode_base64(nil, blind)
    local cipher_cstr = ffi_new(char_arr_t, PUBKEY_G1_LEN)
    local r = mylib.Enc(privatekey_cstr, blind_cstr, cipher_cstr)
    if r == 2 then
        return encode_base64(cipher_cstr, PUBKEY_G1_LEN)
    elseif r == 3 then
        return FAIL
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    elseif r == 1 then
        return C_MALLOC_ERROR, "c malloc error"
    end
    return r
end

--
-- unblind
--
function _M.unblind(syskey_g1, beta, cipher)
    local _, syskey_g1_cstr = decode_base64(nil, syskey_g1)
    local _, beta_cstr = decode_base64(nil, beta)
    local _, cipher_cstr = decode_base64(nil, cipher)
    local cipher_ary = ffi_new(char_arr2d1_t, cipher_cstr)
    local unblind_cstr = ffi_new(char_arr_t, PUBKEY_G1_LEN)
    local r = mylib.Unblinding(cipher_ary, 1, beta_cstr, syskey_g1_cstr, unblind_cstr)
    if r == 2 then
        return encode_base64(unblind_cstr, PUBKEY_G1_LEN)
    elseif r == 3 then
        return FAIL, "unkown"
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    end
    return r
end

--
-- batch verify
--
function _M.verify(_, pubkey_g1, pubkey_g2, did, beta, cipher)
    local _, pubkey_g1_cstr = decode_base64(nil, pubkey_g1)
    local pubkey_g1_ary = ffi_new(char_arr2d1_t, pubkey_g1_cstr)
    local _, pubkey_g2_cstr = decode_base64(nil, pubkey_g2)
    local pubkey_g2_ary = ffi_new(char_arr2d1_t, pubkey_g2_cstr)
    local did_cstr = to_cstr(did)
    local _, beta_cstr = decode_base64(nil, beta)
    local _, cipher_cstr = decode_base64(nil, cipher)
    local cipher_ary = ffi_new(char_arr2d1_t, cipher_cstr)

    local r = mylib.verify_individual(cipher_ary, pubkey_g1_ary, pubkey_g2_ary, did_cstr, 1, beta_cstr)
    if r == 2 then
        return SUCCESS
    elseif r == 3 then
        return FAIL, "unkown"
    elseif r == 0 then
        return C_NULL_POINTER_ERROR, "c null pointer error"
    elseif r == 1 then
        return C_MALLOC_ERROR, "c malloc error"
    elseif r < 0 then
        return -r, "unkown"
    end
    return r
end

return _M