local lib_secureuid = require("secureunionid")
local SUCCESS = lib_secureuid.SUCCESS

local secureuid = lib_secureuid.new()

local function test_libsecureuid()
    assert(lib_secureuid.MASTER_KEY_LEN == 64)
    assert(lib_secureuid._VERSION == "0.1")
    assert(secureuid.MASTER_KEY_LEN == 64)
    assert(secureuid._VERSION == "0.1")
end

local function test_randseed()
    local r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    local seed1 = secureuid:get_randseed()

    r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    local seed2 = secureuid:get_randseed()

    assert(seed1 ~= seed2)
    assert(#seed1 == #seed2)
    assert(#seed1 == 2 * secureuid.MASTER_KEY_LEN)
end

local function test_masterkey()
    local r = SUCCESS

    r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    r = secureuid:gen_masterkey()
    assert(r == SUCCESS)
    local masterkey1 = secureuid:get_masterkey()
    r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    r = secureuid:gen_masterkey()
    assert(r == SUCCESS)
    local masterkey2 = secureuid:get_masterkey()

    assert(masterkey1 ~= masterkey2)

    local masterkey3 = "e019136679dbae3388e74787c74984f095d21ff56a17aa52391bebe79af72a6778fc2d31efde5d2bd044bee9aa8e3e25b4e26911ce1a8caabfb76d716576426e"
    r = secureuid:set_masterkey(masterkey3)
    assert(r == SUCCESS)
    local masterkey4 = secureuid:get_masterkey()
    assert(masterkey3 == masterkey4)

    -- nil master key
    r = secureuid:set_masterkey(nil)
    assert(r ~= SUCCESS)
    -- illegal master key
    r = secureuid:set_masterkey("1")
    assert(r ~= SUCCESS)
end

local function test_key()
    local dspid = "67d5d529-7303-4684-9a4e-99cf352bd092"

    local r, key = secureuid:gen_key(dspid)
    assert(r == SUCCESS)
    assert(key ~= nil)
    local pubkey_g1 = key.pubkey_g1
    local pubkey_g2 = key.pubkey_g2
    local privatekey = key.privatekey
    assert(#pubkey_g1 == secureuid.PUBKEY_G1_LEN * 2)
    assert(#pubkey_g2 == secureuid.PUBKEY_G2_LEN * 2)
    assert(#privatekey == secureuid.PRIVATE_KEY_LEN * 2)

    r = secureuid:gen_key(nil)
    assert(r ~= SUCCESS)

    r = secureuid:gen_key("")
    assert(r ~= SUCCESS)
end

-- gen same systemkey from same masterkey
local function test_key2()
    local r = SUCCESS
    local masterkey = "e019136679dbae3388e74787c74984f095d21ff56a17aa52391bebe79af72a6778fc2d31efde5d2bd044bee9aa8e3e25b4e26911ce1a8caabfb76d716576426e"
    local dspid = "67d5d529-7303-4684-9a4e-99cf352bd092"

    r = secureuid:gen_randseed()
    r = secureuid:set_masterkey(masterkey)
    r, key1 = secureuid:gen_key(dspid)
    _, syskey1 = secureuid:gen_systemkey(key1.pubkey_g1, key1.pubkey_g2)

    r = secureuid:gen_randseed()
    r = secureuid:set_masterkey(masterkey)
    r, key2 = secureuid:gen_key(dspid)
    _, syskey2 = secureuid:gen_systemkey(key2.pubkey_g1, key2.pubkey_g2)

    assert(key1.pubkey_g1, key2.pubkey_g1)
    assert(key1.pubkey_g2, key2.pubkey_g2)
    assert(key1.privatekey, key2.privatekey)
    assert(syskey1.syskey_g1, syskey2.syskey_g1)
    assert(syskey1.syskey_g2, syskey2.syskey_g2)
end

local function test_system_key()
    local dspid = "67d5d529-7303-4684-9a4e-99cf352bd092"

    local r, key = secureuid:gen_key(dspid)
    r, syskey = secureuid:gen_systemkey(key.pubkey_g1, key.pubkey_g2)
    assert(r == SUCCESS)
    local syskey_g1 = syskey.syskey_g1
    local syskey_g2 = syskey.syskey_g2
    assert(#syskey_g1 == secureuid.PUBKEY_G1_LEN * 2)
    assert(#syskey_g2 == secureuid.PUBKEY_G2_LEN * 2)

    r = secureuid:gen_systemkey(nil, key.pubkey_g2)
    assert(r ~= SUCCESS)
    r = secureuid:gen_systemkey(key.pubkey_g1, nil)
    assert(r ~= SUCCESS)
    r = secureuid:gen_systemkey(key.pubkey_g1, "1")
    assert(r ~= SUCCESS)
    r = secureuid:gen_systemkey("2", key.pubkey_g2)
    assert(r ~= SUCCESS)
end

local function test_blind()
    local did = "67d5d529-7303-4684-9a4e-99cf352bd092"

    local r, blind = secureuid:blind(did)
    assert(r == SUCCESS)
    local beta_v = blind.beta
    local blind_v = blind.blind
    assert(#beta_v, 2 * (2 * secureuid.PRIVATE_KEY_LEN + 1))
    assert(#blind_v, 2 * secureuid.PUBKEY_G1_LEN)

    r = secureuid:gen_randseed()
    local _, blind2 = secureuid:blind(did)
    local beta2_v = blind2.beta
    local blind2_v = blind2.blind
    assert(#beta2_v, 2 * (2 * secureuid.PRIVATE_KEY_LEN + 1))
    assert(#blind2_v, 2 * secureuid.PUBKEY_G1_LEN)
    assert(beta2_v ~= beta_v)
    assert(blind2_v ~= blind_v)
end

local function test_encrypt()
    local dspid = "a49fec12-3d31-4603-9d6b-4c94ab72000e"
    local did = "a49fec12-3d31-4603-9d6b-4c94ab72000f"
    local r = SUCCESS
    local cipher = nil
    local key = nil
    local blind = nil

    secureuid:gen_randseed()
    r, blind = secureuid:blind(did)

    secureuid:gen_randseed()
    r, key = secureuid:gen_key(dspid)
    r, cipher = secureuid:encrypt(key.privatekey, blind.blind)
    assert(r == SUCCESS)
    assert(#cipher == 2 * secureuid.PUBKEY_G1_LEN)
    assert(cipher ~= blind.blind)
    assert(cipher ~= blind.beta)
end

local function test_unblind()
    local dspid = "a49fec12-3d31-4603-9d6b-4c94ab72000e"
    local did = "a49fec12-3d31-4603-9d6b-4c94ab72000f"
    local r = SUCCESS
    local cipher = nil
    local key = nil
    local blind = nil
    local syskey = nil
    local unblind_cipher = nil

    secureuid:gen_randseed()
    secureuid:gen_masterkey()
    r, key = secureuid:gen_key(dspid)
    r, syskey = secureuid:gen_systemkey(key.pubkey_g1, key.pubkey_g2)

    secureuid:gen_randseed()
    r, blind = secureuid:blind(did)

    r, cipher = secureuid:encrypt(key.privatekey, blind.blind)

    r, unblind_cipher = secureuid:unblind(syskey.syskey_g1, blind.beta, cipher)
    assert(r == SUCCESS)
    assert(#unblind_cipher == 2 * secureuid.PUBKEY_G1_LEN)
end

local function test_verify()
    local dspid = "a49fec12-3d31-4603-9d6b-4c94ab72000e"
    local did = "a49fec12-3d31-4603-9d6b-4c94ab72000f"
    local r = SUCCESS
    local cipher = nil
    local key = nil
    local blind = nil
    local syskey = nil
    local unblind_cipher = nil

    secureuid:gen_randseed()
    secureuid:gen_masterkey()
    r, key = secureuid:gen_key(dspid)
    r, syskey = secureuid:gen_systemkey(key.pubkey_g1, key.pubkey_g2)

    secureuid:gen_randseed()
    r, blind = secureuid:blind(did)

    r, cipher = secureuid:encrypt(key.privatekey, blind.blind)

    r = secureuid:verify(key.pubkey_g1, key.pubkey_g2, did, blind.beta, cipher)
    assert(r == SUCCESS)
end

local function test_business1()
    local dspid = "a49fec12-3d31-4603-9d6b-4c94ab72000e"
    local did = "a49fec12-3d31-4603-9d6b-4c94ab72000f"

    --
    -- 密钥分发
    --

    -- media: 生成密钥
    secureuid:gen_randseed()
    secureuid:gen_masterkey()
    local _, key = secureuid:gen_key(dspid)
    -- baidu: 为taobao分发公钥
    local _, syskey = secureuid:gen_systemkey(key.pubkey_g1, key.pubkey_g2)

    --
    -- offline 数据对齐
    --

    -- dsp: 盲化 did
    secureuid:gen_randseed()
    local _, blind = secureuid:blind(did)

    -- media: 加密盲化 did
    local _, cipher = secureuid:encrypt(key.privatekey, blind.blind)

    -- dsp: 去盲
    local _, unblind_cipher = secureuid:unblind(syskey.syskey_g1, blind.beta, cipher)

    --
    -- online
    --

    -- media: 产生加密的did
    secureuid:gen_randseed()
    local _, blind2 = secureuid:blind(did)
    local _, cipher2 = secureuid:encrypt(key.privatekey, blind2.blind)
    local _, unblind_cipher2 = secureuid:unblind(syskey.syskey_g1, blind2.beta, cipher2)

    -- dsp: 查询数据库 <加密did -- did>
    assert(unblind_cipher == unblind_cipher2)

    assert(blind2.blind ~= blind.blind)
    assert(blind2.beta ~= blind.beta)
    assert(unblind_cipher ~= did)
    assert(unblind_cipher2 ~= did)
end

test_randseed()
test_libsecureuid()
test_masterkey()
test_key()
test_key2()
test_system_key()
test_blind()
test_encrypt()
test_unblind()
test_verify()
test_business1()