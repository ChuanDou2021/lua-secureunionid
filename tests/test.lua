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
    local _, seed1 = secureuid:get_randseed()

    r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    local _, seed2 = secureuid:get_randseed()

    assert(seed1 ~= seed2)
    assert(#seed1 == #seed2)

    local r, _ = secureuid:set_randseed(seed1)
    assert(r == SUCCESS)
    local _, seed1_1 = secureuid:get_randseed()
    assert(seed1 == seed1_1)
end

local function test_masterkey()
    local r = SUCCESS

    r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    r = secureuid:gen_masterkey()
    assert(r == SUCCESS)
    local _, masterkey1 = secureuid:get_masterkey()
    r = secureuid:gen_randseed()
    assert(r == SUCCESS)
    r = secureuid:gen_masterkey()
    assert(r == SUCCESS)
    local _, masterkey2 = secureuid:get_masterkey()

    assert(masterkey1 ~= masterkey2)

    local masterkey3 = "m7Ji5CWhxDMOp2AOM1RLGSDGkDW1M59IAmt88DSCeu1I_ZabtA5yVk46E-2JsMCPEtW3h1U5MOrIqc6v5rD7qQ"
    r = secureuid:set_masterkey(masterkey3)
    assert(r == SUCCESS)
    local _, masterkey4 = secureuid:get_masterkey()
    assert(masterkey3 == masterkey4)

    -- nil master key
    r = secureuid:set_masterkey(nil)
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

    r = secureuid:gen_key(nil)
    assert(r ~= SUCCESS)

    r = secureuid:gen_key("")
    assert(r ~= SUCCESS)
end

-- gen same systemkey from same masterkey
local function test_key2()
    local r = SUCCESS
    local masterkey = "m7Ji5CWhxDMOp2AOM1RLGSDGkDW1M59IAmt88DSCeu1I_ZabtA5yVk46E-2JsMCPEtW3h1U5MOrIqc6v5rD7qQ"
    local dspid = "67d5d529-7303-4684-9a4e-99cf352bd092"

    r = secureuid:gen_randseed()
    r = secureuid:set_masterkey(masterkey)
    r, key1 = secureuid:gen_key(dspid)
    _, syskey1 = secureuid.gen_systemkey(key1.pubkey_g1, key1.pubkey_g2)

    r = secureuid:gen_randseed()
    r = secureuid:set_masterkey(masterkey)
    r, key2 = secureuid:gen_key(dspid)
    r, syskey2 = secureuid.gen_systemkey(key2.pubkey_g1, key2.pubkey_g2)

    assert(key1.pubkey_g1, key2.pubkey_g1)
    assert(key1.pubkey_g2, key2.pubkey_g2)
    assert(key1.privatekey, key2.privatekey)
    assert(syskey1.syskey_g1, syskey2.syskey_g1)
    assert(syskey1.syskey_g2, syskey2.syskey_g2)
end

local function test_system_key()
    local dspid = "67d5d529-7303-4684-9a4e-99cf352bd092"

    local r, key = secureuid:gen_key(dspid)
    r, syskey = secureuid.gen_systemkey(key.pubkey_g1, key.pubkey_g2)
    assert(r == SUCCESS)
    local syskey_g1 = syskey.syskey_g1
    local syskey_g2 = syskey.syskey_g2

    r = secureuid.gen_systemkey(key.pubkey_g2)
    assert(r ~= SUCCESS)
    r = secureuid.gen_systemkey(key.pubkey_g1, nil)
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
    r, cipher = secureuid.encrypt(key.privatekey, blind.blind)
    assert(r == SUCCESS)
    assert(cipher ~= blind.blind)
    assert(cipher ~= blind.beta)
end

local function test_encrypt2()
    local dspid = "a49fec12-3d31-4603-9d6b-4c94ab72000e"
    local dids = {
        "0000-0000-0000-0000",
        "1111-1111-1111-1111",
        "2222-2222-2222-2222"
    }
    local cipher = nil
    local key = nil
    local blind = nil

    secureuid:gen_randseed()
    local r, key = secureuid:gen_key(dspid)
    assert(r == SUCCESS)

    local i = 100
    while i > 0 do
        local r, syskey = secureuid.gen_systemkey(key.pubkey_g1, key.pubkey_g2)
        assert(r == SUCCESS)
        secureuid:gen_randseed()
        for _, did in ipairs(dids) do
            local r, blind = secureuid:blind(did)
            assert(r == SUCCESS)
            local r, cipher = secureuid.encrypt(key.privatekey, blind.blind)
            assert(r == SUCCESS)
            local r, cipher = secureuid.unblind(syskey.syskey_g1, blind.beta, cipher)
            assert(r == SUCCESS)
        end

        i = i - 1
    end
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
    r, syskey = secureuid.gen_systemkey(key.pubkey_g1, key.pubkey_g2)

    secureuid:gen_randseed()
    r, blind = secureuid:blind(did)

    r, cipher = secureuid.encrypt(key.privatekey, blind.blind)

    r, unblind_cipher = secureuid.unblind(syskey.syskey_g1, blind.beta, cipher)
    assert(r == SUCCESS)
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
    r, syskey = secureuid.gen_systemkey(key.pubkey_g1, key.pubkey_g2)

    secureuid:gen_randseed()
    r, blind = secureuid:blind(did)

    r, cipher = secureuid.encrypt(key.privatekey, blind.blind)

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
    -- media: 为dsp分发公钥
    local _, syskey = secureuid.gen_systemkey(key.pubkey_g1, key.pubkey_g2)

    --
    -- offline 数据对齐
    --

    -- dsp: 盲化 did
    secureuid:gen_randseed()
    local _, blind = secureuid:blind(did)

    -- media: 加密盲化 did
    local _, cipher = secureuid.encrypt(key.privatekey, blind.blind)

    -- dsp: 去盲
    local _, unblind_cipher = secureuid.unblind(syskey.syskey_g1, blind.beta, cipher)

    --
    -- online
    --

    -- media: 产生加密的did
    secureuid:gen_randseed()
    local _, blind2 = secureuid:blind(did)
    local _, cipher2 = secureuid.encrypt(key.privatekey, blind2.blind)
    local _, unblind_cipher2 = secureuid.unblind(syskey.syskey_g1, blind2.beta, cipher2)

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
test_encrypt2()
test_unblind()
test_verify()
test_business1()