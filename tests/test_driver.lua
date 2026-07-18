dofile("tests/compat_bit32.lua")
local Driver = dofile("driver.lua")

-- Opt in to sent-message recording; the driver keeps it off in production
-- because only the tests below read it.
Driver.Companion.record_history = true

local function assert_eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label or "assert_eq", tostring(expected), tostring(actual)), 2)
  end
end

local function assert_table_has(table_value, key, expected)
  assert(table_value ~= nil, "table is nil")
  assert_eq(table_value[key], expected, "field " .. tostring(key))
end

local function bytes_range(first_value, last_value)
  local out = {}
  for value = first_value, last_value do
    out[#out + 1] = string.char(value)
  end
  return table.concat(out)
end

local function dns_name(name)
  local out = {}
  for label in tostring(name):gmatch("[^%.]+") do
    out[#out + 1] = string.char(#label)
    out[#out + 1] = label
  end
  out[#out + 1] = "\0"
  return table.concat(out)
end

local function u16be(value)
  return string.char(math.floor(value / 0x100) % 0x100, value % 0x100)
end

local function u32be(value)
  return u16be(math.floor(value / 0x10000) % 0x10000) .. u16be(value % 0x10000)
end

local function dns_txt(items)
  local out = {}
  for _, item in ipairs(items) do
    out[#out + 1] = string.char(#item) .. item
  end
  return table.concat(out)
end

local function assert_contains(list, expected, label)
  for _, value in ipairs(list) do
    if value == expected then
      return
    end
  end
  error((label or "assert_contains") .. ": missing " .. tostring(expected), 2)
end

local function xor_bytes(a, b)
  assert_eq(#a, #b, "xor byte length")
  local out = {}
  for i = 1, #a do
    local x, y, r, bit = a:byte(i), b:byte(i), 0, 1
    while bit < 256 do
      if (x % (bit * 2) >= bit) ~= (y % (bit * 2) >= bit) then
        r = r + bit
      end
      bit = bit * 2
    end
    out[i] = string.char(r)
  end
  return table.concat(out)
end

-- Captured before any test stubs anything. When lua-openssl is installed the
-- canned-digest tables below are only a fallback: unknown inputs hash for real,
-- so adding a step to a crypto self-test cannot silently break the stub.
local REAL_SHA512
do
  local ok, openssl = pcall(require, "openssl")
  if ok and openssl and openssl.digest then
    REAL_SHA512 = function(data)
      local ctx = openssl.digest.new("sha512")
      ctx:update(data)
      local digest = ctx:final()
      if type(digest) == "string" and #digest == 128 then
        digest = (digest:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
      end
      return digest
    end
  end
end

local function sha512_fallback(data, context)
  if REAL_SHA512 then return REAL_SHA512(data) end
  error(context .. ": no canned digest for SHA-512 input of length " .. tostring(#data) ..
    " and lua-openssl is not installed to hash it for real")
end

local function with_fake_openssl(fake, fn)
  local old_openssl = Driver.OpenSSLCrypto.openssl
  local old_c4 = C4
  Driver.OpenSSLCrypto.openssl = fake
  C4 = nil
  local ok, err = pcall(fn)
  Driver.OpenSSLCrypto.openssl = old_openssl
  C4 = old_c4
  if not ok then
    error(err, 2)
  end
end

local ED25519_VECTOR_SEED = Driver.Bytes.from_hex(
  "9d61b19deffd5a60ba844af492ec2cc4" ..
  "4449c5697b326919703bac031cae7f60"
)
local ED25519_VECTOR_PUBLIC = Driver.Bytes.from_hex(
  "d75a980182b10ab7d54bfed3c964073a" ..
  "0ee172f3daa62325af021a68f707511a"
)
local ED25519_VECTOR_SIGNATURE = Driver.Bytes.from_hex(
  "e5564300c360ac729086e2cc806e828a" ..
  "84877f1eb8e5d974d873e06522490155" ..
  "5fb8821590a33bacc61e39701cf9b46b" ..
  "d25bf5f0595bbe24655141438e7a100b"
)
local ED25519_VECTOR_HASH_SEED = Driver.Bytes.from_hex(
  "357c83864f2833cb427a2ef1c00a013c" ..
  "fdff2768d980c0a3a520f006904de90f" ..
  "9b4f0afe280b746a778684e754425020" ..
  "57b7473a03f08f96f5a38e9287e01f8f"
)
local ED25519_VECTOR_HASH_PREFIX = Driver.Bytes.from_hex(
  "b6b19cd8e0426f5983fa112d89a143aa" ..
  "97dab8bc5deb8d5b6253c928b65272f4" ..
  "044098c2a990039cde5b6a4818df0bfb" ..
  "6e40dc5dee54248032962323e701352d"
)
local ED25519_VECTOR_HASH_CHALLENGE = Driver.Bytes.from_hex(
  "2771062b6b536fe7ffbdda0320c3827b" ..
  "035df10d284df3f08222f04dbca7a4c2" ..
  "0ef15bdc988a22c7207411377c33f2ac" ..
  "09b1e86a046234283768ee7ba03c0e9f"
)

local function with_ed25519_vector_sha512(fn)
  local old_sha512 = Driver.Ed25519Pure._sha512
  Driver.Ed25519Pure._sha512 = function(data)
    if data == ED25519_VECTOR_SEED then return ED25519_VECTOR_HASH_SEED end
    if data == ED25519_VECTOR_HASH_SEED:sub(33, 64) then return ED25519_VECTOR_HASH_PREFIX end
    if data == ED25519_VECTOR_SIGNATURE:sub(1, 32) .. ED25519_VECTOR_PUBLIC then return ED25519_VECTOR_HASH_CHALLENGE end
    return sha512_fallback(data, "Ed25519 vector")
  end
  local ok, err = pcall(fn)
  Driver.Ed25519Pure._sha512 = old_sha512
  if not ok then error(err, 2) end
end

local function with_crypto_self_test_sha512(fn)
  local old_sha512 = Driver.Ed25519Pure._sha512
  local sha512_by_input = {
    [Driver.Bytes.from_hex("5d534f363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363664617461")] =
      Driver.Bytes.from_hex("d0947c5eb5f35336fba826c132ba7bce1834f80e43a89dffdc9eac56a2bebfc2154009913b000c58e9a75590bf8bcdf11c551088277c150c781c1387b13c64a0"),
    [Driver.Bytes.from_hex("3739255c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5cd0947c5eb5f35336fba826c132ba7bce1834f80e43a89dffdc9eac56a2bebfc2154009913b000c58e9a75590bf8bcdf11c551088277c150c781c1387b13c64a0")] =
      Driver.Bytes.from_hex("3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58"),
    [Driver.Bytes.from_hex("363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363664617461")] =
      Driver.Bytes.from_hex("c78669845f0e0d03c8680c8f282589ebd4c6162fc38cb3713808509f204c49949ff57122424bca1ab74a80fc733d97f2cd47d0aefee21b6afc46b78bcd26b103"),
    [Driver.Bytes.from_hex("5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5cc78669845f0e0d03c8680c8f282589ebd4c6162fc38cb3713808509f204c49949ff57122424bca1ab74a80fc733d97f2cd47d0aefee21b6afc46b78bcd26b103")] =
      Driver.Bytes.from_hex("768c8b8791fd5a59d1cd1edb860054d746b181926b0551bcff4bd4e135f4bbc89e395f9f250f8b582ebe92d3ff63dd401d3ab2af85790b24ecd92dce7466c16d"),
    [Driver.Bytes.from_hex("66575f441b6053445f504f1b735855444f46421b65575a423636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")] =
      Driver.Bytes.from_hex("7273d1b04c7e6dd1d7520635ddff69eea41f761386aa24322e9d73ad0236f6aa40af7f4a76cfc0e0703b5fb543cd5f363a4049b4820e1925f1085e5ebbddb2a6"),
    [Driver.Bytes.from_hex("0c3d352e710a392e353a257119323f2e252c28710f3d30285c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c7273d1b04c7e6dd1d7520635ddff69eea41f761386aa24322e9d73ad0236f6aa40af7f4a76cfc0e0703b5fb543cd5f363a4049b4820e1925f1085e5ebbddb2a6")] =
      Driver.Bytes.from_hex("490d7d582bd5f56ac0b28825d324232159c13826cfcd091ed2cf20972cba9517a761d0b079e06dbb1ab1ad9c1687e9becdf7eebe45e00091c8616fc4b87921fd"),
    [Driver.Bytes.from_hex("7f3b4b6e1de3c35cf684be13e51215176ff70e10f9fb3f28e4f916a11a8ca3219157e6864fd65b8d2c879baa20b1df88fbc1d88873d636a7fe5759f28e4f17cb36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636506169722d5665726966792d456e63727970742d496e666f01")] =
      Driver.Bytes.from_hex("3ec8c760fe456d469e30095c3707ac17a9d7500b5f88c6cede0f0fdfdd0e668abb20a17a2293ddc030ce6297b1eb41a68d2c48764bf63eccedb8dd2d655c613f"),
    [Driver.Bytes.from_hex("155121047789a9369ceed4798f787f7d059d647a939155428e937ccb70e6c94bfb3d8cec25bc31e746edf1c04adbb5e291abb2e219bc5ccd943d3398e4257da15c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c3ec8c760fe456d469e30095c3707ac17a9d7500b5f88c6cede0f0fdfdd0e668abb20a17a2293ddc030ce6297b1eb41a68d2c48764bf63eccedb8dd2d655c613f")] =
      Driver.Bytes.from_hex("faf9f3558a8ed1e45219bd94fb6d27e5b43a1bc861157fc2a0d291d8e3df410a50891da5d6730734836ff9391b671ae4faf1635c2005250f6fb03a7659af9abd"),
  }

  Driver.Ed25519Pure._sha512 = function(data)
    if data == ED25519_VECTOR_SEED then return ED25519_VECTOR_HASH_SEED end
    if data == ED25519_VECTOR_HASH_SEED:sub(33, 64) then return ED25519_VECTOR_HASH_PREFIX end
    if data == ED25519_VECTOR_SIGNATURE:sub(1, 32) .. ED25519_VECTOR_PUBLIC then return ED25519_VECTOR_HASH_CHALLENGE end
    if #data == 132 and data:sub(-4) == "data" and data:byte(1) == 0x5d then
      return Driver.Bytes.from_hex("d0947c5eb5f35336fba826c132ba7bce1834f80e43a89dffdc9eac56a2bebfc2154009913b000c58e9a75590bf8bcdf11c551088277c150c781c1387b13c64a0")
    end
    if #data == 192 and data:sub(1, 3) == "79%" then
      return Driver.Bytes.from_hex("3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58")
    end
    if #data == 132 and data:sub(-4) == "data" and data:byte(1) == 0x36 then
      return Driver.Bytes.from_hex("c78669845f0e0d03c8680c8f282589ebd4c6162fc38cb3713808509f204c49949ff57122424bca1ab74a80fc733d97f2cd47d0aefee21b6afc46b78bcd26b103")
    end
    if #data == 192 and data:sub(1, 4) == string.rep("\\", 4) then
      return Driver.Bytes.from_hex("768c8b8791fd5a59d1cd1edb860054d746b181926b0551bcff4bd4e135f4bbc89e395f9f250f8b582ebe92d3ff63dd401d3ab2af85790b24ecd92dce7466c16d")
    end
    if #data == 160 and data:sub(-32) == Driver.Bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") then
      return Driver.Bytes.from_hex("7273d1b04c7e6dd1d7520635ddff69eea41f761386aa24322e9d73ad0236f6aa40af7f4a76cfc0e0703b5fb543cd5f363a4049b4820e1925f1085e5ebbddb2a6")
    end
    if #data == 192 and data:sub(1, 3) == Driver.Bytes.from_hex("0c3d35") then
      return Driver.Bytes.from_hex("490d7d582bd5f56ac0b28825d324232159c13826cfcd091ed2cf20972cba9517a761d0b079e06dbb1ab1ad9c1687e9becdf7eebe45e00091c8616fc4b87921fd")
    end
    if #data == 153 and data:sub(-25) == "Pair-Verify-Encrypt-Info" .. string.char(1) then
      return Driver.Bytes.from_hex("3ec8c760fe456d469e30095c3707ac17a9d7500b5f88c6cede0f0fdfdd0e668abb20a17a2293ddc030ce6297b1eb41a68d2c48764bf63eccedb8dd2d655c613f")
    end
    if #data == 192 and data:sub(1, 3) == Driver.Bytes.from_hex("155121") then
      return Driver.Bytes.from_hex("faf9f3558a8ed1e45219bd94fb6d27e5b43a1bc861157fc2a0d291d8e3df410a50891da5d6730734836ff9391b671ae4faf1635c2005250f6fb03a7659af9abd")
    end
    local digest = sha512_by_input[data]
    if digest then return digest end
    return sha512_fallback(data, "crypto self-test")
  end
  local ok, err = pcall(fn)
  Driver.Ed25519Pure._sha512 = old_sha512
  if not ok then error(err, 2) end
end

local function make_fake_openssl(options)
  options = options or {}
  local calls = {}
  local x25519_publics = {
    string.rep("A", 32),
    string.rep("B", 32),
  }
  local x25519_index = 0

  local function record(value)
    calls[#calls + 1] = value
  end

  local function make_public_key(kind, raw)
    return {
      kind = kind,
      export = function(_, format, raw_flag)
        record("pkey.export:" .. tostring(format) .. ":" .. tostring(raw_flag))
        assert_eq(format, "der", "public export format")
        assert_eq(raw_flag, false, "public export raw flag")
        -- Real lua-openssl returns SubjectPublicKeyInfo DER for X25519 (12-byte header + 32 bytes)
        return string.rep("\0", 12) .. raw
      end,
      verify = function(_, data, signature)
        record("evp_pkey:verify")
        if options.expected_verify_data then
          assert_eq(data, options.expected_verify_data, "verify data")
        end
        if options.expected_verify_signature then
          assert_eq(signature, options.expected_verify_signature, "verify signature")
        end
        return true
      end,
    }
  end

  local function make_private_key(kind, raw)
    return {
      kind = kind,
      get_public = function()
        record("evp_pkey:get_public")
        return make_public_key(kind .. ":public", raw)
      end,
      sign = function(_, data)
        record("evp_pkey:sign")
        if options.expected_sign_data then
          assert_eq(data, options.expected_sign_data, "sign data")
        end
        return options.signature or "signature"
      end,
    }
  end

  local fake = {
    calls = calls,
    pkey = {
      read = function(input, private, format)
        record("pkey.read:" .. tostring(private) .. ":" .. tostring(format))
        assert_eq(format, "der", "pkey.read format")
        if private then
          assert_eq(input:sub(1, 8), Driver.Bytes.from_hex("302e020100300506"), "private key DER prefix")
          return make_private_key("read-private", string.rep("P", 32))
        end
        assert_eq(input:sub(1, 6), Driver.Bytes.from_hex("302a30050603"), "public key DER prefix")
        return make_public_key("read-public", input:sub(#input - 31))
      end,
      ctx_new = function(algorithm)
        record("pkey.ctx_new:" .. tostring(algorithm))
        return {
          keygen = function()
            record("pkey.ctx:keygen:" .. tostring(algorithm))
            if algorithm == "X25519" then
              x25519_index = x25519_index + 1
              return make_private_key("x25519-private", x25519_publics[x25519_index] or string.rep("C", 32))
            end
            assert_eq(algorithm, "ED25519", "ctx_new algorithm")
            return make_private_key("ed25519-private", string.rep("E", 32))
          end,
        }
      end,
      derive = function(private_key, peer_key)
        record("pkey.derive")
        assert(private_key.kind:match("private"), "derive expected private key")
        assert(peer_key.kind:match("public"), "derive expected public key")
        return string.rep("S", 32)
      end,
    },
    bn = {
      text = function(value)
        record("bn.text:" .. tostring(#value))
        return {
          bytes = value,
        }
      end,
      powmod = function(base, exponent, modulus)
        record("bn.powmod")
        assert_eq(base.bytes, "\5", "bn powmod base")
        assert_eq(exponent.bytes, "\3", "bn powmod exponent")
        assert_eq(#modulus.bytes, 384, "bn powmod modulus")
        return {
          bytes = string.char(125),
        }
      end,
      totext = function(value)
        record("bn.totext")
        return value.bytes
      end,
    },
    hmac = {
      hmac = function(digest, message, key, raw)
        record("hmac.hmac:" .. tostring(digest) .. ":" .. tostring(raw))
        assert_eq(digest, "sha512", "hmac digest")
        assert_eq(raw, true, "hmac raw flag")
        assert(type(message) == "string", "hmac message")
        assert(type(key) == "string", "hmac key")
        if key == "key" and message == "data" then
          return Driver.Bytes.from_hex(
            "3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253c" ..
            "b52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58"
          )
        end
        if key == "Pair-Verify-Encrypt-Salt" and
            message == Driver.Bytes.from_hex("000102030405060708090a0b0c0d0e0f" ..
              "101112131415161718191a1b1c1d1e1f") then
          return Driver.Bytes.from_hex(
            "490d7d582bd5f56ac0b28825d324232159c13826cfcd091ed2cf20972cba9517" ..
            "a761d0b079e06dbb1ab1ad9c1687e9becdf7eebe45e00091c8616fc4b87921fd"
          )
        end
        if key == Driver.Bytes.from_hex(
            "490d7d582bd5f56ac0b28825d324232159c13826cfcd091ed2cf20972cba9517" ..
            "a761d0b079e06dbb1ab1ad9c1687e9becdf7eebe45e00091c8616fc4b87921fd"
          ) and message == "Pair-Verify-Encrypt-Info\1" then
          return Driver.Bytes.from_hex(
            "faf9f3558a8ed1e45219bd94fb6d27e5b43a1bc861157fc2a0d291d8e3df410a" ..
            "50891da5d6730734836ff9391b671ae4faf1635c2005250f6fb03a7659af9abd"
          )
        end
        return string.rep("H", 64)
      end,
    },
    rand = {
      bytes = function(n)
        record("rand.bytes:" .. tostring(n))
        return string.rep("R", n)
      end,
    },
  }

  return fake
end

local tests = {}

function tests.frame_roundtrip()
  local frame = Driver.CompanionFrame.encode(0x08, "abc")
  assert_eq(Driver.Bytes.hex(frame), "08000003616263", "frame hex")

  local decoded, rest = Driver.CompanionFrame.try_decode(frame .. "tail")
  assert_eq(decoded.frame_type, 0x08, "frame type")
  assert_eq(decoded.length, 3, "frame length")
  assert_eq(decoded.payload, "abc", "frame payload")
  assert_eq(rest, "tail", "frame rest")
end

function tests.mdns_parses_companion_srv_port()
  local service = "_companion-link._tcp.local"
  local instance = "Office Apple TV._companion-link._tcp.local"
  local question = dns_name(service) .. u16be(12) .. u16be(0x8001)
  local ptr_rdata = dns_name(instance)
  local srv_rdata = u16be(0) .. u16be(0) .. u16be(49222) .. dns_name("Office-Apple-TV.local")
  local response = table.concat({
    u16be(0), u16be(0x8400), u16be(1), u16be(2), u16be(0), u16be(0),
    question,
    string.char(0xC0, 0x0C), u16be(12), u16be(1), u32be(120), u16be(#ptr_rdata), ptr_rdata,
    dns_name(instance), u16be(33), u16be(1), u32be(120), u16be(#srv_rdata), srv_rdata,
  })

  assert_eq(Driver.MDNS.parse_companion_port(response), 49222, "companion SRV port")
end

function tests.mdns_parses_mrp_srv_port()
  local service = "_mediaremotetv._tcp.local"
  local instance = "Office Apple TV._mediaremotetv._tcp.local"
  local question = dns_name(service) .. u16be(12) .. u16be(0x8001)
  local ptr_rdata = dns_name(instance)
  local srv_rdata = u16be(0) .. u16be(0) .. u16be(49154) .. dns_name("Office-Apple-TV.local")
  local response = table.concat({
    u16be(0), u16be(0x8400), u16be(1), u16be(2), u16be(0), u16be(0),
    question,
    string.char(0xC0, 0x0C), u16be(12), u16be(1), u32be(120), u16be(#ptr_rdata), ptr_rdata,
    dns_name(instance), u16be(33), u16be(1), u32be(120), u16be(#srv_rdata), srv_rdata,
  })

  assert_eq(Driver.MDNS.parse_service_port(response, service), 49154, "mrp SRV port")
  assert_eq(Driver.MDNS.parse_companion_port(response), nil, "mrp response is not companion port")
end

function tests.mdns_parses_airplay_srv_and_txt()
  local service = "_airplay._tcp.local"
  local instance = "Office Apple TV._airplay._tcp.local"
  local question = dns_name(service) .. u16be(12) .. u16be(0x8001)
  local ptr_rdata = dns_name(instance)
  local srv_rdata = u16be(0) .. u16be(0) .. u16be(7000) .. dns_name("Office-Apple-TV.local")
  local txt_rdata = dns_txt({
    "deviceid=AA:BB:CC:DD:EE:FF",
    "features=0x4A7FDFD5,0x3C155FDE",
    "model=AppleTV14,1",
    "srcvers=750.0",
    "vv=2",
  })
  local response = table.concat({
    u16be(0), u16be(0x8400), u16be(1), u16be(3), u16be(0), u16be(0),
    question,
    string.char(0xC0, 0x0C), u16be(12), u16be(1), u32be(120), u16be(#ptr_rdata), ptr_rdata,
    dns_name(instance), u16be(33), u16be(1), u32be(120), u16be(#srv_rdata), srv_rdata,
    dns_name(instance), u16be(16), u16be(1), u32be(120), u16be(#txt_rdata), txt_rdata,
  })

  local info = Driver.MDNS.parse_service_info(response, service)
  assert_eq(info.port, 7000, "airplay SRV port")
  assert_eq(info.txt.deviceid, "AA:BB:CC:DD:EE:FF", "airplay TXT deviceid")
  assert_eq(info.txt.model, "AppleTV14,1", "airplay TXT model")
  assert_eq(info.txt.srcvers, "750.0", "airplay TXT source version")
end

function tests.mdns_cached_port_falls_back_to_default()
  Driver.MDNS.invalidate("192.0.2.10")
  assert_eq(Driver.MDNS.has_cached_port("192.0.2.10"), false, "no cached companion port")
  assert_eq(Driver.MDNS.cached_port("192.0.2.10"), 49153, "default companion port")
  Driver.MDNS.last_port_by_host["192.0.2.10"] = 49222
  assert_eq(Driver.MDNS.has_cached_port("192.0.2.10"), true, "has cached companion port")
  assert_eq(Driver.MDNS.cached_port("192.0.2.10"), 49222, "cached companion port")
  Driver.MDNS.invalidate("192.0.2.10")
end

-- Fake C4 with just enough surface for MDNS.discover_service_info to run.
local function with_mdns_c4(fn)
  local old_c4 = C4
  C4 = {
    GetDriverConfigInfo = function() return "Apple TV Companion" end,
    GetDeviceID = function() return 0 end,
    GetBindingAddress = function() return "" end,
    CreateNetworkConnection = function() end,
    NetConnect = function() end,
    NetDisconnect = function() end,
    SetBindingAddress = function() end,
    SendToNetwork = function() end,
    SetTimer = function() return { Cancel = function() end } end,
  }
  Driver.MDNS.cancel_all()
  local ok, err = pcall(fn)
  Driver.MDNS.cancel_all()
  C4 = old_c4
  if not ok then error(err, 2) end
end

function tests.mdns_concurrent_discovery_queues_instead_of_dropping_callbacks()
  with_mdns_c4(function()
    local fired = {}
    Driver.MDNS.discover_companion_port("192.0.2.20", function(port)
      fired[#fired + 1] = "companion:" .. tostring(port)
    end)
    -- A second discovery arriving mid-flight must not steal the first one's slot.
    Driver.MDNS.discover_airplay_info("192.0.2.20", function(info)
      fired[#fired + 1] = "airplay:" .. tostring(info and info.port or "nil")
    end)
    assert_eq(#Driver.MDNS.queue, 1, "second discovery queued")
    assert_eq(#fired, 0, "no callback fired yet")

    Driver.MDNS.finish(nil, "timeout")
    assert_eq(fired[1], "companion:49153", "companion callback got the fallback port")
    assert_eq(Driver.MDNS.in_flight, true, "queued discovery started automatically")
    assert_eq(#Driver.MDNS.queue, 0, "queue drained")

    Driver.MDNS.finish(nil, "timeout")
    assert_eq(fired[2], "airplay:nil", "airplay callback still fired")
    assert_eq(#fired, 2, "both callbacks fired exactly once")
  end)
end

function tests.mdns_stalled_discovery_does_not_wedge_the_queue()
  with_mdns_c4(function()
    local fired = {}
    Driver.MDNS.discover_companion_port("192.0.2.21", function(port)
      fired[#fired + 1] = "first:" .. tostring(port)
    end)
    -- Simulate a discovery whose timeout timer never fired.
    Driver.MDNS.started_at_ms = Driver.MDNS.now_ms() - (Driver.MDNS.TIMEOUT_MS * 10)

    Driver.MDNS.discover_airplay_info("192.0.2.21", function(info)
      fired[#fired + 1] = "second:" .. tostring(info and info.port or "nil")
    end)
    -- The stalled one is force-completed and the new one runs immediately.
    assert_eq(fired[1], "first:49153", "stalled discovery was completed, not orphaned")
    assert_eq(Driver.MDNS.in_flight, true, "new discovery took the slot")
    assert_eq(#Driver.MDNS.queue, 0, "new discovery did not have to queue")
  end)
end

function tests.mdns_queue_cap_answers_dropped_callers()
  with_mdns_c4(function()
    local answered = 0
    Driver.MDNS.discover_companion_port("192.0.2.22", function() answered = answered + 1 end)
    for _ = 1, Driver.MDNS.QUEUE_MAX + 2 do
      Driver.MDNS.discover_companion_port("192.0.2.22", function() answered = answered + 1 end)
    end
    assert_eq(#Driver.MDNS.queue, Driver.MDNS.QUEUE_MAX, "queue capped")
    -- Callers evicted by the cap still get an answer rather than hanging forever.
    assert_eq(answered, 2, "evicted callers were answered")
  end)
end

-- handle_payload skips building the MRP description when debug is off. Its real
-- work (dispatching the update, the device-info bootstrap) must not depend on it.
function tests.airplay_data_channel_dispatches_mrp_update_with_debug_off()
  local PB, BPlist = Driver.PB, Driver.BPlist
  local client = PB.field_string(2, "com.att.tv") .. PB.field_string(7, "DIRECTV")
  local path = PB.field_message(2, client)
  local now_playing = PB.field_string(2, "Channel 12") .. PB.field_string(9, "Live TV")
  local state = PB.field_message(1, now_playing) ..
    PB.field_varint(6, 2) ..
    PB.field_message(9, path)
  local message = PB.field_varint(1, 4) ..
    PB.field_string(2, "state-id") ..
    PB.field_varint(4, 0) ..
    PB.field_message(9, state)
  local payload = BPlist.encode({
    params = { data = BPlist.bytes(PB.varint(#message) .. message) },
  })

  local saved_handler = Driver.C4Driver.handle_airplay_mrp_update
  local saved_debug = DEBUGPRINT
  local seen

  local instance = setmetatable({
    send_post_device_info_bootstrap = function() end,
    send_reply = function() end,
  }, { __index = Driver.AirPlayDataChannelClient })

  Driver.C4Driver.handle_airplay_mrp_update = function(update) seen = update end

  -- Restore before asserting: a throw here would otherwise leave the stubbed
  -- handler installed and break every later test.
  local ok, err = pcall(function()
    for _, debug_on in ipairs({ false, true }) do
      seen = nil
      DEBUGPRINT = debug_on
      instance:handle_payload("event", 1, payload)
      local label = "debug=" .. tostring(debug_on)
      assert(seen ~= nil, "MRP update dispatched with " .. label)
      assert_eq(seen.app_bundle, "com.att.tv", "app bundle with " .. label)
      assert_eq(seen.app_name, "DIRECTV", "app name with " .. label)
      assert_eq(seen.title, "Live TV", "title with " .. label)
      assert_eq(seen.artist, "Channel 12", "artist with " .. label)
    end
  end)

  DEBUGPRINT = saved_debug
  Driver.C4Driver.handle_airplay_mrp_update = saved_handler
  if not ok then error(err, 2) end
end

function tests.airplay_monitor_retry_backs_off_exponentially()
  local AirPlay = Driver.AirPlay
  local saved_attempts = AirPlay.monitor_retry_attempts
  AirPlay.monitor_retry_attempts = 0

  local seen = {}
  for _ = 1, 8 do
    AirPlay.monitor_retry_attempts = AirPlay.monitor_retry_attempts + 1
    seen[#seen + 1] = Driver.C4Driver.airplay_monitor_retry_delay_ms()
  end

  assert_eq(seen[1], 15000, "first retry at the base delay")
  assert_eq(seen[2], 30000, "second retry doubles")
  assert_eq(seen[3], 60000, "third retry doubles again")
  assert_eq(seen[8], AirPlay.monitor_retry_max_ms, "retry delay is capped")
  assert_eq(seen[8] <= AirPlay.monitor_retry_max_ms, true, "never exceeds the cap")

  -- A successful start clears the backoff so the next outage starts fast again.
  Driver.C4Driver.airplay_monitor_retry_succeeded()
  assert_eq(AirPlay.monitor_retry_attempts, 0, "success resets the backoff")

  AirPlay.monitor_retry_attempts = saved_attempts
end

function tests.tlv8_roundtrip()
  local encoded = Driver.TLV8.encode({
    [0] = string.char(0x00),
    [6] = string.char(0x01),
  })
  local decoded = Driver.TLV8.decode(encoded)
  assert_eq(decoded[0], string.char(0x00), "tlv method")
  assert_eq(decoded[6], string.char(0x01), "tlv state")
end

function tests.companion_pair_setup_start_matches_pyatv_docs()
  local pair_setup = Driver.PairSetup.new({
    generate_ed25519_keypair = function()
      return {
        private_key = string.rep("\x01", 32),
        public_key = string.rep("\x02", 32),
      }
    end,
    random_bytes = function(n)
      return string.rep("\x03", n)
    end,
  })
  local frame = pair_setup:start()
  assert_eq(
    Driver.Bytes.hex(frame),
    "03000013e2435f706476000100060101455f7077547909",
    "pair setup M1 frame"
  )
end

function tests.pyatv_hap_credentials_roundtrip()
  local original = table.concat({
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "4154562d4944",
    "434c49454e542d4944",
  }, ":")

  local credentials = Driver.Credentials.parse(original)
  assert_eq(credentials.type, "HAP", "credential type")
  assert_eq(Driver.Bytes.hex(credentials.ltpk), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "ltpk")
  assert_eq(Driver.Bytes.hex(credentials.ltsk), "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "ltsk")
  assert_eq(Driver.Bytes.hex(credentials.atv_id), "4154562d4944", "atv id")
  assert_eq(Driver.Bytes.hex(credentials.client_id), "434c49454e542d4944", "client id")
  assert_eq(Driver.Credentials.stringify(credentials), original, "credential string")
end

function tests.hap_pairing_errors_include_stage_code_and_backoff()
  local payload = Driver.TLV8.encode_ordered({
    { 6, string.char(0x04) },
    { 7, string.char(0x03) },
    { 8, string.char(0x0a) },
  })
  local ok, err = pcall(Driver.PairVerify.decode_hap_response, payload, "AirPlay Pair-Setup M4")
  assert_eq(ok, false, "HAP error response rejected")
  assert(tostring(err):find("AirPlay Pair-Setup M4 error 3 (BackOff)", 1, true), "named HAP error")
  assert(tostring(err):find("state=M4", 1, true), "HAP error state")
  assert(tostring(err):find("backoff=10s", 1, true), "HAP error backoff")
end

function tests.companion_pairing_errors_include_stage_and_code()
  local payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({
      { 6, string.char(0x04) },
      { 7, string.char(0x02) },
    })) },
  }))
  local ok, err = pcall(Driver.PairVerify.decode_pairing_data, payload, "Companion Pair-Setup M4")
  assert_eq(ok, false, "Companion HAP error response rejected")
  assert(tostring(err):find("Companion Pair-Setup M4 error 2 (Authentication)", 1, true),
    "named Companion HAP error")
end


function tests.pair_verify_frames_match_pyatv_source_vectors()
  local public_key = bytes_range(0, 31)
  assert_eq(
    Driver.Bytes.hex(Driver.PairVerify.encode_start(public_key)),
    "05000033e2435f706491250601010320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f455f617554790c",
    "pair verify start"
  )

  local encrypted_data = bytes_range(0, 15)
  assert_eq(
    Driver.Bytes.hex(Driver.PairVerify.encode_next(encrypted_data)),
    "0600001be1435f7064850601030510000102030405060708090a0b0c0d0e0f",
    "pair verify next"
  )
end

function tests.pair_verify_flow_uses_injected_crypto()
  local public_key = bytes_range(0, 31)
  local server_public_key = bytes_range(32, 63)
  local encrypted_challenge = "challenge"
  local encrypted_response = "response"
  local shared_secret = "shared-secret"
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(64, 95)),
    Driver.Bytes.hex(bytes_range(96, 127)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))

  local fake_crypto = {
    generate_x25519_keypair = function()
      return {
        private_key = "private-key",
        public_key = public_key,
      }
    end,
    pair_verify_response = function(received_credentials, private_key, received_public_key, received_server_public_key, received_encrypted_data)
      assert_eq(received_credentials, credentials, "credentials")
      assert_eq(private_key, "private-key", "private key")
      assert_eq(received_public_key, public_key, "client public key")
      assert_eq(received_server_public_key, server_public_key, "server public key")
      assert_eq(received_encrypted_data, encrypted_challenge, "encrypted challenge")
      return encrypted_response, shared_secret
    end,
    hkdf_sha512 = function(salt, info, ikm)
      assert_eq(salt, "", "hkdf salt")
      assert_eq(ikm, shared_secret, "hkdf ikm")
      if info == "ClientEncrypt-main" then
        return "output-key"
      end
      if info == "ServerEncrypt-main" then
        return "input-key"
      end
      error("unexpected hkdf info: " .. tostring(info))
    end,
  }

  local verifier = Driver.PairVerify.new(credentials, fake_crypto)
  local start_frame = verifier:start()
  assert_eq(
    Driver.Bytes.hex(start_frame),
    "05000033e2435f706491250601010320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f455f617554790c",
    "start frame"
  )

  local response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({
      { 3, server_public_key },
      { 5, encrypted_challenge },
    })) },
  }))
  local next_frame, keys = verifier:finish(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, response_payload))
  assert_eq(keys.output_key, "output-key", "output key")
  assert_eq(keys.input_key, "input-key", "input key")

  local decoded_next = Driver.CompanionFrame.try_decode(next_frame)
  local tlv = Driver.PairVerify.decode_pairing_data(decoded_next.payload)
  assert_eq(tlv[6], string.char(0x03), "next seq")
  assert_eq(tlv[5], encrypted_response, "encrypted response")
end

function tests.companion_session_encrypts_with_frame_header_aad()
  local encrypt_nonces = {}
  local decrypt_nonces = {}
  local fake_crypto = {
    encrypt = function(output_key, plaintext, aad, nonce)
      assert_eq(output_key, "output-key", "encrypt key")
      assert_eq(plaintext, "abc", "encrypt plaintext")
      assert_eq(Driver.Bytes.hex(aad), "08000013", "encrypt aad")
      encrypt_nonces[#encrypt_nonces + 1] = Driver.Bytes.hex(nonce)
      return plaintext .. string.rep("\0", 16)
    end,
    decrypt = function(input_key, ciphertext, aad, nonce)
      assert_eq(input_key, "input-key", "decrypt key")
      assert_eq(Driver.Bytes.hex(aad), "08000013", "decrypt aad")
      decrypt_nonces[#decrypt_nonces + 1] = Driver.Bytes.hex(nonce)
      return ciphertext:sub(1, #ciphertext - 16)
    end,
  }

  local session = Driver.CompanionSession.new("output-key", "input-key", fake_crypto)
  local frame = session:encode_frame(Driver.CompanionFrame.E_OPACK, "abc")
  assert_eq(Driver.Bytes.hex(frame), "08000013616263" .. string.rep("00", 16), "encrypted frame")

  local decoded, rest = session:try_decode(frame .. "tail")
  assert_eq(decoded.frame_type, Driver.CompanionFrame.E_OPACK, "decoded frame type")
  assert_eq(decoded.encrypted_length, 19, "decoded encrypted length")
  assert_eq(decoded.length, 3, "decoded plaintext length")
  assert_eq(decoded.payload, "abc", "decoded payload")
  assert_eq(rest, "tail", "decoded rest")
  assert_eq(encrypt_nonces[1], "000000000000000000000000", "first encrypt nonce")
  assert_eq(decrypt_nonces[1], "000000000000000000000000", "first decrypt nonce")
end

function tests.poly1305_matches_rfc7539_vector()
  local key = Driver.Bytes.from_hex(
    "85d6be7857556d337f4452fe42d506a8" ..
    "0103808afb0db2fd4abff6af4149f51b"
  )
  local msg = "Cryptographic Forum Research Group"
  assert_eq(
    Driver.Bytes.hex(Driver.ChaCha20Poly1305Pure.poly1305_mac(msg, key)),
    "a8061dc1305136c6c22b8baf0c0127a9",
    "RFC7539 Poly1305 MAC"
  )
end

function tests.poly1305_handles_varied_block_lengths()
  local key = Driver.Bytes.from_hex(
    "000102030405060708090a0b0c0d0e0f" ..
    "101112131415161718191a1b1c1d1e1f"
  )
  local vectors = {
    { len = 0, tag = "101112131415161718191a1b1c1d1e1f" },
    { len = 1, tag = "1f11131517191b1d1f21232527292b2d" },
    { len = 15, tag = "5305236ca07fc93d9ca416b23664fa50" },
    { len = 16, tag = "a2291a363def0b53845fa4126a6ad364" },
    { len = 17, tag = "f735c97f7308fd79222447fe76a96872" },
    { len = 31, tag = "7c57daa799d3d38243034a4af1f6ed2b" },
    { len = 32, tag = "e4a30dc29abba238e086b49b2916f440" },
    { len = 63, tag = "61abe275b6d2ccf0911fe932877a6643" },
    { len = 64, tag = "ec478e3080abb4e797340d66c9cbc65a" },
    { len = 65, tag = "ded264fe6bf02b57de5b3a7fc23e076a" },
  }

  for _, vector in ipairs(vectors) do
    local msg = bytes_range(0, vector.len - 1)
    assert_eq(
      Driver.Bytes.hex(Driver.ChaCha20Poly1305Pure.poly1305_mac(msg, key)),
      vector.tag,
      "Poly1305 len " .. tostring(vector.len)
    )
  end
end

function tests.x25519_matches_rfc7748_key_exchange_vectors()
  local alice_private = Driver.Bytes.from_hex(
    "77076d0a7318a57d3c16c17251b26645" ..
    "df4c2f87ebc0992ab177fba51db92c2a"
  )
  local bob_private = Driver.Bytes.from_hex(
    "5dab087e624a8a4b79e17f8b83800ee6" ..
    "6f3bb1292618b6fd1c2f8b27ff88e0ebef"
  )
  local alice_public = Driver.Bytes.from_hex(
    "8520f0098930a754748b7ddcb43ef75a" ..
    "0dbf3a0d26381af4eba4a98eaa9b4e6a"
  )
  local bob_public = Driver.Bytes.from_hex(
    "de9edb7d7b7dc1b4d35b61c2ece43537" ..
    "3f8343c85b78674dadfc7e146f882b4f"
  )
  local shared_secret = Driver.Bytes.from_hex(
    "4a5d9d5ba4ce2de1728e3bf480350f25" ..
    "e07e21c947d19e3376f09b3c1e161742"
  )

  assert_eq(Driver.X25519Pure.mul(alice_private, Driver.X25519Pure.BASE_POINT), alice_public, "alice public key")
  assert_eq(Driver.X25519Pure.mul(bob_private, Driver.X25519Pure.BASE_POINT), bob_public, "bob public key")
  assert_eq(Driver.X25519Pure.mul(alice_private, bob_public), shared_secret, "alice shared secret")
  assert_eq(Driver.X25519Pure.mul(bob_private, alice_public), shared_secret, "bob shared secret")
end

function tests.openssl_crypto_self_test_uses_documented_call_shapes()
  local fake = make_fake_openssl()

  with_fake_openssl(fake, function()
    with_crypto_self_test_sha512(function()
      assert_eq(Driver.OpenSSLCrypto.self_test(), true, "self test result")
    end)
  end)

  -- Only calls routed through OpenSSLCrypto.load_openssl() are observable here.
  -- The SRP/curve bignums deliberately require openssl directly (_ensure_curve),
  -- so the fake never sees bn.powmod; self_test asserting A = g^3 mod N == 125 is
  -- what covers the real powmod path.
  assert_contains(fake.calls, "rand.bytes:32", "secure random call")
end

function tests.openssl_crypto_hmac_supports_empty_key_without_c4_hmac()
  with_crypto_self_test_sha512(function()
    local digest = Driver.OpenSSLCrypto.hmac_sha512("key", "data")
    assert_eq(Driver.Bytes.hex(digest),
      "3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253c" ..
      "b52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58",
      "hmac digest")

    local empty_key_digest = Driver.OpenSSLCrypto.hmac_sha512("", "data")
    assert_eq(Driver.Bytes.hex(empty_key_digest),
      "768c8b8791fd5a59d1cd1edb860054d746b181926b0551bcff4bd4e135f4bbc8" ..
      "9e395f9f250f8b582ebe92d3ff63dd401d3ab2af85790b24ecd92dce7466c16d",
      "empty-key hmac digest")
  end)
end

function tests.ed25519_matches_rfc8032_signature_vector()
  with_ed25519_vector_sha512(function()
    local public_key = Driver.Ed25519Pure.public_key_from_private(ED25519_VECTOR_SEED)
    assert_eq(public_key, ED25519_VECTOR_PUBLIC, "public key")
    local signature = Driver.Ed25519Pure.sign(ED25519_VECTOR_SEED, public_key, "")
    assert_eq(signature, ED25519_VECTOR_SIGNATURE, "signature")
    assert_eq(Driver.Ed25519Pure.verify(public_key, signature, ""), true, "verify")
  end)
end

function tests.openssl_crypto_pair_verify_response_uses_pure_x25519_and_ed25519_hooks()
  local private_key = Driver.Bytes.from_hex(
    "77076d0a7318a57d3c16c17251b26645" ..
    "df4c2f87ebc0992ab177fba51db92c2a"
  )
  local public_key = Driver.Bytes.from_hex(
    "8520f0098930a754748b7ddcb43ef75a" ..
    "0dbf3a0d26381af4eba4a98eaa9b4e6a"
  )
  local server_public_key = Driver.Bytes.from_hex(
    "de9edb7d7b7dc1b4d35b61c2ece43537" ..
    "3f8343c85b78674dadfc7e146f882b4f"
  )
  local expected_shared_secret = Driver.Bytes.from_hex(
    "4a5d9d5ba4ce2de1728e3bf480350f25" ..
    "e07e21c947d19e3376f09b3c1e161742"
  )
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(64, 95)),
    Driver.Bytes.hex(bytes_range(96, 127)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local server_signature = "server-signature"
  local decrypted_challenge = Driver.TLV8.encode_ordered({
    { 1, credentials.atv_id },
    { 10, server_signature },
  })
  local fake = make_fake_openssl({
    decrypt_plaintext = decrypted_challenge,
  })

  local old_verify = Driver.OpenSSLCrypto._verify_ed25519
  local old_sign = Driver.OpenSSLCrypto._sign_ed25519
  local old_decrypt = Driver.OpenSSLCrypto._chacha20_poly1305_decrypt
  local old_encrypt = Driver.OpenSSLCrypto._chacha20_poly1305_encrypt
  local old_hkdf = Driver.OpenSSLCrypto.hkdf_sha512
  Driver.OpenSSLCrypto._verify_ed25519 = function(received_public_key, received_signature, received_data)
    assert_eq(received_public_key, credentials.ltpk, "verify public key")
    assert_eq(received_signature, server_signature, "verify signature")
    assert_eq(received_data, server_public_key .. credentials.atv_id .. public_key, "verify data")
    return true
  end
  Driver.OpenSSLCrypto._sign_ed25519 = function(received_private_key, received_data)
    assert_eq(received_private_key, credentials.ltsk, "sign private key")
    assert_eq(received_data, public_key .. credentials.client_id .. server_public_key, "sign data")
    return "controller-signature"
  end
  Driver.OpenSSLCrypto._chacha20_poly1305_decrypt = function()
    return decrypted_challenge
  end
  Driver.OpenSSLCrypto._chacha20_poly1305_encrypt = function()
    return "ciphertext" .. string.rep("T", 16)
  end
  Driver.OpenSSLCrypto.hkdf_sha512 = function(salt, info, ikm)
    assert_eq(salt, "Pair-Verify-Encrypt-Salt", "pair-verify hkdf salt")
    assert_eq(info, "Pair-Verify-Encrypt-Info", "pair-verify hkdf info")
    assert_eq(ikm, expected_shared_secret, "pair-verify hkdf ikm")
    return "session-key"
  end

  with_fake_openssl(fake, function()
    local encrypted_response, shared_secret = Driver.OpenSSLCrypto.pair_verify_response(
      credentials,
      private_key,
      public_key,
      server_public_key,
      "ciphertext" .. string.rep("T", 16)
    )

    assert_eq(shared_secret, expected_shared_secret, "shared secret")
    assert_eq(encrypted_response, "ciphertext" .. string.rep("T", 16), "encrypted response")
  end)
  Driver.OpenSSLCrypto._verify_ed25519 = old_verify
  Driver.OpenSSLCrypto._sign_ed25519 = old_sign
  Driver.OpenSSLCrypto._chacha20_poly1305_decrypt = old_decrypt
  Driver.OpenSSLCrypto._chacha20_poly1305_encrypt = old_encrypt
  Driver.OpenSSLCrypto.hkdf_sha512 = old_hkdf
end

function tests.companion_client_pair_verify_enables_encrypted_session()
  local public_key = bytes_range(0, 31)
  local server_public_key = bytes_range(32, 63)
  local encrypted_challenge = "challenge"
  local encrypted_response = "response"
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(64, 95)),
    Driver.Bytes.hex(bytes_range(96, 127)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local writes = {}
  local states = {}
  local transport = {
    Write = function(_, data)
      writes[#writes + 1] = data
    end,
  }
  local fake_crypto = {
    generate_x25519_keypair = function()
      return {
        private_key = "private-key",
        public_key = public_key,
      }
    end,
    pair_verify_response = function()
      return encrypted_response, "shared-secret"
    end,
    hkdf_sha512 = function(_, info)
      if info == "ClientEncrypt-main" then
        return "output-key"
      end
      if info == "ServerEncrypt-main" then
        return "input-key"
      end
      error("unexpected hkdf info")
    end,
    encrypt = function(_, plaintext)
      return plaintext .. string.rep("\0", 16)
    end,
    decrypt = function(_, ciphertext)
      return ciphertext:sub(1, #ciphertext - 16)
    end,
    random_bytes = function(n)
      assert_eq(n, 4, "session sid random length")
      return "\x78\x56\x34\x12"
    end,
  }

  local client = Driver.CompanionClient.new({
    credentials = credentials,
    crypto = fake_crypto,
    transport = transport,
    on_state = function(state)
      states[#states + 1] = state
    end,
  })

  client:connect("127.0.0.1", 49153)
  assert_eq(states[1], "CONNECTED", "connected state")
  assert_eq(states[2], "PAIR_VERIFY_STARTED", "pair verify state")
  assert_eq(
    Driver.Bytes.hex(writes[1]),
    "05000033e2435f706491250601010320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f455f617554790c",
    "pair verify start write"
  )

  local response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({
      { 3, server_public_key },
      { 5, encrypted_challenge },
    })) },
  }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, response_payload))

  assert_eq(states[3], "PAIR_VERIFY_M3_SENT", "pair verify m3 state")
  assert_eq(client.session, nil, "session not enabled before pair-verify ack")
  assert_eq(writes[3], nil, "session start not sent before pair-verify ack")

  local ack_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({ { 6, string.char(0x04) } })) },
  }))
	  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, ack_payload))
	
	  assert_eq(states[4], "READY", "ready state")
	  assert(client.session ~= nil, "session enabled")
	  assert_eq(Driver.Companion.client, nil, "standalone client does not set global client")
	
	  local second = Driver.CompanionFrame.try_decode(writes[2])
	  local tlv = Driver.PairVerify.decode_pairing_data(second.payload)
  assert_eq(tlv[6], string.char(0x03), "pair verify next seq")
  assert_eq(tlv[5], encrypted_response, "pair verify next encrypted")

	  local decoded_system_info = client.session:try_decode(writes[3])
	  local system_info_msg = Driver.OPACK.decode(decoded_system_info.payload)
	  assert_table_has(system_info_msg, "_i", "_systemInfo")
	  client:start_companion_services()
	  assert_eq(writes[4], nil, "startup sequence does not re-enter while system info is pending")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", system_info_msg._x },
	  }))))
	
	  local decoded_touch_start = client.session:try_decode(writes[4])
	  local touch_start_msg = Driver.OPACK.decode(decoded_touch_start.payload)
	  assert_table_has(touch_start_msg, "_i", "_touchStart")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", touch_start_msg._x },
	  }))))
	
	  local decoded_start_frame = client.session:try_decode(writes[5])
	  local start_msg = Driver.OPACK.decode(decoded_start_frame.payload)
	  assert_table_has(start_msg, "_i", "_sessionStart")
	  assert_table_has(start_msg._c, "_srvT", "com.apple.tvremoteservices")
	  assert_eq(start_msg._c._sid, client.session_local_sid, "session start sid matches local sid")
	  assert_eq(states[5], "SESSION_STARTING", "session starting state")
	  assert_eq(client.session_local_sid, 0x12345678, "local sid from crypto random")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({ { "_sid", 0x87654321 } }) },
	    { "_x", start_msg._x },
	  }))))
	  local tv_rc_frame = client.session:try_decode(writes[6])
	  local tv_rc_msg = Driver.OPACK.decode(tv_rc_frame.payload)
	  assert_table_has(tv_rc_msg, "_i", "TVRCSessionStart")
	  assert_table_has(tv_rc_msg._c, "ProtocolVersionKey", "1.2")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", tv_rc_msg._x },
	  }))))

	  local ti_start_frame = client.session:try_decode(writes[7])
	  local ti_start_msg = Driver.OPACK.decode(ti_start_frame.payload)
	  assert_table_has(ti_start_msg, "_i", "_tiStart")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", ti_start_msg._x },
	  }))))
	
	  local launch_request, launch_frame = client:launch_app("com.netflix.Netflix")
	  assert_table_has(launch_request, "_i", "_launchApp")
  assert_eq(launch_frame:byte(1), Driver.CompanionFrame.E_OPACK, "encrypted launch frame type")
  assert_eq(#launch_frame, #Driver.Companion.encode_request_payload(launch_request) + 20, "encrypted launch frame length")
  local decoded_launch = client.session:try_decode(launch_frame)
  local decoded_request = Driver.OPACK.decode(decoded_launch.payload)
  assert_table_has(decoded_request, "_i", "_launchApp")
  assert_table_has(decoded_request._c, "_bundleID", "com.netflix.Netflix")
end

function tests.driver_imports_and_resets_companion_credentials()
  local old_properties = Properties
  Properties = { ["Launch App"] = "", ["Current App"] = "", ["Pairing PIN"] = "1234" }
  Driver._test_storage = {}

  local credentials = table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":")

  Driver.C4Driver.import_credentials(credentials)
  assert_eq(Driver._test_storage.companion_credentials, credentials, "stored credentials")
  assert_eq(Properties["Connection State"], "Credentials Imported", "import state")
  assert_eq(Driver.Companion.credentials.type, "HAP", "companion credentials")

  Driver.C4Driver.reset_pairing()
  assert_eq(Driver._test_storage.companion_credentials, nil, "reset credentials")
  assert_eq(Driver._test_storage.airplay_credentials, nil, "reset airplay credentials")
  assert_eq(Driver.Companion.credentials, nil, "reset companion credentials")
  assert_eq(Driver.AirPlay.credentials, nil, "reset airplay credentials table")
  assert_eq(Properties["Connection State"], "Disconnected", "reset state")

  Properties = old_properties
end

function tests.driver_imports_and_loads_airplay_credentials()
  local old_properties = Properties
  Properties = { ["Connection State"] = "" }
  Driver._test_storage = {}
  Driver.state = Driver._test_storage

  local credentials = table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("AIRPLAY-ID"),
    Driver.Bytes.hex("AIRPLAY-CLIENT"),
  }, ":")

  Driver.C4Driver.import_airplay_credentials(credentials)
  assert_eq(Driver._test_storage.airplay_credentials, credentials, "stored airplay credentials")
  assert_eq(Properties["Connection State"], "AirPlay Credentials Imported", "airplay import state")
  assert_eq(Driver.AirPlay.credentials.type, "HAP", "airplay credential type")

  Driver.AirPlay.credentials = nil
  Driver.C4Driver.load_persisted_airplay_credentials()
  assert_eq(Driver.Bytes.hex(Driver.AirPlay.credentials.client_id), Driver.Bytes.hex("AIRPLAY-CLIENT"), "loaded airplay client id")

  Properties = old_properties
end

function tests.airplay_credentials_opc_reimports_after_reset_clears_storage()
  local old_properties = Properties
  Properties = { ["Connection State"] = "", ["AirPlay Credentials"] = "" }
  Driver._test_storage = {}
  Driver.state = Driver._test_storage

  local credentials = table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("AIRPLAY-ID"),
    Driver.Bytes.hex("AIRPLAY-CLIENT"),
  }, ":")

  OPC.AirPlay_Credentials(credentials)
  assert_eq(Driver._test_storage.airplay_credentials, credentials, "initial import stored")

  Driver.state.airplay_credentials = nil
  Driver.AirPlay.credentials = nil
  OPC.AirPlay_Credentials(credentials)
  assert_eq(Driver._test_storage.airplay_credentials, credentials, "re-import stored after reset")
  assert_eq(Driver.AirPlay.credentials.type, "HAP", "re-import parsed credentials")

  Properties = old_properties
end

function tests.hap_session_encrypts_with_length_aad_and_padded_counter_nonce()
  local calls = {}
  local fake_crypto = {
    encrypt = function(key, plaintext, aad, nonce)
      calls[#calls + 1] = {
        op = "encrypt",
        key = key,
        plaintext = plaintext,
        aad = aad,
        nonce = nonce,
      }
      return plaintext .. string.rep("T", 16)
    end,
    decrypt = function(key, ciphertext, aad, nonce)
      calls[#calls + 1] = {
        op = "decrypt",
        key = key,
        ciphertext = ciphertext,
        aad = aad,
        nonce = nonce,
      }
      return ciphertext:sub(1, #ciphertext - 16)
    end,
  }

  local session = Driver.HAPSession.new("write-key", "read-key", fake_crypto)
  local encrypted = session:encrypt("hello")
  assert_eq(encrypted:sub(1, 2), Driver.Bytes.uint_le(5, 2), "HAP frame length")
  assert_eq(calls[1].key, "write-key", "HAP encrypt key")
  assert_eq(calls[1].aad, Driver.Bytes.uint_le(5, 2), "HAP length aad")
  assert_eq(Driver.Bytes.hex(calls[1].nonce), "000000000000000000000000", "HAP first nonce")

  local plaintext = session:decrypt(Driver.Bytes.uint_le(5, 2) .. "world" .. string.rep("T", 16))
  assert_eq(plaintext, "world", "HAP decrypted plaintext")
  assert_eq(calls[2].key, "read-key", "HAP decrypt key")
  assert_eq(calls[2].aad, Driver.Bytes.uint_le(5, 2), "HAP decrypt aad")
  assert_eq(Driver.Bytes.hex(calls[2].nonce), "000000000000000000000000", "HAP first decrypt nonce")
end

function tests.hap_session_encrypted_buffer_is_bounded()
  local old_max = Driver.HAPSession.MAX_ENCRYPTED_BUFFER_BYTES
  Driver.HAPSession.MAX_ENCRYPTED_BUFFER_BYTES = 4
  local session = Driver.HAPSession.new("write-key", "read-key", {
    decrypt = function() return "" end,
  })

  local ok, err = pcall(function()
    session:decrypt(string.rep("x", 5))
  end)

  Driver.HAPSession.MAX_ENCRYPTED_BUFFER_BYTES = old_max
  assert_eq(ok, false, "oversized HAP encrypted buffer rejected")
  assert(tostring(err):find("HAP encrypted buffer", 1, true), "HAP buffer error labels source")
  assert_eq(session.encrypted_buffer, "", "oversized HAP encrypted buffer cleared")
end

function tests.airplay_control_client_pair_verifies_then_gets_encrypted_info()
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local fake_crypto = {
    generate_x25519_keypair = function()
      return { private_key = "private-key", public_key = bytes_range(64, 95) }
    end,
    pair_verify_response = function(_, _, _, _, _)
      return "encrypted-response", "shared-secret"
    end,
    hkdf_sha512 = function(_, info, _)
      if info == "Control-Write-Encryption-Key" then return "write-key" end
      if info == "Control-Read-Encryption-Key" then return "read-key" end
      error("unexpected hkdf info")
    end,
    encrypt = function(_, plaintext)
      return plaintext .. string.rep("T", 16)
    end,
    decrypt = function(_, ciphertext)
      return ciphertext:sub(1, #ciphertext - 16)
    end,
  }
  local writes = {}
  local transport = {
    Write = function(_, data)
      writes[#writes + 1] = data
      return true
    end,
  }
  local received_info
  local client = Driver.AirPlayControlClient.new({
    host = "192.0.2.55",
    port = 7000,
    credentials = credentials,
    crypto = fake_crypto,
    transport = transport,
    on_info = function(response)
      received_info = response
    end,
  })

  local function http_response(body, content_type)
    return table.concat({
      "HTTP/1.1 200 OK",
      "Content-Type: " .. (content_type or "application/octet-stream"),
      "Content-Length: " .. tostring(#(body or "")),
      "",
      "",
    }, "\r\n") .. (body or "")
  end

  client:connect()
  assert(writes[1]:find("POST /pair%-verify HTTP/1.1"), "pair verify m1 request")
  client:receive(http_response(Driver.TLV8.encode_ordered({
    { 3, bytes_range(96, 127) },
    { 5, "encrypted-challenge" },
  })))
  assert(writes[2]:find("POST /pair%-verify HTTP/1.1"), "pair verify m3 request")
  client:receive(http_response(Driver.TLV8.encode_ordered({ { 6, string.char(0x04) } })))
  assert_eq(client.state, "ENCRYPTED_INFO", "encrypted info state")
  assert_eq(writes[3]:sub(1, 2), Driver.Bytes.uint_le(#"GET /info HTTP/1.1\r\nHost: 192.0.2.55:7000\r\nUser-Agent: AirPlay/550.10\r\nConnection: keep-alive\r\nAccept: application/x-apple-binary-plist\r\n\r\n", 2), "encrypted GET length")

  local encrypted_response = http_response("bplist-body", "application/x-apple-binary-plist")
  client:receive(Driver.Bytes.uint_le(#encrypted_response, 2) .. encrypted_response .. string.rep("T", 16))
  assert(received_info ~= nil, "encrypted info callback")
  assert_eq(received_info.status, 200, "encrypted info status")
  assert_eq(received_info.body, "bplist-body", "encrypted info body")
end

function tests.bplist_roundtrips_nested_setup_payloads()
  local payload = {
    isRemoteControlOnly = true,
    eventPort = 12345,
    streams = {
      {
        dataPort = 54321,
        wantsDedicatedSocket = true,
        clientTypeUUID = "1910A70F-DBC0-4242-AF95-115DB30604E1",
      },
    },
  }
  local decoded = Driver.BPlist.decode(Driver.BPlist.encode(payload))
  assert_eq(decoded.isRemoteControlOnly, true, "bplist bool")
  assert_eq(decoded.eventPort, 12345, "bplist int")
  assert_eq(decoded.streams[1].dataPort, 54321, "bplist nested int")
  assert_eq(decoded.streams[1].clientTypeUUID, "1910A70F-DBC0-4242-AF95-115DB30604E1", "bplist nested string")
end

function tests.airplay_control_client_runs_rtsp_tunnel_setup_probe()
  local old_c4 = C4
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local random_values = {
    string.rep("\1", 4),
    string.rep("\2", 8),
    string.rep("\3", 16),
    string.rep("\4", 16),
    string.rep("\5", 4),
    string.rep("\6", 16),
    string.rep("\7", 16),
  }
  local fake_crypto = {
    generate_x25519_keypair = function()
      return { private_key = "private-key", public_key = bytes_range(64, 95) }
    end,
    pair_verify_response = function(_, _, _, _, _)
      return "encrypted-response", "shared-secret"
    end,
    hkdf_sha512 = function(_, info, _)
      if info == "Control-Write-Encryption-Key" then return "write-key" end
      if info == "Control-Read-Encryption-Key" then return "read-key" end
      if info == "Events-Read-Encryption-Key" then return "event-write-key" end
      if info == "Events-Write-Encryption-Key" then return "event-read-key" end
      if info == "DataStream-Output-Encryption-Key" then return "data-write-key" end
      if info == "DataStream-Input-Encryption-Key" then return "data-read-key" end
      error("unexpected hkdf info")
    end,
    random_bytes = function(n)
      local value = table.remove(random_values, 1) or string.rep("\8", n)
      return value:sub(1, n)
    end,
    encrypt = function(_, plaintext)
      return plaintext .. string.rep("T", 16)
    end,
    decrypt = function(_, ciphertext)
      return ciphertext:sub(1, #ciphertext - 16)
    end,
  }
  local writes = {}
  local event_writes = {}
  local channel_close_calls = 0
  local transport = {
    Write = function(_, data)
      writes[#writes + 1] = data
      return true
    end,
  }
  C4 = {
    CreateTCPClient = function()
      local callbacks = {}
      local tcp = {
        OnConnect = function(self, cb) callbacks.connect = cb; return self end,
        OnRead = function(self, cb) callbacks.read = cb; return self end,
        OnDisconnect = function(self, cb) callbacks.disconnect = cb; return self end,
        OnError = function(self, cb) callbacks.error = cb; return self end,
        Connect = function(self)
          callbacks.connect(self)
          return self
        end,
        ReadUpTo = function() return true end,
        Write = function(_, data)
          event_writes[#event_writes + 1] = data
          return true
        end,
        Close = function()
          channel_close_calls = channel_close_calls + 1
        end,
      }
      return tcp
    end,
  }
  local tunnel_result
  local client = Driver.AirPlayControlClient.new({
    host = "192.0.2.55",
    port = 7000,
    credentials = credentials,
    crypto = fake_crypto,
    transport = transport,
    probe = "tunnel_setup",
    on_tunnel_setup = function(result)
      tunnel_result = result
    end,
  })

  local function http_response(body, protocol)
    return table.concat({
      (protocol or "HTTP/1.1") .. " 200 OK",
      "Content-Type: application/x-apple-binary-plist",
      "Content-Length: " .. tostring(#(body or "")),
      "",
      "",
    }, "\r\n") .. (body or "")
  end

  local function hap_frame(plaintext)
    return Driver.Bytes.uint_le(#plaintext, 2) .. plaintext .. string.rep("T", 16)
  end

  client:connect()
  client:receive(http_response(Driver.TLV8.encode_ordered({
    { 3, bytes_range(96, 127) },
    { 5, "encrypted-challenge" },
  })))
  client:receive(http_response(Driver.TLV8.encode_ordered({ { 6, string.char(0x04) } })))
  assert_eq(client.state, "RTSP_EVENT_SETUP", "event setup state")
  assert(writes[3]:find("SETUP rtsp://192%.0%.2%.55/"), "encrypted event setup request")

  client:receive(hap_frame(http_response(Driver.BPlist.encode({ eventPort = 49152 }), "RTSP/1.0")))
  assert_eq(client.state, "RTSP_RECORD", "record state")
  assert(client.event_channel ~= nil, "event channel created")
  assert_eq(#event_writes, 0, "event channel does not send on connect")
  client:receive(hap_frame(http_response("", "RTSP/1.0")))
  assert_eq(client.state, "RTSP_DATA_SETUP", "data setup state")
  client:receive(hap_frame(http_response(Driver.BPlist.encode({
    streams = {
      { dataPort = 49153 },
    },
  }), "RTSP/1.0")))

  assert_eq(client.state, "DATA_CHANNEL_ACTIVE", "data channel active state")
  assert(tunnel_result ~= nil, "tunnel callback")
  assert_eq(tunnel_result.event_port, 49152, "event port")
  assert_eq(tunnel_result.data_port, 49153, "data port")
  assert(client.data_channel ~= nil, "data channel created")
  assert_eq(#event_writes, 1, "data channel sends initial device info only")
  client.data_channel:receive(hap_frame(Driver.Bytes.uint_be(1, 4) .. string.rep("\0", 28)))
  assert_eq(channel_close_calls, 1, "invalid data frame closes data channel")
  assert_eq(client.data_channel.buffer, "", "invalid data frame clears buffer")
  C4 = old_c4
end


function tests.execute_command_routes_driver_commands()
  local old_properties = Properties
  Properties = { ["Launch App"] = "", ["Current App"] = "" }
  Driver.Companion.sent_messages = {}
  ExecuteCommand("LAUNCH_APP", { BUNDLE_ID_OR_URL = "com.netflix.Netflix" })
  local launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(launch, "_i", "_launchApp")
  assert_table_has(launch._c, "_bundleID", "com.netflix.Netflix")
  assert_eq(Properties["Current App"], "com.netflix.Netflix", "current app property")

  ExecuteCommand("Launch App", { ["Bundle ID or URL"] = "https://www.netflix.com/title/80234304" })
  launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(launch, "_i", "_launchApp")
  assert_table_has(launch._c, "_urlS", "https://www.netflix.com/title/80234304")

  ExecuteCommand("REFRESH_APP_LIST", {})
  local refresh = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(refresh, "_i", "FetchLaunchableApplicationsEvent")
  Properties = old_properties
end

function tests.programming_launch_app_resolves_property_style_selection()
  local old_properties = Properties
  Properties = { ["Launch App"] = "", ["Current App"] = "" }
  Driver.Companion.app_list = {
    ["com.netflix.Netflix"] = "Netflix",
    ["com.google.ios.youtube"] = "YouTube",
  }
  local _, rows = Driver.Companion.parse_app_list(Driver.Companion.app_list)
  Driver.Companion.app_list_rows = rows
  Driver.Companion.sent_messages = {}

  ExecuteCommand("Launch_App", { ["Bundle ID or URL"] = "Netflix | com.netflix.Netflix" })
  local launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_eq(launch._i, "_launchApp", "programming launch uses resolved selection")
  assert_eq(launch._c._bundleID, "com.netflix.Netflix", "programming launch bundle")

  Driver.Companion.sent_messages = {}
  ExecuteCommand("LAUNCH_APP", { ["Bundle ID or URL"] = "YouTube" })
  launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_eq(launch._c._bundleID, "com.google.ios.youtube", "programming launch resolves app name")

  Driver.Companion.sent_messages = {}
  ExecuteCommand("Launch App By ID", { ["Bundle ID or URL"] = "com.netflix.Netflix" })
  launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_eq(launch._c._bundleID, "com.netflix.Netflix", "free-type launch by id")

  Properties = old_properties
end

function tests.get_command_param_list_returns_launch_app_selector_items()
  Driver.Companion.app_list = {
    ["com.netflix.Netflix"] = "Netflix",
    ["com.google.ios.youtube"] = "YouTube",
  }
  local _, rows = Driver.Companion.parse_app_list(Driver.Companion.app_list)
  Driver.Companion.app_list_rows = rows

  local items = GetCommandParamList("Launch App", "Bundle ID or URL")
  assert(type(items) == "table", "returns a table")
  assert_eq(items[1], "", "leading blank entry")
  local joined = table.concat(items, "\n")
  assert(joined:match("Netflix | com%.netflix%.Netflix"), "includes Netflix row")
  assert(joined:match("YouTube | com%.google%.ios%.youtube"), "includes YouTube row")

  assert_eq(GetCommandParamList("Launch App", "Other"), nil, "unknown param ignored")
end

function tests.refresh_app_list_uses_existing_client()
  local old_properties = Properties
  Properties = { ["Current App"] = "" }
  local writes = {}
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    crypto = {
      encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
      decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    },
    transport = { Write = function(_, data) writes[#writes + 1] = data end },
  })
  client.session = Driver.CompanionSession.new("out", "in", client.crypto)
  client.state = "SESSION_ACTIVE"
  Driver.Companion.client = client
  Driver.Companion.credentials = client.credentials

  Driver.C4Driver.refresh_app_list()
  assert_eq(#writes, 1, "refresh app list writes to active client")
  local decoded = client.session:try_decode(writes[1])
  local message = Driver.OPACK.decode(decoded.payload)
  assert_eq(message._i, "FetchLaunchableApplicationsEvent", "refresh app list command")

  Driver.Companion.client = nil
  Driver.Companion.credentials = nil
  Properties = old_properties
end

function tests.queued_command_does_not_reenter_connect_while_connecting()
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    transport = { Write = function() end },
  })
  local connect_calls = 0
  client.connecting = true
  client.connect = function()
    connect_calls = connect_calls + 1
  end

  client:fetch_apps()
  assert_eq(connect_calls, 0, "queued command did not re-enter connect")
  assert_eq(#client.pending_commands, 1, "command queued for session active")
end

function tests.queued_command_reconnects_from_error_state_once()
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    transport = { Write = function() end },
  })
  local connect_calls = 0
  client.state = "ERROR: previous failure"
  client.connect = function()
    connect_calls = connect_calls + 1
    client.connecting = true
  end

  client:fetch_apps()
  client:launch_app("com.netflix.Netflix")
  assert_eq(connect_calls, 1, "queued commands reconnect from error once")
  assert_eq(#client.pending_commands, 2, "commands queued while reconnecting")
end

function tests.queued_command_queue_is_bounded()
  local old_max = Driver.Companion.pending_commands_max
  Driver.Companion.pending_commands_max = 3
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    transport = { Write = function() end },
  })
  client.connecting = true
  client.connect = function() end

  for i = 1, 5 do
    client:send_or_queue_opack("_launchApp", { _bundleID = "app" .. tostring(i) }, 2)
  end

  Driver.Companion.pending_commands_max = old_max
  assert_eq(#client.pending_commands, 3, "pending Companion commands capped")
  assert_eq(client.pending_commands[1].content._bundleID, "app3", "oldest queued command dropped")
  assert_eq(client.pending_commands[3].content._bundleID, "app5", "newest queued command retained")
end

function tests.companion_receive_buffer_is_bounded()
  local old_max = Driver.Companion.receive_buffer_max
  Driver.Companion.receive_buffer_max = 8
  local client = Driver.CompanionClient.new({})

  local ok, err = pcall(function()
    client:receive(string.rep("x", 9))
  end)

  Driver.Companion.receive_buffer_max = old_max
  assert_eq(ok, false, "oversized Companion receive buffer rejected")
  assert(tostring(err):find("Companion receive buffer", 1, true), "Companion buffer error labels source")
  assert_eq(client.buffer, "", "oversized Companion receive buffer cleared")
end

function tests.companion_dispose_clears_heavy_state_and_callbacks()
  local close_called = false
  local client = Driver.CompanionClient.new({
    credentials = { ltpk = "ltpk" },
    crypto = {},
    host = "192.0.2.10",
    port = 49153,
    transport = { close = function() close_called = true end },
    on_state = function() end,
    on_message = function() end,
    on_paired = function() end,
    on_pair_setup_m2 = function() end,
    on_connection_refused = function() end,
  })
  client.pending_commands = { { identifier = "_launchApp" } }
  client.pending_responses = { [1] = { on_response = function() end } }
  client.verifier = {}
  client.pair_setup = {}

  client:dispose()

  assert_eq(close_called, true, "dispose closes Companion transport")
  assert_eq(client.credentials, nil, "dispose clears Companion credentials")
  assert_eq(client.crypto, nil, "dispose clears Companion crypto")
  assert_eq(client.host, nil, "dispose clears Companion host")
  assert_eq(#client.pending_commands, 0, "dispose clears queued commands")
  assert_eq(next(client.pending_responses), nil, "dispose clears pending responses")
  assert_eq(client.on_state, nil, "dispose clears state callback")
  assert_eq(client.on_message, nil, "dispose clears message callback")
  assert_eq(client.verifier, nil, "dispose clears pair verifier")
  assert_eq(client.pair_setup, nil, "dispose clears pair setup")
end

function tests.companion_reconnect_state_code_ignores_detail_suffix()
  local client = Driver.CompanionClient.new({})
  client.state = "DISCONNECTED: network down"
  assert_eq(client:state_code(), "DISCONNECTED", "disconnected state code")
  assert_eq(client:needs_reconnect(), true, "disconnected detail reconnects")
  client.state = "ERROR: failed"
  assert_eq(client:state_code(), "ERROR", "error state code")
  assert_eq(client:needs_reconnect(), true, "error detail reconnects")
  client.state = "SESSION_ACTIVE"
  assert_eq(client:needs_reconnect(), false, "active session does not reconnect")
end

function tests.queued_hid_commands_are_coalesced_while_connecting()
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    transport = { Write = function() end },
  })
  client.connecting = true
  client.connect = function() end

  client:send_or_queue_opack("_hidC", { _hidC = 5, _hBtS = 1 }, 2)
  client:send_or_queue_opack("_hidC", { _hidC = 5, _hBtS = 2 }, 2)
  client:send_or_queue_opack("_hidC", { _hidC = 5, _hBtS = 1 }, 2)
  client:send_or_queue_opack("_hidC", { _hidC = 5, _hBtS = 2 }, 2)
  client:send_or_queue_opack("_hidC", { _hidC = 1, _hBtS = 1 }, 2)

  assert_eq(#client.pending_commands, 3, "queued HID commands coalesced by button")
  assert_eq(client.pending_commands[1].content._hidC, 5, "menu HID retained")
  assert_eq(client.pending_commands[1].content._hBtS, 1, "menu press retained")
  assert_eq(client.pending_commands[2].content._hidC, 5, "menu release retained")
  assert_eq(client.pending_commands[2].content._hBtS, 2, "menu release retained")
  assert_eq(client.pending_commands[3].content._hidC, 1, "different HID retained")
end

function tests.priority_pending_commands_flush_before_normal_queue()
  local writes = {}
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    crypto = {
      encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
      decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    },
    transport = { Write = function(_, data) writes[#writes + 1] = data end },
  })
  client.session = Driver.CompanionSession.new("out", "in", client.crypto)
  client.state = "SESSION_ACTIVE"
  client.pending_commands = {
    { identifier = "_launchApp", content = { _bundleID = "com.att.tv" }, message_type = 2 },
    { identifier = "_hidC", content = { _hidC = 7, _hBtS = 1 }, message_type = 2, priority = true },
    { identifier = "_hidC", content = { _hidC = 7, _hBtS = 2 }, message_type = 2, priority = true },
  }

  client:flush_pending_commands({ priority_only = true })

  assert_eq(#writes, 2, "priority flush writes only power-off tap")
  assert_eq(#client.pending_commands, 1, "normal command remains queued")
  assert_eq(client.pending_commands[1].identifier, "_launchApp", "normal queued launch remains")
end

function tests.companion_pending_responses_expire_by_ttl()
  local writes = {}
  local now = 1000
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    crypto = {
      encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
      decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    },
    transport = { Write = function(_, data) writes[#writes + 1] = data end },
    response_timeout_ms = 5000,
  })
  client.now_ms = function() return now end
  client.session = Driver.CompanionSession.new("out", "in", client.crypto)
  client.state = "SESSION_ACTIVE"

  local request = client:fetch_apps()
  assert(client.pending_responses[request._x] ~= nil, "pending response stored")
  now = 5999
  client:cleanup_pending_responses()
  assert(client.pending_responses[request._x] ~= nil, "pending response retained before ttl")
  now = 6001
  local expired = client:cleanup_pending_responses()
  assert_eq(expired, 1, "expired response count")
  assert_eq(client.pending_responses[request._x], nil, "pending response expired")
end

function tests.active_session_command_reuses_connection()
  local writes = {}
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    crypto = {
      encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
      decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    },
    transport = { Write = function(_, data) writes[#writes + 1] = data end },
  })
  local connect_calls = 0
  client.connect = function() connect_calls = connect_calls + 1 end
  client.session = Driver.CompanionSession.new("out", "in", client.crypto)
  client.state = "SESSION_ACTIVE"

  client:fetch_apps()
  assert_eq(connect_calls, 0, "active session command does not reconnect")
  assert_eq(#client.pending_commands, 0, "active command is not queued")
  assert_eq(#writes, 1, "active command writes immediately")
  assert(client.last_tx_ms ~= nil, "last tx timestamp recorded")
end

function tests.companion_sent_messages_are_bounded()
  local old_sent = Driver.Companion.sent_messages
  local old_max = Driver.Companion.sent_messages_max
  Driver.Companion.sent_messages = {}
  Driver.Companion.sent_messages_max = 3

  for i = 1, 5 do
    Driver.Companion.record_sent_message({ _i = "m" .. tostring(i) })
  end

  assert_eq(#Driver.Companion.sent_messages, 3, "sent message ring length")
  assert_eq(Driver.Companion.sent_messages[1]._i, "m3", "oldest retained message")
  assert_eq(Driver.Companion.sent_messages[3]._i, "m5", "newest retained message")

  Driver.Companion.sent_messages = old_sent
  Driver.Companion.sent_messages_max = old_max
end

function tests.driver_destroy_closes_client_and_cancels_timers()
  local old_cancel_timer = CancelTimer
  local old_client = Driver.Companion.client
  local old_airplay_client = Driver.AirPlay.control_client
  local old_monitor_enabled = Driver.AirPlay.monitor_enabled
  local cancelled = {}
  local closed = false
  local airplay_closed = false

  CancelTimer = function(name)
    cancelled[#cancelled + 1] = name
  end
  Driver.Companion.client = {
    close = function()
      closed = true
    end,
  }
  Driver.AirPlay.control_client = {
    close = function()
      airplay_closed = true
    end,
  }
  Driver.AirPlay.monitor_enabled = true

  -- Per-room handoff timers must be registered so teardown can find them.
  Driver.C4MiniApps.active_handoff_timers = {
    ["AppleTV_verify_native_handoff_42"] = true,
    ["AppleTV_verify_handoff_42"] = true,
    ["AppleTV_native_driver_handoff_42"] = true,
  }

  Driver.C4Driver.destroy()

  assert_eq(closed, true, "destroy closes Companion client")
  assert_eq(airplay_closed, true, "destroy closes AirPlay client")
  assert_eq(Driver.Companion.client, nil, "destroy clears client")
  assert_eq(Driver.AirPlay.control_client, nil, "destroy clears AirPlay client")
  assert_eq(Driver.AirPlay.monitor_enabled, false, "destroy disables AirPlay monitor")
  assert_contains(cancelled, "AppleTV_reselect_passthrough", "passthrough timer cancelled")
  assert_contains(cancelled, "AppleTV_companion_watchdog", "Companion watchdog timer cancelled")
  assert_contains(cancelled, "AppleTV_airplay_monitor_start", "AirPlay monitor start timer cancelled")
  assert_contains(cancelled, "AppleTV_airplay_monitor_retry", "AirPlay monitor retry timer cancelled")
  assert_contains(cancelled, "AppleTV_airplay_monitor_watchdog", "AirPlay monitor watchdog timer cancelled")
  assert_contains(cancelled, "AppleTV_airplay_monitor_start_watchdog", "AirPlay start watchdog cancelled")
  assert_contains(cancelled, "AppleTV_verify_native_handoff_42", "native handoff verify timer cancelled")
  assert_contains(cancelled, "AppleTV_verify_handoff_42", "room selection verify timer cancelled")
  assert_eq(next(Driver.C4MiniApps.active_handoff_timers), nil, "handoff timer registry cleared")

  CancelTimer = old_cancel_timer
  Driver.Companion.client = old_client
  Driver.AirPlay.control_client = old_airplay_client
  Driver.AirPlay.monitor_enabled = old_monitor_enabled
end

-- The per-room verify timers used to be created without registering their names,
-- so cancel_driver_timers could never find them on destroy.
function tests.handoff_verify_timers_are_registered_for_cancellation()
  local old_c4 = C4
  local old_set_timer = SetTimer
  local old_registry = Driver.C4MiniApps.active_handoff_timers
  local armed = {}

  C4 = {
    GetDriverConfigInfo = function() return "Apple TV Companion" end,
    GetDeviceID = function() return 0 end,
    GetDeviceVariable = function() return 99 end,
    SendToDevice = function() end,
  }
  SetTimer = function(name) armed[#armed + 1] = name end
  Driver.C4MiniApps.active_handoff_timers = {}

  local ok, err = pcall(function()
    Driver.C4MiniApps.verify_native_handoff(42, 99, 98)
    assert_contains(armed, "AppleTV_verify_native_handoff_42", "native handoff verify timer armed")
    assert_eq(Driver.C4MiniApps.active_handoff_timers["AppleTV_verify_native_handoff_42"], true,
      "native handoff verify timer registered for cancellation")

    Driver.C4MiniApps.verify_room_selection(42, 99, "test")
    assert_contains(armed, "AppleTV_verify_handoff_42", "room selection verify timer armed")
    assert_eq(Driver.C4MiniApps.active_handoff_timers["AppleTV_verify_handoff_42"], true,
      "room selection verify timer registered for cancellation")
  end)

  C4 = old_c4
  SetTimer = old_set_timer
  Driver.C4MiniApps.active_handoff_timers = old_registry
  if not ok then error(err, 2) end
end

function tests.import_credentials_closes_existing_companion_client()
  local old_client = Driver.Companion.client
  local old_credentials = Driver.Companion.credentials
  local old_state = Driver.state
  local old_test_storage = Driver._test_storage
  local closed = false
  Driver.Companion.client = {
    close = function()
      closed = true
    end,
  }
  Driver.state = {}
  Driver._test_storage = {}

  Driver.C4Driver.import_credentials(table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))

  assert_eq(closed, true, "existing Companion client closed on import")
  assert_eq(Driver.Companion.client, nil, "Companion client cleared on import")

  Driver.Companion.client = old_client
  Driver.Companion.credentials = old_credentials
  Driver.state = old_state
  Driver._test_storage = old_test_storage
end

function tests.build_companion_client_closes_replaced_client()
  local old_client = Driver.Companion.client
  local closed = false
  Driver.Companion.client = {
    close = function()
      closed = true
    end,
  }

  local client = Driver.C4Driver.build_companion_client("192.0.2.10", {})

  assert_eq(closed, true, "replaced Companion client closed")
  assert_eq(Driver.Companion.client, client, "new Companion client installed")

  Driver.Companion.client = old_client
end

function tests.companion_read_error_closes_transport()
  local old_c4 = C4
  local callbacks = {}
  local close_called = false
  local read_up_to_calls = 0
  C4 = {
    CreateTCPClient = function()
      local tcp = {
        OnConnect = function(self, cb) callbacks.connect = cb; return self end,
        OnRead = function(self, cb) callbacks.read = cb; return self end,
        OnDisconnect = function(self, cb) callbacks.disconnect = cb; return self end,
        OnError = function(self, cb) callbacks.error = cb; return self end,
        Connect = function(self)
          callbacks.connect(self)
          return self
        end,
        ReadUpTo = function()
          read_up_to_calls = read_up_to_calls + 1
          return true
        end,
        Close = function()
          close_called = true
        end,
      }
      return tcp
    end,
  }

  local client = Driver.CompanionClient.new({})
  client:connect("192.0.2.10", 49153)
  client.receive = function()
    error("boom")
  end
  callbacks.read(client.transport, "bad")

  assert_eq(close_called, true, "transport closed after receive error")
  assert_eq(client.transport, nil, "transport cleared after receive error")
  assert_eq(client.connected, false, "client runtime state cleared")
  assert_eq(read_up_to_calls, 1, "read loop not rescheduled after receive error")
  assert(client.state:match("^ERROR:"), "client state records receive error")

  C4 = old_c4
end

function tests.airplay_control_connect_is_guarded_while_pending()
  local old_c4 = C4
  local callbacks = {}
  local connect_calls = 0
  local writes = 0
  C4 = {
    CreateTCPClient = function()
      local tcp = {
        OnConnect = function(self, cb) callbacks.connect = cb; return self end,
        OnRead = function(self, cb) callbacks.read = cb; return self end,
        OnDisconnect = function(self, cb) callbacks.disconnect = cb; return self end,
        OnError = function(self, cb) callbacks.error = cb; return self end,
        Connect = function(self)
          connect_calls = connect_calls + 1
          return self
        end,
        ReadUpTo = function() return true end,
        Write = function()
          writes = writes + 1
          return true
        end,
      }
      return tcp
    end,
  }
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(0, 31)),
    Driver.Bytes.hex(bytes_range(32, 63)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local fake_crypto = {
    generate_x25519_keypair = function()
      return { private_key = "private-key", public_key = bytes_range(64, 95) }
    end,
  }

  local client = Driver.AirPlayControlClient.new({
    host = "192.0.2.10",
    port = 7000,
    credentials = credentials,
    crypto = fake_crypto,
  })

  client:connect()
  client:connect()
  assert_eq(connect_calls, 1, "second pending connect does not create another TCP client")
  callbacks.connect(client.transport)
  assert_eq(client.connected, true, "client marked connected")
  client:connect()
  assert_eq(connect_calls, 1, "connected connect call reuses existing TCP client")
  assert_eq(writes, 1, "Pair-Verify start written once")

  C4 = old_c4
end

function tests.airplay_control_close_releases_nested_channels_and_callbacks()
  local event_closed = false
  local data_closed = false
  local transport_closed = false
  local client = Driver.AirPlayControlClient.new({
    credentials = { type = "HAP" },
    crypto = {},
    on_info = function() end,
    on_tunnel_setup = function() end,
    on_activity = function() end,
    on_error = function() end,
    on_disconnect = function() end,
    on_state = function() end,
  })
  client.event_channel = { close = function() event_closed = true end }
  client.data_channel = { close = function() data_closed = true end }
  client.transport = { close = function() transport_closed = true end }
  client.raw_buffer = "raw"
  client.http_buffer = "http"
  client.verifier = {}
  client.session = { encrypted_buffer = "ciphertext" }
  client.connected = true
  client.rtsp_session_id = "session"
  client.data_seed = "seed"
  client.pending_control_keys = { output_key = "out", input_key = "in" }

  client:close()

  assert_eq(event_closed, true, "AirPlay close closes event channel")
  assert_eq(data_closed, true, "AirPlay close closes data channel")
  assert_eq(transport_closed, true, "AirPlay close closes transport")
  assert_eq(client.event_channel, nil, "AirPlay close clears event channel")
  assert_eq(client.data_channel, nil, "AirPlay close clears data channel")
  assert_eq(client.transport, nil, "AirPlay close clears transport")
  assert_eq(client.raw_buffer, "", "AirPlay close clears raw buffer")
  assert_eq(client.http_buffer, "", "AirPlay close clears HTTP buffer")
  assert_eq(client.verifier, nil, "AirPlay close clears verifier")
  assert_eq(client.session, nil, "AirPlay close clears session")
  assert_eq(client.connected, false, "AirPlay close clears connected flag")
  assert_eq(client.rtsp_session_id, nil, "AirPlay close clears RTSP session")
  assert_eq(client.data_seed, nil, "AirPlay close clears data seed")
  assert_eq(client.pending_control_keys, nil, "AirPlay close clears pending control keys")
  assert_eq(client.on_error, nil, "AirPlay close clears error callback")
  assert_eq(client.on_disconnect, nil, "AirPlay close clears disconnect callback")
  assert_eq(client.credentials, nil, "AirPlay close clears credentials")
  assert_eq(client.crypto, nil, "AirPlay close clears crypto")
end

function tests.opack_launch_request_roundtrip()
  Driver.Companion.tx = 0
  local request, frame = Driver.Companion.encode_opack_request("_launchApp", {
    _bundleID = "com.netflix.Netflix",
  }, 2)

  assert_table_has(request, "_i", "_launchApp")
  assert_table_has(request, "_t", 2)
  assert_table_has(request._c, "_bundleID", "com.netflix.Netflix")

  local decoded_frame = Driver.CompanionFrame.try_decode(frame)
  local decoded_request = Driver.OPACK.decode(decoded_frame.payload)
  assert_table_has(decoded_request, "_i", "_launchApp")
  assert_table_has(decoded_request, "_t", 2)
  assert_table_has(decoded_request._c, "_bundleID", "com.netflix.Netflix")
end

function tests.opack_requests_match_pyatv_source_vectors()
  local vectors = {
    {
      name = "launch bundle",
      request = { _i = "_launchApp", _t = 2, _c = { _bundleID = "com.netflix.Netflix" }, _x = 1 },
      hex = "e4425f694a5f6c61756e6368417070425f740a425f63e1495f62756e646c65494453636f6d2e6e6574666c69782e4e6574666c6978425f7809",
    },
    {
      name = "launch url",
      request = { _i = "_launchApp", _t = 2, _c = { _urlS = "https://www.netflix.com/title/80234304" }, _x = 2 },
      hex = "e4425f694a5f6c61756e6368417070425f740a425f63e1455f75726c53612668747470733a2f2f7777772e6e6574666c69782e636f6d2f7469746c652f3830323334333034425f780a",
    },
    {
      name = "fetch apps",
      request = { _i = "FetchLaunchableApplicationsEvent", _t = 2, _c = {}, _x = 3 },
      hex = "e4425f696046657463684c61756e636861626c654170706c69636174696f6e734576656e74425f740a425f63e0425f780b",
    },
    {
      name = "hid up release",
      request = { _i = "_hidC", _t = 2, _c = { _hBtS = 2, _hidC = 1 }, _x = 4 },
      hex = "e4425f69455f68696443425f740a425f63e2455f684274530aa109425f780c",
    },
    {
      name = "session start",
      request = { _i = "_sessionStart", _t = 2, _c = { _srvT = "com.apple.tvremoteservices", _sid = 123456 }, _x = 5 },
      hex = "e4425f694d5f73657373696f6e5374617274425f740a425f63e2455f737276545a636f6d2e6170706c652e747672656d6f74657365727669636573445f7369643240e20100425f780d",
    },
  }

  for _, vector in ipairs(vectors) do
    assert_eq(Driver.Bytes.hex(Driver.Companion.encode_request_payload(vector.request)), vector.hex, vector.name)
  end
end

function tests.mini_app_launch_from_registered_binding()
  local old_last_launch_id = Driver.C4MiniApps.last_launch_id
  local old_last_launch_at_ms = Driver.C4MiniApps.last_launch_at_ms
  Driver.C4MiniApps.last_launch_id = nil
  Driver.C4MiniApps.last_launch_at_ms = nil
  Driver.Companion.sent_messages = {}
  Driver.C4MiniApps.register_binding(3101, {
    name = "Netflix",
    service_id = "com.netflix.Netflix",
  })

  ReceivedFromProxy(3101, "SELECT", {})

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.netflix.Netflix")
  Driver.C4MiniApps.last_launch_id = old_last_launch_id
  Driver.C4MiniApps.last_launch_at_ms = old_last_launch_at_ms
end

function tests.mini_app_launch_debounces_duplicate_switcher_burst()
  local old_c4 = C4
  local old_now_ms = Driver.C4MiniApps.now_ms
  local old_last_launch_id = Driver.C4MiniApps.last_launch_id
  local old_last_launch_at_ms = Driver.C4MiniApps.last_launch_at_ms
  local old_app_list = Driver.Companion.app_list
  local old_app_rows = Driver.Companion.app_list_rows
  Driver.C4MiniApps.last_launch_id = nil
  Driver.C4MiniApps.last_launch_at_ms = nil
  Driver.C4MiniApps.now_ms = function() return 100000 end
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      assert_eq(device_id, 42, "device id")
      assert_eq(binding_id, 5002, "switcher binding")
      return { [9001] = "App Switcher" }
    end,
    GetBoundProviderDevice = function(_, device_id, binding_id)
      if device_id == 9001 and binding_id == 3103 then
        return 9103
      end
      if device_id == 9103 and binding_id == 5001 then
        return 9203
      end
      return nil
    end,
    GetDeviceVariables = function(_, device_id)
      assert_eq(device_id, 9203, "app device id")
      return {
        { name = "APP_NAME", value = "YouTube" },
        { name = "UM_APPLETV", value = "YouTube" },
      }
    end,
  }
  Driver.Companion.app_list = {
    ["com.google.ios.youtube"] = "YouTube",
  }
  Driver.Companion.app_list_rows = {
    { name = "YouTube", identifier = "com.google.ios.youtube" },
  }
  Driver.Companion.sent_messages = {}

  ReceivedFromProxy(5002, "SET_INPUT", { INPUT = "3103" })
  ReceivedFromProxy(5002, "SET_INPUT", { INPUT = "3103" })

  assert_eq(#Driver.Companion.sent_messages, 1, "duplicate SET_INPUT sends one launch")
  assert_eq(Driver.Companion.sent_messages[1]._c._bundleID, "com.google.ios.youtube", "launched YouTube")

  C4 = old_c4
  Driver.C4MiniApps.now_ms = old_now_ms
  Driver.C4MiniApps.last_launch_id = old_last_launch_id
  Driver.C4MiniApps.last_launch_at_ms = old_last_launch_at_ms
  Driver.Companion.app_list = old_app_list
  Driver.Companion.app_list_rows = old_app_rows
end

function tests.mini_app_launch_schedules_startup_retry()
  local old_c4 = C4
  local old_set_timer = SetTimer
  local old_cancel_timer = CancelTimer
  local old_client = Driver.Companion.client
  local old_last_launch_id = Driver.C4MiniApps.last_launch_id
  local old_last_launch_at_ms = Driver.C4MiniApps.last_launch_at_ms
  local old_retry_id = Driver.C4MiniApps.pending_launch_retry_id
  local scheduled
  local cancelled

  C4 = {
    GetTime = function() return 2000 end,
  }
  SetTimer = function(name, delay, callback)
    scheduled = { name = name, delay = delay, callback = callback }
  end
  CancelTimer = function(name)
    cancelled = name
  end
  Driver.Companion.client = {
    state = "SESSION_ACTIVE",
    session_active_since_ms = 1000,
  }
  Driver.C4MiniApps.last_launch_id = nil
  Driver.C4MiniApps.last_launch_at_ms = nil
  Driver.C4MiniApps.pending_launch_retry_id = nil
  Driver.C4MiniApps.register_binding(3101, {
    name = "DirecTV",
    service_id = "DirecTV",
  })
  Driver.Companion.sent_messages = {}

  ReceivedFromProxy(3101, "SELECT", {})

  assert_eq(Driver.Companion.sent_messages[1]._c._bundleID, "com.att.tv", "initial directv launch")
  assert(scheduled ~= nil, "startup retry scheduled")
  assert_eq(scheduled.name, Driver.C4MiniApps.launch_retry_timer, "retry timer name")
  assert_eq(scheduled.delay, Driver.C4MiniApps.launch_retry_delay_ms, "retry timer delay")
  assert_eq(cancelled, Driver.C4MiniApps.launch_retry_timer, "old retry timer cancelled")

  scheduled.callback()

  assert_eq(Driver.Companion.sent_messages[2]._c._bundleID, "com.att.tv", "retry directv launch")

  C4 = old_c4
  SetTimer = old_set_timer
  CancelTimer = old_cancel_timer
  Driver.Companion.client = old_client
  Driver.C4MiniApps.last_launch_id = old_last_launch_id
  Driver.C4MiniApps.last_launch_at_ms = old_last_launch_at_ms
  Driver.C4MiniApps.pending_launch_retry_id = old_retry_id
end

function tests.mini_app_launch_before_session_defers_startup_retry()
  local old_c4 = C4
  local old_set_timer = SetTimer
  local old_cancel_timer = CancelTimer
  local old_client = Driver.Companion.client
  local old_last_launch_id = Driver.C4MiniApps.last_launch_id
  local old_last_launch_at_ms = Driver.C4MiniApps.last_launch_at_ms
  local old_retry_id = Driver.C4MiniApps.pending_launch_retry_id
  local scheduled

  C4 = {
    GetTime = function() return 3000 end,
  }
  SetTimer = function(name, delay, callback)
    scheduled = { name = name, delay = delay, callback = callback }
  end
  CancelTimer = function() end
  Driver.Companion.client = {
    state = "DISCONNECTED",
  }
  Driver.C4MiniApps.last_launch_id = nil
  Driver.C4MiniApps.last_launch_at_ms = nil
  Driver.C4MiniApps.pending_launch_retry_id = nil
  Driver.C4MiniApps.register_binding(3101, {
    name = "DirecTV",
    service_id = "DirecTV",
  })
  Driver.Companion.sent_messages = {}

  ReceivedFromProxy(3101, "SELECT", {})

  assert_eq(Driver.Companion.sent_messages[1]._c._bundleID, "com.att.tv", "initial directv launch requested")
  assert_eq(scheduled, nil, "retry waits for startup window")
  assert_eq(Driver.C4MiniApps.pending_launch_retry_id, "com.att.tv", "retry id retained")

  Driver.Companion.client.session_active_since_ms = 2500

  Driver.C4MiniApps.schedule_pending_launch_retry()

  assert(scheduled ~= nil, "retry scheduled once session is active")
  assert_eq(scheduled.name, Driver.C4MiniApps.launch_retry_timer, "retry timer name")

  scheduled.callback()

  assert_eq(Driver.Companion.sent_messages[2]._c._bundleID, "com.att.tv", "deferred retry directv launch")

  C4 = old_c4
  SetTimer = old_set_timer
  CancelTimer = old_cancel_timer
  Driver.Companion.client = old_client
  Driver.C4MiniApps.last_launch_id = old_last_launch_id
  Driver.C4MiniApps.last_launch_at_ms = old_last_launch_at_ms
  Driver.C4MiniApps.pending_launch_retry_id = old_retry_id
end

function tests.mini_apps_and_companion_client_use_c4_wall_clock()
  local old_c4 = C4
  C4 = {
    GetTime = function()
      return 123456
    end,
  }

  local client = Driver.CompanionClient.new({})
  assert_eq(client:now_ms(), 123456, "Companion client wall clock")
  assert_eq(Driver.C4MiniApps.now_ms(), 123456, "mini app wall clock")

  C4 = old_c4
end

function tests.mini_app_ignores_composer_routing_chatter()
  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5002, "BINDING_CHANGE_ACTION", { BINDING_ID = "3103", IS_BOUND = "True" })
  ReceivedFromProxy(5002, "CONNECT_OUTPUT", { OUTPUT = "2110", AUDIO = "True", VIDEO = "False" })
  assert_eq(#Driver.Companion.sent_messages, 0, "routing chatter does not send Companion commands")
end

function tests.mini_app_launch_resolves_friendly_name_from_dynamic_app_list()
  local old_app_list = Driver.Companion.app_list
  local old_app_rows = Driver.Companion.app_list_rows
  Driver.Companion.sent_messages = {}
  Driver.Companion.app_list = {
    ["com.wbd.stream"] = "HBO Max",
  }
  Driver.Companion.app_list_rows = {
    { name = "HBO Max", identifier = "com.wbd.stream" },
  }
  Driver.C4MiniApps.register_binding(3101, {
    name = "Max",
    service_id = "Max",
  })

  ReceivedFromProxy(3101, "SELECT", {})

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.wbd.stream")
  Driver.Companion.app_list = old_app_list
  Driver.Companion.app_list_rows = old_app_rows
end

function tests.mini_app_launch_resolves_predefined_alias()
  local old_app_list = Driver.Companion.app_list
  local old_app_rows = Driver.Companion.app_list_rows
  Driver.Companion.sent_messages = {}
  Driver.Companion.app_list = {}
  Driver.Companion.app_list_rows = {}
  Driver.C4MiniApps.register_binding(3101, {
    name = "Peacock TV",
    service_id = "Peacock TV",
  })

  ReceivedFromProxy(3101, "SELECT", {})

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.peacocktv.peacock")
  Driver.Companion.app_list = old_app_list
  Driver.Companion.app_list_rows = old_app_rows
end

function tests.mini_app_launch_from_switcher_set_input()
  local old_c4 = C4
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      assert_eq(device_id, 42, "device id")
      assert_eq(binding_id, 5002, "switcher binding")
      return { [9001] = "App Switcher" }
    end,
    GetBoundProviderDevice = function(_, device_id, binding_id)
      if device_id == 9001 and binding_id == 3102 then
        return 9102
      end
      if device_id == 9102 and binding_id == 5001 then
        return 9202
      end
      return nil
    end,
    GetDeviceVariables = function(_, device_id)
      assert_eq(device_id, 9202, "app device id")
      return {
        { name = "APP_NAME", value = "Netflix" },
        { name = "UM_APPLETV", value = "com.netflix.Netflix" },
      }
    end,
  }

  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5002, "SET_INPUT", { INPUT = "3102" })

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.netflix.Netflix")
  C4 = old_c4
end

function tests.native_apple_tv_driver_list_populates_dropdown()
  local old_c4 = C4
  local property_lists = {}
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetDevices = function(_, _)
      return {
        [42] = { name = "Custom Apple TV", driverFileName = "control4_apple_tv.c4z" },
        [1106] = { name = "Apple TV Office", driverFileName = "/system/drivers/appleTV.c4z" },
        [1107] = { name = "Apple TV Clone", driverFileName = "apple_tv.c4z" },
        [1099] = { name = "Apple TV App Switcher", driverFileName = "control4_apple_tv.c4z" },
        [1109] = { name = "Apple TV Office", driverFileName = "" },
        [1200] = { name = "Roku", driverFileName = "roku.c4z" },
      }
    end,
    UpdatePropertyList = function(_, name, items)
      property_lists[name] = items
    end,
  }

  local items = Driver.C4MiniApps.refresh_native_apple_tv_drivers()

  assert_eq(items[1], "Not Selected", "first native driver item")
  assert_contains(items, "Apple TV Office [1106]", "native Apple TV candidate")
  assert(not property_lists["Native Apple TV Driver"]:match("%[42%]"), "own driver excluded from native list")
  assert(not property_lists["Native Apple TV Driver"]:match("%[1107%]"), "non-exact Apple TV filename excluded")
  assert(not property_lists["Native Apple TV Driver"]:match("%[1099%]"), "custom app switcher excluded")
  assert(not property_lists["Native Apple TV Driver"]:match("%[1109%]"), "Apple TV name without driver filename excluded")
  assert(not property_lists["Native Apple TV Driver"]:match("Roku"), "non Apple TV driver excluded")
  C4 = old_c4
end

function tests.native_apple_tv_driver_refresh_resets_stale_selection()
  local old_c4 = C4
  local old_properties = Properties
  Properties = {
    ["Native Apple TV Driver"] = "Apple TV [1095]",
  }
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetDevices = function(_, _)
      return {
        [1106] = { name = "Apple TV Office", driverFileName = "appleTV.c4z" },
      }
    end,
    UpdatePropertyList = function(_, _, _) end,
  }

  Driver.C4MiniApps.refresh_native_apple_tv_drivers()

  assert_eq(Properties["Native Apple TV Driver"], "Not Selected", "stale native driver selection reset")
  C4 = old_c4
  Properties = old_properties
end

function tests.native_apple_tv_driver_selection_parses_device_id()
  assert_eq(Driver.C4MiniApps.parse_native_driver_selection("Apple TV Office [1106]"), 1106, "bracketed native id")
  assert_eq(Driver.C4MiniApps.parse_native_driver_selection("1106"), 1106, "raw native id")
  assert_eq(Driver.C4MiniApps.parse_native_driver_selection("Not Selected"), nil, "not selected native id")
end

function tests.native_handoff_selects_native_driver_after_mini_app_launch()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local selections = {}
  Properties = {
    ["After Mini App Launch"] = "Select Native Apple TV Driver",
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9102,
    [261] = 1234,
  }
  C4 = {
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      assert_eq(device_id, 1106, "native driver id")
      assert_eq(binding_id, 5001, "native media proxy binding")
      return { [1110] = "Apple TV Office Proxy" }
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = {
        room_id = room_id,
        command = command,
        deviceid = params.deviceid,
        DEVICE_ID = params.DEVICE_ID,
      }
    end,
  }
  SetTimer = nil

  Driver.C4MiniApps.after_launch_selection(9102)

  assert_eq(#selections, 1, "native handoff selection count")
  assert_eq(selections[1].room_id, 260, "native handoff room")
  assert_eq(selections[1].command, "SELECT_VIDEO_DEVICE", "native handoff command")
  assert_eq(selections[1].deviceid, 1106, "native handoff selects native driver")
  assert_eq(selections[1].DEVICE_ID, 1106, "native handoff uppercase native driver")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
end

function tests.native_handoff_returns_false_when_no_room_matches_app_proxy()
  local old_c4 = C4
  local old_properties = Properties
  local old_room_sources = Driver.C4MiniApps.room_sources
  local selections = {}
  Properties = {
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 1234,
  }
  C4 = {
    GetBoundConsumerDevices = function(_, _, binding_id)
      if binding_id == 5001 then
        return { [1110] = "Apple TV Office Proxy" }
      end
      return {}
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = { room_id = room_id, command = command, params = params }
    end,
  }

  local selected = Driver.C4MiniApps.select_native_apple_tv_after_launch(9102)

  assert_eq(selected, false, "native handoff not scheduled without selected room")
  assert_eq(#selections, 0, "native handoff sends no selection without matched room")
  C4 = old_c4
  Properties = old_properties
  Driver.C4MiniApps.room_sources = old_room_sources
end

function tests.native_handoff_uses_room_scoped_timers()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local old_timers = Driver.C4MiniApps.active_handoff_timers
  local timers = {}
  Properties = {
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9102,
    [261] = 9102,
  }
  Driver.C4MiniApps.active_handoff_timers = {}
  C4 = {
    GetBoundConsumerDevices = function(_, _, binding_id)
      if binding_id == 5001 then
        return { [1110] = "Apple TV Office Proxy" }
      end
      return {}
    end,
    SendToDevice = function() end,
  }
  SetTimer = function(timer_name, _, _)
    timers[#timers + 1] = timer_name
  end

  local selected = Driver.C4MiniApps.select_native_apple_tv_after_launch(9102)

  assert_eq(selected, true, "native handoff scheduled")
  assert_contains(timers, "AppleTV_native_driver_handoff_260", "room 260 handoff timer")
  assert_contains(timers, "AppleTV_native_driver_handoff_261", "room 261 handoff timer")
  assert(Driver.C4MiniApps.active_handoff_timers["AppleTV_native_driver_handoff_260"], "room 260 timer tracked")
  assert(Driver.C4MiniApps.active_handoff_timers["AppleTV_native_driver_handoff_261"], "room 261 timer tracked")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
  Driver.C4MiniApps.active_handoff_timers = old_timers
end

function tests.native_handoff_allows_passthrough_intermediate_selection()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local old_timers = Driver.C4MiniApps.active_handoff_timers
  local scheduled
  local selections = {}
  Properties = {
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9102,
  }
  Driver.C4MiniApps.active_handoff_timers = {}
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      if device_id == 42 and binding_id == 5001 then
        return { [50010] = "Custom Apple TV Proxy" }
      end
      if device_id == 1106 and binding_id == 5001 then
        return { [1110] = "Apple TV Office Proxy" }
      end
      return {}
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = {
        room_id = room_id,
        command = command,
        deviceid = params.deviceid,
        DEVICE_ID = params.DEVICE_ID,
      }
    end,
  }
  SetTimer = function(timer_name, _, callback)
    scheduled = { name = timer_name, callback = callback }
  end

  local selected = Driver.C4MiniApps.select_native_apple_tv_after_launch(9102)
  Driver.C4MiniApps.room_sources[260] = 50010
  scheduled.callback()

  assert_eq(selected, true, "native handoff scheduled")
  assert_eq(scheduled.name, "AppleTV_native_driver_handoff_260", "native handoff timer")
  assert_eq(#selections, 1, "native handoff selection count")
  assert_eq(selections[1].deviceid, 1106, "native handoff target")
  assert_eq(selections[1].DEVICE_ID, 1106, "native handoff uppercase target")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
  Driver.C4MiniApps.active_handoff_timers = old_timers
end

function tests.native_handoff_falls_back_to_proxy_when_driver_id_does_not_select()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local old_timers = Driver.C4MiniApps.active_handoff_timers
  local timers = {}
  local selections = {}
  local current_selected = 9102
  Properties = {
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9102,
  }
  Driver.C4MiniApps.active_handoff_timers = {}
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      if device_id == 42 and binding_id == 5001 then
        return { [50010] = "Custom Apple TV Proxy" }
      end
      if device_id == 1106 and binding_id == 5001 then
        return { [1110] = "Apple TV Office Proxy" }
      end
      return {}
    end,
    GetDeviceVariable = function(_, room_id, variable_id)
      assert_eq(room_id, 260, "room id")
      assert_eq(variable_id, 1000, "selected device variable")
      return current_selected
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = {
        room_id = room_id,
        command = command,
        deviceid = params.deviceid,
        DEVICE_ID = params.DEVICE_ID,
      }
      if params.deviceid == 1110 then
        current_selected = 1110
      end
    end,
  }
  SetTimer = function(timer_name, _, callback)
    timers[timer_name] = callback
  end

  local selected = Driver.C4MiniApps.select_native_apple_tv_after_launch(9102)
  timers["AppleTV_native_driver_handoff_260"]()
  current_selected = 50010
  timers["AppleTV_verify_native_handoff_260"]()

  assert_eq(selected, true, "native handoff scheduled")
  assert_eq(#selections, 2, "native handoff plus proxy fallback")
  assert_eq(selections[1].deviceid, 1106, "first tries native driver")
  assert_eq(selections[2].deviceid, 1110, "fallback selects native proxy")
  assert_eq(selections[2].DEVICE_ID, 1110, "fallback uppercase native proxy")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
  Driver.C4MiniApps.active_handoff_timers = old_timers
end

function tests.direct_mini_app_binding_hands_off_to_native_driver()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local old_last_launch_id = Driver.C4MiniApps.last_launch_id
  local old_last_launch_at_ms = Driver.C4MiniApps.last_launch_at_ms
  local selections = {}
  Properties = {
    ["After Mini App Launch"] = "Select Native Apple TV Driver",
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9101,
  }
  Driver.C4MiniApps.last_launch_id = nil
  Driver.C4MiniApps.last_launch_at_ms = nil
  Driver.Companion.sent_messages = {}
  Driver.C4MiniApps.register_binding(3101, {
    name = "Netflix",
    service_id = "com.netflix.Netflix",
  })
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      if device_id == 42 and binding_id == 5002 then
        return { [9001] = "App Switcher" }
      end
      if device_id == 1106 and binding_id == 5001 then
        return { [1110] = "Apple TV Office Proxy" }
      end
      return {}
    end,
    GetBoundProviderDevice = function(_, device_id, binding_id)
      if device_id == 9001 and binding_id == 3101 then
        return 9101
      end
      if device_id == 9101 and binding_id == 5001 then
        return 9201
      end
      return nil
    end,
    GetDeviceVariables = function(_, _)
      return {}
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = {
        room_id = room_id,
        command = command,
        deviceid = params.deviceid,
        DEVICE_ID = params.DEVICE_ID,
      }
    end,
  }
  SetTimer = nil

  ReceivedFromProxy(3101, "SELECT", {})

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.netflix.Netflix")
  assert_eq(#selections, 1, "direct binding native handoff selection count")
  assert_eq(selections[1].deviceid, 1106, "direct binding native handoff target")
  assert_eq(selections[1].DEVICE_ID, 1106, "direct binding native handoff uppercase target")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
  Driver.C4MiniApps.last_launch_id = old_last_launch_id
  Driver.C4MiniApps.last_launch_at_ms = old_last_launch_at_ms
  Driver.C4MiniApps.bindings[3101] = nil
end

function tests.after_mini_app_launch_native_selects_native_driver()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local selections = {}
  Properties = {
    ["After Mini App Launch"] = "Select Native Apple TV Driver",
    ["Native Apple TV Driver"] = "Apple TV Office [1106]",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9102,
  }
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, _, binding_id)
      if binding_id == 5001 then
        return { [1110] = "Apple TV Office Proxy" }
      end
      return {}
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = {
        room_id = room_id,
        command = command,
        deviceid = params.deviceid,
        DEVICE_ID = params.DEVICE_ID,
      }
    end,
  }
  SetTimer = nil

  Driver.C4MiniApps.after_launch_selection(9102)

  assert_eq(#selections, 1, "native handoff selection count")
  assert_eq(selections[1].deviceid, 1106, "native handoff target")
  assert_eq(selections[1].DEVICE_ID, 1106, "native handoff uppercase target")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
end

function tests.after_mini_app_launch_return_selects_this_driver_proxy()
  local old_c4 = C4
  local old_properties = Properties
  local old_set_timer = SetTimer
  local old_room_sources = Driver.C4MiniApps.room_sources
  local selections = {}
  Properties = {
    ["After Mini App Launch"] = "Return To This Driver",
  }
  Driver.C4MiniApps.room_sources = {
    [260] = 9102,
  }
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, _, binding_id)
      if binding_id == 5001 then
        return { [50010] = "Main Apple TV Proxy" }
      end
      return {}
    end,
    SendToDevice = function(_, room_id, command, params)
      selections[#selections + 1] = {
        room_id = room_id,
        command = command,
        deviceid = params.deviceid,
        DEVICE_ID = params.DEVICE_ID,
      }
    end,
  }
  SetTimer = nil

  Driver.C4MiniApps.after_launch_selection(9102)

  assert_eq(#selections, 1, "return to this driver selection count")
  assert_eq(selections[1].deviceid, 50010, "return to main proxy target")
  assert_eq(selections[1].DEVICE_ID, 50010, "return to main proxy uppercase target")
  C4 = old_c4
  Properties = old_properties
  SetTimer = old_set_timer
  Driver.C4MiniApps.room_sources = old_room_sources
end

function tests.mini_app_switcher_resolves_app_id_that_is_friendly_name()
  local old_c4 = C4
  local old_app_list = Driver.Companion.app_list
  local old_app_rows = Driver.Companion.app_list_rows
  C4 = {
    GetDeviceID = function()
      return 42
    end,
    GetBoundConsumerDevices = function(_, device_id, binding_id)
      assert_eq(device_id, 42, "device id")
      assert_eq(binding_id, 5002, "switcher binding")
      return { [9001] = "App Switcher" }
    end,
    GetBoundProviderDevice = function(_, device_id, binding_id)
      if device_id == 9001 and binding_id == 3102 then
        return 9102
      end
      if device_id == 9102 and binding_id == 5001 then
        return 9202
      end
      return nil
    end,
    GetDeviceVariables = function(_, device_id)
      assert_eq(device_id, 9202, "app device id")
      return {
        { name = "APP_NAME", value = "HBO Max" },
        { name = "UM_APPLETV", value = "Max" },
      }
    end,
  }
  Driver.Companion.app_list = {
    ["com.wbd.stream"] = "HBO Max",
  }
  Driver.Companion.app_list_rows = {
    { name = "HBO Max", identifier = "com.wbd.stream" },
  }
  Driver.Companion.sent_messages = {}

  ReceivedFromProxy(5002, "SET_INPUT", { INPUT = "3102" })

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.wbd.stream")
  C4 = old_c4
  Driver.Companion.app_list = old_app_list
  Driver.Companion.app_list_rows = old_app_rows
end

function tests.opack_int64_encoding()
  -- low32=1, high32=2 → little-endian bytes: 01 00 00 00 02 00 00 00
  local val = Driver.OPACK.int64(2, 1)
  local encoded = Driver.OPACK.encode(val)
  assert_eq(encoded:byte(1), 0x33, "int64 tag")
  assert_eq(encoded:byte(2), 0x01, "low byte 0")
  assert_eq(encoded:byte(3), 0x00, "low byte 1")
  assert_eq(encoded:byte(4), 0x00, "low byte 2")
  assert_eq(encoded:byte(5), 0x00, "low byte 3")
  assert_eq(encoded:byte(6), 0x02, "high byte 0")
  assert_eq(encoded:byte(7), 0x00, "high byte 1")
  assert_eq(encoded:byte(8), 0x00, "high byte 2")
  assert_eq(encoded:byte(9), 0x00, "high byte 3")
  assert_eq(#encoded, 9, "int64 encoded length")
end

function tests.session_start_response_advances_to_session_active()
  local public_key = bytes_range(0, 31)
  local server_public_key = bytes_range(32, 63)
  local encrypted_challenge = "challenge"
  local encrypted_response = "response"
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(64, 95)),
    Driver.Bytes.hex(bytes_range(96, 127)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local writes = {}
  local states = {}
  local fake_crypto = {
    generate_x25519_keypair = function()
      return { private_key = "private-key", public_key = public_key }
    end,
    pair_verify_response = function() return encrypted_response, "shared-secret" end,
    hkdf_sha512 = function(_, info)
      if info == "ClientEncrypt-main" then return "output-key" end
      if info == "ServerEncrypt-main" then return "input-key" end
      error("unexpected hkdf info")
    end,
    encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
    decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    random_bytes = function(n)
      assert_eq(n, 4, "session sid random length")
      return "\x78\x56\x34\x12"
    end,
  }
  local client = Driver.CompanionClient.new({
    credentials = credentials,
    crypto = fake_crypto,
    transport = { Write = function(_, data) writes[#writes + 1] = data end },
    on_state = function(s) states[#states + 1] = s end,
  })

  client:connect("127.0.0.1", 49153)
  local response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({
      { 3, server_public_key },
      { 5, encrypted_challenge },
    })) },
  }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, response_payload))
  assert_eq(states[3], "PAIR_VERIFY_M3_SENT", "pair verify m3 after m2")

  local ack_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({ { 6, string.char(0x04) } })) },
  }))
	  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, ack_payload))
	  local system_info_frame = client.session:try_decode(writes[3])
	  local system_info = Driver.OPACK.decode(system_info_frame.payload)
	  assert_table_has(system_info, "_i", "_systemInfo")
	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", system_info._x },
	  }))))
	  local touch_start_frame = client.session:try_decode(writes[4])
	  local touch_start = Driver.OPACK.decode(touch_start_frame.payload)
	  assert_table_has(touch_start, "_i", "_touchStart")
	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", touch_start._x },
	  }))))
	  assert_eq(states[5], "SESSION_STARTING", "session starting after sequential startup responses")
	
	  -- Simulate _sessionStart response from Apple TV (_t=3 is Response)
	  local remote_sid = 0xABCD1234
  local session_response = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_t", 3 },
    { "_c", Driver.OPACK.dict({ { "_sid", remote_sid } }) },
    { "_x", client.session_start_xid },
  }))
  local response_frame = client.session:encode_frame(Driver.CompanionFrame.E_OPACK, session_response)
	  client:receive(response_frame)
	
	  assert_eq(states[6], "SESSION_ACTIVE", "session active after _sessionStart response")
	  assert_eq(client.session_remote_sid, remote_sid, "remote sid stored")
	
	  local tv_rc_frame = client.session:try_decode(writes[#writes])
	  local tv_rc_start = Driver.OPACK.decode(tv_rc_frame.payload)
	  assert_table_has(tv_rc_start, "_i", "TVRCSessionStart")
	  assert_table_has(tv_rc_start._c, "ProtocolVersionKey", "1.2")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", tv_rc_start._x },
	  }))))

	  local ti_start_frame = client.session:try_decode(writes[#writes])
	  local ti_start = Driver.OPACK.decode(ti_start_frame.payload)
	  assert_table_has(ti_start, "_i", "_tiStart")

	  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, Driver.OPACK.encode(Driver.OPACK.dict({
	    { "_t", 3 },
	    { "_c", Driver.OPACK.dict({}) },
	    { "_x", ti_start._x },
	  }))))
	
	  local interest_frame = client.session:try_decode(writes[#writes])
	  local interest = Driver.OPACK.decode(interest_frame.payload)
  assert_table_has(interest, "_i", "_interest")
  assert_eq(interest._t, 1, "interest is event message")
end

function tests.reentrant_session_start_response_cannot_regress_active_state()
  local client
  local transport = {
    Write = function(_, frame)
      local decoded = Driver.CompanionFrame.try_decode(frame)
      local request = Driver.OPACK.decode(decoded.payload)
      local pending = client.pending_responses[request._x]
      assert(pending and pending.on_response, "session response registered before write")
      client.pending_responses[request._x] = nil
      pending.on_response({ _x = request._x, _c = { _sid = 12345 } })
    end,
  }
  client = Driver.CompanionClient.new({
    transport = transport,
    crypto = { random_bytes = function() return "\x01\x02\x03\x04" end },
  })
  client.state = "READY"
  client:start_session()
  assert_eq(client.state, "SESSION_ACTIVE", "reentrant response leaves session active")
  assert_eq(client.session_start_xid, nil, "completed session has no pending xid")
  assert_eq(client.session_remote_sid, 12345, "reentrant response stores remote sid")
end

function tests.session_stop_sent_on_close()
  local public_key = bytes_range(0, 31)
  local server_public_key = bytes_range(32, 63)
  local encrypted_challenge = "challenge"
  local encrypted_response = "response"
  local credentials = Driver.Credentials.parse(table.concat({
    Driver.Bytes.hex(bytes_range(64, 95)),
    Driver.Bytes.hex(bytes_range(96, 127)),
    Driver.Bytes.hex("ATV-ID"),
    Driver.Bytes.hex("CLIENT-ID"),
  }, ":"))
  local writes = {}
  local closed = false
  local fake_crypto = {
    generate_x25519_keypair = function()
      return { private_key = "private-key", public_key = public_key }
    end,
    pair_verify_response = function() return encrypted_response, "shared-secret" end,
    hkdf_sha512 = function(_, info)
      if info == "ClientEncrypt-main" then return "output-key" end
      if info == "ServerEncrypt-main" then return "input-key" end
      error("unexpected hkdf info")
    end,
    encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
    decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    random_bytes = function(n)
      assert_eq(n, 4, "session sid random length")
      return "\x78\x56\x34\x12"
    end,
  }
  local client = Driver.CompanionClient.new({
    credentials = credentials,
    crypto = fake_crypto,
    transport = {
      Write = function(_, data) writes[#writes + 1] = data end,
      close = function() closed = true end,
    },
  })

  client:connect("127.0.0.1", 49153)
  local response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({
      { 3, server_public_key },
      { 5, encrypted_challenge },
    })) },
  }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, response_payload))

  local ack_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({ { 6, string.char(0x04) } })) },
  }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, ack_payload))

	  -- Set remote_sid so _sessionStop is triggered on close
	  client.session_remote_sid = 0xDEADBEEF
	  client.session_local_sid = client.session_local_sid or 0x12345678

  local local_sid = client.session_local_sid
  local cleanup_session = client.session
	  local writes_before_close = #writes
	  client:close()
	  assert(#writes > writes_before_close, "_sessionStop was written before close")
  assert_eq(client.session, nil, "session cleared after close")
  assert_eq(next(client.pending_responses), nil, "pending responses cleared after close")
  assert_eq(#client.pending_commands, 0, "pending commands cleared after close")
	  local stop_msg, stop_frame
	  local saw_interest, saw_touch_stop, saw_ti_stop = false, false, false
	  for i = writes_before_close + 1, #writes do
	    local decoded = cleanup_session:try_decode(writes[i])
	    local msg = Driver.OPACK.decode(decoded.payload)
	    if msg._i == "_interest" then saw_interest = true end
	    if msg._i == "_touchStop" then saw_touch_stop = true end
	    if msg._i == "_tiStop" then saw_ti_stop = true end
	    if msg._i == "_sessionStop" then
	      stop_msg = msg
	      stop_frame = decoded
	    end
	  end
	  assert(saw_interest, "_interest deregistration was written before close")
	  assert(saw_touch_stop, "_touchStop was written before close")
	  assert(saw_ti_stop, "_tiStop was written before close")
	  assert(stop_msg, "_sessionStop was written before close")
	  -- Verify the _sid was encoded as a 64-bit int (0x33 tag) by checking the raw payload bytes.
  -- OPACK.decode returns a number for 0x33, not the int64 table; check encoded bytes directly.
  local payload = stop_frame.payload
  assert(payload:find("\x33", 1, true) ~= nil, "_sessionStop payload contains 0x33 int64 tag")
  -- The 8 bytes after 0x33 are low32 LE then high32 LE.
  -- Verify local_sid low byte appears (full byte-level check would require known local_sid).
  local sid_pos = payload:find("\x33", 1, true)
  local low0  = payload:byte(sid_pos + 1)
  local low1  = payload:byte(sid_pos + 2)
  local low2  = payload:byte(sid_pos + 3)
  local low3  = payload:byte(sid_pos + 4)
  local reconstructed_low32 = low0 + low1 * 0x100 + low2 * 0x10000 + low3 * 0x1000000
  assert_eq(reconstructed_low32, local_sid, "_sessionStop sid low32 bytes match local_sid")
  local high0 = payload:byte(sid_pos + 5)
  local high1 = payload:byte(sid_pos + 6)
  local high2 = payload:byte(sid_pos + 7)
  local high3 = payload:byte(sid_pos + 8)
  local reconstructed_high32 = high0 + high1 * 0x100 + high2 * 0x10000 + high3 * 0x1000000
  assert_eq(reconstructed_high32, 0xDEADBEEF, "_sessionStop sid high32 bytes match remote_sid")
  assert_eq(closed, true, "transport closed")
end

function tests.remote_passthrough()
  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5001, "UP", {})

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_hidC")
  assert_table_has(last._c, "_hidC", 1)
  assert_table_has(last._c, "_hBtS", 2)
end

function tests.remote_passthrough_supports_doubletap_and_hold_actions()
  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5001, "SELECT", { ACTION = "doubletap" })
  assert_eq(#Driver.Companion.sent_messages, 4, "doubletap sends four HID frames")
  assert_eq(Driver.Companion.sent_messages[1]._c._hBtS, 1, "doubletap press 1")
  assert_eq(Driver.Companion.sent_messages[2]._c._hBtS, 2, "doubletap release 1")
  assert_eq(Driver.Companion.sent_messages[3]._c._hBtS, 1, "doubletap press 2")
  assert_eq(Driver.Companion.sent_messages[4]._c._hBtS, 2, "doubletap release 2")

  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5001, "START_UP", {})
  ReceivedFromProxy(5001, "STOP_UP", {})
  assert_eq(#Driver.Companion.sent_messages, 2, "start/stop sends press and release")
  assert_eq(Driver.Companion.sent_messages[1]._c._hBtS, 1, "start press")
  assert_eq(Driver.Companion.sent_messages[2]._c._hBtS, 2, "stop release")
end

function tests.remote_passthrough_uses_configurable_button_mapping()
  local old_properties = Properties
  Properties = {
    ["CANCEL Button"] = "Menu",
    ["INFO Button"] = "Home",
  }

  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5002, "PASSTHROUGH", {
    PASSTHROUGH_COMMAND = "CANCEL",
    BEGIN = "1",
  })
  ReceivedFromProxy(5002, "PASSTHROUGH", {
    PASSTHROUGH_COMMAND = "END_CANCEL",
    DURATION = "11",
  })
  assert_eq(#Driver.Companion.sent_messages, 2, "cancel maps to menu press/release")
  assert_eq(Driver.Companion.sent_messages[1]._c._hidC, 5, "cancel menu hid")
  assert_eq(Driver.Companion.sent_messages[1]._c._hBtS, 1, "cancel menu press")
  assert_eq(Driver.Companion.sent_messages[2]._c._hBtS, 2, "cancel menu release")

  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5001, "INFO", {})
  assert_eq(Driver.Companion.sent_messages[1]._c._hidC, 7, "info home hid")

  Properties = old_properties
end

function tests.remote_passthrough_uses_power_off_mapping()
  local old_properties = Properties
  local old_monitor_enabled = Driver.AirPlay.monitor_enabled
  local old_client = Driver.AirPlay.control_client
  local old_state = Driver.AirPlay.monitor_state
  local old_last_power_off_hid = Driver.C4MiniApps.last_power_off_hid
  local old_last_power_off_at_ms = Driver.C4MiniApps.last_power_off_at_ms

  local function assert_power_off_mapping(value, expected_hid, label)
    Properties = { ["On Power Off"] = value }
    Driver.Companion.sent_messages = {}
    Driver.AirPlay.monitor_enabled = true
    Driver.AirPlay.control_client = nil
    Driver.C4MiniApps.last_power_off_hid = nil
    Driver.C4MiniApps.last_power_off_at_ms = nil

    ReceivedFromProxy(5001, "OFF", {})

    if expected_hid then
      assert_eq(#Driver.Companion.sent_messages, 2, label .. " sends a tap")
      assert_eq(Driver.Companion.sent_messages[1]._c._hidC, expected_hid, label .. " hid")
    else
      assert_eq(#Driver.Companion.sent_messages, 0, label .. " sends no hid")
    end
    assert_eq(Driver.AirPlay.monitor_enabled, false, label .. " stops monitor")
    assert_eq(Driver.AirPlay.monitor_state, "STOPPED", label .. " monitor stopped state")
  end

  assert_power_off_mapping("Do Nothing", nil, "power off do nothing")
  assert_power_off_mapping("Home", 7, "power off home")
  assert_power_off_mapping("Back", 5, "power off back")
  assert_power_off_mapping("Menu", 5, "power off menu")

  Properties = old_properties
  Driver.AirPlay.monitor_enabled = old_monitor_enabled
  Driver.AirPlay.control_client = old_client
  Driver.AirPlay.monitor_state = old_state
  Driver.C4MiniApps.last_power_off_hid = old_last_power_off_hid
  Driver.C4MiniApps.last_power_off_at_ms = old_last_power_off_at_ms
end

function tests.remote_passthrough_debounces_duplicate_power_off_from_proxies()
  local old_properties = Properties
  local old_now_ms = Driver.C4MiniApps.now_ms
  local old_last_power_off_hid = Driver.C4MiniApps.last_power_off_hid
  local old_last_power_off_at_ms = Driver.C4MiniApps.last_power_off_at_ms

  Properties = { ["On Power Off"] = "Home" }
  Driver.C4MiniApps.now_ms = function() return 123000 end
  Driver.C4MiniApps.last_power_off_hid = nil
  Driver.C4MiniApps.last_power_off_at_ms = nil
  Driver.Companion.sent_messages = {}

  ReceivedFromProxy(5001, "OFF", {})
  ReceivedFromProxy(5002, "OFF", {})

  assert_eq(#Driver.Companion.sent_messages, 2, "duplicate proxy off sends one tap")
  assert_eq(Driver.Companion.sent_messages[1]._c._hidC, 7, "home press hid")
  assert_eq(Driver.Companion.sent_messages[2]._c._hidC, 7, "home release hid")

  Properties = old_properties
  Driver.C4MiniApps.now_ms = old_now_ms
  Driver.C4MiniApps.last_power_off_hid = old_last_power_off_hid
  Driver.C4MiniApps.last_power_off_at_ms = old_last_power_off_at_ms
end

function tests.remote_passthrough_uses_color_button_mappings()
  local old_properties = Properties
  local cases = {
    { command = "RED", property = "Red Button", value = "TV/Home", hid = 7 },
    { command = "GREEN", property = "Green Button", value = "Menu", hid = 5 },
    { command = "YELLOW", property = "Yellow Button", value = "Play/Pause", hid = 14 },
    { command = "BLUE", property = "Blue Button", value = "Select", hid = 6 },
    { command = "RED", property = "Red Button", value = "Up", hid = 1 },
    { command = "GREEN", property = "Green Button", value = "Down", hid = 2 },
    { command = "YELLOW", property = "Yellow Button", value = "Left", hid = 3 },
    { command = "BLUE", property = "Blue Button", value = "Right", hid = 4 },
  }

  for _, case in ipairs(cases) do
    Properties = { [case.property] = case.value }
    Driver.Companion.sent_messages = {}
    ReceivedFromProxy(5001, case.command, {})
    assert_eq(#Driver.Companion.sent_messages, 2, case.property .. " " .. case.value .. " sends a tap")
    assert_eq(Driver.Companion.sent_messages[1]._c._hidC, case.hid, case.property .. " " .. case.value .. " hid")
  end

  Properties = {}
  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5001, "RED", {})
  assert_eq(#Driver.Companion.sent_messages, 0, "red defaults to do nothing")

  Properties = { ["Blue Button"] = "Right" }
  Driver.Companion.sent_messages = {}
  ReceivedFromProxy(5002, "PASSTHROUGH", {
    PASSTHROUGH_COMMAND = "BLUE",
  })
  assert_eq(#Driver.Companion.sent_messages, 2, "blue passthrough sends a tap")
  assert_eq(Driver.Companion.sent_messages[1]._c._hidC, 4, "blue passthrough right hid")

  Properties = old_properties
end

function tests.app_list_current_app_and_now_playing_are_published()
  local old_c4 = C4
  local old_properties = Properties
  C4 = nil
  Properties = {}
  Driver._test_storage = {}
  Driver.Companion.app_list = {}
  Driver.Companion.app_list_rows = {}

  Driver.C4Driver.handle_companion_message({
    _i = "FetchLaunchableApplicationsEvent",
    _t = 3,
    _c = {
      ["com.netflix.Netflix"] = "Netflix",
      ["com.apple.TVWatchList"] = "Apple TV",
    },
  })
  assert_eq(Driver.Companion.app_list["com.netflix.Netflix"], "Netflix", "stored app list bundle")
  assert_eq(Driver._test_storage.app_list["com.netflix.Netflix"], "Netflix", "persisted app list")

  Driver.C4Driver.launch_app("com.netflix.Netflix")
  assert_eq(Properties["Current App"], "Netflix | com.netflix.Netflix", "current app uses app list name")

  Driver.C4Driver.handle_companion_message({
    _i = "NowPlaying",
    _t = 1,
    _c = {
      title = "Episode One",
      artist = "A Show",
      album = "Season 1",
    },
  })
  assert_eq(Properties["Now Playing"], "Episode One - A Show - Season 1", "now playing property")

  Driver.C4Driver.handle_companion_message({
    _i = "_iMC",
    _t = 1,
    _c = {
      name = "Office",
    },
  })
  assert_eq(Properties["Now Playing"], "Episode One - A Show - Season 1", "generic Companion name does not replace now playing")

  Driver.C4Driver.handle_airplay_mrp_update({
    app_bundle = "com.apple.TVWatchList",
    app_name = "Apple TV",
  })
  assert_eq(Properties["Current App"], "Apple TV | com.apple.TVWatchList", "MRP app-only update changes current app")
  assert_eq(Properties["Now Playing"], "", "MRP app-only update clears stale now playing")

  local client = Driver.PB.field_string(2, "com.att.tv") .. Driver.PB.field_string(7, "DIRECTV")
  local path = Driver.PB.field_message(2, client)
  local now_playing = Driver.PB.field_string(2, "Channel 12") .. Driver.PB.field_string(9, "Live TV")
  local state = Driver.PB.field_message(1, now_playing) ..
    Driver.PB.field_varint(6, 2) ..
    Driver.PB.field_message(9, path)
  local message = Driver.PB.field_varint(1, 4) ..
    Driver.PB.field_string(2, "state-id") ..
    Driver.PB.field_varint(4, 0) ..
    Driver.PB.field_message(9, state)
  Driver.C4Driver.handle_airplay_mrp_update(Driver.PB.extract_protocol_update(message))
  assert_eq(Properties["Current App"], "DIRECTV | com.att.tv", "MRP state updates current app")
  assert_eq(Properties["Now Playing"], "Live TV - Channel 12", "MRP state updates now playing")

  local youtube_client = Driver.PB.field_string(2, "com.google.ios.youtube")
  local youtube_path = Driver.PB.field_message(2, youtube_client)
  local queue_metadata = Driver.PB.field_string(1, "Last Week Tonight") ..
    Driver.PB.field_string(7, "LastWeekTonight")
  local queue_item = Driver.PB.field_string(1, "queue-item-id") ..
    Driver.PB.field_message(2, queue_metadata)
  local queue = Driver.PB.field_varint(1, 0) ..
    Driver.PB.field_message(2, queue_item)
  local queue_state = Driver.PB.field_message(3, queue) ..
    Driver.PB.field_message(9, youtube_path)
  local queue_message = Driver.PB.field_varint(1, 4) ..
    Driver.PB.field_string(2, "queue-state-id") ..
    Driver.PB.field_varint(4, 0) ..
    Driver.PB.field_message(9, queue_state)
  Driver.C4Driver.handle_airplay_mrp_update(Driver.PB.extract_protocol_update(queue_message))
  assert_eq(Properties["Current App"], "com.google.ios.youtube", "MRP queue state updates YouTube app")
  assert_eq(Properties["Now Playing"], "Last Week Tonight - LastWeekTonight", "MRP queue metadata updates now playing")

  C4 = old_c4
  Properties = old_properties
end

function tests.app_list_populates_launch_app_dynamic_list_and_launches_selection()
  local old_properties = Properties
  local old_c4 = C4
  local property_lists = {}
  Properties = {}
  C4 = {
    UpdatePropertyList = function(_, name, items)
      property_lists[name] = items
    end,
  }
  Driver.Companion.sent_messages = {}
  Driver.Companion.app_list = {}
  Driver.Companion.app_list_rows = {}

  Driver.C4Driver.handle_companion_message({
    _i = "FetchLaunchableApplicationsEvent",
    _t = 3,
    _c = {
      ["com.netflix.Netflix"] = "Netflix",
      ["com.google.ios.youtube"] = "YouTube",
    },
  })

  assert(property_lists["Launch App"]:match("Netflix | com.netflix.Netflix"), "launch app list contains Netflix")
  assert(property_lists["Launch App"]:match("YouTube | com.google.ios.youtube"), "launch app list contains YouTube")

  Properties["Launch App"] = "Netflix | com.netflix.Netflix"
  Driver.C4Driver.launch_selected_app()
  local launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_eq(launch._i, "_launchApp", "selected app launches")
  assert_eq(launch._c._bundleID, "com.netflix.Netflix", "selected app bundle")

  C4 = old_c4
  Properties = old_properties
end

function tests.print_app_list_outputs_row_identifier()
  local old_print = print
  local lines = {}
  print = function(line)
    lines[#lines + 1] = tostring(line)
  end

  Driver.Companion.app_list_rows = {
    { name = "Netflix", identifier = "com.netflix.Netflix" },
  }

  local ok = Driver.C4Driver.print_app_list()
  assert_eq(ok, true, "print app list succeeds")
  assert_eq(lines[2], "[AppleTV]   Netflix | com.netflix.Netflix", "printed identifier")

  print = old_print
end

function tests.response_matching_adds_identifier_for_app_list()
  local received
  local client = Driver.CompanionClient.new({
    credentials = Driver.Credentials.parse(table.concat({
      Driver.Bytes.hex(string.rep("\x01", 32)),
      Driver.Bytes.hex(string.rep("\x02", 32)),
      Driver.Bytes.hex("ATV-ID"),
      Driver.Bytes.hex("CLIENT-ID"),
    }, ":")),
    crypto = {
      encrypt = function(_, plaintext) return plaintext .. string.rep("\0", 16) end,
      decrypt = function(_, ciphertext) return ciphertext:sub(1, #ciphertext - 16) end,
    },
    transport = {
      Write = function() end,
    },
    on_message = function(message) received = message end,
  })
  client.session = Driver.CompanionSession.new("out", "in", client.crypto)
  client.state = "SESSION_ACTIVE"
  local request = client:fetch_apps()
  local response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
    { "_t", 3 },
    { "_c", Driver.OPACK.dict({ { "com.netflix.Netflix", "Netflix" } }) },
    { "_x", request._x },
  }))
  client:receive(client.session:encode_frame(Driver.CompanionFrame.E_OPACK, response_payload))
  assert_eq(received._i, "FetchLaunchableApplicationsEvent", "matched response gets request identifier")
  assert_eq(received._c["com.netflix.Netflix"], "Netflix", "response content preserved")
end

function tests.disconnect_companion_keeps_credentials()
  local old_properties = Properties
  Properties = {}
  local closed = false
  local credentials = { type = "HAP" }
  Driver.Companion.credentials = credentials
  Driver.Companion.client = {
    close = function()
      closed = true
    end,
  }

  Driver.C4Driver.disconnect_companion()
  assert_eq(closed, true, "client close called")
  assert_eq(Driver.Companion.credentials, credentials, "credentials retained")
  assert_eq(Driver.Companion.client, nil, "client cleared")
  assert_eq(Properties["Connection State"], "Disconnected", "disconnect state")
  assert_eq(Driver.Companion.state, "Disconnected", "disconnect companion state")
  assert_eq(Driver.AirPlay.monitor_state, "STOPPED", "disconnect stops AirPlay monitor")
  Properties = old_properties
end

function tests.connection_state_also_publishes_companion_state()
  local old_properties = Properties
  Properties = {}
  Driver.C4Driver.set_connection_state("SESSION_ACTIVE")
  assert_eq(Properties["Connection State"], "SESSION_ACTIVE", "connection state")
  assert_eq(Driver.Companion.state, "SESSION_ACTIVE", "companion state")
  Properties = old_properties
end

function tests.companion_watchdog_reconnects_stale_session()
  local old_properties = Properties
  local old_client = Driver.Companion.client
  local old_now = Driver.C4Driver.now_ms
  local old_interval = Driver.Companion.watchdog_interval_ms
  local old_stale = Driver.Companion.watchdog_stale_ms
  local closed = false
  local connect_calls = 0

  Properties = {}
  Driver.Companion.watchdog_interval_ms = 60000
  Driver.Companion.watchdog_stale_ms = 60000
  Driver.C4Driver.now_ms = function() return 120000 end
  Driver.Companion.client = {
    state = "SESSION_ACTIVE",
    credentials = { type = "HAP" },
    session = {},
    transport = {
      Close = function()
        closed = true
      end,
    },
    last_rx_ms = 1000,
    pending_commands = {
      { identifier = "_launchApp" },
    },
  }
  setmetatable(Driver.Companion.client, { __index = Driver.CompanionClient })
  Driver.Companion.client.connect = function(self)
    connect_calls = connect_calls + 1
    self.connecting = true
  end

  Driver.C4Driver.check_companion_watchdog()
  assert_eq(closed, true, "stale Companion transport closed")
  assert_eq(connect_calls, 1, "stale Companion reconnect requested")
  assert_eq(#Driver.Companion.client.pending_commands, 1, "queued commands preserved")
  assert_eq(Properties["Connection State"], "DISCONNECTED", "watchdog disconnect state")

  Properties = old_properties
  Driver.Companion.client = old_client
  Driver.C4Driver.now_ms = old_now
  Driver.Companion.watchdog_interval_ms = old_interval
  Driver.Companion.watchdog_stale_ms = old_stale
end

function tests.airplay_monitor_watchdog_sends_heartbeat()
  local old_properties = Properties
  local old_client = Driver.AirPlay.control_client
  local old_enabled = Driver.AirPlay.monitor_enabled
  local old_last = Driver.AirPlay.monitor_last_activity_ms
  local old_now = Driver.C4Driver.now_ms
  local sent = false

  Properties = {}
  Driver.AirPlay.monitor_enabled = true
  Driver.AirPlay.monitor_last_activity_ms = 1000
  Driver.C4Driver.now_ms = function() return 2000 end
  Driver.AirPlay.control_client = {
    data_channel = {
      transport = {},
      send_heartbeat = function()
        sent = true
      end,
    },
  }

  Driver.C4Driver.check_airplay_monitor_watchdog()
  assert_eq(sent, true, "watchdog heartbeat sent")
  assert_eq(Driver.AirPlay.control_client ~= nil, true, "active monitor remains connected")

  Properties = old_properties
  Driver.AirPlay.control_client = old_client
  Driver.AirPlay.monitor_enabled = old_enabled
  Driver.AirPlay.monitor_last_activity_ms = old_last
  Driver.C4Driver.now_ms = old_now
end

function tests.room_power_scopes_airplay_monitor()
  local old_c4 = C4
  local old_set_timer = SetTimer
  local old_cancel_timer = CancelTimer
  local old_properties = Properties
  local old_airplay_credentials = Driver.AirPlay.credentials
  local old_state = Driver.state
  local old_monitor_enabled = Driver.AirPlay.monitor_enabled
  local old_client = Driver.AirPlay.control_client
  local old_companion_client = Driver.Companion.client
  local scheduled = {}
  local cancelled = {}
  local closed = false

  C4 = { GetDeviceID = function() return 42 end }
  SetTimer = function(name, delay, fn)
    scheduled[#scheduled + 1] = { name = name, delay = delay, fn = fn }
    return name
  end
  CancelTimer = function(name)
    cancelled[#cancelled + 1] = name
  end
  Properties = {}
  Driver.state = {}
  Driver.AirPlay.credentials = { type = "HAP" }
  Driver.AirPlay.monitor_enabled = false
  Driver.AirPlay.control_client = nil
  Driver.Companion.client = { state = "SESSION_ACTIVE" }

  ReceivedFromProxy(5002, "ON", {})

  assert_eq(#scheduled, 1, "room on schedules monitor start")
  assert_eq(scheduled[1].name, "AppleTV_airplay_monitor_start", "monitor start timer")
  assert_eq(Driver.AirPlay.monitor_state, "SCHEDULED", "monitor scheduled state")

  Driver.AirPlay.monitor_enabled = true
  Driver.AirPlay.control_client = {
    close = function()
      closed = true
    end,
  }
  Driver.Companion.sent_messages = {}

  ReceivedFromProxy(5002, "OFF", {})

  assert_eq(#Driver.Companion.sent_messages, 0, "room off defaults to no remote command")
  assert_eq(closed, true, "room off closes monitor client")
  assert_eq(Driver.AirPlay.monitor_enabled, false, "room off disables monitor")
  assert_eq(Driver.AirPlay.control_client, nil, "room off clears monitor client")
  assert_eq(Driver.AirPlay.monitor_state, "STOPPED", "monitor stopped state")
  assert_contains(cancelled, "AppleTV_airplay_monitor_start", "room off cancels scheduled start")
  assert_contains(cancelled, "AppleTV_airplay_monitor_retry", "room off cancels retry")
  assert_contains(cancelled, "AppleTV_airplay_monitor_watchdog", "room off cancels watchdog")

  C4 = old_c4
  SetTimer = old_set_timer
  CancelTimer = old_cancel_timer
  Properties = old_properties
  Driver.AirPlay.credentials = old_airplay_credentials
  Driver.state = old_state
  Driver.AirPlay.monitor_enabled = old_monitor_enabled
  Driver.AirPlay.control_client = old_client
  Driver.Companion.client = old_companion_client
end

function tests.airplay_monitor_watchdog_restarts_stale_channel()
  local old_properties = Properties
  local old_client = Driver.AirPlay.control_client
  local old_enabled = Driver.AirPlay.monitor_enabled
  local old_last = Driver.AirPlay.monitor_last_activity_ms
  local old_stale = Driver.AirPlay.monitor_stale_ms
  local old_now = Driver.C4Driver.now_ms
  local closed = false

  Properties = {}
  Driver.AirPlay.monitor_enabled = true
  Driver.AirPlay.monitor_last_activity_ms = 1000
  Driver.AirPlay.monitor_stale_ms = 500
  Driver.C4Driver.now_ms = function() return 2000 end
  Driver.AirPlay.control_client = {
    data_channel = {
      transport = {},
    },
    close = function()
      closed = true
    end,
  }

  Driver.C4Driver.check_airplay_monitor_watchdog()
  assert_eq(closed, true, "stale monitor closes old client")
  assert_eq(Driver.AirPlay.control_client, nil, "stale monitor clears old client")
  assert_eq(Driver.AirPlay.monitor_state, "STALE", "stale monitor state")
  assert_eq(Properties["Connection State"], nil, "metadata failure does not alter control state")

  Properties = old_properties
  Driver.AirPlay.control_client = old_client
  Driver.AirPlay.monitor_enabled = old_enabled
  Driver.AirPlay.monitor_last_activity_ms = old_last
  Driver.AirPlay.monitor_stale_ms = old_stale
  Driver.C4Driver.now_ms = old_now
end

function tests.srp_vectors_match_pyatv_srptools()
  local vectors = {
    pin = "1234",
    salt = "0102030405060708090a0b0c0d0e0f10",
    a = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    x = "38aeb8f8f46de00187e6642bf2431424243369f93b436bb1d4c7742eb2922c741b50ef9d9a7c6c8f02ef61c49065298eebc5b0408c3b87ccf133b18b8d1d04de",
    A = "203e5bc55133e8d2917aac4b7d78b82c725d9085efc46dd33c449ebfb09816bee2ae6e218c9873a99a1e01bd0e7ca47edca05889319bfebb30bdea7701cba20c6419a59b7c6ee0f80c59fcb9ec9e43da57885775e6d343288c7bdca766361e511c8d7f1ac4c521c2fbdd22e145fb83fcf0722949ab5520de4963661c5d27658a010cb50514a6d8ff10a8448117545c4a9cd12002b1bf0f81775f0426ad609d2eaaee21736fc6d766a9e8977a4b467c1a67a4de79e6c185b555028633cd028b3917fc6f0d8e07871b2d531ea6e4f9f5bbed5cf6aaee6f1f429126c6bac9644df264bf61fcf5a8c5a42c99d42f1bf87c89488649991be2bcdce6c1d87a6a463a7998150a20b33e7fbbcaa366e8a77c5529421dadf8132ef97e09d30eadae3149b8f15025354b7c6148fbd754c9ca6caead032f4e322fc93049805f5ea415bf535deab62f603340cc2d9bd99874c9bdf2c6a07d1963bfb79ee527fc252db63696b00ec434bdc69e9158ba02ac9dbe0ff85e5263c57f178dd4d529eaa23940ed2e47",
    B = "f81399b8a8414df7d5073b9308a3935d7bf363e1ba08fee455ea4973dcd5b6e086433b4e8250dcca821681e51d0596b6c94887fd9cd5fd7fcedd1fe2af3650fc535d77c25b8041af40a10dc0be2228e7d5ef0e8ca919c48200d673ddea6bb792fc1186ea527ff0ecddfe59687e9bb089116bcd5383e78ab9e2c5b2f14038363faf7b4610cce1dd2093f7eb36e767596274e31d7973d44f162bf4e61fbbde5d0f6e67871bd2e1afd1162bd011809b2e47d6b4289433fc1190168a421854190ff47503a295a0d9b8a9e2ea89682c30c05da1f30a38490ed848112c345029dc3011994b33ecdd07e6fd0268d366ee9c5958322a3dcd5e24ac0ba4c1968ff3353ef725489e4939cef2c0f1b25b8f839bcdb37ac90763a4414b79b45cf5d81825ff6eafa6a928b5a566554fd38615ac053aafe0c6e904a991c1c30efff106aab7aaee002b1c2aa6b0f922487f675be7d8d6c45b87fe3a3acfe5f2c9659d63d6ea1f4f124f5f65504c3021b651dee60ddd2a207b73a44fbfb3c60f713abe4c00914831",
    u = "952b387d311bfbfef5227758f683a0154d17e0090cd5f0a601a17690f793e3a3c67447f1e9f564ce2e489d6c6cfbefbf5eb73b94ed8a709200256a5e60724c8a",
    K = "336ad7e31250344ad8bc609e26e73f14766b43b756eda35b39b199e5835e7a4a20548c0eb763e7bdd09b7307dfaa695e418b73282b656858d12b52b5587d0067",
    M1 = "23241f87768048087f4f65154f339e4c55c4504d6cdf3458acce212dc9d781a5e26b85b1442402b67ab7088947ce21fd8469c1644811c60dbdbe7d27985f1cbe",
    M2 = "7a7c66303dccd0609c7df1d5ab3cd7f1062b4fff9754bda5a8b2814ba8374f9bbc6af072f764e93cdcf807325fbc830dfb1d19b5f52321b131cd040e874aac59",
  }
  local sha_vectors = {
    inner = "0bd484fe9c62b5165b2c6aa6775153a129c1b241144138894065d5f1651df8df27780b99d35bdb7477aacfe426d043156e965fcbde4c4729dcc8581a9c9538e2",
    h_n = "ba8900b220aed4bbaaaaa9c6e3afe0f5d4e2ba69d364dc910d9eb00b5891a5f42551427fb8f570a9d14bd13ea1c869ca8587e0181b1fc1496efeb934cb1e7c46",
    h_g = "095f3e448a55fa2c3c7049c01dcf12fb87c44477cf367993132ca74c92a27a1eaaa341c2fd5724ea449cec2728547e80edbb7e6029891c5ffd157e283ebb41e5",
    h_user = "cd3fa890ac891aa9a9d23346f1e4f698b01240ad810cf029d5d57fc79f1b1fc4e2c40862dfb3828ed2c58aa80f678a45a7f4d78b9c4ac33fdc5546f2a10430b3",
    k = "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b285033a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0",
    s_input = "afca1c213eb79915a21c424415e3803947c6f0766e64970cdfcad6f95505df69cfead9ad2ed74113dac56c8789e1b9e24d6a9d7362fb7ff21a2e778e5a3ec1a314565bafa28fb53506370612a487244d746dff016c9f3d7d4dc38da1b367f6594e062f2cd2dcf3aa74aad800c6e847243026490c833687c6c543ef376f5c0b16ca1afd3698df568655b608270f5ea1bac890853834678450feee78281b0e1a50b5af299f3b37a977b8a954708d4466434f019d4d1d18f85b07b486725948b18d34fce17bf929b6f441d1c01b2f28c360df751715bfadfb53e14fa2acdf7d82d07492e085f161a1784228bd4565f3a3ebea099847f7087fb019621dcb79d505dbc218142f3521d3b414484a82cc7ac12e0ed7955617053a1ed14864c9086233fb77a122797bd21a86722c99cb300dba2e67f78ba1cc8bc3d2110eec581c377a478ab55f91bd511f6e5f22c8e518368596e6b2c8f32156aac326b1fa74eaf3e86ba6f36dc0de4ed9013000a8fc3ff0f597376342518e0484ef862d37f3d8fee01d",
  }

  local salt = Driver.Bytes.from_hex(vectors.salt)
  local a_bytes = Driver.Bytes.from_hex(vectors.a)
  local B_bytes = Driver.Bytes.from_hex(vectors.B)
  local A_bytes = Driver.Bytes.from_hex(vectors.A)
  local K = Driver.Bytes.from_hex(vectors.K)
  local M1 = Driver.Bytes.from_hex(vectors.M1)
  local h_n = Driver.Bytes.from_hex(sha_vectors.h_n)
  local h_g = Driver.Bytes.from_hex(sha_vectors.h_g)
  local h_user = Driver.Bytes.from_hex(sha_vectors.h_user)

  local map = {}
  map[Driver.Bytes.hex("Pair-Setup:" .. vectors.pin)] = sha_vectors.inner
  map[Driver.Bytes.hex(salt .. Driver.Bytes.from_hex(sha_vectors.inner))] = vectors.x
  map[Driver.Bytes.hex(Driver.SRP.N_BYTES .. string.rep("\0", 383) .. string.char(5))] = sha_vectors.k
  map[Driver.Bytes.hex(A_bytes .. B_bytes)] = vectors.u
  map[sha_vectors.s_input] = vectors.K
  map[Driver.Bytes.hex(Driver.SRP.N_BYTES)] = sha_vectors.h_n
  map[Driver.Bytes.hex(string.char(5))] = sha_vectors.h_g
  map[Driver.Bytes.hex("Pair-Setup")] = sha_vectors.h_user
  map[Driver.Bytes.hex(xor_bytes(h_n, h_g) .. h_user .. salt .. A_bytes .. B_bytes .. K)] = vectors.M1
  map[Driver.Bytes.hex(A_bytes .. M1 .. K)] = vectors.M2

  local ossl_bn = require("openssl").bn
  local function bn_be(v, len)
    local b = ossl_bn.totext(v)
    return string.rep("\0", len - #b) .. b
  end

  local old_sha512 = Driver.SRP.sha512
  local old_initialized = Driver.SRP._initialized
  local old_k = Driver.SRP._k_bytes
  Driver.SRP._initialized = false
  Driver.SRP._k_bytes = nil
  Driver.SRP.sha512 = function(data)
    local digest = map[Driver.Bytes.hex(data)]
    assert(digest, "unexpected SRP SHA-512 input: " .. Driver.Bytes.hex(data))
    return Driver.Bytes.from_hex(digest)
  end

  local ok, err = pcall(function()
    local x = Driver.SRP.compute_x(salt, vectors.pin)
    assert_eq(Driver.Bytes.hex(bn_be(x, 64)), vectors.x, "SRP x")

    local A = Driver.SRP.compute_A(a_bytes)
    assert_eq(Driver.Bytes.hex(A), vectors.A, "SRP A")

    local u = Driver.SRP.compute_u(A, B_bytes)
    assert_eq(Driver.Bytes.hex(bn_be(u, 64)), vectors.u, "SRP u")

    local computed_K = Driver.SRP.compute_session_key(B_bytes, a_bytes, x, u)
    assert_eq(Driver.Bytes.hex(computed_K), vectors.K, "SRP K")

    local computed_M1 = Driver.SRP.compute_M1(A, B_bytes, computed_K, salt)
    assert_eq(Driver.Bytes.hex(computed_M1), vectors.M1, "SRP M1")
    assert_eq(Driver.SRP.verify_M2(A, computed_M1, computed_K, Driver.Bytes.from_hex(vectors.M2)), true, "SRP M2 verify")
  end)

  Driver.SRP.sha512 = old_sha512
  Driver.SRP._initialized = old_initialized
  Driver.SRP._k_bytes = old_k

  if not ok then
    error(err, 2)
  end
end

function tests.opack_array_encode_decode()
  -- Encode an array with 3 elements
  local arr = Driver.OPACK.array({1, "hello", true})
  local encoded = Driver.OPACK.encode(arr)
  assert_eq(encoded:byte(1), 0xD3, "array tag for 3 elements")

  -- Round-trip via decode
  local decoded = Driver.OPACK.decode(encoded)
  assert(type(decoded) == "table", "decoded array is a table")
  assert_eq(#decoded, 3, "decoded array length")
  assert_eq(decoded[1], 1, "array element 1")
  assert_eq(decoded[2], "hello", "array element 2")
  assert_eq(decoded[3], true, "array element 3")

  -- Empty array
  local empty = Driver.OPACK.encode(Driver.OPACK.array({}))
  assert_eq(empty:byte(1), 0xD0, "empty array tag")
  local decoded_empty = Driver.OPACK.decode(empty)
  assert_eq(#decoded_empty, 0, "decoded empty array length")

  -- Array inside dict (as Apple TV uses for app list responses)
  local dict_with_array = Driver.OPACK.dict({
    { "apps", Driver.OPACK.array({"com.netflix.Netflix", "com.apple.TVShows"}) },
  })
  local enc2 = Driver.OPACK.encode(dict_with_array)
  local dec2 = Driver.OPACK.decode(enc2)
  assert(type(dec2) == "table", "dict decoded")
  assert(type(dec2.apps) == "table", "apps field is array")
  assert_eq(#dec2.apps, 2, "apps array length")
  assert_eq(dec2.apps[1], "com.netflix.Netflix", "apps[1]")
end

function tests.opack_object_references_decode()
  local encoded = "\xe2" .. "\x43" .. "_pd" .. "\xa0" .. "\x44" .. "copy" .. "\xa0"
  local decoded = Driver.OPACK.decode(encoded)
  assert_eq(decoded._pd, "_pd", "short object reference")
  assert_eq(decoded.copy, "_pd", "second object reference")
end

function tests.opack_duplicate_literals_do_not_shift_object_references()
  local encoded = "\xd4" .. "\x41a" .. "\x41a" .. "\x41b" .. "\xa1"
  local decoded = Driver.OPACK.decode(encoded)
  assert_eq(decoded[1], "a", "first literal")
  assert_eq(decoded[2], "a", "duplicate literal")
  assert_eq(decoded[3], "b", "second unique literal")
  assert_eq(decoded[4], "b", "reference indexes unique object table")
end

function tests.opack_uuid_nil_and_endless_dict_decode()
  local uuid_bytes = Driver.Bytes.from_hex("00112233445566778899aabbccddeeff")
  local encoded_uuid = "\x05" .. uuid_bytes
  assert_eq(Driver.OPACK.decode(encoded_uuid), "00112233-4455-6677-8899-aabbccddeeff", "uuid marker")

  local encoded = "\xef" ..
    "\x44" .. "none" .. "\x04" ..
    "\x44" .. "uuid" .. encoded_uuid ..
    "\x03"
  local decoded = Driver.OPACK.decode(encoded)
  assert_eq(decoded.none, nil, "nil marker")
  assert_eq(decoded.uuid, "00112233-4455-6677-8899-aabbccddeeff", "uuid in endless dict")
end

function tests.opack_float_decode()
  local decoded32 = Driver.OPACK.decode("\x35\x00\x00\xc0\x3f")
  assert(math.abs(decoded32 - 1.5) < 0.000001, "float32 marker")

  local decoded64 = Driver.OPACK.decode("\x36\x00\x00\x00\x00\x00\x00\x02\xc0")
  assert(math.abs(decoded64 + 2.25) < 0.000001, "float64 marker")

  local encoded = "\xd2" .. "\x35\x00\x00\x20\x40" .. "\xa0"
  local decoded = Driver.OPACK.decode(encoded)
  assert(math.abs(decoded[1] - 2.5) < 0.000001, "float32 in array")
  assert_eq(decoded[2], decoded[1], "float object reference")
end


function tests.pair_setup_m1_to_m6_with_mock_crypto()
  -- Full M1→M6 flow with injected crypto.
  -- The SRP computation is bypassed: mock returns pre-cooked A, K, M1 values.
  local FAKE_PRIVATE = string.rep("\xAB", 32)
  local FAKE_PUBLIC  = string.rep("\xCD", 32)
  local FAKE_A      = string.rep("\xAA", 384)
  local FAKE_K      = string.rep("\xBB", 64)
  local FAKE_M1     = string.rep("\xCC", 64)
  local FAKE_SIG    = string.rep("\xDD", 64)
  local FAKE_SALT   = string.rep("\x01", 16)
  local FAKE_B      = string.rep("\x02", 384)
  local FAKE_M2     = string.rep("\x03", 64)

  local writes = {}
  local states = {}
  local pair_setup_nonces = {}
  local transport = { Write = function(_, d) writes[#writes + 1] = d end }

  -- Pre-seeded SRP mock: override crypto-dependent functions to avoid openssl dependency
  local orig_compute_x            = Driver.SRP.compute_x
  local orig_compute_A            = Driver.SRP.compute_A
  local orig_compute_u            = Driver.SRP.compute_u
  local orig_compute_session_key  = Driver.SRP.compute_session_key
  local orig_compute_M1           = Driver.SRP.compute_M1
  local orig_verify_M2            = Driver.SRP.verify_M2
  Driver.SRP.compute_x            = function() return require("openssl").bn.text(string.rep("\x42", 64)) end
  Driver.SRP.compute_A            = function() return FAKE_A end
  Driver.SRP.compute_u            = function() return require("openssl").bn.text(string.rep("\x43", 64)) end
  Driver.SRP.compute_session_key  = function() return FAKE_K end
  Driver.SRP.compute_M1           = function() return FAKE_M1 end
  Driver.SRP.verify_M2            = function() return true end

  local fake_crypto = {
    generate_ed25519_keypair = function()
      return { private_key = FAKE_PRIVATE, public_key = FAKE_PUBLIC }
    end,
    random_bytes = function(n) return string.rep("\x42", n) end,
    hkdf_sha512 = function(_, info, _)
      return string.rep("\xEE", 32)
    end,
    ed25519_sign = function(_, _) return FAKE_SIG end,
    encrypt = function(_, plaintext, _, nonce)
      pair_setup_nonces[#pair_setup_nonces + 1] = Driver.Bytes.hex(nonce)
      assert_eq(nonce, string.rep("\0", 4) .. "PS-Msg05", "M5 HAP nonce")
      return plaintext .. string.rep("\0", 16)
    end,
    decrypt = function(_, ciphertext, _, nonce)
      pair_setup_nonces[#pair_setup_nonces + 1] = Driver.Bytes.hex(nonce)
      assert_eq(nonce, string.rep("\0", 4) .. "PS-Msg06", "M6 HAP nonce")
      return ciphertext:sub(1, #ciphertext - 16)
    end,
  }

  local client = Driver.CompanionClient.new({
    transport = transport,
    crypto = fake_crypto,
    on_state = function(s) states[#states + 1] = s end,
  })

  -- M1: connect and start pairing
  client:connect("127.0.0.1", 49153)
  client:start_pair_setup()
  assert_eq(client.state, "PAIR_SETUP_M1_SENT", "state after M1")
  assert(writes[1] ~= nil, "M1 frame written")
  local m1_frame = Driver.CompanionFrame.try_decode(writes[1])
  assert_eq(m1_frame.frame_type, Driver.CompanionFrame.PS_START, "M1 is PS_START")

  -- M2: Apple TV responds with salt + B. Hardware uses PS_NEXT here.
  local m2_tlv = Driver.TLV8.encode_ordered({
    { 6, string.char(0x02) },  -- SeqNo = M2
    { 2, FAKE_SALT },          -- Salt
    { 3, FAKE_B },             -- PublicKey = B
  })
  local m2_payload = Driver.OPACK.encode(Driver.OPACK.dict({ { "_pd", Driver.OPACK.bytes(m2_tlv) } }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PS_NEXT, m2_payload))
  assert_eq(client.state, "PAIR_SETUP_AWAITING_PIN", "state after M2")

  -- PIN submission → M3
  client:pair_setup_submit_pin("1234")
  assert_eq(client.state, "PAIR_SETUP_M3_SENT", "state after M3")
  local m3_frame = Driver.CompanionFrame.try_decode(writes[2])
  assert_eq(m3_frame.frame_type, Driver.CompanionFrame.PS_NEXT, "M3 is PS_NEXT")
  local m3_tlv = Driver.PairVerify.decode_pairing_data(m3_frame.payload)
  assert_eq(m3_tlv[6], string.char(0x03), "M3 seq=3")
  assert_eq(m3_tlv[3], FAKE_A, "M3 contains A")
  assert_eq(m3_tlv[4], FAKE_M1, "M3 contains M1 proof")

  -- M4: Apple TV proves it knows verifier
  local m4_tlv = Driver.TLV8.encode_ordered({
    { 6, string.char(0x04) },  -- SeqNo = M4
    { 4, FAKE_M2 },            -- Proof = M2
  })
  local m4_payload = Driver.OPACK.encode(Driver.OPACK.dict({ { "_pd", Driver.OPACK.bytes(m4_tlv) } }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PS_NEXT, m4_payload))
  -- After M4, driver auto-sends M5
  assert_eq(client.state, "PAIR_SETUP_M5_SENT", "state after M4→M5")
  local m5_frame = Driver.CompanionFrame.try_decode(writes[3])
  assert_eq(m5_frame.frame_type, Driver.CompanionFrame.PS_NEXT, "M5 is PS_NEXT")
  local m5_tlv = Driver.PairVerify.decode_pairing_data(m5_frame.payload)
  assert_eq(m5_tlv[6], string.char(0x05), "M5 seq=5")
  assert(m5_tlv[5] ~= nil, "M5 contains encrypted data")

  -- M6: Apple TV sends its identity (encrypted)
  local FAKE_ATV_ID   = "atv-device-id-bytes"
  local FAKE_ATV_LTPK = string.rep("\xFF", 32)
  local inner_tlv = Driver.TLV8.encode_ordered({
    { 1, FAKE_ATV_ID },
    { 3, FAKE_ATV_LTPK },
    { 10, FAKE_SIG },
  })
  -- fake_crypto.decrypt strips 16 bytes, so pad with 16 zeros
  local m6_encrypted = inner_tlv .. string.rep("\0", 16)
  local m6_tlv = Driver.TLV8.encode_ordered({
    { 6, string.char(0x06) },
    { 5, m6_encrypted },
  })
  local m6_payload = Driver.OPACK.encode(Driver.OPACK.dict({ { "_pd", Driver.OPACK.bytes(m6_tlv) } }))
  client:receive(Driver.CompanionFrame.encode(Driver.CompanionFrame.PS_NEXT, m6_payload))
  assert_eq(client.state, "PAIR_SETUP_COMPLETE", "state after M6")
  assert(client.credentials ~= nil, "credentials stored after pairing")
  assert_eq(Driver.Bytes.hex(client.credentials.ltpk), Driver.Bytes.hex(FAKE_ATV_LTPK), "ltpk matches ATV public key")
  assert_eq(pair_setup_nonces[1], "0000000050532d4d73673035", "recorded PS-Msg05 nonce")
  assert_eq(pair_setup_nonces[2], "0000000050532d4d73673036", "recorded PS-Msg06 nonce")

  -- Restore SRP
  Driver.SRP.compute_x           = orig_compute_x
  Driver.SRP.compute_A           = orig_compute_A
  Driver.SRP.compute_u           = orig_compute_u
  Driver.SRP.compute_session_key = orig_compute_session_key
  Driver.SRP.compute_M1          = orig_compute_M1
  Driver.SRP.verify_M2           = orig_verify_M2
end

local names = {}
for name in pairs(tests) do
  names[#names + 1] = name
end
table.sort(names)

-- Tests run under pcall so one failure reports instead of aborting the run and
-- hiding every test after it. Restore the globals a test body may swap in but
-- not put back if it fails partway, so a single failure does not cascade.
local passed, skipped = 0, 0
local failures = {}

for _, name in ipairs(names) do
  local saved_c4, saved_properties, saved_debug = C4, Properties, DEBUGPRINT
  local ok, err = pcall(tests[name])
  C4, Properties, DEBUGPRINT = saved_c4, saved_properties, saved_debug

  if ok then
    passed = passed + 1
    print("ok - " .. name)
  elseif not REAL_SHA512 and tostring(err):match("openssl") then
    -- lua-openssl is absent locally; these paths are exercised on the controller.
    skipped = skipped + 1
    print("skip - " .. name .. " (requires lua-openssl)")
  else
    failures[#failures + 1] = { name = name, err = err }
    print("not ok - " .. name)
    print("  " .. tostring(err))
  end
end

print(string.format("\n%d passed, %d skipped, %d failed (of %d tests)",
  passed, skipped, #failures, #names))

if #failures > 0 then
  print("\nFAILURES:")
  for _, failure in ipairs(failures) do
    print("  " .. failure.name .. ": " .. tostring(failure.err))
  end
  os.exit(1)
end
