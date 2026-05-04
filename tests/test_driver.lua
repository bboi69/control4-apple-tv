local Driver = dofile("driver.lua")

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
    error("unexpected Ed25519 vector SHA-512 input length " .. tostring(#data))
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
    error("unexpected crypto self-test SHA-512 input length " .. tostring(#data))
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

  local function make_cipher_ctx(mode)
    local vector_plaintext = false
    return {
      init = function(_, key, nonce, pad)
        record("cipher." .. mode .. ".init")
        assert_eq(#key, 32, mode .. " key length")
        assert_eq(#nonce, 12, mode .. " nonce length")
        assert_eq(pad, nil, mode .. " padding")
        return true
      end,
      update = function(_, data, aad)
        if aad then
          record("cipher." .. mode .. ".aad:" .. data)
          return nil
        end
        record("cipher." .. mode .. ".update:" .. data)
        if mode == "encrypt" then
          if data == "plaintext" then
            vector_plaintext = true
            return Driver.Bytes.from_hex("f99769694763c038c3")
          end
          return options.encrypt_ciphertext or "ciphertext"
        end
        if data == Driver.Bytes.from_hex("f99769694763c038c3") then
          return "plaintext"
        end
        return options.decrypt_plaintext or "plaintext"
      end,
      final = function()
        record("cipher." .. mode .. ".final")
        return ""
      end,
      ctrl = function(_, control, value)
        record("cipher." .. mode .. ".ctrl:" .. tostring(control))
        if control == Driver.OpenSSLCrypto.EVP_CTRL_AEAD_SET_IVLEN then
          assert_eq(value, 12, "iv length")
          return true
        end
        if mode == "encrypt" then
          assert_eq(control, Driver.OpenSSLCrypto.EVP_CTRL_AEAD_GET_TAG, "get tag ctrl")
          assert_eq(value, 16, "tag length")
          if mode == "encrypt" and options.encrypt_tag then
            return options.encrypt_tag
          end
          if vector_plaintext then
            return Driver.Bytes.from_hex("88540d8367db9102148f2c2034e779d0")
          end
          return string.rep("T", 16)
        end
        assert_eq(control, Driver.OpenSSLCrypto.EVP_CTRL_AEAD_SET_TAG, "set tag ctrl")
        if value == Driver.Bytes.from_hex("88540d8367db9102148f2c2034e779d0") then
          return true
        end
        if value ~= string.rep("T", 16) then
          return false
        end
        return true
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
    cipher = {
          get = function(algorithm)
        record("cipher.get:" .. tostring(algorithm))
        assert_eq(algorithm, "chacha20-poly1305", "cipher algorithm")
        return {
          encrypt_new = function(_, key, nonce, pad)
            record("cipher:encrypt_new")
            assert_eq(key, nil, "encrypt key deferred until init")
            assert_eq(nonce, nil, "encrypt nonce deferred until init")
            assert_eq(pad, nil, "encrypt padding deferred until init")
            return make_cipher_ctx("encrypt")
          end,
          decrypt_new = function(_, key, nonce, pad)
            record("cipher:decrypt_new")
            assert_eq(key, nil, "decrypt key deferred until init")
            assert_eq(nonce, nil, "decrypt nonce deferred until init")
            assert_eq(pad, nil, "decrypt padding deferred until init")
            return make_cipher_ctx("decrypt")
          end,
        }
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
  local frame = Driver.Companion.encode_pair_setup_start()
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

function tests.openssl_crypto_wraps_raw_hap_keys_as_der()
  local key = bytes_range(0, 31)
  assert_eq(
    Driver.Bytes.hex(Driver.OpenSSLCrypto._spki_der("x25519", key)),
    "302a300506032b656e032100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "x25519 spki"
  )
  assert_eq(
    Driver.Bytes.hex(Driver.OpenSSLCrypto._pkcs8_der("ed25519", key)),
    "302e020100300506032b657004220420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "ed25519 pkcs8"
  )
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

  assert_contains(fake.calls, "bn.powmod", "native SRP BN modpow")
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
	  assert_eq(Driver.Companion.session, client.session, "global session")
	  assert_eq(Driver.Companion.socket, client, "global socket")
	
	  local second = Driver.CompanionFrame.try_decode(writes[2])
	  local tlv = Driver.PairVerify.decode_pairing_data(second.payload)
  assert_eq(tlv[6], string.char(0x03), "pair verify next seq")
  assert_eq(tlv[5], encrypted_response, "pair verify next encrypted")

	  local decoded_system_info = client.session:try_decode(writes[3])
	  local system_info_msg = Driver.OPACK.decode(decoded_system_info.payload)
	  assert_table_has(system_info_msg, "_i", "_systemInfo")

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
	  local ti_start_frame = client.session:try_decode(writes[6])
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
  Properties = {}
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
  assert_eq(Driver.Companion.credentials, nil, "reset companion credentials")
  assert_eq(Properties["Connection State"], "Disconnected", "reset state")

  Properties = old_properties
end

function tests.crypto_provider_failure_logs_without_last_error_property()
  local old_properties = Properties
  local old_provider = Driver.Crypto.provider
  local old_openssl = Driver.OpenSSLCrypto.openssl
  Properties = {}
  Driver.Crypto.provider = nil
  Driver.OpenSSLCrypto.openssl = {}

  local ok, err = Driver.C4Driver.check_crypto_provider()
  assert_eq(ok, false, "crypto check result")
  assert(err, "crypto check should return error detail")
  assert_eq(Properties["Connection State"], "Crypto Provider Failed", "crypto failure state")
  assert_eq(Properties["Last Error"], nil, "last error property is not used")

  Driver.Crypto.provider = old_provider
  Driver.OpenSSLCrypto.openssl = old_openssl
  Properties = old_properties
end

function tests.execute_command_routes_driver_commands()
  local old_properties = Properties
  Properties = {}
  Driver.Companion.sent_messages = {}
  ExecuteCommand("LAUNCH_APP", { BUNDLE_ID_OR_URL = "com.netflix.Netflix" })
  local launch = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(launch, "_i", "_launchApp")
  assert_table_has(launch._c, "_bundleID", "com.netflix.Netflix")
  assert_eq(Properties["Current App"], "com.netflix.Netflix", "current app property")

  ExecuteCommand("REFRESH_APP_LIST", {})
  local refresh = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(refresh, "_i", "FetchLaunchableApplicationsEvent")
  Properties = old_properties
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
  Driver.Companion.sent_messages = {}
  Driver.C4MiniApps.register_binding(3101, {
    name = "Netflix",
    service_id = "com.netflix.Netflix",
  })

  ReceivedFromProxy(3101, "SELECT", {})

  local last = Driver.Companion.sent_messages[#Driver.Companion.sent_messages]
  assert_table_has(last, "_i", "_launchApp")
  assert_table_has(last._c, "_bundleID", "com.netflix.Netflix")
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
	  local writes_before_close = #writes
	  client:close()
	  assert(#writes > writes_before_close, "_sessionStop was written before close")
	  local stop_msg, stop_frame
	  local saw_interest, saw_touch_stop, saw_ti_stop = false, false, false
	  for i = writes_before_close + 1, #writes do
	    local decoded = client.session:try_decode(writes[i])
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

function tests.app_list_current_app_and_now_playing_are_published()
  local old_properties = Properties
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
  assert(Properties["App List"]:match("Apple TV | com.apple.TVWatchList"), "app list contains Apple TV")
  assert(Properties["App List"]:match("Netflix | com.netflix.Netflix"), "app list contains Netflix")
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

  Properties = old_properties
end

function tests.disconnect_companion_keeps_credentials()
  local old_properties = Properties
  Properties = {}
  local closed = false
  local credentials = { type = "HAP" }
  Driver.Companion.credentials = credentials
  Driver.Companion.session = {}
  Driver.Companion.socket = {}
  Driver.Companion.client = {
    close = function()
      closed = true
    end,
  }

  Driver.C4Driver.disconnect_companion()
  assert_eq(closed, true, "client close called")
  assert_eq(Driver.Companion.credentials, credentials, "credentials retained")
  assert_eq(Driver.Companion.client, nil, "client cleared")
  assert_eq(Driver.Companion.socket, nil, "socket cleared")
  assert_eq(Driver.Companion.session, nil, "session cleared")
  assert_eq(Properties["Connection State"], "Disconnected", "disconnect state")
  Properties = old_properties
end

function tests.bigint_arithmetic()
  local BI = Driver.BigInt

  -- from/to bytes roundtrip
  local n_bytes = string.rep("\0", 3) .. "\x01\x02\x03\x04"  -- = 0x01020304
  local v = BI.from_bytes_be(n_bytes)
  local back = BI.to_bytes_be(v, 4)
  assert_eq(Driver.Bytes.hex(back), "01020304", "from/to bytes roundtrip")

  -- from_number
  local v_100 = BI.from_number(100)
  assert_eq(BI.compare(v_100, BI.from_number(100)), 0, "compare equal")
  assert_eq(BI.compare(v_100, BI.from_number(99)), 1, "compare greater")
  assert_eq(BI.compare(v_100, BI.from_number(101)), -1, "compare less")

  -- add
  local sum = BI.add(BI.from_number(65535), BI.from_number(1))
  assert_eq(BI.compare(sum, BI.from_number(65536)), 0, "add across limb boundary")

  -- mul
  local prod = BI.mul(BI.from_number(15), BI.from_number(17))
  assert_eq(BI.compare(prod, BI.from_number(255)), 0, "mul 15*17=255")

  -- sub
  local diff = BI.sub(BI.from_number(1000), BI.from_number(1))
  assert_eq(BI.compare(diff, BI.from_number(999)), 0, "sub 1000-1=999")

  -- mod
  local r = BI.mod(BI.from_number(100), BI.from_number(7))
  assert_eq(BI.compare(r, BI.from_number(2)), 0, "100 mod 7 = 2")

  local r2 = BI.mod(BI.from_number(2187), BI.from_number(13))
  assert_eq(BI.compare(r2, BI.from_number(3)), 0, "2187 mod 13 = 3")

  -- bit_length
  assert_eq(BI.bit_length(BI.from_number(255)), 8, "bit_length 255 = 8")
  assert_eq(BI.bit_length(BI.from_number(256)), 9, "bit_length 256 = 9")
  assert_eq(BI.bit_length(BI.from_number(0)), 0, "bit_length 0 = 0")
end

function tests.bigint_mont_modpow_small()
  local BI = Driver.BigInt

  -- Use small odd primes as modulus for Montgomery
  -- 3^7 mod 13 = 3 (since 3^6 = 729 = 56*13+1, 3^7 = 2187 = 3 mod 13)
  local N = BI.from_number(13)
  local k = 1
  local n_prime = BI.compute_n_prime(N[1])
  local R2 = BI.compute_r2_mod_n(N, k)

  local result = BI.mont_modpow(
    BI.from_number(3), BI.from_number(7), N, R2, k, n_prime
  )
  assert_eq(BI.compare(result, BI.from_number(3)), 0, "3^7 mod 13 = 3")

  -- mont_modpow(2, 10, 997) = 1024 mod 997 = 27
  local N2 = BI.from_number(997)
  local n_prime2 = BI.compute_n_prime(N2[1])
  local R2_mod_997 = BI.compute_r2_mod_n(N2, 1)
  local result2 = BI.mont_modpow(
    BI.from_number(2), BI.from_number(10), N2, R2_mod_997, 1, n_prime2
  )
  assert_eq(BI.compare(result2, BI.from_number(27)), 0, "2^10 mod 997 = 27")
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
  map[Driver.Bytes.hex(Driver.SRP.N_BYTES .. Driver.BigInt.to_bytes_be(Driver.SRP.g, 384))] = sha_vectors.k
  map[Driver.Bytes.hex(A_bytes .. B_bytes)] = vectors.u
  map[sha_vectors.s_input] = vectors.K
  map[Driver.Bytes.hex(Driver.SRP.N_BYTES)] = sha_vectors.h_n
  map[Driver.Bytes.hex(string.char(5))] = sha_vectors.h_g
  map[Driver.Bytes.hex("Pair-Setup")] = sha_vectors.h_user
  map[Driver.Bytes.hex(xor_bytes(h_n, h_g) .. h_user .. salt .. A_bytes .. B_bytes .. K)] = vectors.M1
  map[Driver.Bytes.hex(A_bytes .. M1 .. K)] = vectors.M2

  local old_sha512 = Driver.SRP.sha512
  local old_initialized = Driver.SRP._initialized
  local old_k = Driver.SRP._k_bytes
  local old_r2 = Driver.SRP._R2
  local old_n_prime = Driver.SRP._n_prime
  Driver.SRP._initialized = false
  Driver.SRP._k_bytes = nil
  Driver.SRP._R2 = nil
  Driver.SRP._n_prime = nil
  Driver.SRP.sha512 = function(data)
    local digest = map[Driver.Bytes.hex(data)]
    assert(digest, "unexpected SRP SHA-512 input: " .. Driver.Bytes.hex(data))
    return Driver.Bytes.from_hex(digest)
  end

  local ok, err = pcall(function()
    local x = Driver.SRP.compute_x(salt, vectors.pin)
    assert_eq(Driver.Bytes.hex(Driver.BigInt.to_bytes_be(x, 64)), vectors.x, "SRP x")

    local A = Driver.SRP.compute_A(a_bytes)
    assert_eq(Driver.Bytes.hex(A), vectors.A, "SRP A")

    local u = Driver.SRP.compute_u(A, B_bytes)
    assert_eq(Driver.Bytes.hex(Driver.BigInt.to_bytes_be(u, 64)), vectors.u, "SRP u")

    local computed_K = Driver.SRP.compute_session_key(B_bytes, a_bytes, x, u)
    assert_eq(Driver.Bytes.hex(computed_K), vectors.K, "SRP K")

    local computed_M1 = Driver.SRP.compute_M1(A, B_bytes, computed_K, salt)
    assert_eq(Driver.Bytes.hex(computed_M1), vectors.M1, "SRP M1")
    assert_eq(Driver.SRP.verify_M2(A, computed_M1, computed_K, Driver.Bytes.from_hex(vectors.M2)), true, "SRP M2 verify")
  end)

  Driver.SRP.sha512 = old_sha512
  Driver.SRP._initialized = old_initialized
  Driver.SRP._k_bytes = old_k
  Driver.SRP._R2 = old_r2
  Driver.SRP._n_prime = old_n_prime

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
  Driver.SRP.compute_x            = function() return Driver.BigInt.from_bytes_be(string.rep("\x42", 64)) end
  Driver.SRP.compute_A            = function() return FAKE_A end
  Driver.SRP.compute_u            = function() return Driver.BigInt.from_bytes_be(string.rep("\x43", 64)) end
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

for _, name in ipairs(names) do
  tests[name]()
  print("ok - " .. name)
end

print(string.format("%d tests passed", #names))
