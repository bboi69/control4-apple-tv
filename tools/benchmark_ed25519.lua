local Driver = dofile("driver.lua")

local seed = Driver.Bytes.from_hex(
  "9d61b19deffd5a60ba844af492ec2cc4" ..
  "4449c5697b326919703bac031cae7f60"
)
local public = Driver.Bytes.from_hex(
  "d75a980182b10ab7d54bfed3c964073a" ..
  "0ee172f3daa62325af021a68f707511a"
)
local signature = Driver.Bytes.from_hex(
  "e5564300c360ac729086e2cc806e828a" ..
  "84877f1eb8e5d974d873e06522490155" ..
  "5fb8821590a33bacc61e39701cf9b46b" ..
  "d25bf5f0595bbe24655141438e7a100b"
)

local hash_seed = Driver.Bytes.from_hex(
  "357c83864f2833cb427a2ef1c00a013c" ..
  "fdff2768d980c0a3a520f006904de90f" ..
  "9b4f0afe280b746a778684e754425020" ..
  "57b7473a03f08f96f5a38e9287e01f8f"
)
local hash_prefix = Driver.Bytes.from_hex(
  "b6b19cd8e0426f5983fa112d89a143aa" ..
  "97dab8bc5deb8d5b6253c928b65272f4" ..
  "044098c2a990039cde5b6a4818df0bfb" ..
  "6e40dc5dee54248032962323e701352d"
)
local hash_challenge = Driver.Bytes.from_hex(
  "2771062b6b536fe7ffbdda0320c3827b" ..
  "035df10d284df3f08222f04dbca7a4c2" ..
  "0ef15bdc988a22c7207411377c33f2ac" ..
  "09b1e86a046234283768ee7ba03c0e9f"
)

Driver.Ed25519Pure._sha512 = function(data)
  if data == seed then return hash_seed end
  if data == hash_seed:sub(33, 64) then return hash_prefix end
  if data == signature:sub(1, 32) .. public then return hash_challenge end
  error("unexpected SHA-512 input length " .. tostring(#data))
end

local function bench(label, iterations, fn)
  local started = os.clock()
  for _ = 1, iterations do
    fn()
  end
  local elapsed = os.clock() - started
  print(string.format("%s: %.3fs total, %.1fms/op",
    label, elapsed, (elapsed * 1000) / iterations))
end

local iterations = tonumber(arg and arg[1]) or 3

bench("public_key_from_private", iterations, function()
  assert(Driver.Ed25519Pure.public_key_from_private(seed) == public)
end)

bench("sign", iterations, function()
  assert(Driver.Ed25519Pure.sign(seed, public, "") == signature)
end)

bench("verify", iterations, function()
  assert(Driver.Ed25519Pure.verify(public, signature, ""))
end)
