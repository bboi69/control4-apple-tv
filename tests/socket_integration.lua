local socket = require("socket")
local Driver = dofile("driver.lua")

local function assert_eq(actual, expected, label)
  if actual ~= expected then
    error(string.format("%s: expected %s, got %s", label or "assert_eq", tostring(expected), tostring(actual)), 2)
  end
end

local function bytes_range(first_value, last_value)
  local out = {}
  for value = first_value, last_value do
    out[#out + 1] = string.char(value)
  end
  return table.concat(out)
end

local function read_exact(conn, length)
  local data, err, partial = conn:receive(length)
  if not data then
    error("socket read failed: " .. tostring(err) .. " partial=" .. tostring(partial))
  end
  return data
end

local function read_frame(conn)
  local header = read_exact(conn, 4)
  local frame_type = header:byte(1)
  local length = header:byte(2) * 65536 + header:byte(3) * 256 + header:byte(4)
  return frame_type, read_exact(conn, length), header
end

local function decode_encrypted_message(session, frame_type, payload)
  assert_eq(frame_type, Driver.CompanionFrame.E_OPACK, "encrypted OPACK frame type")
  local frame = string.char(frame_type) .. Driver.Bytes.u24be(#payload) .. payload
  local decoded = session:try_decode(frame)
  return Driver.OPACK.decode(decoded.payload)
end

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
    return encrypted_response, "shared-secret"
  end,
  hkdf_sha512 = function(_, info)
    if info == "ClientEncrypt-main" then
      return "output-key"
    end
    if info == "ServerEncrypt-main" then
      return "input-key"
    end
    error("unexpected hkdf info: " .. tostring(info))
  end,
  encrypt = function(output_key, plaintext, aad, nonce)
    assert_eq(output_key, "output-key", "encrypt key")
    assert_eq(#aad, 4, "encrypt aad length")
    assert_eq(#nonce, 12, "encrypt nonce length")
    return plaintext .. string.rep("\0", 16)
  end,
  decrypt = function(input_key, ciphertext)
    assert_eq(input_key, "input-key", "decrypt key")
    return ciphertext:sub(1, #ciphertext - 16)
  end,
}

local server = assert(socket.bind("127.0.0.1", 0))
local host, port = assert(server:getsockname())
server:settimeout(2)

local transport = assert(socket.tcp())
transport:settimeout(2)
assert(transport:connect(host, port))
local accepted = assert(server:accept())
accepted:settimeout(2)

local states = {}
local client = Driver.CompanionClient.new({
  host = host,
  port = port,
  credentials = credentials,
  crypto = fake_crypto,
  transport = transport,
  on_state = function(state)
    states[#states + 1] = state
  end,
})

client:connect()
assert_eq(states[1], "CONNECTED", "connected state")
assert_eq(states[2], "PAIR_VERIFY_STARTED", "pair verify state")

local frame_type, payload = read_frame(accepted)
assert_eq(frame_type, Driver.CompanionFrame.PV_START, "pair verify start frame type")
local tlv = Driver.PairVerify.decode_pairing_data(payload)
assert_eq(tlv[6], string.char(0x01), "pair verify start seq")
assert_eq(tlv[3], public_key, "pair verify start public key")

local response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
  { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({
    { 3, server_public_key },
    { 5, encrypted_challenge },
  })) },
}))
local response_frame = Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, response_payload)
assert(accepted:send(response_frame))

client:receive(read_exact(transport, #response_frame))
assert_eq(states[3], "PAIR_VERIFY_M3_SENT", "pair verify m3 state")

frame_type, payload = read_frame(accepted)
assert_eq(frame_type, Driver.CompanionFrame.PV_NEXT, "pair verify next frame type")
tlv = Driver.PairVerify.decode_pairing_data(payload)
assert_eq(tlv[6], string.char(0x03), "pair verify next seq")
assert_eq(tlv[5], encrypted_response, "pair verify next encrypted response")

local ack_payload = Driver.OPACK.encode(Driver.OPACK.dict({
  { "_pd", Driver.OPACK.bytes(Driver.TLV8.encode_ordered({ { 6, string.char(0x04) } })) },
}))
local ack_frame = Driver.CompanionFrame.encode(Driver.CompanionFrame.PV_NEXT, ack_payload)
assert(accepted:send(ack_frame))
client:receive(read_exact(transport, #ack_frame))
assert_eq(states[4], "READY", "ready state")
assert_eq(states[5], "SESSION_STARTING", "session starting state")

frame_type, payload = read_frame(accepted)
local session_start = decode_encrypted_message(client.session, frame_type, payload)
assert_eq(session_start._i, "_sessionStart", "session start identifier")
assert_eq(session_start._c._srvT, "com.apple.tvremoteservices", "session start service")
assert_eq(session_start._c._sid, client.session_local_sid, "session start local sid")

local session_response_payload = Driver.OPACK.encode(Driver.OPACK.dict({
  { "_t", 3 },
  { "_c", Driver.OPACK.dict({ { "_sid", 0x12345678 } }) },
  { "_x", client.session_start_xid },
}))
local session_response_frame = client.session:encode_frame(Driver.CompanionFrame.E_OPACK, session_response_payload)
assert(accepted:send(session_response_frame))
client:receive(read_exact(transport, #session_response_frame))
assert_eq(states[6], "SESSION_ACTIVE", "session active state")

client:launch_app("com.netflix.Netflix")
frame_type, payload = read_frame(accepted)
local launch = decode_encrypted_message(client.session, frame_type, payload)
assert_eq(launch._i, "_launchApp", "launch identifier")
assert_eq(launch._c._bundleID, "com.netflix.Netflix", "launch bundle id")

accepted:close()
transport:close()
server:close()

print("socket integration ok")
