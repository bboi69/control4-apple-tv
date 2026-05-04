-- Self-contained Control4 Apple TV driver scaffold.
-- The goal is to keep the Companion protocol core testable outside Control4.

-- Provide a minimal C4 stub so DCP libraries can be required outside Control4.
-- On real hardware, C4 is provided by the runtime before this file runs (never nil).
-- In local tests it is absent, so we install a sentinel stub.
-- has_c4() checks identity against the sentinel so tests can temporarily swap in
-- a fake C4 table and have it treated as real.
local _C4_STUB
if C4 == nil then
  _C4_STUB = {
    GetDriverConfigInfo = function() return "Apple TV Companion" end,
    GetDeviceID = function() return 0 end,
  }
  C4 = _C4_STUB
end

require('drivers-common-public.global.lib')
require('drivers-common-public.global.timer')
require('drivers-common-public.global.handlers')

local Driver = {
  VERSION = "0.1.25-dev",
}

local function has_c4()
  return C4 ~= nil and C4 ~= _C4_STUB
end

local Log = {}

function Log.debug(message)
  if has_c4() and not DEBUGPRINT then
    return
  end
  local line = "[AppleTV] [DEBUG] " .. tostring(message)
  if has_c4() and C4.DebugLog then
    print(line)
    C4:DebugLog(line)
  else
    print(line)
  end
end

function Log.error(message)
  local line = "[AppleTV] [ERROR] " .. tostring(message)
  if has_c4() and C4.ErrorLog then
    print(line)
    C4:ErrorLog(line)
  else
    io.stderr:write(line .. "\n")
  end
end

local Bytes = {}

function Bytes.byte(value)
  assert(value >= 0 and value <= 255, "byte out of range")
  return string.char(value)
end

function Bytes.u24be(value)
  assert(value >= 0 and value <= 0xFFFFFF, "u24 out of range")
  local b1 = math.floor(value / 0x10000) % 0x100
  local b2 = math.floor(value / 0x100) % 0x100
  local b3 = value % 0x100
  return string.char(b1, b2, b3)
end

function Bytes.read_u24be(data, offset)
  offset = offset or 1
  local b1, b2, b3 = data:byte(offset, offset + 2)
  assert(b1 and b2 and b3, "not enough bytes for u24")
  return b1 * 0x10000 + b2 * 0x100 + b3
end

function Bytes.hex(data)
  return (data:gsub(".", function(ch)
    return string.format("%02x", ch:byte())
  end))
end

function Bytes.from_hex(hex)
  hex = hex:gsub("%s+", "")
  assert(#hex % 2 == 0, "hex string must have even length")
  return (hex:gsub("..", function(pair)
    return string.char(tonumber(pair, 16))
  end))
end

function Bytes.uint_le(value, length)
  assert(value >= 0 and value == math.floor(value), "integer required")
  local out = {}
  for i = 0, length - 1 do
    out[#out + 1] = string.char(math.floor(value / (0x100 ^ i)) % 0x100)
  end
  return table.concat(out)
end

local TLV8 = {}

function TLV8.encode_ordered(entries)
  local out = {}
  for _, entry in ipairs(entries) do
    local tag = entry[1]
    local value = entry[2]
    assert(type(tag) == "number" and tag >= 0 and tag <= 255, "TLV tag must be a byte")
    if type(value) == "number" then
      value = string.char(value)
    end
    assert(type(value) == "string", "TLV value must be a string or byte-sized number")

    local index = 1
    repeat
      local chunk = value:sub(index, index + 254)
      out[#out + 1] = string.char(tag, #chunk) .. chunk
      index = index + 255
    until index > #value
  end
  return table.concat(out)
end

function TLV8.encode(fields)
  local tags = {}
  for tag in pairs(fields) do
    tags[#tags + 1] = tag
  end
  table.sort(tags)

  local entries = {}
  for _, tag in ipairs(tags) do
    entries[#entries + 1] = { tag, fields[tag] }
  end
  return TLV8.encode_ordered(entries)
end

function TLV8.decode(data)
  local fields = {}
  local index = 1
  while index <= #data do
    local tag, length = data:byte(index, index + 1)
    assert(tag and length, "truncated TLV")
    local value_start = index + 2
    local value_end = value_start + length - 1
    assert(value_end <= #data, "truncated TLV value")
    local value = data:sub(value_start, value_end)
    fields[tag] = (fields[tag] or "") .. value
    index = value_end + 1
  end
  return fields
end

local CompanionFrame = {
  PS_START = 0x03,
  PS_NEXT = 0x04,
  PV_START = 0x05,
  PV_NEXT = 0x06,
  U_OPACK = 0x07,
  E_OPACK = 0x08,
}

function CompanionFrame.encode(frame_type, payload)
  assert(type(frame_type) == "number", "frame_type must be a number")
  assert(type(payload) == "string", "payload must be a string")
  return string.char(frame_type) .. Bytes.u24be(#payload) .. payload
end

function CompanionFrame.name(frame_type)
  local names = {
    [CompanionFrame.PS_START] = "PS_START",
    [CompanionFrame.PS_NEXT] = "PS_NEXT",
    [CompanionFrame.PV_START] = "PV_START",
    [CompanionFrame.PV_NEXT] = "PV_NEXT",
    [CompanionFrame.U_OPACK] = "U_OPACK",
    [CompanionFrame.E_OPACK] = "E_OPACK",
  }
  return names[frame_type] or ("0x" .. string.format("%02x", tonumber(frame_type) or 0))
end

function CompanionFrame.try_decode(buffer)
  if #buffer < 4 then
    return nil, buffer
  end
  local frame_type = buffer:byte(1)
  local length = Bytes.read_u24be(buffer, 2)
  local frame_end = 4 + length
  if #buffer < frame_end then
    return nil, buffer
  end
  local payload = buffer:sub(5, frame_end)
  local rest = buffer:sub(frame_end + 1)
  return {
    frame_type = frame_type,
    length = length,
    payload = payload,
  }, rest
end

local OPACK = {}

function OPACK.bytes(data)
  assert(type(data) == "string", "OPACK bytes data must be a string")
  return {
    __opack_type = "bytes",
    data = data,
  }
end

function OPACK.dict(entries)
  assert(type(entries) == "table", "OPACK dict entries must be a table")
  return {
    __opack_type = "dict",
    entries = entries,
  }
end

function OPACK.array(elements)
  assert(type(elements) == "table", "OPACK array elements must be a table")
  return { __opack_type = "array", elements = elements }
end

function OPACK.int64(high32, low32)
  -- Stores a 64-bit integer as two 32-bit halves to avoid Lua double precision loss
  -- (2^53 mantissa bits can't represent arbitrary 64-bit values).
  -- Used for the combined Companion session SID from remote/local sid halves.
  assert(type(high32) == "number" and high32 >= 0 and high32 <= 0xFFFFFFFF, "int64 high32 out of range")
  assert(type(low32) == "number" and low32 >= 0 and low32 <= 0xFFFFFFFF, "int64 low32 out of range")
  return { __opack_type = "int64", high32 = high32, low32 = low32 }
end

local function opack_ordered_entries(value)
  local keys = {}
  for key in pairs(value) do
    keys[#keys + 1] = key
  end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)

  local entries = {}
  for _, key in ipairs(keys) do
    entries[#entries + 1] = { key, value[key] }
  end
  return entries
end

-- Minimal OPACK subset based on pyatv's public protocol documentation:
--   0x01 true, 0x02 false, 0x08+n small integer, 0x40+n short string,
--   0x70+n short bytes, 0xE0+n dictionary with n key/value pairs.
-- This is intentionally small. Golden-vector tests against pyatv must pass
-- before expanding this for real Apple TV traffic.
local function opack_reuse_or_store(packed_bytes, object_list)
  if #packed_bytes <= 1 then
    return packed_bytes
  end

  for index, existing in ipairs(object_list) do
    if existing == packed_bytes then
      local object_index = index - 1
      if object_index < 0x21 then
        return string.char(0xA0 + object_index)
      end
      if object_index <= 0xFF then
        return string.char(0xC1, object_index)
      end
      if object_index <= 0xFFFF then
        return string.char(0xC2, object_index % 0x100, math.floor(object_index / 0x100) % 0x100)
      end
      error("OPACK pointer index too large")
    end
  end

  object_list[#object_list + 1] = packed_bytes
  return packed_bytes
end

function OPACK._encode(value, object_list)
  local value_type = type(value)
  local packed_bytes

  if value_type == "table" and value.__opack_type == "bytes" then
    if #value.data <= 0x20 then
      packed_bytes = string.char(0x70 + #value.data) .. value.data
    elseif #value.data <= 0xFF then
      packed_bytes = string.char(0x91, #value.data) .. value.data
    elseif #value.data <= 0xFFFF then
      packed_bytes = string.char(0x92, #value.data % 0x100, math.floor(#value.data / 0x100) % 0x100) .. value.data
    elseif #value.data <= 0xFFFFFFFF then
      local out = { string.char(0x93) }
      for i = 0, 3 do
        out[#out + 1] = string.char(math.floor(#value.data / (0x100 ^ i)) % 0x100)
      end
      out[#out + 1] = value.data
      packed_bytes = table.concat(out)
    else
      error("OPACK byte string is too large")
    end
    return opack_reuse_or_store(packed_bytes, object_list)
  end

  if value_type == "table" and value.__opack_type == "dict" then
    assert(#value.entries <= 15, "only small OPACK dictionaries are implemented")
    local out = { string.char(0xE0 + #value.entries) }
    for _, entry in ipairs(value.entries) do
      out[#out + 1] = OPACK._encode(entry[1], object_list)
      out[#out + 1] = OPACK._encode(entry[2], object_list)
    end
    packed_bytes = table.concat(out)
    return opack_reuse_or_store(packed_bytes, object_list)
  end

  if value_type == "table" and value.__opack_type == "array" then
    local n = #value.elements
    local out
    if n < 15 then
      out = { string.char(0xD0 + n) }
    else
      out = { string.char(0xDF) }
    end
    for _, elem in ipairs(value.elements) do
      out[#out + 1] = OPACK._encode(elem, object_list)
    end
    if n >= 15 then out[#out + 1] = string.char(0x03) end
    packed_bytes = table.concat(out)
    return opack_reuse_or_store(packed_bytes, object_list)
  end

  if value_type == "table" and value.__opack_type == "int64" then
    packed_bytes = string.char(0x33)
      .. Bytes.uint_le(value.low32, 4)
      .. Bytes.uint_le(value.high32, 4)
    return opack_reuse_or_store(packed_bytes, object_list)
  end

  if value_type == "boolean" then
    return value and string.char(0x01) or string.char(0x02)
  end

  if value_type == "number" then
    assert(value >= 0 and value == math.floor(value), "unsupported OPACK integer")
    if value < 0x28 then
      return string.char(0x08 + value)
    end
    if value <= 0xFF then
      packed_bytes = string.char(0x30, value)
      return opack_reuse_or_store(packed_bytes, object_list)
    end
    if value <= 0xFFFF then
      packed_bytes = string.char(0x31, value % 0x100, math.floor(value / 0x100) % 0x100)
      return opack_reuse_or_store(packed_bytes, object_list)
    end
    if value <= 0xFFFFFFFF then
      local out = { string.char(0x32) }
      for i = 0, 3 do
        out[#out + 1] = string.char(math.floor(value / (0x100 ^ i)) % 0x100)
      end
      packed_bytes = table.concat(out)
      return opack_reuse_or_store(packed_bytes, object_list)
    end
    local out = { string.char(0x33) }
    for i = 0, 7 do
      out[#out + 1] = string.char(math.floor(value / (0x100 ^ i)) % 0x100)
    end
    packed_bytes = table.concat(out)
    return opack_reuse_or_store(packed_bytes, object_list)
  end

  if value_type == "string" then
    if #value <= 0x20 then
      packed_bytes = string.char(0x40 + #value) .. value
      return opack_reuse_or_store(packed_bytes, object_list)
    end
    if #value <= 0xFF then
      packed_bytes = string.char(0x61, #value) .. value
      return opack_reuse_or_store(packed_bytes, object_list)
    end
    if #value <= 0xFFFF then
      packed_bytes = string.char(0x62, #value % 0x100, math.floor(#value / 0x100) % 0x100) .. value
      return opack_reuse_or_store(packed_bytes, object_list)
    end
    error("OPACK string is too large")
  end

  if value_type == "table" then
    local entries = opack_ordered_entries(value)
    assert(#entries <= 15, "only small OPACK dictionaries are implemented")

    local out = { string.char(0xE0 + #entries) }
    for _, entry in ipairs(entries) do
      out[#out + 1] = OPACK._encode(entry[1], object_list)
      out[#out + 1] = OPACK._encode(entry[2], object_list)
    end
    packed_bytes = table.concat(out)
    return opack_reuse_or_store(packed_bytes, object_list)
  end

  error("unsupported OPACK type: " .. value_type)
end

function OPACK.encode(value)
  return OPACK._encode(value, {})
end

local function decode_ieee754(sign, exponent, fraction, exponent_bits, fraction_bits, bias)
  local sign_multiplier = sign == 1 and -1 or 1
  local max_exponent = (2 ^ exponent_bits) - 1
  if exponent == max_exponent then
    if fraction == 0 then
      return sign_multiplier * math.huge
    end
    return 0 / 0
  end
  if exponent == 0 then
    if fraction == 0 then
      return sign_multiplier * 0
    end
    return sign_multiplier * (fraction / (2 ^ fraction_bits)) * (2 ^ (1 - bias))
  end
  return sign_multiplier * (1 + fraction / (2 ^ fraction_bits)) * (2 ^ (exponent - bias))
end

local function decode_float32_le(data, index)
  local b1, b2, b3, b4 = data:byte(index, index + 3)
  assert(b1 and b2 and b3 and b4, "truncated OPACK float32")
  local raw = b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
  local sign = math.floor(raw / 0x80000000)
  local exponent = math.floor(raw / 0x800000) % 0x100
  local fraction = raw % 0x800000
  return decode_ieee754(sign, exponent, fraction, 8, 23, 127)
end

local function decode_float64_le(data, index)
  local b = { data:byte(index, index + 7) }
  assert(#b == 8, "truncated OPACK float64")
  local low32 = b[1] + b[2] * 0x100 + b[3] * 0x10000 + b[4] * 0x1000000
  local high32 = b[5] + b[6] * 0x100 + b[7] * 0x10000 + b[8] * 0x1000000
  local sign = math.floor(high32 / 0x80000000)
  local exponent = math.floor(high32 / 0x100000) % 0x800
  local high_fraction = high32 % 0x100000
  local fraction = high_fraction * 0x100000000 + low32
  return decode_ieee754(sign, exponent, fraction, 11, 52, 1023)
end

local function opack_decode_at(data, index, object_list)
  object_list = object_list or {}
  local marker = data:byte(index)
  assert(marker, "truncated OPACK")

  if marker == 0x01 then
    return true, index + 1
  end
  if marker == 0x02 then
    return false, index + 1
  end
  if marker == 0x04 then
    return nil, index + 1
  end
  if marker == 0x05 then
    local value = data:sub(index + 1, index + 16)
    assert(#value == 16, "truncated OPACK UUID")
    local hex = Bytes.hex(value)
    local uuid = hex:sub(1, 8) .. "-" ..
      hex:sub(9, 12) .. "-" ..
      hex:sub(13, 16) .. "-" ..
      hex:sub(17, 20) .. "-" ..
      hex:sub(21, 32)
    object_list[#object_list + 1] = uuid
    return uuid, index + 17
  end
  if marker == 0x06 then
    local value = 0
    for i = 0, 7 do
      local byte = data:byte(index + 1 + i)
      assert(byte, "truncated OPACK absolute time")
      value = value + byte * (0x100 ^ i)
    end
    object_list[#object_list + 1] = value
    return value, index + 9
  end
  if marker >= 0x08 and marker <= 0x2F then
    return marker - 0x08, index + 1
  end
  if marker == 0x35 then
    local value = decode_float32_le(data, index + 1)
    object_list[#object_list + 1] = value
    return value, index + 5
  end
  if marker == 0x36 then
    local value = decode_float64_le(data, index + 1)
    object_list[#object_list + 1] = value
    return value, index + 9
  end
  if marker >= 0x30 and marker <= 0x33 then
    local length = 2 ^ (marker - 0x30)
    local value = 0
    for i = 0, length - 1 do
      local byte = data:byte(index + 1 + i)
      assert(byte, "truncated OPACK integer")
      value = value + byte * (0x100 ^ i)
    end
    return value, index + 1 + length
  end
  if marker >= 0x40 and marker <= 0x60 then
    local length = marker - 0x40
    local value = data:sub(index + 1, index + length)
    assert(#value == length, "truncated OPACK string")
    if value ~= "" then object_list[#object_list + 1] = value end
    return value, index + 1 + length
  end
  if marker > 0x60 and marker <= 0x64 then
    local length_bytes = marker - 0x60
    local length = 0
    for i = 0, length_bytes - 1 do
      local byte = data:byte(index + 1 + i)
      assert(byte, "truncated OPACK string length")
      length = length + byte * (0x100 ^ i)
    end
    local value_start = index + 1 + length_bytes
    local value = data:sub(value_start, value_start + length - 1)
    assert(#value == length, "truncated OPACK string")
    if value ~= "" then object_list[#object_list + 1] = value end
    return value, value_start + length
  end
  if marker >= 0x70 and marker <= 0x90 then
    local length = marker - 0x70
    local value = data:sub(index + 1, index + length)
    assert(#value == length, "truncated OPACK bytes")
    local wrapped = OPACK.bytes(value)
    if #value > 0 then object_list[#object_list + 1] = wrapped end
    return wrapped, index + 1 + length
  end
  if marker >= 0x91 and marker <= 0x94 then
    local length_bytes = 2 ^ (marker - 0x91)
    local length = 0
    for i = 0, length_bytes - 1 do
      local byte = data:byte(index + 1 + i)
      assert(byte, "truncated OPACK bytes length")
      length = length + byte * (0x100 ^ i)
    end
    local value_start = index + 1 + length_bytes
    local value = data:sub(value_start, value_start + length - 1)
    assert(#value == length, "truncated OPACK bytes")
    local wrapped = OPACK.bytes(value)
    object_list[#object_list + 1] = wrapped
    return wrapped, value_start + length
  end
  if marker >= 0xD0 and marker <= 0xDF then
    local count = marker - 0xD0
    local result = {}
    index = index + 1
    if count == 0x0F then  -- endless array terminated by 0x03
      while data:byte(index) ~= 0x03 do
        local elem
        elem, index = opack_decode_at(data, index, object_list)
        result[#result + 1] = elem
      end
      index = index + 1
    else
      for _ = 1, count do
        local elem
        elem, index = opack_decode_at(data, index, object_list)
        result[#result + 1] = elem
      end
    end
    return result, index
  end

  if marker >= 0xE0 and marker <= 0xEF then
    local count = marker - 0xE0
    local result = {}
    index = index + 1
    if count == 0x0F then  -- endless dictionary terminated by 0x03
      while data:byte(index) ~= 0x03 do
        local key
        key, index = opack_decode_at(data, index, object_list)
        local value
        value, index = opack_decode_at(data, index, object_list)
        result[key] = value
      end
      index = index + 1
    else
      for _ = 1, count do
        local key
        key, index = opack_decode_at(data, index, object_list)
        local value
        value, index = opack_decode_at(data, index, object_list)
        result[key] = value
      end
    end
    return result, index
  end

  if marker >= 0xA0 and marker <= 0xC0 then
    local object_index = marker - 0xA0 + 1
    local value = object_list[object_index]
    assert(value ~= nil, "invalid OPACK object reference")
    return value, index + 1
  end

  if marker >= 0xC1 and marker <= 0xC4 then
    local length_bytes = marker - 0xC0
    local object_index = 0
    for i = 0, length_bytes - 1 do
      local byte = data:byte(index + 1 + i)
      assert(byte, "truncated OPACK object reference")
      object_index = object_index + byte * (0x100 ^ i)
    end
    local value = object_list[object_index + 1]
    assert(value ~= nil, "invalid OPACK object reference")
    return value, index + 1 + length_bytes
  end

  error(string.format("unsupported OPACK marker 0x%02x", marker))
end

function OPACK.decode(data)
  local value, index = opack_decode_at(data, 1, {})
  assert(index == #data + 1, "trailing OPACK bytes")
  return value
end

-- BigInt: arbitrary-precision unsigned integers for SRP.
-- Base 2^16. Limbs stored little-endian. Montgomery multiplication for fast modpow.
local BigInt = {}
BigInt.BASE = 65536
BigInt.BITS = 16

function BigInt.from_number(n)
  assert(type(n) == "number" and n >= 0 and n == math.floor(n))
  if n == 0 then return {0} end
  local B, limbs = BigInt.BASE, {}
  while n > 0 do limbs[#limbs + 1] = n % B; n = math.floor(n / B) end
  return limbs
end

function BigInt.from_bytes_be(s)
  local n, limbs = #s, {}
  local i = n
  while i >= 2 do
    limbs[#limbs + 1] = s:byte(i - 1) * 256 + s:byte(i)
    i = i - 2
  end
  if i == 1 then limbs[#limbs + 1] = s:byte(1) end
  while #limbs > 1 and limbs[#limbs] == 0 do limbs[#limbs] = nil end
  if #limbs == 0 then return {0} end
  return limbs
end

function BigInt.to_bytes_be(v, len)
  local bytes = {}
  for i = 1, #v do
    bytes[2 * i - 1] = v[i] % 256
    bytes[2 * i] = math.floor(v[i] / 256)
  end
  while #bytes > 0 and bytes[#bytes] == 0 do bytes[#bytes] = nil end
  while #bytes < len do bytes[#bytes + 1] = 0 end
  local out = {}
  for i = len, 1, -1 do out[#out + 1] = string.char(bytes[i] or 0) end
  return table.concat(out)
end

function BigInt.to_minimal_bytes_be(v)
  if BigInt.is_zero(v) then
    return string.char(0)
  end

  local bytes = {}
  for i = 1, #v do
    bytes[2 * i - 1] = v[i] % 256
    bytes[2 * i] = math.floor(v[i] / 256)
  end
  while #bytes > 0 and bytes[#bytes] == 0 do bytes[#bytes] = nil end
  local out = {}
  for i = #bytes, 1, -1 do out[#out + 1] = string.char(bytes[i]) end
  return table.concat(out)
end

local function bi_trim(v)
  while #v > 1 and v[#v] == 0 do v[#v] = nil end
end

function BigInt.is_zero(v) return #v == 1 and v[1] == 0 end

function BigInt.compare(a, b)
  local na, nb = #a, #b
  if na ~= nb then return na < nb and -1 or 1 end
  for i = na, 1, -1 do
    if a[i] ~= b[i] then return a[i] < b[i] and -1 or 1 end
  end
  return 0
end

function BigInt.add(a, b)
  local B, result, carry = BigInt.BASE, {}, 0
  local n = math.max(#a, #b)
  for i = 1, n do
    local s = (a[i] or 0) + (b[i] or 0) + carry
    result[i] = s % B; carry = math.floor(s / B)
  end
  if carry > 0 then result[n + 1] = carry end
  return result
end

function BigInt.sub(a, b)
  local B, result, borrow = BigInt.BASE, {}, 0
  for i = 1, #a do
    local d = (a[i] or 0) - (b[i] or 0) - borrow
    if d < 0 then d = d + B; borrow = 1 else borrow = 0 end
    result[i] = d
  end
  bi_trim(result)
  if #result == 0 then return {0} end
  return result
end

function BigInt.mul(a, b)
  local B = BigInt.BASE
  local na, nb = #a, #b
  local result = {}
  for i = 1, na + nb do result[i] = 0 end
  for i = 1, na do
    local carry, ai = 0, a[i]
    for j = 1, nb do
      local p = ai * b[j] + result[i + j - 1] + carry
      result[i + j - 1] = p % B; carry = math.floor(p / B)
    end
    local k = i + nb
    while carry > 0 do
      local v = result[k] + carry; result[k] = v % B; carry = math.floor(v / B); k = k + 1
    end
  end
  bi_trim(result); return result
end

function BigInt.bit_length(v)
  if #v == 1 and v[1] == 0 then return 0 end
  local top = v[#v]
  local bits = (#v - 1) * BigInt.BITS
  while top > 0 do bits = bits + 1; top = math.floor(top / 2) end
  return bits
end

function BigInt.bit_at(v, bit_index)
  local limb = v[math.floor(bit_index / BigInt.BITS) + 1] or 0
  local mask = 2 ^ (bit_index % BigInt.BITS)
  return math.floor(limb / mask) % 2
end

local function bi_shr1(v)
  local B, carry, result = BigInt.BASE, 0, {}
  for i = #v, 1, -1 do
    local val = v[i] + carry * B
    result[i] = math.floor(val / 2); carry = val % 2
  end
  bi_trim(result)
  if #result == 0 then return {0} end
  return result
end

-- Naive shift-and-subtract mod. O(bit_diff * limbs). Used for init only.
function BigInt.mod(a, n)
  if BigInt.compare(a, n) < 0 then return a end
  local B = BigInt.BASE
  local shift = BigInt.bit_length(a) - BigInt.bit_length(n)
  if shift < 0 then return a end
  local lshift, bshift = math.floor(shift / BigInt.BITS), shift % BigInt.BITS
  local factor = 2 ^ bshift
  local shifted = {}
  for i = 1, lshift do shifted[i] = 0 end
  local carry = 0
  for i = 1, #n do
    local val = n[i] * factor + carry
    shifted[i + lshift] = val % B; carry = math.floor(val / B)
  end
  if carry > 0 then shifted[#shifted + 1] = carry end
  local r = {}
  for i = 1, #a do r[i] = a[i] end
  for _ = 0, shift do
    if BigInt.compare(r, shifted) >= 0 then r = BigInt.sub(r, shifted) end
    carry = 0
    for j = #shifted, 1, -1 do
      local val = shifted[j] + carry * B
      shifted[j] = math.floor(val / 2); carry = val % 2
    end
    bi_trim(shifted)
    if #shifted == 0 then shifted = {0} end
  end
  return r
end

-- Montgomery REDC: T * R^{-1} mod N where R = BASE^k.
-- n_prime = -N[1]^{-1} mod BASE. Requires T < N * R.
local function mont_redc(T_in, N, k, n_prime)
  local B = BigInt.BASE
  local t = {}
  for i = 1, 2 * k + 2 do t[i] = T_in[i] or 0 end
  for i = 1, k do
    local m = (t[i] * n_prime) % B
    if m ~= 0 then
      local c = 0
      for j = 1, k do
        local val = t[i + j - 1] + m * N[j] + c
        t[i + j - 1] = val % B; c = math.floor(val / B)
      end
      local idx = i + k
      while c > 0 do
        local val = (t[idx] or 0) + c
        t[idx] = val % B; c = math.floor(val / B); idx = idx + 1
      end
    end
  end
  local result = {}
  for i = 1, k + 1 do result[i] = t[i + k] or 0 end
  bi_trim(result)
  if BigInt.compare(result, N) >= 0 then result = BigInt.sub(result, N) end
  return result
end

-- Montgomery multiply: a * b * R^{-1} mod N (both inputs already in Montgomery domain).
local function mont_mul(a, b, N, k, n_prime)
  return mont_redc(BigInt.mul(a, b), N, k, n_prime)
end

-- Compute R^2 mod N by repeated doubling. R = BASE^k = 2^(BITS*k).
-- Called once per SRP session. Uses simple compare-and-subtract (at most 1 needed per step).
local function compute_r2_mod_n(N, k)
  local B, r = BigInt.BASE, {1}
  for _ = 1, 2 * k * BigInt.BITS do
    local carry, doubled = 0, {}
    for i = 1, #r do
      local val = r[i] * 2 + carry; doubled[i] = val % B; carry = math.floor(val / B)
    end
    if carry > 0 then doubled[#doubled + 1] = carry end
    r = BigInt.compare(doubled, N) >= 0 and BigInt.sub(doubled, N) or doubled
  end
  return r
end

-- Compute n_prime = -N[1]^{-1} mod BASE via Newton's method (Hensel lifting).
local function compute_n_prime(n0)
  local B = BigInt.BASE
  assert(n0 % 2 == 1, "Montgomery requires odd modulus")
  local x = 1
  for _ = 1, 16 do x = x * (2 - n0 * x % B) % B; if x < 0 then x = x + B end end
  assert(n0 * x % B == 1, "n_prime compute failed")
  return (B - x) % B
end

BigInt.compute_n_prime = compute_n_prime
BigInt.compute_r2_mod_n = compute_r2_mod_n

-- Montgomery modular exponentiation. base, exp, N are standard BigInt tables.
function BigInt.mont_modpow(base, exp, N, R2, k, n_prime)
  if BigInt.is_zero(exp) then return {1} end
  local base_hat = mont_mul(base, R2, N, k, n_prime)
  local result_hat = mont_mul({1}, R2, N, k, n_prime)
  local exp_bits = BigInt.bit_length(exp)
  for bit = 0, exp_bits - 1 do
    if BigInt.bit_at(exp, bit) == 1 then
      result_hat = mont_mul(result_hat, base_hat, N, k, n_prime)
    end
    base_hat = mont_mul(base_hat, base_hat, N, k, n_prime)
  end
  local padded = {}
  for i = 1, #result_hat do padded[i] = result_hat[i] end
  for i = #result_hat + 1, 2 * k do padded[i] = 0 end
  return mont_redc(padded, N, k, n_prime)
end

local Bit32 = {}
do
  if bit32 then
    Bit32.band = bit32.band
    Bit32.bor = bit32.bor
    Bit32.bxor = bit32.bxor
    Bit32.lshift = bit32.lshift
    Bit32.rshift = bit32.rshift
  elseif bit then
    Bit32.band = bit.band
    Bit32.bor = bit.bor
    Bit32.bxor = bit.bxor
    Bit32.lshift = bit.lshift
    Bit32.rshift = bit.rshift
  else
    local function bitop(a, b, op)
      local result, bit = 0, 1
      a = a % 0x100000000
      b = b % 0x100000000
      for _ = 0, 31 do
        local aa, bb = a % 2, b % 2
        if op(aa, bb) then result = result + bit end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
      end
      return result
    end
    Bit32.band = function(a, b) return bitop(a, b, function(x, y) return x == 1 and y == 1 end) end
    Bit32.bor = function(a, b) return bitop(a, b, function(x, y) return x == 1 or y == 1 end) end
    Bit32.bxor = function(a, b) return bitop(a, b, function(x, y) return x ~= y end) end
    Bit32.lshift = function(a, n) return (a * (2 ^ n)) % 0x100000000 end
    Bit32.rshift = function(a, n) return math.floor((a % 0x100000000) / (2 ^ n)) end
  end
end

function Bit32.add(a, b)
  return (a + b) % 0x100000000
end

function Bit32.rotl(a, n)
  return Bit32.bor(Bit32.lshift(a, n), Bit32.rshift(a, 32 - n))
end

local ChaCha20Poly1305Pure = {}
local _CHACHA_CONST = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }
local _POLY1305_P = BigInt.from_bytes_be(Bytes.from_hex("03fffffffffffffffffffffffffffffffb"))
local _POLY1305_2_128 = BigInt.from_bytes_be(Bytes.from_hex("0100000000000000000000000000000000"))

local function _read_u32_le(s, offset)
  local b1, b2, b3, b4 = s:byte(offset, offset + 3)
  return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
end

local function _write_u32_le(v)
  v = v % 0x100000000
  return string.char(
    v % 0x100,
    math.floor(v / 0x100) % 0x100,
    math.floor(v / 0x10000) % 0x100,
    math.floor(v / 0x1000000) % 0x100
  )
end

local function _reverse_bytes(s)
  local out = {}
  for i = #s, 1, -1 do out[#out + 1] = s:sub(i, i) end
  return table.concat(out)
end

local function _bigint_from_le(s)
  return BigInt.from_bytes_be(_reverse_bytes(s))
end

local function _bigint_to_le(v, len)
  return _reverse_bytes(BigInt.to_bytes_be(v, len))
end

local function _quarter_round(x, a, b, c, d)
  x[a] = Bit32.add(x[a], x[b]); x[d] = Bit32.rotl(Bit32.bxor(x[d], x[a]), 16)
  x[c] = Bit32.add(x[c], x[d]); x[b] = Bit32.rotl(Bit32.bxor(x[b], x[c]), 12)
  x[a] = Bit32.add(x[a], x[b]); x[d] = Bit32.rotl(Bit32.bxor(x[d], x[a]), 8)
  x[c] = Bit32.add(x[c], x[d]); x[b] = Bit32.rotl(Bit32.bxor(x[b], x[c]), 7)
end

function ChaCha20Poly1305Pure.block(key, counter, nonce)
  assert(#key == 32 and #nonce == 12, "ChaCha20 key/nonce length invalid")
  local state = {
    _CHACHA_CONST[1], _CHACHA_CONST[2], _CHACHA_CONST[3], _CHACHA_CONST[4],
    _read_u32_le(key, 1), _read_u32_le(key, 5), _read_u32_le(key, 9), _read_u32_le(key, 13),
    _read_u32_le(key, 17), _read_u32_le(key, 21), _read_u32_le(key, 25), _read_u32_le(key, 29),
    counter % 0x100000000, _read_u32_le(nonce, 1), _read_u32_le(nonce, 5), _read_u32_le(nonce, 9),
  }
  local x = {}
  for i = 1, 16 do x[i] = state[i] end
  for _ = 1, 10 do
    _quarter_round(x, 1, 5, 9, 13)
    _quarter_round(x, 2, 6, 10, 14)
    _quarter_round(x, 3, 7, 11, 15)
    _quarter_round(x, 4, 8, 12, 16)
    _quarter_round(x, 1, 6, 11, 16)
    _quarter_round(x, 2, 7, 12, 13)
    _quarter_round(x, 3, 8, 9, 14)
    _quarter_round(x, 4, 5, 10, 15)
  end
  local out = {}
  for i = 1, 16 do out[i] = _write_u32_le(Bit32.add(x[i], state[i])) end
  return table.concat(out)
end

function ChaCha20Poly1305Pure.chacha20_xor(key, nonce, initial_counter, data)
  local out, pos, counter = {}, 1, initial_counter
  while pos <= #data do
    local block = ChaCha20Poly1305Pure.block(key, counter, nonce)
    local n = math.min(64, #data - pos + 1)
    local chunk = {}
    for i = 1, n do
      chunk[i] = string.char(Bit32.bxor(data:byte(pos + i - 1), block:byte(i)))
    end
    out[#out + 1] = table.concat(chunk)
    pos = pos + n
    counter = (counter + 1) % 0x100000000
  end
  return table.concat(out)
end

local function _poly1305_clamp(r)
  local b = { r:byte(1, 16) }
  b[4] = Bit32.band(b[4], 15)
  b[8] = Bit32.band(b[8], 15)
  b[12] = Bit32.band(b[12], 15)
  b[16] = Bit32.band(b[16], 15)
  b[5] = Bit32.band(b[5], 252)
  b[9] = Bit32.band(b[9], 252)
  b[13] = Bit32.band(b[13], 252)
  local out = {}
  for i = 1, 16 do out[i] = string.char(b[i]) end
  return table.concat(out)
end

local function _pad16(s)
  local rem = #s % 16
  if rem == 0 then return "" end
  return string.rep("\0", 16 - rem)
end

function ChaCha20Poly1305Pure.poly1305_mac(msg, one_time_key)
  local r = _bigint_from_le(_poly1305_clamp(one_time_key:sub(1, 16)))
  local s = _bigint_from_le(one_time_key:sub(17, 32))
  local acc = BigInt.from_number(0)
  local pos = 1
  while pos <= #msg do
    local block = msg:sub(pos, pos + 15)
    local n = _bigint_from_le(block .. "\1")
    acc = BigInt.mod(BigInt.mul(BigInt.add(acc, n), r), _POLY1305_P)
    pos = pos + 16
  end
  return _bigint_to_le(BigInt.mod(BigInt.add(acc, s), _POLY1305_2_128), 16)
end

function ChaCha20Poly1305Pure.encrypt(key, nonce, plaintext, aad)
  aad = aad or ""
  local otk = ChaCha20Poly1305Pure.block(key, 0, nonce):sub(1, 32)
  local ciphertext = ChaCha20Poly1305Pure.chacha20_xor(key, nonce, 1, plaintext)
  local mac_data = aad .. _pad16(aad) .. ciphertext .. _pad16(ciphertext) ..
    Bytes.uint_le(#aad, 8) .. Bytes.uint_le(#ciphertext, 8)
  return ciphertext .. ChaCha20Poly1305Pure.poly1305_mac(mac_data, otk)
end

function ChaCha20Poly1305Pure.auth_tag(key, nonce, ciphertext, aad)
  aad = aad or ""
  local otk = ChaCha20Poly1305Pure.block(key, 0, nonce):sub(1, 32)
  local mac_data = aad .. _pad16(aad) .. ciphertext .. _pad16(ciphertext) ..
    Bytes.uint_le(#aad, 8) .. Bytes.uint_le(#ciphertext, 8)
  return ChaCha20Poly1305Pure.poly1305_mac(mac_data, otk)
end

function ChaCha20Poly1305Pure.decrypt(key, nonce, ciphertext_and_tag, aad)
  assert(#ciphertext_and_tag >= 16, "ChaCha20-Poly1305 ciphertext is missing auth tag")
  local ciphertext = ciphertext_and_tag:sub(1, #ciphertext_and_tag - 16)
  local tag = ciphertext_and_tag:sub(#ciphertext_and_tag - 15)
  local expected = ChaCha20Poly1305Pure.auth_tag(key, nonce, ciphertext, aad or "")
  assert(tag == expected, "ChaCha20-Poly1305 authentication failed")
  return ChaCha20Poly1305Pure.chacha20_xor(key, nonce, 1, ciphertext)
end

-- SRP-6a with HAP parameters: RFC 3526 3072-bit prime, g=5, SHA-512.
local SRP = {}

SRP.N_BYTES = Bytes.from_hex(
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" ..
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" ..
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" ..
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" ..
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" ..
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" ..
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" ..
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" ..
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" ..
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" ..
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" ..
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" ..
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" ..
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" ..
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" ..
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
SRP.N_LIMBS = 192  -- 3072 / 16
SRP.N = BigInt.from_bytes_be(SRP.N_BYTES)
SRP.g = BigInt.from_number(5)
SRP._initialized = false
SRP._n_prime = nil
SRP._R2 = nil
SRP._k_bytes = nil
SRP._modpow = nil

-- Pure-Lua X25519 (RFC 7748) over GF(2^255-19).
-- Used because Control4's lua-openssl pkey.derive rejects Curve25519/OKP keys.
local X25519Pure = {}

-- X25519 uses a separate 15-bit limb field engine instead of the generic
-- 16-bit BigInt path. Control4's Lua runtime appears to mis-handle 65535^2
-- sized products; 15-bit limbs keep every product under signed 32-bit range.
-- Since 255 = 17 * 15, reduction for p = 2^255 - 19 is also simple.
local _FE_BASE = 32768
local _FE_BITS = 15
local _FE_LIMBS = 17
local _FE_P = {
  32749, 32767, 32767, 32767, 32767, 32767, 32767, 32767, 32767,
  32767, 32767, 32767, 32767, 32767, 32767, 32767, 32767,
}
local _FE_P_MINUS_2 = {
  32747, 32767, 32767, 32767, 32767, 32767, 32767, 32767, 32767,
  32767, 32767, 32767, 32767, 32767, 32767, 32767, 32767,
}

local function _fe_from_number(n)
  local out = {}
  for i = 1, _FE_LIMBS do
    out[i] = n % _FE_BASE
    n = math.floor(n / _FE_BASE)
  end
  return out
end

local _A24 = _fe_from_number(121665) -- (486662-2)/4 for Curve25519 ladder

local function _fe_carry(c)
  local carry = 0
  local n = math.max(#c, _FE_LIMBS)
  for i = 1, n do
    local value = (c[i] or 0) + carry
    c[i] = value % _FE_BASE
    carry = math.floor(value / _FE_BASE)
  end
  while carry > 0 do
    n = n + 1
    c[n] = carry % _FE_BASE
    carry = math.floor(carry / _FE_BASE)
  end
  while #c > 1 and c[#c] == 0 do c[#c] = nil end
  return c
end

local function _fe_compare(a, b)
  for i = _FE_LIMBS, 1, -1 do
    local av, bv = a[i] or 0, b[i] or 0
    if av ~= bv then return av < bv and -1 or 1 end
  end
  return 0
end

local function _fe_sub_raw(a, b)
  local out, borrow = {}, 0
  for i = 1, _FE_LIMBS do
    local value = (a[i] or 0) - (b[i] or 0) - borrow
    if value < 0 then
      value = value + _FE_BASE
      borrow = 1
    else
      borrow = 0
    end
    out[i] = value
  end
  return out, borrow
end

local function _fe_reduce(c)
  for _ = 1, 4 do
    _fe_carry(c)
    if #c <= _FE_LIMBS then break end
    for i = #c, _FE_LIMBS + 1, -1 do
      local value = c[i] or 0
      if value ~= 0 then
        c[i] = 0
        c[i - _FE_LIMBS] = (c[i - _FE_LIMBS] or 0) + value * 19
      end
    end
  end
  _fe_carry(c)
  for i = #c, _FE_LIMBS + 1, -1 do c[i] = nil end
  while _fe_compare(c, _FE_P) >= 0 do
    c = _fe_sub_raw(c, _FE_P)
  end
  for i = 1, _FE_LIMBS do c[i] = c[i] or 0 end
  return c
end

local function _fp_add(a, b)
  local out = {}
  for i = 1, _FE_LIMBS do out[i] = (a[i] or 0) + (b[i] or 0) end
  return _fe_reduce(out)
end

local function _fp_sub(a, b)
  local out
  if _fe_compare(a, b) >= 0 then
    out = _fe_sub_raw(a, b)
  else
    local with_p = {}
    for i = 1, _FE_LIMBS do with_p[i] = (a[i] or 0) + _FE_P[i] end
    _fe_carry(with_p)
    out = _fe_sub_raw(with_p, b)
  end
  return _fe_reduce(out)
end

local function _fp_mul(a, b)
  local out = {}
  for i = 1, _FE_LIMBS * 2 do out[i] = 0 end
  for i = 1, _FE_LIMBS do
    local carry = 0
    for j = 1, _FE_LIMBS do
      local k = i + j - 1
      local value = out[k] + (a[i] or 0) * (b[j] or 0) + carry
      out[k] = value % _FE_BASE
      carry = math.floor(value / _FE_BASE)
    end
    local k = i + _FE_LIMBS
    while carry > 0 do
      local value = (out[k] or 0) + carry
      out[k] = value % _FE_BASE
      carry = math.floor(value / _FE_BASE)
      k = k + 1
    end
  end
  return _fe_reduce(out)
end

local function _fp_sq(a) return _fp_mul(a, a) end

local function _fe_bit(v, bit_index)
  local limb = v[math.floor(bit_index / _FE_BITS) + 1] or 0
  return math.floor(limb / (2 ^ (bit_index % _FE_BITS))) % 2
end

local function _fp_inv(a)
  local result = _fe_from_number(1)
  for bit = 254, 0, -1 do
    result = _fp_sq(result)
    if _fe_bit(_FE_P_MINUS_2, bit) == 1 then
      result = _fp_mul(result, a)
    end
  end
  return result
end

local function _le32_to_fe(s)
  local out = {}
  for limb = 1, _FE_LIMBS do
    local value = 0
    for bit = 0, _FE_BITS - 1 do
      local source_bit = (limb - 1) * _FE_BITS + bit
      local byte = s:byte(math.floor(source_bit / 8) + 1) or 0
      local bit_value = math.floor(byte / (2 ^ (source_bit % 8))) % 2
      if bit_value == 1 then value = value + 2 ^ bit end
    end
    out[limb] = value
  end
  return _fe_reduce(out)
end

local function _fe_to_le32(v)
  local reduced = {}
  for i = 1, #v do reduced[i] = v[i] end
  v = _fe_reduce(reduced)
  local bytes = {}
  for i = 1, 32 do bytes[i] = 0 end
  for limb = 1, _FE_LIMBS do
    local value = v[limb] or 0
    for bit = 0, _FE_BITS - 1 do
      if math.floor(value / (2 ^ bit)) % 2 == 1 then
        local target_bit = (limb - 1) * _FE_BITS + bit
        if target_bit < 256 then
          local byte_index = math.floor(target_bit / 8) + 1
          bytes[byte_index] = bytes[byte_index] + 2 ^ (target_bit % 8)
        end
      end
    end
  end
  local out = {}
  for i = 1, 32 do out[i] = string.char(bytes[i]) end
  return table.concat(out)
end

local function _clamp32(k)
  local b = {k:byte(1, 32)}
  b[1]  = b[1] - (b[1] % 8)           -- clear bits 0-2
  local top = b[32] % 128             -- clear bit 7
  if top < 64 then top = top + 64 end -- set bit 6
  b[32] = top
  local out = {}
  for i = 1, 32 do out[i] = string.char(b[i]) end
  return table.concat(out)
end

-- Compute k * u (Montgomery ladder on Curve25519).
function X25519Pure.mul(k_bytes, u_bytes)
  k_bytes = _clamp32(k_bytes)
  -- Clear the high bit of u per RFC 7748
  local ub = {u_bytes:byte(1, 32)}
  ub[32] = ub[32] % 128
  local u_str = {}
  for i = 1, 32 do u_str[i] = string.char(ub[i]) end
  local u  = _le32_to_fe(table.concat(u_str))
  local x2 = _fe_from_number(1)
  local z2 = _fe_from_number(0)
  local x3 = u
  local z3 = _fe_from_number(1)
  local swap = 0
  local kb = {k_bytes:byte(1, 32)}
  for t = 254, 0, -1 do
    local k_t = math.floor(kb[math.floor(t / 8) + 1] / (2 ^ (t % 8))) % 2
    swap = (swap + k_t) % 2
    if swap == 1 then x2, x3 = x3, x2; z2, z3 = z3, z2 end
    swap = k_t
    local A  = _fp_add(x2, z2)
    local AA = _fp_sq(A)
    local B  = _fp_sub(x2, z2)
    local BB = _fp_sq(B)
    local E  = _fp_sub(AA, BB)
    local C  = _fp_add(x3, z3)
    local D  = _fp_sub(x3, z3)
    local DA = _fp_mul(D, A)
    local CB = _fp_mul(C, B)
    x3 = _fp_sq(_fp_add(DA, CB))
    z3 = _fp_mul(u, _fp_sq(_fp_sub(DA, CB)))
    x2 = _fp_mul(AA, BB)
    z2 = _fp_mul(E, _fp_add(AA, _fp_mul(_A24, E)))
  end
  if swap == 1 then x2, x3 = x3, x2; z2, z3 = z3, z2 end
  return _fe_to_le32(_fp_mul(x2, _fp_inv(z2)))
end

-- Base point u=9 in little-endian
X25519Pure.BASE_POINT = string.char(9) .. string.rep("\0", 31)

-- Pure-Lua Ed25519 (RFC 8032). Used because Control4's lua-openssl binding
-- exposes Ed25519 keys but routes signing through a digest API that OpenSSL
-- rejects for PureEdDSA.
local Ed25519Pure = {}

local function _sha512_bytes(data)
  if Ed25519Pure._sha512 then
    return Ed25519Pure._sha512(data)
  end

  if has_c4() and C4.Hash then
    local result, err = C4:Hash("SHA512", data, {
      return_encoding = "NONE",
      data_encoding = "NONE",
    })
    assert(not err, err)
    return result
  end

  local ok, openssl = pcall(require, "openssl")
  assert(ok, "openssl is required for SHA-512")
  local ctx = openssl.digest.new("sha512")
  assert(ctx, "SHA-512 not available in openssl.digest")
  ctx:update(data)
  return ctx:final()
end

local _ED_L = {
  21485, 14827, 3177, 16531, 19813, 24307, 30632, 28540, 20,
  0, 0, 0, 0, 0, 0, 0, 4096, 0,
}
local _ED_D = {
  30883, 9906, 14120, 12122, 2743, 10299, 4944, 14341, 6144,
  29649, 26077, 14851, 14540, 32718, 2779, 13943, 20995,
}
local _ED_2D = {
  29017, 19813, 28240, 24244, 5486, 20598, 9888, 28682, 12288,
  26530, 19387, 29703, 29080, 32668, 5559, 27886, 9222,
}
local _ED_SQRT_M1 = {
  8368, 5149, 27805, 10096, 18316, 9724, 427, 8588, 10031,
  30639, 25847, 26628, 12980, 15329, 5104, 4672, 11139,
}
local _ED_BASE = {
  X = {21786, 7755, 13698, 19121, 31532, 9396, 22565, 5731, 23657, 11704, 18423, 10001, 27658, 19071, 29531, 7017, 8553},
  Y = {26200, 19660, 6553, 13107, 26214, 19660, 6553, 13107, 26214, 19660, 6553, 13107, 26214, 19660, 6553, 13107, 26214},
  Z = _fe_from_number(1),
  T = nil,
}
_ED_BASE.T = _fp_mul(_ED_BASE.X, _ED_BASE.Y)

local function _limb_copy(v, n)
  local out = {}
  for i = 1, n or #v do out[i] = v[i] or 0 end
  return out
end

local function _scalar_trim(v)
  while #v > 1 and v[#v] == 0 do v[#v] = nil end
  if #v == 0 then v[1] = 0 end
  return v
end

local function _scalar_compare(a, b)
  _scalar_trim(a); _scalar_trim(b)
  if #a ~= #b then return #a < #b and -1 or 1 end
  for i = #a, 1, -1 do
    if (a[i] or 0) ~= (b[i] or 0) then return (a[i] or 0) < (b[i] or 0) and -1 or 1 end
  end
  return 0
end

local function _scalar_sub(a, b)
  local out, borrow = {}, 0
  for i = 1, #a do
    local value = (a[i] or 0) - (b[i] or 0) - borrow
    if value < 0 then
      value = value + _FE_BASE
      borrow = 1
    else
      borrow = 0
    end
    out[i] = value
  end
  return _scalar_trim(out)
end

local function _scalar_bit_length(v)
  _scalar_trim(v)
  local top = v[#v]
  local bits = (#v - 1) * _FE_BITS
  while top > 0 do bits = bits + 1; top = math.floor(top / 2) end
  return bits
end

local function _scalar_shift_left(v, bits)
  local limb_shift = math.floor(bits / _FE_BITS)
  local bit_shift = bits % _FE_BITS
  local factor = 2 ^ bit_shift
  local out = {}
  for i = 1, limb_shift do out[i] = 0 end
  local carry = 0
  for i = 1, #v do
    local value = v[i] * factor + carry
    out[i + limb_shift] = value % _FE_BASE
    carry = math.floor(value / _FE_BASE)
  end
  if carry > 0 then out[#out + 1] = carry end
  return _scalar_trim(out)
end

local function _scalar_shift_right_one(v)
  local out, carry = {}, 0
  for i = #v, 1, -1 do
    local value = v[i] + carry * _FE_BASE
    out[i] = math.floor(value / 2)
    carry = value % 2
  end
  return _scalar_trim(out)
end

local function _scalar_reduce(v)
  v = _scalar_trim(_limb_copy(v))
  local shift = _scalar_bit_length(v) - _scalar_bit_length(_ED_L)
  if shift < 0 then return v end
  local shifted = _scalar_shift_left(_ED_L, shift)
  for _ = 0, shift do
    if _scalar_compare(v, shifted) >= 0 then
      v = _scalar_sub(v, shifted)
    end
    shifted = _scalar_shift_right_one(shifted)
  end
  return _scalar_trim(v)
end

local function _scalar_from_le_bytes_mod(s)
  local v = {}
  for i = 1, #s do
    local byte = s:byte(i)
    local bit_offset = (i - 1) * 8
    local limb = math.floor(bit_offset / _FE_BITS) + 1
    local shift = bit_offset % _FE_BITS
    v[limb] = (v[limb] or 0) + byte * (2 ^ shift)
    if shift > _FE_BITS - 8 then
      v[limb + 1] = (v[limb + 1] or 0) + math.floor((v[limb] or 0) / _FE_BASE)
      v[limb] = (v[limb] or 0) % _FE_BASE
    end
  end
  return _scalar_reduce(_fe_carry(v))
end

local function _scalar_to_le32(v)
  v = _scalar_reduce(v)
  local bytes = {}
  for i = 1, 32 do bytes[i] = 0 end
  for limb = 1, #v do
    local value = v[limb] or 0
    for bit = 0, _FE_BITS - 1 do
      if math.floor(value / (2 ^ bit)) % 2 == 1 then
        local target_bit = (limb - 1) * _FE_BITS + bit
        if target_bit < 256 then
          local byte_index = math.floor(target_bit / 8) + 1
          bytes[byte_index] = bytes[byte_index] + 2 ^ (target_bit % 8)
        end
      end
    end
  end
  local out = {}
  for i = 1, 32 do out[i] = string.char(bytes[i]) end
  return table.concat(out)
end

local function _scalar_add(a, b)
  local out = {}
  local n = math.max(#a, #b)
  for i = 1, n do out[i] = (a[i] or 0) + (b[i] or 0) end
  return _scalar_reduce(_fe_carry(out))
end

local function _scalar_mul(a, b)
  local out = {}
  for i = 1, #a + #b do out[i] = 0 end
  for i = 1, #a do
    local carry = 0
    for j = 1, #b do
      local k = i + j - 1
      local value = out[k] + (a[i] or 0) * (b[j] or 0) + carry
      out[k] = value % _FE_BASE
      carry = math.floor(value / _FE_BASE)
    end
    local k = i + #b
    while carry > 0 do
      local value = (out[k] or 0) + carry
      out[k] = value % _FE_BASE
      carry = math.floor(value / _FE_BASE)
      k = k + 1
    end
  end
  return _scalar_reduce(out)
end

local function _ed_identity()
  return { X = _fe_from_number(0), Y = _fe_from_number(1), Z = _fe_from_number(1), T = _fe_from_number(0) }
end

local function _ed_point_add(P, Q)
  local A = _fp_mul(_fp_sub(P.Y, P.X), _fp_sub(Q.Y, Q.X))
  local B = _fp_mul(_fp_add(P.Y, P.X), _fp_add(Q.Y, Q.X))
  local C = _fp_mul(_fp_mul(P.T, Q.T), _ED_2D)
  local D = _fp_add(_fp_mul(P.Z, Q.Z), _fp_mul(P.Z, Q.Z))
  local E = _fp_sub(B, A)
  local F = _fp_sub(D, C)
  local G = _fp_add(D, C)
  local H = _fp_add(B, A)
  return {
    X = _fp_mul(E, F),
    Y = _fp_mul(G, H),
    Z = _fp_mul(F, G),
    T = _fp_mul(E, H),
  }
end

local function _ed_scalar_bit(s, bit_index)
  return _fe_bit(s, bit_index)
end

local function _ed_scalar_mult(point, scalar)
  local result = _ed_identity()
  for bit = _scalar_bit_length(scalar) - 1, 0, -1 do
    result = _ed_point_add(result, result)
    if _ed_scalar_bit(scalar, bit) == 1 then
      result = _ed_point_add(result, point)
    end
  end
  return result
end

local function _ed_point_equal(P, Q)
  return _fe_compare(_fp_mul(P.X, Q.Z), _fp_mul(Q.X, P.Z)) == 0 and
    _fe_compare(_fp_mul(P.Y, Q.Z), _fp_mul(Q.Y, P.Z)) == 0
end

local function _ed_encode_point(P)
  local iz = _fp_inv(P.Z)
  local x = _fp_mul(P.X, iz)
  local y = _fp_mul(P.Y, iz)
  local out = { _fe_to_le32(y):byte(1, 32) }
  out[32] = out[32] + (_fe_bit(x, 0) * 128)
  local bytes = {}
  for i = 1, 32 do bytes[i] = string.char(out[i]) end
  return table.concat(bytes)
end

local function _ed_decode_point(s)
  if type(s) ~= "string" or #s ~= 32 then return nil end
  local bytes = { s:byte(1, 32) }
  local sign = math.floor(bytes[32] / 128)
  bytes[32] = bytes[32] % 128
  local y_parts = {}
  for i = 1, 32 do y_parts[i] = string.char(bytes[i]) end
  local y = _le32_to_fe(table.concat(y_parts))
  local y2 = _fp_sq(y)
  local u = _fp_sub(y2, _fe_from_number(1))
  local v = _fp_add(_fp_mul(_ED_D, y2), _fe_from_number(1))
  local x = _fp_mul(u, _fp_inv(v))
  x = _fp_pow_p38 and x or x
  -- x = sqrt(u/v) = (u/v)^((p+3)/8)
  local candidate = _fe_from_number(1)
  local exp = {
    32766, 32767, 32767, 32767, 32767, 32767, 32767, 32767, 32767,
    32767, 32767, 32767, 32767, 32767, 32767, 32767, 4095,
  }
  local uv = x
  for bit = 252, 0, -1 do
    candidate = _fp_sq(candidate)
    if _fe_bit(exp, bit) == 1 then candidate = _fp_mul(candidate, uv) end
  end
  x = candidate
  if _fe_compare(_fp_sq(x), uv) ~= 0 then
    x = _fp_mul(x, _ED_SQRT_M1)
  end
  if _fe_compare(_fp_sq(x), uv) ~= 0 then return nil end
  if _fe_bit(x, 0) ~= sign then
    x = _fp_sub(_fe_from_number(0), x)
  end
  return { X = x, Y = y, Z = _fe_from_number(1), T = _fp_mul(x, y) }
end

local function _ed_clamped_scalar_from_hash(h)
  local b = { h:byte(1, 32) }
  b[1] = b[1] - (b[1] % 8)
  b[32] = (b[32] % 64) + 64
  local s = {}
  for i = 1, 32 do s[i] = string.char(b[i]) end
  return _scalar_from_le_bytes_mod(table.concat(s))
end

function Ed25519Pure.public_key_from_private(private_key)
  local h = _sha512_bytes(private_key)
  local a = _ed_clamped_scalar_from_hash(h)
  return _ed_encode_point(_ed_scalar_mult(_ED_BASE, a))
end

function Ed25519Pure.sign(private_key, public_key, message)
  local h = _sha512_bytes(private_key)
  local a = _ed_clamped_scalar_from_hash(h)
  local prefix = h:sub(33, 64)
  local r = _scalar_from_le_bytes_mod(_sha512_bytes(prefix .. message))
  local R = _ed_encode_point(_ed_scalar_mult(_ED_BASE, r))
  local k = _scalar_from_le_bytes_mod(_sha512_bytes(R .. public_key .. message))
  local S = _scalar_add(r, _scalar_mul(k, a))
  return R .. _scalar_to_le32(S)
end

function Ed25519Pure.verify(public_key, signature, message)
  if type(signature) ~= "string" or #signature ~= 64 then return false end
  local A = _ed_decode_point(public_key)
  local R = _ed_decode_point(signature:sub(1, 32))
  if not A or not R then return false end
  local S = _scalar_from_le_bytes_mod(signature:sub(33, 64))
  if _scalar_to_le32(S) ~= signature:sub(33, 64) then return false end
  local k = _scalar_from_le_bytes_mod(_sha512_bytes(signature:sub(1, 32) .. public_key .. message))
  local left = _ed_scalar_mult(_ED_BASE, S)
  local right = _ed_point_add(R, _ed_scalar_mult(A, k))
  return _ed_point_equal(left, right)
end

function SRP.sha512(data)
  return _sha512_bytes(data)
end

local function srp_xor_bytes(a, b)
  assert(#a == #b, "XOR operands must be equal length")
  local out = {}
  for i = 1, #a do
    local x, y, r, bit = a:byte(i), b:byte(i), 0, 1
    while bit < 256 do
      if (x % (bit * 2) >= bit) ~= (y % (bit * 2) >= bit) then r = r + bit end
      bit = bit * 2
    end
    out[i] = string.char(r)
  end
  return table.concat(out)
end

function SRP.init()
  if SRP._initialized then return end
  SRP._n_prime = compute_n_prime(SRP.N[1])
  SRP._R2 = compute_r2_mod_n(SRP.N, SRP.N_LIMBS)
  SRP._k_bytes = SRP.sha512(SRP.N_BYTES .. BigInt.to_bytes_be(SRP.g, 384))
  SRP._initialized = true
end

function SRP.compute_x(salt, pin)
  local inner = SRP.sha512("Pair-Setup:" .. tostring(pin))
  return BigInt.from_bytes_be(SRP.sha512(salt .. inner))
end

function SRP.compute_A(a_bytes)
  SRP.init()
  if SRP._modpow then
    return SRP._modpow(BigInt.to_minimal_bytes_be(SRP.g), a_bytes, 384)
  end
  local a = BigInt.from_bytes_be(a_bytes)
  local A = BigInt.mont_modpow(SRP.g, a, SRP.N, SRP._R2, SRP.N_LIMBS, SRP._n_prime)
  return BigInt.to_bytes_be(A, 384)
end

function SRP.compute_u(A_bytes, B_bytes)
  return BigInt.from_bytes_be(SRP.sha512(A_bytes .. B_bytes))
end

function SRP.compute_session_key(B_bytes, a_bytes, x, u)
  SRP.init()
  local B_big = BigInt.from_bytes_be(B_bytes)
  local a = BigInt.from_bytes_be(a_bytes)
  local k_big = BigInt.from_bytes_be(SRP._k_bytes)
  Log.debug("Pair-Setup M3 progress: SRP g^x started")
  local gx
  if SRP._modpow then
    gx = BigInt.from_bytes_be(SRP._modpow(
      BigInt.to_minimal_bytes_be(SRP.g),
      BigInt.to_minimal_bytes_be(x),
      384
    ))
  else
    gx = BigInt.mont_modpow(SRP.g, x, SRP.N, SRP._R2, SRP.N_LIMBS, SRP._n_prime)
  end
  Log.debug("Pair-Setup M3 progress: SRP g^x computed")
  local kgx = BigInt.mod(BigInt.mul(k_big, gx), SRP.N)
  local Bkgx
  if BigInt.compare(B_big, kgx) >= 0 then
    Bkgx = BigInt.sub(B_big, kgx)
  else
    Bkgx = BigInt.sub(BigInt.add(B_big, SRP.N), kgx)
    if BigInt.compare(Bkgx, SRP.N) >= 0 then Bkgx = BigInt.sub(Bkgx, SRP.N) end
  end
  local exp = BigInt.add(a, BigInt.mul(u, x))
  Log.debug("Pair-Setup M3 progress: SRP shared secret started")
  local S
  if SRP._modpow then
    S = BigInt.from_bytes_be(SRP._modpow(
      BigInt.to_minimal_bytes_be(Bkgx),
      BigInt.to_minimal_bytes_be(exp),
      384
    ))
  else
    S = BigInt.mont_modpow(Bkgx, exp, SRP.N, SRP._R2, SRP.N_LIMBS, SRP._n_prime)
  end
  Log.debug("Pair-Setup M3 progress: SRP shared secret computed")
  local K = SRP.sha512(BigInt.to_minimal_bytes_be(S))
  return K
end

function SRP.compute_M1(A_bytes, B_bytes, K, salt)
  SRP.init()
  local H_N = SRP.sha512(SRP.N_BYTES)
  local H_g = SRP.sha512(BigInt.to_minimal_bytes_be(SRP.g))
  local H_I = SRP.sha512("Pair-Setup")
  return SRP.sha512(srp_xor_bytes(H_N, H_g) .. H_I .. salt .. A_bytes .. B_bytes .. K)
end

function SRP.verify_M2(A_bytes, M1, K, atv_M2)
  return SRP.sha512(A_bytes .. M1 .. K) == atv_M2
end

local Storage = {}
Storage.KEY = "apple_tv_companion_state"

function Storage.load()
  if has_c4() then
    return PersistGetValue(Storage.KEY, true) or {}
  end
  return Driver._test_storage or {}
end

function Storage.save(state)
  if has_c4() then
    PersistSetValue(Storage.KEY, state, true)
  else
    Driver._test_storage = state
  end
end

local Credentials = {}

function Credentials.parse(detail_string)
  if detail_string == nil or detail_string == "" then
    return {
      ltpk = "",
      ltsk = "",
      atv_id = "",
      client_id = "",
      type = "Null",
    }
  end

  local parts = {}
  for part in string.gmatch(detail_string, "([^:]+)") do
    parts[#parts + 1] = part
  end

  assert(#parts == 4, "Companion credentials must be pyatv HAP credentials: ltpk:ltsk:atv_id:client_id")

  local credentials = {
    ltpk = Bytes.from_hex(parts[1]),
    ltsk = Bytes.from_hex(parts[2]),
    atv_id = Bytes.from_hex(parts[3]),
    client_id = Bytes.from_hex(parts[4]),
  }

  assert(credentials.ltpk ~= "" and credentials.ltsk ~= "" and credentials.atv_id ~= "" and credentials.client_id ~= "", "invalid HAP credentials")
  credentials.type = "HAP"
  return credentials
end

function Credentials.stringify(credentials)
  assert(type(credentials) == "table", "credentials must be a table")
  return table.concat({
    Bytes.hex(credentials.ltpk or ""),
    Bytes.hex(credentials.ltsk or ""),
    Bytes.hex(credentials.atv_id or ""),
    Bytes.hex(credentials.client_id or ""),
  }, ":")
end

local Crypto = {
  provider = nil,
}

function Crypto.set_provider(provider)
  Crypto.provider = provider
end

local function crypto_method(crypto, name)
  local provider = crypto
  if provider == nil or provider == Crypto then
    provider = Crypto.provider
  end
  if provider and type(provider[name]) == "function" then
    return provider[name]
  end

  error("crypto provider does not implement " .. name)
end

local function optional_crypto_method(crypto, name)
  local provider = crypto
  if provider == nil or provider == Crypto then
    provider = Crypto.provider
  end
  if provider and type(provider[name]) == "function" then
    return provider[name]
  end
  return nil
end

function Crypto.hmac_sha512(key, data)
  if Crypto.provider and type(Crypto.provider.hmac_sha512) == "function" then
    return Crypto.provider.hmac_sha512(key, data)
  end

  if has_c4() and C4.HMAC then
    local result, err = C4:HMAC("SHA512", key, data, {
      return_encoding = "NONE",
      key_encoding = "NONE",
      data_encoding = "NONE",
    })
    assert(not err, err)
    return result
  end

  error("hmac_sha512 requires Control4 C4:HMAC or an injected crypto provider")
end

function Crypto.sha512(data)
  return _sha512_bytes(data)
end

function Crypto.hkdf_sha512(salt, info, ikm)
  if Crypto.provider and type(Crypto.provider.hkdf_sha512) == "function" then
    return Crypto.provider.hkdf_sha512(salt, info, ikm)
  end

  local prk = Crypto.hmac_sha512(salt or "", ikm)
  return Crypto.hmac_sha512(prk, info .. string.char(0x01)):sub(1, 32)
end

function Crypto.generate_x25519_keypair()
  return crypto_method(Crypto, "generate_x25519_keypair")()
end

function Crypto.pair_verify_response(credentials, private_key, public_key, server_public_key, encrypted_data)
  return crypto_method(Crypto, "pair_verify_response")(credentials, private_key, public_key, server_public_key, encrypted_data)
end

function Crypto.encrypt(output_key, plaintext, aad, nonce)
  return crypto_method(Crypto, "encrypt")(output_key, plaintext, aad, nonce)
end

function Crypto.decrypt(input_key, ciphertext, aad, nonce)
  return crypto_method(Crypto, "decrypt")(input_key, ciphertext, aad, nonce)
end

function Crypto.random_bytes(n)
  if Crypto.provider and type(Crypto.provider.random_bytes) == "function" then
    return Crypto.provider.random_bytes(n)
  end
  local bytes = {}
  for i = 1, n do bytes[i] = string.char(math.random(0, 255)) end
  return table.concat(bytes)
end

function Crypto.generate_ed25519_keypair()
  return crypto_method(Crypto, "generate_ed25519_keypair")()
end

function Crypto.ed25519_sign(private_key_bytes, message)
  return crypto_method(Crypto, "ed25519_sign")(private_key_bytes, message)
end

local OpenSSLCrypto = {
  openssl = nil,
  out_counter = 0,
  in_counter = 0,
  self_tested = false,
}

OpenSSLCrypto.EVP_CTRL_AEAD_GET_TAG = 0x10
OpenSSLCrypto.EVP_CTRL_AEAD_SET_TAG = 0x11
OpenSSLCrypto.EVP_CTRL_AEAD_SET_IVLEN = 0x09
OpenSSLCrypto.chacha_variant = nil

function OpenSSLCrypto.load_openssl()
  if OpenSSLCrypto.openssl then
    return OpenSSLCrypto.openssl
  end

  local ok, openssl_or_err = pcall(require, "openssl")
  assert(ok, "Control4 lua-openssl is required for live Companion crypto: " .. tostring(openssl_or_err))
  OpenSSLCrypto.openssl = openssl_or_err
  return OpenSSLCrypto.openssl
end

function OpenSSLCrypto._spki_der(algorithm, public_key)
  assert(type(public_key) == "string" and #public_key == 32, algorithm .. " public key must be 32 bytes")
  local prefixes = {
    x25519 = "302a300506032b656e032100",
    ed25519 = "302a300506032b6570032100",
  }
  return Bytes.from_hex(assert(prefixes[string.lower(algorithm)], "unsupported public key algorithm")) .. public_key
end

function OpenSSLCrypto._pkcs8_der(algorithm, private_key)
  assert(type(private_key) == "string" and #private_key == 32, algorithm .. " private key must be 32 bytes")
  local prefixes = {
    x25519 = "302e020100300506032b656e04220420",
    ed25519 = "302e020100300506032b657004220420",
  }
  return Bytes.from_hex(assert(prefixes[string.lower(algorithm)], "unsupported private key algorithm")) .. private_key
end

function OpenSSLCrypto._nonce12(value)
  return Bytes.uint_le(value, 12)
end

function OpenSSLCrypto._hap_nonce(label)
  assert(type(label) == "string" and #label <= 12, "HAP nonce label is too long")
  return string.rep("\0", 12 - #label) .. label
end

local function openssl_assert(value, err, label)
  if value == nil or value == false then
    error(label .. " failed: " .. tostring(err))
  end
  return value
end

function OpenSSLCrypto._pkey()
  local openssl = OpenSSLCrypto.load_openssl()
  assert(openssl.pkey, "lua-openssl pkey module is required")
  return openssl.pkey
end

function OpenSSLCrypto._read_public_key(algorithm, public_key)
  local pkey = OpenSSLCrypto._pkey()
  local key, err = pkey.read(OpenSSLCrypto._spki_der(algorithm, public_key), false, "der")
  return openssl_assert(key, err, "read " .. algorithm .. " public key")
end

function OpenSSLCrypto._read_private_key(algorithm, private_key)
  local pkey = OpenSSLCrypto._pkey()
  local key, err = pkey.read(OpenSSLCrypto._pkcs8_der(algorithm, private_key), true, "der")
  return openssl_assert(key, err, "read " .. algorithm .. " private key")
end

function OpenSSLCrypto._export_raw_public_key(key)
  local public_key, public_key_err = key:get_public()
  public_key = openssl_assert(public_key, public_key_err, "get public key")
  -- pkey:export("der") for X25519 always returns SubjectPublicKeyInfo DER (i2d_PUBKEY_bio),
  -- not raw bytes -- the raw=true switch in pkey.c only handles RSA/DSA/EC, X25519 falls
  -- to default which is the same i2d_PUBKEY_bio call. Strip the 12-byte SPKI header.
  local der, export_err = public_key:export("der", false)
  der = openssl_assert(der, export_err, "export X25519 public key")
  assert(type(der) == "string" and #der == 44,
    "X25519 SPKI DER expected 44 bytes, got " .. tostring(#der))
  return der:sub(13)
end

function OpenSSLCrypto.generate_x25519_keypair()
  local scalar = OpenSSLCrypto.random_bytes(32)
  return {
    private_key = scalar,
    public_key  = X25519Pure.mul(scalar, X25519Pure.BASE_POINT),
  }
end

function OpenSSLCrypto._derive_x25519(private_key, server_public_key)
  assert(type(private_key) == "string" and #private_key == 32,
    "X25519 private key must be 32 raw bytes")
  return X25519Pure.mul(private_key, server_public_key)
end

function OpenSSLCrypto._sign_ed25519(private_key_bytes, data, public_key)
  public_key = public_key or Ed25519Pure.public_key_from_private(private_key_bytes)
  return Ed25519Pure.sign(private_key_bytes, public_key, data)
end

function OpenSSLCrypto._verify_ed25519(public_key_bytes, signature, data)
  return Ed25519Pure.verify(public_key_bytes, signature, data)
end

function OpenSSLCrypto._cipher()
  local openssl = OpenSSLCrypto.load_openssl()
  assert(openssl.cipher, "lua-openssl cipher module is required")
  return openssl.cipher
end

function OpenSSLCrypto._cipher_ctrl(name, fallback)
  local cipher = OpenSSLCrypto._cipher()
  return cipher[name] or fallback
end

function OpenSSLCrypto._chacha_algorithm()
  local cipher = OpenSSLCrypto._cipher()
  local algorithm, algorithm_err = cipher.get("chacha20-poly1305")
  return openssl_assert(algorithm, algorithm_err, "get ChaCha20-Poly1305 cipher")
end

function OpenSSLCrypto._cipher_ctx(encrypting, key, nonce, variant)
  local cipher = OpenSSLCrypto._cipher()
  local algorithm = OpenSSLCrypto._chacha_algorithm()
  local ctx, err
  variant = variant or OpenSSLCrypto.chacha_variant or "method_init_ctrl"

  if variant == "method_args" then
    if encrypting then
      ctx, err = algorithm:encrypt_new(key, nonce)
    else
      ctx, err = algorithm:decrypt_new(key, nonce)
    end
    return openssl_assert(ctx, err, "create ChaCha20-Poly1305 " .. (encrypting and "encrypt" or "decrypt") .. " context")
  end

  if variant == "method_args_pad_false" then
    if encrypting then
      ctx, err = algorithm:encrypt_new(key, nonce, false)
    else
      ctx, err = algorithm:decrypt_new(key, nonce, false)
    end
    return openssl_assert(ctx, err, "create ChaCha20-Poly1305 " .. (encrypting and "encrypt" or "decrypt") .. " context")
  end

  if variant == "module_new_ctrl" or variant == "module_new_no_ctrl" then
    assert(cipher.new, "lua-openssl cipher.new is required for " .. variant)
    ctx, err = cipher.new(algorithm, encrypting)
    ctx = openssl_assert(ctx, err, "create ChaCha20-Poly1305 context")
  elseif variant == "module_new_named_ctrl" or variant == "module_new_named_no_ctrl" then
    assert(cipher.new, "lua-openssl cipher.new is required for " .. variant)
    ctx, err = cipher.new("chacha20-poly1305", encrypting)
    ctx = openssl_assert(ctx, err, "create ChaCha20-Poly1305 context")
  else
    if encrypting then
      ctx, err = algorithm:encrypt_new()
      ctx = openssl_assert(ctx, err, "create ChaCha20-Poly1305 encrypt context")
    else
      ctx, err = algorithm:decrypt_new()
      ctx = openssl_assert(ctx, err, "create ChaCha20-Poly1305 decrypt context")
    end
  end

  assert(ctx.init, "lua-openssl cipher context init is required for ChaCha20-Poly1305 AEAD")
  if variant ~= "method_init_no_ctrl" and variant ~= "module_new_no_ctrl" and variant ~= "module_new_named_no_ctrl" then
    openssl_assert(ctx:ctrl(OpenSSLCrypto._cipher_ctrl("EVP_CTRL_GCM_SET_IVLEN", OpenSSLCrypto.EVP_CTRL_AEAD_SET_IVLEN), #nonce),
      nil, "set ChaCha20-Poly1305 IV length")
  end
  openssl_assert(ctx:init(key, nonce), nil, "initialize ChaCha20-Poly1305 context")
  return ctx
end

function OpenSSLCrypto._chacha20_poly1305_encrypt_variant(variant, key, nonce, plaintext, aad)
  local ctx = OpenSSLCrypto._cipher_ctx(true, key, nonce, variant)
  if aad and aad ~= "" then
    ctx:update(aad, true)
  end
  local ciphertext = (ctx:update(plaintext) or "") .. (ctx:final() or "")
  local tag = assert(ctx:ctrl(OpenSSLCrypto._cipher_ctrl("EVP_CTRL_GCM_GET_TAG", OpenSSLCrypto.EVP_CTRL_AEAD_GET_TAG), 16),
    "failed to get ChaCha20-Poly1305 auth tag")
  return ciphertext .. tag
end

function OpenSSLCrypto._chacha20_poly1305_decrypt_variant(variant, key, nonce, ciphertext_and_tag, aad)
  assert(#ciphertext_and_tag >= 16, "ChaCha20-Poly1305 ciphertext is missing auth tag")
  local ciphertext = ciphertext_and_tag:sub(1, #ciphertext_and_tag - 16)
  local tag = ciphertext_and_tag:sub(#ciphertext_and_tag - 15)
  local ctx = OpenSSLCrypto._cipher_ctx(false, key, nonce, variant)
  assert(ctx:ctrl(OpenSSLCrypto._cipher_ctrl("EVP_CTRL_GCM_SET_TAG", OpenSSLCrypto.EVP_CTRL_AEAD_SET_TAG), tag),
    "failed to set ChaCha20-Poly1305 auth tag")
  if aad and aad ~= "" then
    ctx:update(aad, true)
  end
  return (ctx:update(ciphertext) or "") .. (ctx:final() or "")
end

function OpenSSLCrypto._select_chacha_variant()
  if OpenSSLCrypto.chacha_variant then
    return OpenSSLCrypto.chacha_variant
  end
  local variants = {
    "method_init_ctrl",
    "method_init_no_ctrl",
    "method_args",
    "method_args_pad_false",
    "module_new_ctrl",
    "module_new_no_ctrl",
    "module_new_named_ctrl",
    "module_new_named_no_ctrl",
  }
  local key = Bytes.from_hex(
    "000102030405060708090a0b0c0d0e0f" ..
    "101112131415161718191a1b1c1d1e1f"
  )
  local nonce = Bytes.from_hex("000102030405060708090a0b")
  local expected = Bytes.from_hex("f99769694763c038c388540d8367db9102148f2c2034e779d0")
  local diagnostics = {}
  for _, variant in ipairs(variants) do
    local ok, result = pcall(OpenSSLCrypto._chacha20_poly1305_encrypt_variant,
      variant, key, nonce, "plaintext", "aad")
    if ok and result == expected then
      OpenSSLCrypto.chacha_variant = variant
      Log.debug("crypto self-test: ChaCha20-Poly1305 using variant " .. variant)
      return variant
    end
    diagnostics[#diagnostics + 1] = variant .. "=" .. (ok and Bytes.hex(result) or tostring(result))
  end
  error("no usable ChaCha20-Poly1305 lua-openssl call shape: " .. table.concat(diagnostics, "; "))
end

function OpenSSLCrypto._chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
  assert(#key == 32, "ChaCha20-Poly1305 key must be 32 bytes")
  assert(#nonce == 12, "ChaCha20-Poly1305 nonce must be 12 bytes")
  return ChaCha20Poly1305Pure.encrypt(key, nonce, plaintext, aad or "")
end

function OpenSSLCrypto._chacha20_poly1305_decrypt(key, nonce, ciphertext_and_tag, aad)
  assert(#key == 32, "ChaCha20-Poly1305 key must be 32 bytes")
  assert(#nonce == 12, "ChaCha20-Poly1305 nonce must be 12 bytes")
  return ChaCha20Poly1305Pure.decrypt(key, nonce, ciphertext_and_tag, aad or "")
end

function OpenSSLCrypto.encrypt(output_key, plaintext, aad, nonce)
  if not nonce then
    nonce = OpenSSLCrypto._nonce12(OpenSSLCrypto.out_counter)
    OpenSSLCrypto.out_counter = OpenSSLCrypto.out_counter + 1
  end
  return OpenSSLCrypto._chacha20_poly1305_encrypt(output_key, nonce, plaintext, aad)
end

function OpenSSLCrypto.decrypt(input_key, ciphertext, aad, nonce)
  if not nonce then
    nonce = OpenSSLCrypto._nonce12(OpenSSLCrypto.in_counter)
    OpenSSLCrypto.in_counter = OpenSSLCrypto.in_counter + 1
  end
  return OpenSSLCrypto._chacha20_poly1305_decrypt(input_key, nonce, ciphertext, aad)
end

function OpenSSLCrypto.hmac_sha512(key, data)
  assert(type(key) == "string" and type(data) == "string", "HMAC-SHA512 requires string inputs")
  local block_size = 128
  if #key > block_size then
    key = _sha512_bytes(key)
  end
  if #key < block_size then
    key = key .. string.rep("\0", block_size - #key)
  end
  local ipad, opad = {}, {}
  for i = 1, block_size do
    local b = key:byte(i)
    ipad[i] = string.char(Bit32.bxor(b, 0x36))
    opad[i] = string.char(Bit32.bxor(b, 0x5c))
  end
  return _sha512_bytes(table.concat(opad) .. _sha512_bytes(table.concat(ipad) .. data))
end

function OpenSSLCrypto.hkdf_sha512(salt, info, ikm)
  local prk = OpenSSLCrypto.hmac_sha512(salt or "", ikm)
  return OpenSSLCrypto.hmac_sha512(prk, info .. string.char(0x01)):sub(1, 32)
end

local function left_pad_bytes(value, len)
  if #value > len then
    local i = 1
    while i <= #value - len and value:byte(i) == 0 do
      i = i + 1
    end
    value = value:sub(i)
  end
  assert(#value <= len, "native SRP modpow returned too many bytes")
  if #value < len then
    return string.rep("\0", len - #value) .. value
  end
  return value
end

function OpenSSLCrypto.srp_modpow(base_bytes, exponent_bytes, len)
  local openssl = OpenSSLCrypto.load_openssl()
  local bn = openssl.bn
  assert(bn and bn.text and bn.powmod and bn.totext, "lua-openssl bn.text/powmod/totext are required for native SRP modpow")

  local base = bn.text(base_bytes)
  local exponent = bn.text(exponent_bytes)
  local modulus = bn.text(SRP.N_BYTES)
  local result, err = bn.powmod(base, exponent, modulus)
  result = openssl_assert(result, err, "native SRP BN_mod_exp")
  return left_pad_bytes(bn.totext(result), len or 384)
end

function OpenSSLCrypto.random_bytes(n)
  assert(type(n) == "number" and n >= 0, "random byte count must be non-negative")
  local openssl = OpenSSLCrypto.load_openssl()
  local rand = openssl.rand
  if rand and type(rand.bytes) == "function" then
    local bytes, err = rand.bytes(n)
    bytes = openssl_assert(bytes, err, "openssl.rand.bytes")
    assert(#bytes == n, "openssl.rand.bytes returned wrong length")
    return bytes
  end

  local file, err = io.open("/dev/urandom", "rb")
  assert(file, "secure random source unavailable: openssl.rand.bytes and /dev/urandom failed: " .. tostring(err))
  local bytes = file:read(n)
  file:close()
  assert(type(bytes) == "string" and #bytes == n, "secure random source returned wrong length")
  return bytes
end

function OpenSSLCrypto.generate_ed25519_keypair()
  local private_key = OpenSSLCrypto.random_bytes(32)
  return {
    private_key = private_key,
    public_key = Ed25519Pure.public_key_from_private(private_key),
  }
end

function OpenSSLCrypto.ed25519_sign(private_key_bytes, message)
  assert(type(private_key_bytes) == "string" and #private_key_bytes == 32)
  return OpenSSLCrypto._sign_ed25519(private_key_bytes, message)
end

local function elapsed_ms(start_time)
  return math.floor(((os.clock() - start_time) * 1000) + 0.5)
end

function OpenSSLCrypto.pair_verify_response(credentials, private_key, public_key, server_public_key, encrypted_data)
  local total_start = os.clock()
  local shared_secret = OpenSSLCrypto._derive_x25519(private_key, server_public_key)
  local session_key = OpenSSLCrypto.hkdf_sha512("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared_secret)
  local nonce = OpenSSLCrypto._hap_nonce("PV-Msg02")
  local function fp(value)
    local ok, digest = pcall(_sha512_bytes, value)
    return ok and Bytes.hex(digest:sub(1, 8)) or "unavailable"
  end
  Log.debug("Pair-Verify M2 decrypt: server_public_len=" .. tostring(#server_public_key) ..
    " encrypted_len=" .. tostring(#encrypted_data))
  Log.debug("Pair-Verify M2 diagnostics: client_pub_sha=" .. fp(public_key) ..
    " server_pub_sha=" .. fp(server_public_key) ..
    " shared_sha=" .. fp(shared_secret) ..
    " session_sha=" .. fp(session_key) ..
    " nonce=" .. Bytes.hex(nonce) ..
    " tag=" .. Bytes.hex(encrypted_data:sub(#encrypted_data - 15)))
  local decrypted = OpenSSLCrypto._chacha20_poly1305_decrypt(
    session_key,
    nonce,
    encrypted_data
  )
  Log.debug("Pair-Verify M2 decrypt: decrypted_len=" .. tostring(#(decrypted or "")))
  local step_start = os.clock()
  local ok, decrypted_tlv_or_err = pcall(TLV8.decode, decrypted)
  if not ok then
    Log.error("Pair-Verify decrypted TLV decode failed: len=" .. tostring(#(decrypted or "")) ..
      " head=" .. Bytes.hex((decrypted or ""):sub(1, 32)) ..
      " tail=" .. Bytes.hex((decrypted or ""):sub(math.max(1, #(decrypted or "") - 31))) ..
      " encrypted_head=" .. Bytes.hex(encrypted_data:sub(1, 32)))
    error(decrypted_tlv_or_err, 2)
  end
  local decrypted_tlv = decrypted_tlv_or_err
  Log.debug("Pair-Verify M2 timing: tlv_decode_ms=" .. tostring(elapsed_ms(step_start)))

  local identifier = decrypted_tlv[1]
  local signature = decrypted_tlv[10]
  assert(identifier == credentials.atv_id, "incorrect Apple TV Pair-Verify identifier")
  assert(signature, "Apple TV Pair-Verify signature missing")

  local device_info = server_public_key .. identifier .. public_key
  step_start = os.clock()
  assert(OpenSSLCrypto._verify_ed25519(credentials.ltpk, signature, device_info), "Apple TV Pair-Verify signature invalid")
  Log.debug("Pair-Verify M2 timing: atv_signature_verify_ms=" .. tostring(elapsed_ms(step_start)))

  local controller_info = public_key .. credentials.client_id .. server_public_key
  step_start = os.clock()
  if not credentials.controller_ltpk then
    local public_ok, controller_ltpk = pcall(Ed25519Pure.public_key_from_private, credentials.ltsk)
    if public_ok then
      credentials.controller_ltpk = controller_ltpk
    end
  end
  local controller_signature = OpenSSLCrypto._sign_ed25519(credentials.ltsk, controller_info, credentials.controller_ltpk)
  Log.debug("Pair-Verify M2 timing: controller_signature_ms=" .. tostring(elapsed_ms(step_start)))
  local response_tlv = TLV8.encode_ordered({
    { 1, credentials.client_id },
    { 10, controller_signature },
  })

  step_start = os.clock()
  local encrypted_response = OpenSSLCrypto._chacha20_poly1305_encrypt(session_key, OpenSSLCrypto._hap_nonce("PV-Msg03"), response_tlv)
  Log.debug("Pair-Verify M2 timing: response_encrypt_ms=" .. tostring(elapsed_ms(step_start)) ..
    " total_ms=" .. tostring(elapsed_ms(total_start)))
  return encrypted_response, shared_secret
end

function OpenSSLCrypto.install()
  Crypto.set_provider(OpenSSLCrypto)
end

function OpenSSLCrypto.self_test(progress)
  progress = progress or function() end
  -- X25519: RFC 7748 Section 6.1 test vector (pure-Lua path, no openssl needed)
  progress("crypto self-test: X25519 RFC 7748 started")
  local x_alice_priv = Bytes.from_hex(
    "77076d0a7318a57d3c16c17251b26645" ..
    "df4c2f87ebc0992ab177fba51db92c2a"
  )
  local x_bob_pub = Bytes.from_hex(
    "de9edb7d7b7dc1b4d35b61c2ece43537" ..
    "3f8343c85b78674dadfc7e146f882b4f"
  )
  local x_alice_pub = Bytes.from_hex(
    "8520f0098930a754748b7ddcb43ef75a" ..
    "0dbf3a0d26381af4eba4a98eaa9b4e6a"
  )
  local x_expected = Bytes.from_hex(
    "4a5d9d5ba4ce2de1728e3bf480350f25" ..
    "e07e21c947d19e3376f09b3c1e161742"
  )
  local x_public = X25519Pure.mul(x_alice_priv, X25519Pure.BASE_POINT)
  if x_public ~= x_alice_pub then
    error("X25519 RFC 7748 base point vector failed: got " ..
      Bytes.hex(x_public) .. " expected " .. Bytes.hex(x_alice_pub))
  end
  local x_shared = OpenSSLCrypto._derive_x25519(x_alice_priv, x_bob_pub)
  if x_shared ~= x_expected then
    error("X25519 RFC 7748 test vector failed: got " ..
      Bytes.hex(x_shared) .. " expected " .. Bytes.hex(x_expected))
  end
  progress("crypto self-test: X25519 RFC 7748 passed")

  progress("crypto self-test: HMAC-SHA512 started")
  local hmac = OpenSSLCrypto.hmac_sha512("key", "data")
  local expected_hmac = Bytes.from_hex(
    "3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253c" ..
    "b52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58"
  )
  assert(hmac == expected_hmac, "HMAC-SHA512 vector failed")
  progress("crypto self-test: HMAC-SHA512 passed")

  progress("crypto self-test: HKDF-SHA512 started")
  local hkdf = OpenSSLCrypto.hkdf_sha512(
    "Pair-Verify-Encrypt-Salt",
    "Pair-Verify-Encrypt-Info",
    Bytes.from_hex("000102030405060708090a0b0c0d0e0f" ..
      "101112131415161718191a1b1c1d1e1f")
  )
  local expected_hkdf = Bytes.from_hex(
    "faf9f3558a8ed1e45219bd94fb6d27e5b43a1bc861157fc2a0d291d8e3df410a"
  )
  assert(hkdf == expected_hkdf, "HKDF-SHA512 vector failed")
  progress("crypto self-test: HKDF-SHA512 passed")

  progress("crypto self-test: native SRP BN modpow started")
  local srp_native = OpenSSLCrypto.srp_modpow(
    BigInt.to_minimal_bytes_be(SRP.g),
    string.char(3),
    384
  )
  assert(BigInt.from_bytes_be(srp_native)[1] == 125, "native SRP BN modpow failed")
  progress("crypto self-test: native SRP BN modpow passed")

  progress("crypto self-test: ChaCha20-Poly1305 started")
  local key = Bytes.from_hex(
    "000102030405060708090a0b0c0d0e0f" ..
    "101112131415161718191a1b1c1d1e1f"
  )
  local nonce = Bytes.from_hex("000102030405060708090a0b")
  local plaintext = "plaintext"
  local aad = "aad"
  local expected_ciphertext = Bytes.from_hex("f99769694763c038c388540d8367db9102148f2c2034e779d0")
  local ciphertext = OpenSSLCrypto._chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
  if ciphertext ~= expected_ciphertext then
    error("ChaCha20-Poly1305 encrypt vector failed: got " ..
      Bytes.hex(ciphertext) .. " expected " .. Bytes.hex(expected_ciphertext))
  end
  plaintext = OpenSSLCrypto._chacha20_poly1305_decrypt(key, nonce, ciphertext, aad)
  assert(plaintext == "plaintext", "ChaCha20-Poly1305 roundtrip failed")
  local bad_tag = ciphertext:sub(1, #ciphertext - 1) ..
    string.char((ciphertext:byte(#ciphertext) + 1) % 256)
  local bad_ok = pcall(OpenSSLCrypto._chacha20_poly1305_decrypt, key, nonce, bad_tag, aad)
  assert(not bad_ok, "ChaCha20-Poly1305 bad tag was accepted")
  progress("crypto self-test: ChaCha20-Poly1305 passed")

  progress("crypto self-test: secure random started")
  local random_sample = OpenSSLCrypto.random_bytes(32)
  assert(type(random_sample) == "string" and #random_sample == 32, "secure random failed")
  progress("crypto self-test: secure random passed")

  progress("crypto self-test: Ed25519 started")
  local ed_seed = Bytes.from_hex("9d61b19deffd5a60ba844af492ec2cc4" .. "4449c5697b326919703bac031cae7f60")
  local ed_public = Ed25519Pure.public_key_from_private(ed_seed)
  local ed_expected_public = Bytes.from_hex("d75a980182b10ab7d54bfed3c964073a" .. "0ee172f3daa62325af021a68f707511a")
  assert(ed_public == ed_expected_public, "Ed25519 RFC 8032 public key vector failed")
  local ed_signature = Ed25519Pure.sign(ed_seed, ed_public, "")
  local ed_expected_signature = Bytes.from_hex(
    "e5564300c360ac729086e2cc806e828a" ..
    "84877f1eb8e5d974d873e06522490155" ..
    "5fb8821590a33bacc61e39701cf9b46b" ..
    "d25bf5f0595bbe24655141438e7a100b"
  )
  assert(ed_signature == ed_expected_signature, "Ed25519 RFC 8032 signature vector failed")
  assert(Ed25519Pure.verify(ed_public, ed_signature, ""), "Ed25519 RFC 8032 verify vector failed")
  progress("crypto self-test: Ed25519 passed")

  OpenSSLCrypto.self_tested = true
  return true
end

local PairVerify = {
  SALT = "",
  OUTPUT_INFO = "ClientEncrypt-main",
  INPUT_INFO = "ServerEncrypt-main",
}

function PairVerify.encode_start(public_key)
  local pairing_data = TLV8.encode_ordered({
    { 6, string.char(0x01) },
    { 3, public_key },
  })
  local payload = OPACK.encode(OPACK.dict({
    { "_pd", OPACK.bytes(pairing_data) },
    { "_auTy", 4 },
  }))
  return CompanionFrame.encode(CompanionFrame.PV_START, payload)
end

function PairVerify.encode_next(encrypted_data)
  local pairing_data = TLV8.encode_ordered({
    { 6, string.char(0x03) },
    { 5, encrypted_data },
  })
  local payload = OPACK.encode(OPACK.dict({
    { "_pd", OPACK.bytes(pairing_data) },
  }))
  return CompanionFrame.encode(CompanionFrame.PV_NEXT, payload)
end

function PairVerify.decode_pairing_data(payload)
  local message = OPACK.decode(payload)
  assert(type(message) == "table" and message._pd and message._pd.__opack_type == "bytes", "no pairing data in Companion auth message")
  local ok, tlv_or_err = pcall(TLV8.decode, message._pd.data)
  if not ok then
    Log.error("Pair-Verify pairing data TLV decode failed: len=" .. tostring(#message._pd.data) ..
      " head=" .. Bytes.hex(message._pd.data:sub(1, 32)) ..
      " tail=" .. Bytes.hex(message._pd.data:sub(math.max(1, #message._pd.data - 31))))
    error(tlv_or_err, 2)
  end
  local tlv = tlv_or_err
  assert(not tlv[7], "Apple TV returned pairing error")
  return tlv, message
end

function PairVerify.new(credentials, crypto)
  return setmetatable({
    credentials = credentials,
    crypto = crypto or Crypto,
    keypair = nil,
    shared_secret = nil,
    output_key = nil,
    input_key = nil,
  }, { __index = PairVerify })
end

function PairVerify:start()
  local keypair = crypto_method(self.crypto, "generate_x25519_keypair")()
  assert(type(keypair) == "table" and type(keypair.public_key) == "string", "invalid X25519 keypair")
  self.keypair = keypair
  return PairVerify.encode_start(keypair.public_key)
end

function PairVerify:finish(response_frame)
  assert(self.keypair, "pair verify has not started")
  local frame = response_frame
  if type(response_frame) == "string" then
    frame = CompanionFrame.try_decode(response_frame)
  end
  assert(frame and frame.frame_type == CompanionFrame.PV_NEXT, "expected Pair-Verify next frame")

  local tlv = PairVerify.decode_pairing_data(frame.payload)
  local server_public_key = tlv[3]
  local encrypted_data = tlv[5]
  assert(server_public_key and encrypted_data, "Pair-Verify response missing public key or encrypted data")

  local encrypted_response, shared_secret = crypto_method(self.crypto, "pair_verify_response")(
    self.credentials,
    self.keypair.private_key,
    self.keypair.public_key,
    server_public_key,
    encrypted_data
  )

  self.shared_secret = shared_secret
  self.output_key = crypto_method(self.crypto, "hkdf_sha512")(PairVerify.SALT, PairVerify.OUTPUT_INFO, shared_secret)
  self.input_key = crypto_method(self.crypto, "hkdf_sha512")(PairVerify.SALT, PairVerify.INPUT_INFO, shared_secret)

  return PairVerify.encode_next(encrypted_response), {
    output_key = self.output_key,
    input_key = self.input_key,
  }
end

-- PairSetup: Companion Pair-Setup M1-M6 state machine (SRP-6a / HAP).
-- Depends on BigInt and SRP modules above.
local PairSetup = {}

function PairSetup.new(crypto)
  return setmetatable({
    crypto = crypto or Crypto,
    auth_private = nil,  -- Ed25519 32-byte private key for this session
    auth_public = nil,   -- Ed25519 32-byte public key
    pairing_id = nil,    -- UUID string (36 chars)
    a_bytes = nil,       -- SRP client private (32 bytes random)
    A_bytes = nil,       -- SRP client public (384 bytes, g^a mod N)
    K = nil,             -- SHA-512(S): SRP session key
    session_key = nil,   -- HKDF key for ChaCha20 encryption in M5/M6
    _M1 = nil,           -- client proof
    _salt = nil,
    _B_bytes = nil,
    state = "IDLE",
  }, { __index = PairSetup })
end

function PairSetup:start()
  Log.debug("Pair-Setup M1 start: generating controller Ed25519 key and pairing id")
  local keypair = crypto_method(self.crypto, "generate_ed25519_keypair")()
  self.auth_private = keypair.private_key
  self.auth_public = keypair.public_key
  local uuid_bytes = crypto_method(self.crypto, "random_bytes")(16)
  local h = Bytes.hex(uuid_bytes)
  self.pairing_id = h:sub(1,8).."-"..h:sub(9,12).."-"..h:sub(13,16).."-"..h:sub(17,20).."-"..h:sub(21,32)
  local pairing_data = TLV8.encode_ordered({
    { 0, string.char(0x00) },  -- Method = 0 (Pair-Setup)
    { 6, string.char(0x01) },  -- SeqNo = M1
  })
  local payload = OPACK.encode(OPACK.dict({
    { "_pd", OPACK.bytes(pairing_data) },
    { "_pwTy", 1 },
  }))
  self.state = "M1_SENT"
  Log.debug("Pair-Setup M1 sent: public_key_len=" .. tostring(#self.auth_public) ..
    " pairing_id=" .. tostring(self.pairing_id))
  return CompanionFrame.encode(CompanionFrame.PS_START, payload)
end

function PairSetup:handle_m2(frame)
  Log.debug("Pair-Setup M2 received: frame_type=" .. CompanionFrame.name(frame.frame_type) ..
    " payload_len=" .. tostring(#(frame.payload or "")))
  assert(self.state == "M1_SENT", "unexpected M2 in state " .. self.state)
  local tlv = PairVerify.decode_pairing_data(frame.payload)
  local salt = tlv[2]
  local B_bytes = tlv[3]
  assert(salt and #salt == 16, "SRP salt must be 16 bytes, got " .. tostring(salt and #salt))
  assert(B_bytes and #B_bytes == 384, "SRP server public key must be 384 bytes")
  self._salt = salt
  self._B_bytes = B_bytes
  self.state = "M2_RECEIVED"
  Log.debug("Pair-Setup M2 parsed: salt_len=" .. tostring(#salt) ..
    " server_public_len=" .. tostring(#B_bytes))
  return salt, B_bytes
end

function PairSetup:compute_m3(pin)
  Log.debug("Pair-Setup M3 compute started: deriving SRP proof from PIN")
  assert(self.state == "M2_RECEIVED", "must receive M2 before computing M3")
  local old_modpow = SRP._modpow
  SRP._modpow = optional_crypto_method(self.crypto, "srp_modpow")
  if SRP._modpow then
    Log.debug("Pair-Setup M3 using native SRP BN modpow")
  else
    Log.debug("Pair-Setup M3 using pure Lua SRP modpow")
  end
  self.a_bytes = crypto_method(self.crypto, "random_bytes")(32)
  Log.debug("Pair-Setup M3 progress: random SRP secret generated")
  local ok, err = pcall(function()
    self.A_bytes = SRP.compute_A(self.a_bytes)
    Log.debug("Pair-Setup M3 progress: SRP public key computed")
    local x = SRP.compute_x(self._salt, pin)
    Log.debug("Pair-Setup M3 progress: SRP x computed")
    local u = SRP.compute_u(self.A_bytes, self._B_bytes)
    Log.debug("Pair-Setup M3 progress: SRP u computed")
    self.K = SRP.compute_session_key(self._B_bytes, self.a_bytes, x, u)
    Log.debug("Pair-Setup M3 progress: SRP session key computed")
  end)
  SRP._modpow = old_modpow
  if not ok then
    error(err, 2)
  end
  self._M1 = SRP.compute_M1(self.A_bytes, self._B_bytes, self.K, self._salt)
  Log.debug("Pair-Setup M3 progress: SRP client proof computed")
  local pairing_data = TLV8.encode_ordered({
    { 6, string.char(0x03) },  -- SeqNo = M3
    { 3, self.A_bytes },       -- PublicKey = A (384 bytes)
    { 4, self._M1 },           -- Proof = M1 (64 bytes)
  })
  local payload = OPACK.encode(OPACK.dict({
    { "_pd", OPACK.bytes(pairing_data) },
    { "_pwTy", 1 },
  }))
  self.state = "M3_SENT"
  Log.debug("Pair-Setup M3 sent: client_public_len=" .. tostring(#self.A_bytes) ..
    " proof_len=" .. tostring(#self._M1))
  return CompanionFrame.encode(CompanionFrame.PS_NEXT, payload)
end

function PairSetup:handle_m4(frame)
  Log.debug("Pair-Setup M4 received: frame_type=" .. CompanionFrame.name(frame.frame_type) ..
    " payload_len=" .. tostring(#(frame.payload or "")))
  assert(self.state == "M3_SENT", "unexpected M4 in state " .. self.state)
  local tlv = PairVerify.decode_pairing_data(frame.payload)
  local atv_M2 = tlv[4]
  assert(atv_M2 and #atv_M2 == 64, "server M4 proof must be 64 bytes")
  Log.debug("Pair-Setup M4 progress: verifying server proof")
  assert(SRP.verify_M2(self.A_bytes, self._M1, self.K, atv_M2), "SRP M2 proof verification failed")
  Log.debug("Pair-Setup M4 progress: server proof verified")
  self.session_key = crypto_method(self.crypto, "hkdf_sha512")(
    "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", self.K)
  self.state = "M4_VERIFIED"
  Log.debug("Pair-Setup M4 verified: encryption key derived")
end

function PairSetup:compute_m5()
  Log.debug("Pair-Setup M5 compute started: signing controller identity")
  assert(self.state == "M4_VERIFIED", "must verify M4 before computing M5")
  local ios_device_x = crypto_method(self.crypto, "hkdf_sha512")(
    "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", self.K)
  local device_info = ios_device_x .. self.pairing_id .. self.auth_public
  local signature = crypto_method(self.crypto, "ed25519_sign")(self.auth_private, device_info)
  local inner_tlv = TLV8.encode_ordered({
    { 1, self.pairing_id },
    { 3, self.auth_public },
    { 10, signature },
  })
  local nonce = string.rep("\0", 4) .. "PS-Msg05"  -- 12-byte nonce for ChaCha20
  local encrypted = crypto_method(self.crypto, "encrypt")(self.session_key, inner_tlv, "", nonce)
  Log.debug("Pair-Setup M5 progress: identity signed and encrypted")
  local pairing_data = TLV8.encode_ordered({
    { 6, string.char(0x05) },  -- SeqNo = M5
    { 5, encrypted },          -- EncryptedData
  })
  local payload = OPACK.encode(OPACK.dict({
    { "_pd", OPACK.bytes(pairing_data) },
    { "_pwTy", 1 },
  }))
  self.state = "M5_SENT"
  Log.debug("Pair-Setup M5 sent: encrypted_len=" .. tostring(#encrypted))
  return CompanionFrame.encode(CompanionFrame.PS_NEXT, payload)
end

function PairSetup:handle_m6(frame)
  Log.debug("Pair-Setup M6 received: frame_type=" .. CompanionFrame.name(frame.frame_type) ..
    " payload_len=" .. tostring(#(frame.payload or "")))
  assert(self.state == "M5_SENT", "unexpected M6 in state " .. self.state)
  local tlv = PairVerify.decode_pairing_data(frame.payload)
  local encrypted_data = tlv[5]
  assert(encrypted_data, "server M6 encrypted data missing")
  Log.debug("Pair-Setup M6 progress: encrypted_len=" .. tostring(#encrypted_data) .. ", decrypting")
  local nonce = string.rep("\0", 4) .. "PS-Msg06"
  local decrypted = crypto_method(self.crypto, "decrypt")(self.session_key, encrypted_data, "", nonce)
  assert(decrypted, "M6 decrypt failed")
  Log.debug("Pair-Setup M6 progress: decrypted_len=" .. tostring(#decrypted))
  local inner = TLV8.decode(decrypted)
  local atv_id = inner[1]
  local atv_ltpk = inner[3]
  assert(atv_id and atv_ltpk, "M6 response missing identifier or public key")
  -- Note: pyatv also leaves atv_signature verification as a TODO
  local credentials_str = table.concat({
    Bytes.hex(atv_ltpk),
    Bytes.hex(self.auth_private),
    Bytes.hex(atv_id),
    Bytes.hex(self.pairing_id),
  }, ":")
  self.state = "PAIRED"
  Log.debug("Pair-Setup M6 parsed: atv_id_len=" .. tostring(#atv_id) ..
    " atv_public_key_len=" .. tostring(#atv_ltpk))
  return Credentials.parse(credentials_str)
end

local CompanionSession = {}
CompanionSession.AUTH_TAG_LENGTH = 16

function CompanionSession.new(output_key, input_key, crypto)
  return setmetatable({
    output_key = output_key,
    input_key = input_key,
    crypto = crypto or Crypto,
    out_counter = 0,
    in_counter = 0,
  }, { __index = CompanionSession })
end

function CompanionSession:encode_frame(frame_type, payload)
  assert(type(payload) == "string", "payload must be a string")
  if #payload == 0 then
    return CompanionFrame.encode(frame_type, payload)
  end

  local encrypted_length = #payload + CompanionSession.AUTH_TAG_LENGTH
  local header = string.char(frame_type) .. Bytes.u24be(encrypted_length)
  local nonce = Bytes.uint_le(self.out_counter, 12)
  self.out_counter = self.out_counter + 1
  local encrypted = crypto_method(self.crypto, "encrypt")(self.output_key, payload, header, nonce)
  assert(#encrypted == encrypted_length, "encrypted Companion payload length must include auth tag")
  return header .. encrypted
end

function CompanionSession:try_decode(buffer)
  if #buffer < 4 then
    return nil, buffer
  end

  local frame_type = buffer:byte(1)
  local encrypted_length = Bytes.read_u24be(buffer, 2)
  local frame_end = 4 + encrypted_length
  if #buffer < frame_end then
    return nil, buffer
  end

  local header = buffer:sub(1, 4)
  local payload = buffer:sub(5, frame_end)
  if #payload > 0 then
    local nonce = Bytes.uint_le(self.in_counter, 12)
    self.in_counter = self.in_counter + 1
    payload = crypto_method(self.crypto, "decrypt")(self.input_key, payload, header, nonce)
  end

  return {
    frame_type = frame_type,
    encrypted_length = encrypted_length,
    payload = payload,
    length = #payload,
  }, buffer:sub(frame_end + 1)
end

local Companion = {
  state = "DISCONNECTED",
  port = 49153,
  tx = 0,
  socket = nil,
  sent_messages = {},
  pending_commands = {},
  session = nil,
  credentials = nil,
  client = nil,
  app_list = {},
  current_app = nil,
  now_playing = {},
}

function Companion.next_x()
  Companion.tx = Companion.tx + 1
  return Companion.tx
end

function Companion.build_request(identifier, content, message_type)
  return {
    _i = identifier,
    _t = message_type or 2,
    _x = Companion.next_x(),
    _c = content or {},
  }
end

function Companion.content_entries(identifier, content)
  content = content or {}
  local preferred = {
    _launchApp = { "_bundleID", "_urlS" },
    _hidC = { "_hBtS", "_hidC" },
    _sessionStart = { "_srvT", "_sid" },
    _sessionStop = { "_srvT", "_sid" },
  }

  local seen = {}
  local entries = {}
  for _, key in ipairs(preferred[identifier] or {}) do
    if content[key] ~= nil then
      entries[#entries + 1] = { key, content[key] }
      seen[key] = true
    end
  end

  local extra = {}
  for key in pairs(content) do
    if not seen[key] then
      extra[#extra + 1] = key
    end
  end
  table.sort(extra)
  for _, key in ipairs(extra) do
    entries[#entries + 1] = { key, content[key] }
  end

  return entries
end

function Companion.encode_request_payload(request)
  return OPACK.encode(OPACK.dict({
    { "_i", request._i },
    { "_t", request._t },
    { "_c", OPACK.dict(Companion.content_entries(request._i, request._c)) },
    { "_x", request._x },
  }))
end

function Companion.encode_opack_request(identifier, content, message_type)
  local request = Companion.build_request(identifier, content, message_type)
  local payload = Companion.encode_request_payload(request)
  local frame = Companion.session and Companion.session:encode_frame(CompanionFrame.E_OPACK, payload) or CompanionFrame.encode(CompanionFrame.E_OPACK, payload)
  return request, frame
end

function Companion.encode_pair_setup_start()
  local pairing_data = TLV8.encode({
    [0] = string.char(0x00),
    [6] = string.char(0x01),
  })
  local payload = OPACK.encode(OPACK.dict({
    { "_pd", OPACK.bytes(pairing_data) },
    { "_pwTy", 1 },
  }))
  return CompanionFrame.encode(CompanionFrame.PS_START, payload)
end

function Companion.send_opack(identifier, content, message_type)
  if Companion.client and Companion.client.send_or_queue_opack then
    return Companion.client:send_or_queue_opack(identifier, content, message_type)
  end

  local request, frame = Companion.encode_opack_request(identifier, content, message_type)
  Companion.sent_messages[#Companion.sent_messages + 1] = request

  if Companion.socket and Companion.socket.send then
    Companion.socket:send(frame)
  else
    Log.debug("queued Companion request " .. identifier)
  end

  return request, frame
end

function Companion.app_name_for_bundle(bundle_id)
  if not bundle_id or type(Companion.app_list) ~= "table" then
    return nil
  end
  return Companion.app_list[bundle_id]
end

function Companion.set_current_app(bundle_id_or_url)
  if type(bundle_id_or_url) ~= "string" or bundle_id_or_url == "" then
    return nil
  end
  local app = {
    identifier = bundle_id_or_url,
    name = Companion.app_name_for_bundle(bundle_id_or_url) or bundle_id_or_url,
  }
  Companion.current_app = app
  return app
end

function Companion.launch_app(bundle_id_or_url)
  assert(type(bundle_id_or_url) == "string" and bundle_id_or_url ~= "", "bundle id or URL required")
  local key = string.match(bundle_id_or_url, "^[%a][%w+.-]*:") and "_urlS" or "_bundleID"
  Companion.set_current_app(bundle_id_or_url)
  return Companion.send_opack("_launchApp", { [key] = bundle_id_or_url }, 2)
end

function Companion.fetch_apps()
  return Companion.send_opack("FetchLaunchableApplicationsEvent", {}, 2)
end

function Companion.parse_app_list(content)
  local apps = {}
  local rows = {}
  if type(content) ~= "table" then
    return apps, rows
  end

  for bundle_id, name in pairs(content) do
    if type(bundle_id) == "string" and type(name) == "string" then
      apps[bundle_id] = name
      rows[#rows + 1] = { name = name, identifier = bundle_id }
    end
  end
  table.sort(rows, function(a, b)
    return string.lower(a.name) < string.lower(b.name)
  end)
  return apps, rows
end

function Companion.render_app_list(rows)
  local lines = {}
  for _, app in ipairs(rows or {}) do
    lines[#lines + 1] = app.name .. " | " .. app.identifier
  end
  return table.concat(lines, "\n")
end

function Companion.app_display_name(app)
  if type(app) ~= "table" then return "" end
  return tostring(app.name or app.identifier or "") .. " | " .. tostring(app.identifier or "")
end

function Companion.app_selector_items(rows)
  local items = { "" }
  for _, app in ipairs(rows or {}) do
    local item = Companion.app_display_name(app):gsub(",", " ")
    if item ~= " | " then
      items[#items + 1] = item
    end
  end
  return items
end

function Companion.resolve_app_selection(selection)
  selection = tostring(selection or "")
  if selection == "" then return nil end
  if Companion.app_list[selection] then return selection end

  local exact_name_match
  for _, app in ipairs(Companion.app_list_rows or {}) do
    if selection == Companion.app_display_name(app) or selection == app.name then
      if selection == app.name and exact_name_match and exact_name_match ~= app.identifier then
        return nil, "multiple apps match name " .. selection .. "; select the full app entry"
      end
      exact_name_match = app.identifier
    end
  end
  if exact_name_match then return exact_name_match end

  local needle = selection:lower()
  local fuzzy_match
  for _, app in ipairs(Companion.app_list_rows or {}) do
    local name = tostring(app.name or ""):lower()
    local identifier = tostring(app.identifier or ""):lower()
    if name:find(needle, 1, true) or identifier:find(needle, 1, true) then
      if fuzzy_match and fuzzy_match ~= app.identifier then
        return nil, "multiple apps match " .. selection .. "; select the full app entry"
      end
      fuzzy_match = app.identifier
    end
  end
  return fuzzy_match
end

function Companion.render_current_app(app)
  if type(app) ~= "table" then
    return ""
  end
  if app.name and app.identifier and app.name ~= app.identifier then
    return app.name .. " | " .. app.identifier
  end
  return app.identifier or app.name or ""
end

function Companion.render_now_playing(now_playing)
  if type(now_playing) ~= "table" then
    return ""
  end
  local title = now_playing.title or now_playing.name
  local artist = now_playing.artist
  local album = now_playing.album
  local parts = {}
  if title and title ~= "" then parts[#parts + 1] = title end
  if artist and artist ~= "" then parts[#parts + 1] = artist end
  if album and album ~= "" then parts[#parts + 1] = album end
  return table.concat(parts, " - ")
end

function Companion.update_from_message(message)
  if type(message) ~= "table" then
    return nil
  end

  local changed = {}
  local content = type(message._c) == "table" and message._c or {}

  if message._i == "FetchLaunchableApplicationsEvent" and message._t == 3 then
    local apps, rows = Companion.parse_app_list(content)
    Companion.app_list = apps
    Companion.app_list_rows = rows
    changed.app_list = true
    if Companion.current_app and Companion.current_app.identifier then
      Companion.set_current_app(Companion.current_app.identifier)
      changed.current_app = true
    end
  end

  local launched = content._bundleID or content._urlS or content.bundleID or content.bundle_id
  if message._i == "_launchApp" and launched then
    Companion.set_current_app(launched)
    changed.current_app = true
  end

  local app_id = content.app_id or content.appID or content.bundleID or content._bundleID
  local app_name = content.app or content.appName or content.name
  if app_id or (message._i == "CurrentApp" and app_name) then
    Companion.current_app = {
      identifier = app_id or app_name,
      name = app_name or Companion.app_name_for_bundle(app_id) or app_id,
    }
    changed.current_app = true
  end

  local title = content.title or content._title or content.name
  local artist = content.artist or content._artist
  local album = content.album or content._album
  if title or artist or album or content.duration or content.position then
    Companion.now_playing = {
      title = title,
      artist = artist,
      album = album,
      duration = content.duration,
      position = content.position,
      repeat_state = content.repeat_state or content["repeat"],
      shuffle = content.shuffle,
    }
    changed.now_playing = true
  end

  return next(changed) and changed or nil
end

local HID_COMMANDS = {
  UP = 1,
  DOWN = 2,
  LEFT = 3,
  RIGHT = 4,
  MENU = 5,
  SELECT = 6,
  HOME = 7,
  VOLUME_UP = 8,
  VOLUME_DOWN = 9,
  SLEEP = 12,
  WAKE = 13,
  PLAY_PAUSE = 14,
  GUIDE = 17,
}

function Companion.button(name, state)
  local command = HID_COMMANDS[name]
  assert(command, "unsupported HID command: " .. tostring(name))
  return Companion.send_opack("_hidC", {
    _hidC = command,
    _hBtS = state or 2,
  }, 2)
end

function Companion.button_action(name, action)
  action = string.lower(tostring(action or "single"))
  if action == "singletap" or action == "tap" or action == "single" or action == "" then
    return { Companion.button(name, 1), Companion.button(name, 2) }
  end
  if action == "doubletap" or action == "double" then
    return {
      Companion.button(name, 1),
      Companion.button(name, 2),
      Companion.button(name, 1),
      Companion.button(name, 2),
    }
  end
  if action == "hold" or action == "longpress" or action == "long_press" then
    return { Companion.button(name, 1), Companion.button(name, 2) }
  end
  if action == "down" or action == "press" or action == "start" then
    return { Companion.button(name, 1) }
  end
  if action == "up" or action == "release" or action == "stop" then
    return { Companion.button(name, 2) }
  end
  error("unsupported HID action: " .. tostring(action))
end

local CompanionClient = {}

function CompanionClient.new(options)
  options = options or {}
  return setmetatable({
    host = options.host,
    port = options.port or 49153,
    credentials = options.credentials,
    crypto = options.crypto or Crypto,
    transport = options.transport,
    buffer = "",
    verifier = nil,
    pair_setup = nil,
    pending_pair_setup = false,
    pending_pair_verify_keys = nil,
    session = nil,
    session_local_sid = nil,
    session_remote_sid = nil,
    session_start_xid = nil,
    pending_responses = {},
    pending_commands = {},
    startup_steps = nil,
    startup_index = 0,
    post_session_started = false,
    injected_transport = options.transport ~= nil,
    connecting = false,
    connected = false,
    state = "DISCONNECTED",
    received_messages = {},
    on_state = options.on_state,
    on_message = options.on_message,
    on_paired = options.on_paired,
    on_pair_setup_m2 = options.on_pair_setup_m2,
  }, { __index = CompanionClient })
end

function CompanionClient:set_state(state)
  if self.state ~= state then
    Log.debug("Companion state: " .. tostring(self.state) .. " -> " .. tostring(state))
  else
    Log.debug("Companion state: " .. tostring(state))
  end
  self.state = state
  if self.on_state then
    self.on_state(state)
  end
end

function CompanionClient:send_raw(frame)
  assert(type(frame) == "string", "frame must be a string")
  assert(self.transport, "Companion transport is not connected")
  if #frame >= 4 then
    local frame_type = frame:byte(1)
    local length = Bytes.read_u24be(frame, 2)
    Log.debug("Companion send frame: type=" .. CompanionFrame.name(frame_type) ..
      " payload_len=" .. tostring(length))
  else
    Log.debug("Companion send raw bytes: len=" .. tostring(#frame))
  end
  if self.transport.Write then
    return self.transport:Write(frame)
  end
  if self.transport.write then
    return self.transport:write(frame)
  end
  if self.transport.send then
    return self.transport:send(frame)
  end
  error("Companion transport has no write method")
end

function CompanionClient:send(frame)
  return self:send_raw(frame)
end

function CompanionClient:close()
  if self.session then
    pcall(function()
      self:send_opack("_interest", {
        _deregEvents = OPACK.array({ "_iMC" }),
      }, 1)
    end)
  end
  if self.session and self.session_local_sid and self.session_remote_sid then
    local sid = OPACK.int64(self.session_remote_sid, self.session_local_sid)
    pcall(function()
      self:send_opack("_sessionStop", {
        _srvT = "com.apple.tvremoteservices",
        _sid = sid,
      }, 2)
    end)
  end
  if self.session then
    pcall(function()
      self:send_opack("_touchStop", { _i = 1 }, 2)
    end)
    pcall(function()
      self:send_opack("_tiStop", {}, 2)
    end)
  end
  if self.transport and self.transport.Close then
    self.transport:Close()
  elseif self.transport and self.transport.close then
    self.transport:close()
  end
  self.transport = nil
  self.connecting = false
  self.connected = false
  self:set_state("DISCONNECTED")
end

function CompanionClient:connect(host, port)
  self.host = host or self.host
  self.port = port or self.port
  assert(type(self.host) == "string" and self.host ~= "", "Apple TV address is required")

  if self.connected and self.transport then
    Log.debug("Companion TCP already connected")
    return self
  end
  if self.connecting then
    Log.debug("Companion TCP connect already in progress")
    return self
  end

  Log.debug("Companion TCP connect requested: host=" .. tostring(self.host) ..
    " port=" .. tostring(self.port))

  if self.transport and self.injected_transport then
    Log.debug("Companion TCP using injected transport")
    self:on_connected(self.transport)
    return self
  end
  if self.transport and not self.injected_transport then
    Log.debug("Companion TCP socket exists, waiting for connect callback")
    self.connecting = true
    return self
  end

  assert(has_c4() and C4.CreateTCPClient, "Control4 TCP client is not available")
  local client
  self.connecting = true
  client = C4:CreateTCPClient()
    :OnConnect(function(tcp_client)
      Log.debug("Companion TCP connected")
      self:on_connected(tcp_client)
      tcp_client:ReadUpTo(4096)
    end)
    :OnRead(function(tcp_client, data)
      Log.debug("Companion TCP read: bytes=" .. tostring(#(data or "")))
      local ok, err = pcall(function() self:receive(data) end)
      if not ok then
        Log.error("Companion receive failed: " .. tostring(err))
        self:set_state("ERROR: " .. tostring(err))
      end
      tcp_client:ReadUpTo(4096)
    end)
    :OnDisconnect(function(_, err_code, err_msg)
      Log.debug("Companion TCP disconnected: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.connecting = false
      self.connected = false
      self.transport = nil
      self:set_state((err_code and err_code ~= 0) and ("DISCONNECTED: " .. tostring(err_msg)) or "DISCONNECTED")
    end)
    :OnError(function(_, err_code, err_msg)
      Log.error("Companion TCP error: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.connecting = false
      self.connected = false
      self.transport = nil
      self:set_state("ERROR: " .. tostring(err_code) .. " " .. tostring(err_msg))
    end)
    :Connect(self.host, self.port)

  self.transport = client
  return self
end

function CompanionClient:on_connected(transport)
  self.transport = transport
  self.connecting = false
  self.connected = true
  self:set_state("CONNECTED")
  Log.debug("Companion TCP ready: credentials_present=" .. tostring(self.credentials ~= nil))
  if self.credentials then
    self:start_pair_verify()
  elseif self.pending_pair_setup then
    self.pending_pair_setup = false
    self:start_pair_setup()
  end
end

function CompanionClient:start_pair_verify()
  assert(self.credentials, "Companion credentials are required")
  self.verifier = PairVerify.new(self.credentials, self.crypto)
  local frame = self.verifier:start()
  self:set_state("PAIR_VERIFY_STARTED")
  self:send_raw(frame)
  return frame
end

function CompanionClient:enable_session(keys)
  self.session = CompanionSession.new(keys.output_key, keys.input_key, self.crypto)
  Companion.session = self.session
  Companion.socket = self
  self:set_state("READY")
  self:start_companion_services()
end

function CompanionClient:send_system_info()
  return self:send_opack("_systemInfo", {
    _bf = 0,
    _cf = 512,
    _clFl = 128,
    _i = "Control4",
    _idsID = self.credentials and self.credentials.client_id or "",
    _pubID = "Control4",
    _sf = 256,
    _sv = Driver.VERSION,
    model = "Control4",
    name = "Control4",
  }, 2, function()
    self:send_next_startup_step()
  end)
end

function CompanionClient:start_touch()
  return self:send_opack("_touchStart", {
    _height = 1000,
    _tFl = 0,
    _width = 1000,
  }, 2, function()
    self:send_next_startup_step()
  end)
end

function CompanionClient:start_companion_services()
  self.startup_steps = {
    function() self:send_system_info() end,
    function() self:start_touch() end,
    function() self:start_session() end,
    function() self:start_text_input() end,
    function() self:subscribe_initial_events() end,
  }
  self.startup_index = 0
  self:send_next_startup_step()
end

function CompanionClient:send_next_startup_step()
  if not self.startup_steps then return end
  self.startup_index = self.startup_index + 1
  local step = self.startup_steps[self.startup_index]
  if step then
    step()
    return
  end
  self.startup_steps = nil
  self.startup_index = 0
  self:flush_pending_commands()
end

function CompanionClient:start_session()
  local random_bytes = optional_crypto_method(self.crypto, "random_bytes") or Crypto.random_bytes
  local sid_bytes = random_bytes(4)
  assert(type(sid_bytes) == "string" and #sid_bytes == 4, "session SID random source returned wrong length")
  self.session_local_sid = sid_bytes:byte(1) +
    sid_bytes:byte(2) * 0x100 +
    sid_bytes:byte(3) * 0x10000 +
    sid_bytes:byte(4) * 0x1000000
  local request = self:send_opack("_sessionStart", {
    _srvT = "com.apple.tvremoteservices",
    _sid = self.session_local_sid,
  }, 2, function(message)
    if type(message._c) ~= "table" then
      error("_sessionStart response missing content")
    end
    self.session_remote_sid = message._c._sid
    self.session_start_xid = nil
    self:set_state("SESSION_ACTIVE")
    Log.debug("Companion session active, remote_sid=" .. tostring(self.session_remote_sid))
    self:send_next_startup_step()
  end)
  self.session_start_xid = request._x
  self:set_state("SESSION_STARTING")
end

function CompanionClient:start_text_input()
  if self.post_session_started then return end
  self.post_session_started = true
  self:send_opack("_tiStart", {}, 2, function()
    self:send_next_startup_step()
  end)
end

function CompanionClient:subscribe_initial_events()
  self:send_opack("_interest", {
    _regEvents = OPACK.array({ "_iMC" }),
  }, 1)
  self:send_next_startup_step()
end

function CompanionClient:receive(data)
  self.buffer = self.buffer .. (data or "")
  Log.debug("Companion receive buffered: buffer_len=" .. tostring(#self.buffer) ..
    " encrypted_session=" .. tostring(self.session ~= nil))
  while true do
    local frame
    if self.session then
      frame, self.buffer = self.session:try_decode(self.buffer)
    else
      frame, self.buffer = CompanionFrame.try_decode(self.buffer)
    end
    if not frame then
      Log.debug("Companion receive waiting for complete frame: buffer_len=" .. tostring(#self.buffer))
      return
    end
    Log.debug("Companion receive frame: type=" .. CompanionFrame.name(frame.frame_type) ..
      " payload_len=" .. tostring(#(frame.payload or "")) ..
      " remaining_buffer=" .. tostring(#self.buffer))
    self:handle_frame(frame)
  end
end

function CompanionClient:handle_frame(frame)
  if self.verifier and self.state == "PAIR_VERIFY_STARTED" and frame.frame_type == CompanionFrame.PV_NEXT then
    Log.debug("Pair-Verify M2 received: finishing Pair-Verify")
    local next_frame, keys = self.verifier:finish(frame)
    self:send_raw(next_frame)
    self.pending_pair_verify_keys = keys
    self:set_state("PAIR_VERIFY_M3_SENT")
    return
  end

  if self.verifier and self.state == "PAIR_VERIFY_M3_SENT" and frame.frame_type == CompanionFrame.PV_NEXT then
    Log.debug("Pair-Verify M4 received: enabling encrypted session")
    local keys = assert(self.pending_pair_verify_keys, "missing Pair-Verify session keys")
    self.pending_pair_verify_keys = nil
    self:enable_session(keys)
    return
  end

  -- Pair-Setup M2 response (Apple TV sends salt + server public key)
  if self.pair_setup and self.state == "PAIR_SETUP_M1_SENT"
     and (frame.frame_type == CompanionFrame.PS_START or frame.frame_type == CompanionFrame.PS_NEXT)
  then
    local salt, B_bytes = self.pair_setup:handle_m2(frame)
    if self.on_pair_setup_m2 then self.on_pair_setup_m2(salt, B_bytes) end
    self:set_state("PAIR_SETUP_AWAITING_PIN")
    return
  end

  -- Pair-Setup M4 response (Apple TV proves it knows the verifier)
  if self.pair_setup and self.state == "PAIR_SETUP_M3_SENT"
     and frame.frame_type == CompanionFrame.PS_NEXT
  then
    local ok, err = pcall(function() self.pair_setup:handle_m4(frame) end)
    if not ok then
      Log.error("Pair-Setup M4 failed: " .. tostring(err))
      self:set_state("PAIR_SETUP_FAILED: " .. tostring(err))
      return
    end
    local m5_ok, m5_frame = pcall(function() return self.pair_setup:compute_m5() end)
    if not m5_ok then
      Log.error("Pair-Setup M5 compute failed: " .. tostring(m5_frame))
      self:set_state("PAIR_SETUP_FAILED: " .. tostring(m5_frame))
      return
    end
    self:send_raw(m5_frame)
    self:set_state("PAIR_SETUP_M5_SENT")
    return
  end

  -- Pair-Setup M6 response (Apple TV sends its identity)
  if self.pair_setup and self.state == "PAIR_SETUP_M5_SENT"
     and frame.frame_type == CompanionFrame.PS_NEXT
  then
    local ok, result = pcall(function() return self.pair_setup:handle_m6(frame) end)
    if not ok then
      Log.error("Pair-Setup M6 failed: " .. tostring(result))
      self:set_state("PAIR_SETUP_FAILED: " .. tostring(result))
      return
    end
    self.credentials = result
    if self.on_paired then self.on_paired(result) end
    self:set_state("PAIR_SETUP_COMPLETE")
    Log.debug("Pair-Setup complete: credentials available")
    return
  end

  if frame.frame_type == CompanionFrame.U_OPACK or frame.frame_type == CompanionFrame.E_OPACK then
    local message = OPACK.decode(frame.payload)
    Log.debug("Companion OPACK message: id=" .. tostring(message._i) ..
      " type=" .. tostring(message._t) ..
      " xid=" .. tostring(message._x))
    self.received_messages[#self.received_messages + 1] = message

    if message._t == 3 and message._x ~= nil then
      local pending = self.pending_responses[message._x]
      if pending then
        self.pending_responses[message._x] = nil
        if message._i == nil then
          message._i = pending.identifier
        end
        if message._em ~= nil then
          local err = "Companion command failed: " .. tostring(message._em)
          Log.error(err)
          if pending.on_error then pending.on_error(message) end
          if not pending.on_error then self:set_state("ERROR: " .. err) end
        elseif pending.on_response then
          pending.on_response(message)
        end
      else
        Log.debug("Companion response without pending request: xid=" .. tostring(message._x))
      end
    end

    if self.on_message then
      self.on_message(message)
    end
    return
  end

  Log.debug("unhandled Companion frame type " .. tostring(frame.frame_type))
end

function CompanionClient:start_pair_setup()
  Log.debug("Pair-Setup start requested")
  self.pair_setup = PairSetup.new(self.crypto)
  local frame = self.pair_setup:start()
  self:set_state("PAIR_SETUP_M1_SENT")
  self:send_raw(frame)
  return frame
end

function CompanionClient:request_pair_setup()
  if self.state == "CONNECTED" then
    return self:start_pair_setup()
  end
  Log.debug("Pair-Setup queued until TCP connected")
  self.pending_pair_setup = true
  return nil
end

function CompanionClient:pair_setup_submit_pin(pin)
  assert(self.state == "PAIR_SETUP_AWAITING_PIN",
    "not awaiting PIN, state is " .. tostring(self.state))
  Log.debug("Pair-Setup PIN submitted: computing M3")
  local ok, m3_frame = pcall(function() return self.pair_setup:compute_m3(pin) end)
  if not ok then
    Log.error("Pair-Setup M3 compute failed: " .. tostring(m3_frame))
    self:set_state("PAIR_SETUP_FAILED: " .. tostring(m3_frame))
    error(m3_frame)
  end
  self:set_state("PAIR_SETUP_M3_SENT")
  self:send_raw(m3_frame)
  return m3_frame
end

function CompanionClient:send_opack(identifier, content, message_type, on_response, on_error, request)
  request = request or Companion.build_request(identifier, content, message_type)
  local payload = Companion.encode_request_payload(request)
  local frame = self.session and self.session:encode_frame(CompanionFrame.E_OPACK, payload) or CompanionFrame.encode(CompanionFrame.E_OPACK, payload)
  if request._t == 2 then
    self.pending_responses[request._x] = {
      identifier = identifier,
      on_response = on_response,
      on_error = on_error,
    }
  end
  self:send_raw(frame)
  return request, frame
end

function CompanionClient:is_ready_for_commands()
  return self.state == "SESSION_ACTIVE" and self.session ~= nil
end

function CompanionClient:send_or_queue_opack(identifier, content, message_type)
  local request = Companion.build_request(identifier, content, message_type)
  Companion.sent_messages[#Companion.sent_messages + 1] = request
  if self:is_ready_for_commands() then
    return self:send_opack(identifier, content, message_type, nil, nil, request)
  end
  Log.debug("queued Companion request until session active: " .. tostring(identifier))
  self.pending_commands[#self.pending_commands + 1] = {
    identifier = identifier,
    content = content,
    message_type = message_type,
    request = request,
  }
  if (self.state == "DISCONNECTED" or self.state:match("^DISCONNECTED")) and not self.connecting then
    self:connect()
  end
  return request, nil
end

function CompanionClient:flush_pending_commands()
  if not self:is_ready_for_commands() then
    return
  end
  if #self.pending_commands == 0 then
    return
  end
  local queued = self.pending_commands
  self.pending_commands = {}
  Log.debug("flushing queued Companion requests: count=" .. tostring(#queued))
  for _, item in ipairs(queued) do
    self:send_opack(item.identifier, item.content, item.message_type, nil, nil, item.request)
  end
end

function CompanionClient:launch_app(bundle_id_or_url)
  assert(type(bundle_id_or_url) == "string" and bundle_id_or_url ~= "", "bundle id or URL required")
  local key = string.match(bundle_id_or_url, "^[%a][%w+.-]*:") and "_urlS" or "_bundleID"
  return self:send_or_queue_opack("_launchApp", { [key] = bundle_id_or_url }, 2)
end

function CompanionClient:fetch_apps()
  return self:send_or_queue_opack("FetchLaunchableApplicationsEvent", {}, 2)
end

local C4Driver

local C4MiniApps = {
  PASSTHROUGH_PROXY = 5001,
  SWITCHER_PROXY = 5002,
  USES_DEDICATED_SWITCHER = true,
  MINIAPP_BINDING_START = 3101,
  MINIAPP_BINDING_END = 3125,
  MINIAPP_TYPE = "UM_APPLETV",
  bindings = {},
  room_ids = {},
  room_sources = {},
}

function C4MiniApps.is_binding(binding_id)
  return binding_id >= C4MiniApps.MINIAPP_BINDING_START and binding_id <= C4MiniApps.MINIAPP_BINDING_END
end

function C4MiniApps.register_binding(binding_id, service)
  assert(C4MiniApps.is_binding(binding_id), "binding is outside mini app range")
  assert(type(service) == "table", "service must be a table")
  assert(type(service.service_id) == "string", "service.service_id is required")
  C4MiniApps.bindings[binding_id] = service
end

function C4MiniApps.resolve(binding_id, params)
  local bound = C4MiniApps.bindings[binding_id]
  if bound then
    return bound.service_id, bound
  end

  if params then
    return params.SERVICE_ID or params.service_id or params.APP_ID or params.app_id
  end

  return nil
end

function C4MiniApps.get_relevant_universal_app_id(device_id, source)
  if not (has_c4() and C4.GetDeviceVariables) then
    return nil
  end

  local vars = C4:GetDeviceVariables(device_id)
  for _, var in pairs(vars or {}) do
    if var.name == source then
      return var.value
    end
  end

  if source ~= "APP_ID" then
    return C4MiniApps.get_relevant_universal_app_id(device_id, "APP_ID")
  end

  return nil
end

function C4MiniApps.resolve_bound_minidriver(input)
  if not (has_c4() and C4.GetDeviceID and C4.GetBoundConsumerDevices and C4.GetBoundProviderDevice) then
    return nil
  end

  local consumers = C4:GetBoundConsumerDevices(C4:GetDeviceID(), C4MiniApps.SWITCHER_PROXY) or {}
  local proxy_device_id = next(consumers)
  if not proxy_device_id then
    return nil
  end

  local app_proxy_id = C4:GetBoundProviderDevice(proxy_device_id, input)
  if not app_proxy_id then
    return nil
  end

  local app_device_id = C4:GetBoundProviderDevice(app_proxy_id, 5001)
  if not app_device_id then
    return nil
  end

  return {
    service_id = C4MiniApps.get_relevant_universal_app_id(app_device_id, C4MiniApps.MINIAPP_TYPE),
    name = C4MiniApps.get_relevant_universal_app_id(app_device_id, "APP_NAME"),
    app_proxy_id = app_proxy_id,
    app_device_id = app_device_id,
  }
end

function C4MiniApps.hide_proxy_in_all_rooms(binding_id)
  if not (has_c4() and C4.GetBoundConsumerDevices and C4.GetDevicesByC4iName and C4.SendToDevice) then
    return
  end

  local id, name = next(C4:GetBoundConsumerDevices(C4:GetDeviceID(), binding_id) or {})
  if not id then
    return
  end

  Log.debug("hiding proxy " .. tostring(name) .. " in all rooms")
  for room_id in pairs(C4:GetDevicesByC4iName("roomdevice.c4i") or {}) do
    C4:SendToDevice(room_id, "SET_DEVICE_HIDDEN_STATE", {
      PROXY_GROUP = "ALL",
      DEVICE_ID = id,
      IS_HIDDEN = true,
    })
  end
end

function C4MiniApps.register_rooms()
  if not (has_c4() and C4.GetDevicesByC4iName and C4.GetDeviceVariable) then
    return
  end

  local rooms = C4:GetDevicesByC4iName("roomdevice.c4i") or {}
  C4MiniApps.room_sources = {}
  for room_id in pairs(rooms) do
    C4MiniApps.room_sources[room_id] = tonumber(C4:GetDeviceVariable(room_id, 1000)) or 0
    RegisterVariableListener(room_id, 1000, function(idDevice, _, strValue)
      C4MiniApps.room_sources[idDevice] = tonumber(strValue) or 0
    end)
  end
end

function C4MiniApps.reselect_passthrough_if_needed(app_proxy_id)
  if (Properties and (Properties["Passthrough Mode"] or "On") == "On") then
    return
  end
  if not (has_c4() and C4.GetBoundConsumerDevices and C4.SendToDevice) then
    return
  end

  local passthrough_proxy_device_id = next(C4:GetBoundConsumerDevices(C4:GetDeviceID(), C4MiniApps.PASSTHROUGH_PROXY) or {})
  if not passthrough_proxy_device_id then
    return
  end

  local function reselect()
    for room_id, device_id in pairs(C4MiniApps.room_sources or {}) do
      if device_id == app_proxy_id then
        C4:SendToDevice(room_id, "SELECT_VIDEO_DEVICE", {
          deviceid = passthrough_proxy_device_id,
        })
      end
    end
  end

  if has_c4() then
    SetTimer("AppleTV_reselect_passthrough", 500, reselect)
  else
    reselect()
  end
end

function C4MiniApps.handle_proxy_command(binding_id, command, params)
  if binding_id == nil or command == nil then
    return nil
  end

  params = params or {}

  if binding_id == C4MiniApps.SWITCHER_PROXY and command == "PASSTHROUGH" then
    binding_id = C4MiniApps.PASSTHROUGH_PROXY
    command = params.PASSTHROUGH_COMMAND
  end

  if binding_id == C4MiniApps.SWITCHER_PROXY and command == "SET_INPUT" then
    local input = tonumber(params.INPUT)
    if input and C4MiniApps.is_binding(input) then
      local service = C4MiniApps.resolve_bound_minidriver(input) or C4MiniApps.bindings[input]
      local service_id = service and service.service_id
      if service_id then
        Log.debug("launch mini app " .. service_id)
        local request, frame = C4Driver.launch_app(service_id)
        C4MiniApps.reselect_passthrough_if_needed(service.app_proxy_id)
        return request, frame
      end
      Log.error("mini app selected without a " .. C4MiniApps.MINIAPP_TYPE .. " service id on input " .. tostring(input))
      return nil
    end
  end

  if C4MiniApps.is_binding(binding_id) then
    local service_id = C4MiniApps.resolve(binding_id, params)
    if service_id then
      Log.debug("launch mini app " .. service_id)
      return C4Driver.launch_app(service_id)
    end
    Log.error("mini app selected without a service id on binding " .. tostring(binding_id))
    return nil
  end

  -- Power: ON triggers a connect attempt if not already connected.
  if command == "ON" then
    if not Companion.client or Companion.client.state == "DISCONNECTED" then
      C4Driver.connect_companion()
    end
    return
  end
  if command == "OFF" then return end  -- stay connected; Apple TV handles its own sleep

  local remote_command = {
    UP = "UP",
    DOWN = "DOWN",
    LEFT = "LEFT",
    RIGHT = "RIGHT",
    SELECT = "SELECT",
    ENTER = "SELECT",
    MENU = "MENU",
    BACK = "MENU",
    HOME = "HOME",
    PLAY = "PLAY_PAUSE",
    PAUSE = "PLAY_PAUSE",
    PLAY_PAUSE = "PLAY_PAUSE",
    STOP = "PLAY_PAUSE",
    SKIP_FWD = "RIGHT",
    SKIP_REV = "LEFT",
    GUIDE = "GUIDE",
  }

  local action = params.ACTION or params.action or params.INPUT_ACTION or params.input_action
  if command:match("^START_") then
    action = "down"
    command = command:gsub("^START_", "")
  elseif command:match("^STOP_") then
    action = "up"
    command = command:gsub("^STOP_", "")
  end

  local hid = remote_command[command]
  if hid then
    if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
      C4Driver.ensure_companion_client()
    end
    return Companion.button_action(hid, action)
  end

  Log.debug("unhandled proxy command " .. tostring(command))
  return nil
end

C4Driver = {}

function C4Driver.ensure_crypto_provider()
  if not Crypto.provider then
    OpenSSLCrypto.install()
  end
  return Crypto.provider
end

function C4Driver.ensure_pairing_crypto_ready()
  C4Driver.ensure_crypto_provider()
  if Crypto.provider == OpenSSLCrypto and not OpenSSLCrypto.self_tested then
    Log.debug("pairing crypto preflight started")
    OpenSSLCrypto.self_test(Log.debug)
    Log.debug("pairing crypto preflight passed")
  end
end

function C4Driver.update_property(name, value)
  local str_value = tostring(value or "")
  if has_c4() and type(UpdateProperty) == "function" and type(Properties) == "table" then
    UpdateProperty(name, str_value)
  end
  if type(Properties) == "table" then
    Properties[name] = str_value
  end
end

function C4Driver.update_property_list(name, items)
  if has_c4() and C4.UpdatePropertyList then
    C4:UpdatePropertyList(name, table.concat(items or {}, ","))
  end
end

function C4Driver.set_connection_state(value)
  Companion.state = value
  C4Driver.update_property("Connection State", value)
end

function C4Driver.publish_current_app()
  C4Driver.update_property("Current App", Companion.render_current_app(Companion.current_app))
end

function C4Driver.publish_now_playing()
  C4Driver.update_property("Now Playing", Companion.render_now_playing(Companion.now_playing))
end

function C4Driver.publish_app_list()
  local rows = Companion.app_list_rows or {}
  C4Driver.update_property("App List", Companion.render_app_list(rows))
  C4Driver.update_property("App Count", tostring(#rows))
  C4Driver.update_property_list("Selected App", Companion.app_selector_items(rows))
end

function C4Driver.handle_companion_message(message)
  local changed = Companion.update_from_message(message)
  if not changed then
    return
  end

  Driver.state = Driver.state or {}
  if changed.app_list then
    Driver.state.app_list = Companion.app_list
    Storage.save(Driver.state)
    C4Driver.publish_app_list()
  end
  if changed.current_app then
    C4Driver.publish_current_app()
  end
  if changed.now_playing then
    C4Driver.publish_now_playing()
  end
end

function C4Driver.launch_app(bundle_id_or_url)
  if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
    C4Driver.ensure_companion_client()
  end
  local request, frame = Companion.launch_app(bundle_id_or_url)
  C4Driver.publish_current_app()
  return request, frame
end

function C4Driver.refresh_app_list()
  if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
    C4Driver.ensure_companion_client()
  end
  return Companion.fetch_apps()
end

function C4Driver.launch_selected_app()
  local selection = Properties and Properties["Selected App"] or ""
  local app_id, err = Companion.resolve_app_selection(selection)
  if not app_id then
    err = err or "select an app after refreshing the app list"
    Log.error("Launch Selected App failed: " .. tostring(err))
    error(err)
  end
  return C4Driver.launch_app(app_id)
end

function C4Driver.import_credentials(detail_string)
  assert(type(detail_string) == "string" and detail_string ~= "", "Companion credentials are required")
  local credentials = Credentials.parse(detail_string)
  local canonical = Credentials.stringify(credentials)

  Driver.state = Driver.state or {}
  Driver.state.companion_credentials = canonical
  Companion.credentials = credentials
  Companion.session = nil
  Companion.socket = nil
  Companion.client = nil
  Storage.save(Driver.state)
  C4Driver.set_connection_state("Credentials Imported")
  return credentials
end

function C4Driver.load_persisted_credentials()
  local raw = Driver.state and Driver.state.companion_credentials
  if not raw or raw == "" then
    return nil
  end

  local ok, credentials_or_err = pcall(Credentials.parse, raw)
  if not ok then
    Log.error("stored Companion credentials are invalid: " .. tostring(credentials_or_err))
    C4Driver.set_connection_state("Invalid Credentials")
    return nil
  end

  Companion.credentials = credentials_or_err
  C4Driver.set_connection_state("Credentials Loaded")
  return credentials_or_err
end

function C4Driver.reset_pairing()
  if Companion.client and Companion.client.close then
    Companion.client:close()
  end
  Driver.state = Driver.state or {}
  Driver.state.companion_credentials = nil
  Driver.state.app_list = nil
  Companion.credentials = nil
  Companion.session = nil
  Companion.socket = nil
  Companion.client = nil
  Companion.pending_commands = {}
  Companion.app_list = {}
  Companion.app_list_rows = {}
  Companion.current_app = nil
  Companion.now_playing = {}
  Storage.save(Driver.state)
  C4Driver.update_property("App List", "")
  C4Driver.update_property("App Count", "0")
  C4Driver.update_property("Selected App", "")
  C4Driver.update_property_list("Selected App", { "" })
  C4Driver.update_property("Current App", "")
  C4Driver.update_property("Now Playing", "")
  C4Driver.set_connection_state("Disconnected")
end

function C4Driver.disconnect_companion()
  if Companion.client and Companion.client.close then
    Companion.client:close()
  end
  Companion.client = nil
  Companion.socket = nil
  Companion.session = nil
  C4Driver.set_connection_state("Disconnected")
end

function C4Driver.ensure_companion_client()
  if Companion.client then
    if Companion.client.state == "DISCONNECTED" or tostring(Companion.client.state):match("^DISCONNECTED") then
      Companion.client:connect()
    end
    return Companion.client
  end
  return C4Driver.connect_companion()
end

function C4Driver.connect_companion()
  C4Driver.ensure_crypto_provider()
  local host = Properties and Properties["Apple TV Address"]
  local credentials = Companion.credentials or C4Driver.load_persisted_credentials()
  if not credentials then
    Log.error("pair this driver before connecting")
    error("pair this driver before connecting")
  end
  if Companion.client and Companion.client.state ~= "DISCONNECTED" and not tostring(Companion.client.state):match("^DISCONNECTED") then
    Log.debug("Companion connect requested while client exists: state=" .. tostring(Companion.client.state))
    return Companion.client
  end

  local client = CompanionClient.new({
    host = host,
    port = Companion.port,
    credentials = credentials,
    crypto = Crypto,
    on_state = function(state)
      C4Driver.set_connection_state(state)
    end,
    on_message = function(message)
      C4Driver.handle_companion_message(message)
    end,
  })
  Companion.client = client
  Companion.socket = client
  client:connect()
  return client
end

function C4Driver.pair_companion()
  C4Driver.ensure_pairing_crypto_ready()
  local host = Properties and Properties["Apple TV Address"]
  if not host or host == "" then
    Log.error("set Apple TV Address before pairing")
    error("Apple TV Address is required for pairing")
  end
  local client = CompanionClient.new({
    host = host,
    port = Companion.port,
    crypto = Crypto,
    on_state = function(state) C4Driver.set_connection_state(state) end,
    on_message = function(message) C4Driver.handle_companion_message(message) end,
    on_pair_setup_m2 = function()
      C4Driver.set_connection_state("Enter PIN from Apple TV")
    end,
    on_paired = function(credentials)
      C4Driver.import_credentials(Credentials.stringify(credentials))
      Log.debug("Pair-Setup complete, credentials saved")
    end,
  })
  Companion.client = client
  Companion.socket = client
  client:connect()
  client:request_pair_setup()
  return client
end

function C4Driver.check_crypto_provider()
  Log.debug("crypto provider check started")
  local ok, err = pcall(function()
    Log.debug("crypto provider install started")
    C4Driver.ensure_crypto_provider()
    Log.debug("crypto provider install passed")
    OpenSSLCrypto.self_test(Log.debug)
  end)
  if ok then
    C4Driver.set_connection_state("Crypto Provider OK")
    Log.debug("crypto provider check passed")
    return true
  end
  Log.error("crypto provider check failed: " .. tostring(err))
  C4Driver.set_connection_state("Crypto Provider Failed")
  return false, err
end

-- EC: Composer action and command dispatch (DCP normalises spaces→underscores and handles LUA_ACTION)
EC.LAUNCH_APP = function(params)
  return C4Driver.launch_app(params.BUNDLE_ID_OR_URL or params.bundle_id_or_url)
end
EC.REFRESH_APP_LIST = function()
  return C4Driver.refresh_app_list()
end
EC.LAUNCH_SELECTED_APP = function()
  return C4Driver.launch_selected_app()
end
EC.RESET_PAIRING = function()
  return C4Driver.reset_pairing()
end
EC.CONNECT_COMPANION = function()
  return C4Driver.connect_companion()
end
EC.DISCONNECT_COMPANION = function()
  return C4Driver.disconnect_companion()
end
EC.CHECK_CRYPTO_PROVIDER = function()
  return C4Driver.check_crypto_provider()
end
EC.IMPORT_COMPANION_CREDENTIALS = function(params)
  return C4Driver.import_credentials(params.CREDENTIALS or params.credentials or "")
end
EC.PAIR_COMPANION = function()
  return C4Driver.pair_companion()
end

function C4Driver.init()
  math.randomseed(os.time())
  Driver.state = Storage.load()
  DEBUGPRINT = Properties and Properties["Debug Mode"] == "On"
  Companion.app_list = Driver.state.app_list or {}
  local _, rows = Companion.parse_app_list(Companion.app_list)
  Companion.app_list_rows = rows
  C4Driver.update_property("Driver Version", Driver.VERSION)
  C4Driver.publish_app_list()
  C4Driver.load_persisted_credentials()
  C4MiniApps.PASSTHROUGH_PROXY = 5001
  C4MiniApps.SWITCHER_PROXY = 5002
  C4MiniApps.USES_DEDICATED_SWITCHER = true
  C4MiniApps.MINIAPP_BINDING_START = 3101
  C4MiniApps.MINIAPP_BINDING_END = 3125
  C4MiniApps.MINIAPP_TYPE = "UM_APPLETV"
  Log.debug("driver init " .. Driver.VERSION)
end

function C4Driver.late_init()
  if C4MiniApps.USES_DEDICATED_SWITCHER then
    C4MiniApps.hide_proxy_in_all_rooms(C4MiniApps.SWITCHER_PROXY)
  end
  C4MiniApps.register_rooms()
  Log.debug("driver late init")
end

function C4Driver.destroy()
  Log.debug("driver destroyed")
end

-- OPC: Property change dispatch (DCP replaces spaces with underscores in the key)
OPC.Pairing_PIN = function(value)
  if value and value ~= "" then
    if Companion.client and Companion.client.state == "PAIR_SETUP_AWAITING_PIN" then
      local ok, err = pcall(function() Companion.client:pair_setup_submit_pin(value) end)
      if not ok then
        Log.error("PIN submission failed: " .. tostring(err))
      end
    end
  end
end

OPC.Debug_Mode = function(value)
  DEBUGPRINT = (value == "On")
end

-- OSE: System event dispatch (DCP parses the event name automatically)
OSE.OnPIP = function()
  C4MiniApps.register_rooms()
end

-- RFP: Proxy command dispatch — route all proxy bindings to handle_proxy_command
local function rfp_handler(idBinding, strCommand, tParams)
  return C4MiniApps.handle_proxy_command(idBinding, strCommand, tParams)
end
RFP[5001] = rfp_handler
RFP[5002] = rfp_handler
for _bid = 3101, 3125 do
  RFP[_bid] = rfp_handler
end

-- OnDriver* lifecycle callbacks — DCP does not define these, so we keep them.
function OnDriverInit(dit)
  C4Driver.init(dit)
end

function OnDriverLateInit(dit)
  C4Driver.late_init(dit)
  for property, _ in pairs(Properties or {}) do
    OnPropertyChanged(property)
  end
end

function OnDriverDestroyed(dit)
  C4Driver.destroy(dit)
end

-- ExecuteCommand, OnPropertyChanged, OnSystemEvent, OnWatchedVariableChanged,
-- and ReceivedFromProxy are all defined by DCP handlers.lua and dispatch via the
-- EC, OPC, OSE, OWVC, and RFP tables registered above.

Driver.Log = Log
Driver.Bytes = Bytes
Driver.TLV8 = TLV8
Driver.OPACK = OPACK
Driver.BigInt = BigInt
Driver.SRP = SRP
Driver.CompanionFrame = CompanionFrame
Driver.CompanionSession = CompanionSession
Driver.CompanionClient = CompanionClient
Driver.Companion = Companion
Driver.PairVerify = PairVerify
Driver.PairSetup = PairSetup
Driver.Crypto = Crypto
Driver.OpenSSLCrypto = OpenSSLCrypto
Driver.X25519Pure = X25519Pure
Driver.Ed25519Pure = Ed25519Pure
Driver.Storage = Storage
Driver.Credentials = Credentials
Driver.C4MiniApps = C4MiniApps
Driver.C4Driver = C4Driver

return Driver
