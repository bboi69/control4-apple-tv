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
  VERSION = "0.1.42-dev",
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

function Log.output(message)
  local line = "[AppleTV] " .. tostring(message)
  print(line)
  if has_c4() and C4.DebugLog then
    C4:DebugLog(line)
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

local MDNS = {}
MDNS.SERVICE = "_companion-link._tcp.local"
MDNS.MRP_SERVICE = "_mediaremotetv._tcp.local"
MDNS.AIRPLAY_SERVICE = "_airplay._tcp.local"
MDNS.PORT = 5353
MDNS.DEFAULT_COMPANION_PORT = 49153
MDNS.binding = nil
MDNS.host = nil
MDNS.pending_callback = nil
MDNS.pending_fallback_port = nil
MDNS.pending_label = nil
MDNS.pending_cache_companion_port = false
MDNS.pending_info_callback = false
MDNS.timeout_timer = nil
MDNS.last_port_by_host = {}

local function dns_encode_name(name)
  local out = {}
  for label in tostring(name):gmatch("[^%.]+") do
    assert(#label <= 63, "DNS label too long")
    out[#out + 1] = string.char(#label)
    out[#out + 1] = label
  end
  out[#out + 1] = "\0"
  return table.concat(out)
end

local function dns_read_u16(data, index)
  local b1, b2 = data:byte(index, index + 1)
  assert(b1 and b2, "truncated DNS u16")
  return b1 * 0x100 + b2, index + 2
end

local function dns_read_u32(data, index)
  local high, next_index = dns_read_u16(data, index)
  local low
  low, next_index = dns_read_u16(data, next_index)
  return high * 0x10000 + low, next_index
end

local function dns_read_name(data, index, depth)
  depth = depth or 0
  assert(depth < 16, "DNS name compression loop")
  local labels = {}
  local jumped = false
  local original_next = nil

  while true do
    local length = data:byte(index)
    assert(length, "truncated DNS name")

    if length == 0 then
      index = index + 1
      break
    end

    local prefix = math.floor(length / 0x40)
    if prefix == 3 then
      local b2 = data:byte(index + 1)
      assert(b2, "truncated DNS compression pointer")
      local pointer = ((length % 0x40) * 0x100) + b2 + 1
      if not jumped then original_next = index + 2 end
      local pointed_name = dns_read_name(data, pointer, depth + 1)
      if pointed_name ~= "" then labels[#labels + 1] = pointed_name end
      jumped = true
      index = original_next
      break
    end

    assert(prefix == 0, "unsupported DNS label type")
    local label = data:sub(index + 1, index + length)
    assert(#label == length, "truncated DNS label")
    labels[#labels + 1] = label
    index = index + length + 1
  end

  return table.concat(labels, "."), index
end

function MDNS.build_query(service_name)
  local id = 0
  local flags = 0
  local qdcount = 1
  local header = string.char(
    math.floor(id / 0x100), id % 0x100,
    math.floor(flags / 0x100), flags % 0x100,
    0, qdcount,
    0, 0,
    0, 0,
    0, 0
  )
  -- PTR query, QU class bit set so the Apple TV can reply directly to us.
  return header .. dns_encode_name(service_name) .. string.char(0, 12, 0x80, 1)
end

function MDNS.parse_service_port(data, service_name)
  local info = MDNS.parse_service_info(data, service_name)
  return info and info.port or nil
end

function MDNS.parse_txt_rdata(data, rdata_start, rdata_end)
  local txt = {}
  local index = rdata_start
  while index <= rdata_end do
    local length = data:byte(index)
    if not length then break end
    index = index + 1
    local item = data:sub(index, index + length - 1)
    index = index + length
    local key, value = item:match("^([^=]+)=(.*)$")
    if key then
      txt[key] = value
      txt[key:lower()] = value
    elseif item ~= "" then
      txt[item] = true
      txt[item:lower()] = true
    end
  end
  return txt
end

function MDNS.parse_service_info(data, service_name)
  if type(data) ~= "string" or #data < 12 then return nil end
  service_name = service_name or MDNS.SERVICE
  local qdcount = data:byte(5) * 0x100 + data:byte(6)
  local ancount = data:byte(7) * 0x100 + data:byte(8)
  local nscount = data:byte(9) * 0x100 + data:byte(10)
  local arcount = data:byte(11) * 0x100 + data:byte(12)
  local index = 13
  local service_names = {
    [service_name] = true,
    [service_name .. "."] = true,
  }

  local parse_ok, info = pcall(function()
    local result = { port = nil, txt = {}, instance = nil, service = service_name }
    for _ = 1, qdcount do
      local _
      _, index = dns_read_name(data, index)
      index = index + 4
    end
    for _ = 1, ancount + nscount + arcount do
      local name
      name, index = dns_read_name(data, index)
      local rr_type; rr_type, index = dns_read_u16(data, index)
      local _rr_class; _rr_class, index = dns_read_u16(data, index)
      local _ttl; _ttl, index = dns_read_u32(data, index)
      local rdlength; rdlength, index = dns_read_u16(data, index)
      local rdata_start = index
      local rdata_end = rdata_start + rdlength - 1
      assert(rdata_end <= #data, "truncated DNS rdata")
      if rr_type == 12 and (name == service_name or name == service_name .. ".") then
        local ptr_name = dns_read_name(data, rdata_start)
        service_names[ptr_name] = true
        result.instance = result.instance or ptr_name
      elseif rr_type == 33 and service_names[name] then
        local _priority, i = dns_read_u16(data, rdata_start)
        local _weight; _weight, i = dns_read_u16(data, i)
        local srv_port; srv_port = dns_read_u16(data, i)
        if srv_port and srv_port > 0 then result.port = srv_port end
      elseif rr_type == 16 and service_names[name] then
        result.txt = MDNS.parse_txt_rdata(data, rdata_start, rdata_end)
      end
      index = rdata_end + 1
    end
    if result.port or next(result.txt) ~= nil then
      return result
    end
    return nil
  end)
  return parse_ok and info or nil
end

function MDNS.parse_companion_port(data)
  return MDNS.parse_service_port(data, MDNS.SERVICE)
end

function MDNS.cached_port(host)
  return MDNS.last_port_by_host[host] or MDNS.DEFAULT_COMPANION_PORT
end

function MDNS.has_cached_port(host)
  return host ~= nil and MDNS.last_port_by_host[host] ~= nil
end

function MDNS.invalidate(host)
  if host then
    MDNS.last_port_by_host[host] = nil
  end
end

function MDNS.allocate_binding()
  if MDNS.binding then return MDNS.binding end
  local binding = 6889
  if has_c4() and C4.GetBindingAddress then
    while binding >= 6850 do
      local address = C4:GetBindingAddress(binding)
      if address == nil or address == "" then
        MDNS.binding = binding
        return binding
      end
      binding = binding - 1
    end
  end
  MDNS.binding = 6889
  return MDNS.binding
end

function MDNS.close()
  if MDNS.timeout_timer then
    if type(CancelTimer) == "function" then pcall(CancelTimer, MDNS.timeout_timer) end
    MDNS.timeout_timer = nil
  end
  if has_c4() and MDNS.binding then
    pcall(function() C4:NetDisconnect(MDNS.binding, MDNS.PORT, "UDP") end)
    if RFN then RFN[MDNS.binding] = nil end
    if OCS then OCS[MDNS.binding] = nil end
    if C4.SetBindingAddress then pcall(function() C4:SetBindingAddress(MDNS.binding, "") end) end
  end
  MDNS.pending_callback = nil
  MDNS.pending_fallback_port = nil
  MDNS.pending_label = nil
  MDNS.pending_cache_companion_port = false
  MDNS.pending_info_callback = false
  MDNS.host = nil
end

function MDNS.finish(info_or_port, source)
  local callback = MDNS.pending_callback
  local host = MDNS.host
  local fallback_port = MDNS.pending_fallback_port
  local label = MDNS.pending_label or "mDNS"
  local cache_companion_port = MDNS.pending_cache_companion_port
  local info_callback = MDNS.pending_info_callback
  local info = type(info_or_port) == "table" and info_or_port or { port = info_or_port }
  local port = info.port
  if port and host and cache_companion_port then
    MDNS.last_port_by_host[host] = port
  end
  if port then
    Log.debug(tostring(label) .. " discovered port=" .. tostring(port) ..
      " source=" .. tostring(source or "response"))
  end
  MDNS.close()
  if callback then
    if info_callback then
      if port or (info.txt and next(info.txt) ~= nil) then
        callback(info)
      else
        callback(nil)
      end
    else
      callback(port or fallback_port)
    end
  end
end

function MDNS.discover_service_info(host, service_name, fallback_port, label, callback)
  if not host or host == "" then
    callback(fallback_port and { port = fallback_port } or nil)
    return
  end

  if not (has_c4() and C4.CreateNetworkConnection and C4.NetConnect and C4.SendToNetwork) then
    callback(fallback_port and { port = fallback_port } or nil)
    return
  end

  MDNS.close()
  RFN = RFN or {}
  OCS = OCS or {}
  local binding = MDNS.allocate_binding()
  MDNS.host = host
  MDNS.pending_callback = callback
  MDNS.pending_fallback_port = fallback_port
  MDNS.pending_label = label
  MDNS.pending_cache_companion_port = service_name == MDNS.SERVICE
  MDNS.pending_info_callback = true

  RFN[binding] = function(_, _, data)
    local info = MDNS.parse_service_info(data, service_name)
    if info and (info.port or (info.txt and next(info.txt) ~= nil)) then
      MDNS.finish(info, "mdns")
    end
  end

  OCS[binding] = function(_, _, status)
    if status == "ONLINE" then
      Log.debug(tostring(label or "mDNS") .. " query requested: host=" .. tostring(host) ..
        " service=" .. tostring(service_name))
      C4:SendToNetwork(binding, MDNS.PORT, MDNS.build_query(service_name))
    end
  end

  Log.debug(tostring(label or "mDNS") .. " discovery starting: host=" .. tostring(host))
  C4:CreateNetworkConnection(binding, host)
  C4:NetConnect(binding, MDNS.PORT, "UDP")

  if type(SetTimer) == "function" then
    MDNS.timeout_timer = "AppleTV_mdns_timeout"
    SetTimer(MDNS.timeout_timer, 1500, function()
      Log.debug(tostring(label or "mDNS") .. " discovery timed out")
      MDNS.finish(nil, "timeout")
    end)
  end
end

function MDNS.discover_service_port(host, service_name, fallback_port, label, callback)
  return MDNS.discover_service_info(host, service_name, fallback_port, label, function(info)
    callback((info and info.port) or fallback_port)
  end)
end

function MDNS.discover_companion_port(host, callback)
  return MDNS.discover_service_port(host, MDNS.SERVICE, MDNS.cached_port(host), "Companion mDNS", callback)
end

function MDNS.discover_mrp_port(host, callback)
  return MDNS.discover_service_port(host, MDNS.MRP_SERVICE, nil, "MRP mDNS", callback)
end

function MDNS.discover_airplay_info(host, callback)
  return MDNS.discover_service_info(host, MDNS.AIRPLAY_SERVICE, nil, "AirPlay mDNS", callback)
end

function Bytes.uint_le(value, length)
  assert(value >= 0 and value == math.floor(value), "integer required")
  local out = {}
  for i = 1, length do
    out[i] = string.char(value % 0x100)
    value = math.floor(value / 0x100)
  end
  return table.concat(out)
end

function Bytes.read_u16le(data, offset)
  offset = offset or 1
  local b1, b2 = data:byte(offset, offset + 1)
  assert(b1 and b2, "not enough bytes for u16le")
  return b1 + b2 * 0x100
end

function Bytes.read_uint_be(data, offset, length)
  offset = offset or 1
  local value = 0
  for i = 0, length - 1 do
    local b = data:byte(offset + i)
    assert(b, "not enough bytes for uint")
    value = value * 0x100 + b
  end
  return value
end

function Bytes.uint_be(value, length)
  assert(value >= 0 and value == math.floor(value), "integer required")
  local out = {}
  for i = length - 1, 0, -1 do
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
local _POLY1305_LIMB_BASE = 8192
local _POLY1305_POW2 = {}
for _i = 0, 13 do _POLY1305_POW2[_i] = 2 ^ _i end

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

local function _store_bytes(out, ...)
  local count = select("#", ...)
  for i = 1, count do
    out[i] = select(i, ...)
  end
  return count
end

function ChaCha20Poly1305Pure.chacha20_xor(key, nonce, initial_counter, data)
  local out, pos, counter = {}, 1, initial_counter
  local chunk, data_bytes, block_bytes = {}, {}, {}
  while pos <= #data do
    local block = ChaCha20Poly1305Pure.block(key, counter, nonce)
    local n = math.min(64, #data - pos + 1)
    _store_bytes(data_bytes, data:byte(pos, pos + n - 1))
    _store_bytes(block_bytes, block:byte(1, n))
    for i = 1, n do
      chunk[i] = string.char(Bit32.bxor(data_bytes[i], block_bytes[i]))
    end
    for i = n + 1, 64 do chunk[i] = nil end
    out[#out + 1] = table.concat(chunk)
    pos = pos + n
    counter = (counter + 1) % 0x100000000
  end
  return table.concat(out)
end

local function _poly1305_clamp(r)
  local b = { r:byte(1, 16) }
  return string.char(
    b[1], b[2], b[3], Bit32.band(b[4], 15),
    Bit32.band(b[5], 252), b[6], b[7], Bit32.band(b[8], 15),
    Bit32.band(b[9], 252), b[10], b[11], Bit32.band(b[12], 15),
    Bit32.band(b[13], 252), b[14], b[15], Bit32.band(b[16], 15)
  )
end

local function _poly1305_limbs_from_le_bytes(s)
  local limbs, acc, bits = {}, 0, 0
  for i = 1, #s do
    acc = acc + s:byte(i) * _POLY1305_POW2[bits]
    bits = bits + 8
    while bits >= 13 and #limbs < 10 do
      limbs[#limbs + 1] = acc % _POLY1305_LIMB_BASE
      acc = math.floor(acc / _POLY1305_LIMB_BASE)
      bits = bits - 13
    end
  end
  if #limbs < 10 then
    limbs[#limbs + 1] = acc
  end
  while #limbs < 10 do
    limbs[#limbs + 1] = 0
  end
  return limbs
end

local function _poly1305_block_limbs(block)
  if #block < 16 then
    block = block .. "\1" .. string.rep("\0", 16 - #block)
  else
    block = block .. "\1"
  end
  return _poly1305_limbs_from_le_bytes(block)
end

local function _poly1305_carry(h)
  local carry
  for _ = 1, 2 do
    for i = 1, 9 do
      carry = math.floor(h[i] / _POLY1305_LIMB_BASE)
      h[i] = h[i] % _POLY1305_LIMB_BASE
      h[i + 1] = h[i + 1] + carry
    end
    carry = math.floor(h[10] / _POLY1305_LIMB_BASE)
    h[10] = h[10] % _POLY1305_LIMB_BASE
    h[1] = h[1] + carry * 5
  end
end

local function _poly1305_ge_p(h)
  if h[10] ~= _POLY1305_LIMB_BASE - 1 then
    return h[10] > _POLY1305_LIMB_BASE - 1
  end
  for i = 9, 2, -1 do
    if h[i] ~= _POLY1305_LIMB_BASE - 1 then
      return h[i] > _POLY1305_LIMB_BASE - 1
    end
  end
  return h[1] >= _POLY1305_LIMB_BASE - 5
end

local function _poly1305_sub_p(h)
  h[1] = h[1] + 5
  local carry = math.floor(h[1] / _POLY1305_LIMB_BASE)
  h[1] = h[1] % _POLY1305_LIMB_BASE
  for i = 2, 10 do
    h[i] = h[i] + carry
    carry = math.floor(h[i] / _POLY1305_LIMB_BASE)
    h[i] = h[i] % _POLY1305_LIMB_BASE
  end
end

local function _poly1305_mul_mod(h, r)
  local d = {}
  for i = 1, 10 do d[i] = 0 end
  for i = 1, 10 do
    local hi = 11 - i
    for j = 1, hi do
      local k = i + j - 1
      d[k] = d[k] + h[i] * r[j]
    end
    for j = hi + 1, 10 do
      local k = i + j - 11
      d[k] = d[k] + h[i] * r[j] * 5
    end
  end
  _poly1305_carry(d)
  if _poly1305_ge_p(d) then
    _poly1305_sub_p(d)
  end
  return d
end

local function _poly1305_low128(h)
  local out, acc, bits = {}, 0, 0
  for i = 1, 10 do
    acc = acc + h[i] * _POLY1305_POW2[bits]
    bits = bits + 13
    while bits >= 8 and #out < 16 do
      out[#out + 1] = acc % 256
      acc = math.floor(acc / 256)
      bits = bits - 8
    end
  end
  while #out < 16 do
    out[#out + 1] = 0
  end
  return out
end

local function _poly1305_add_s(h, s)
  local out, carry = _poly1305_low128(h), 0
  for i = 1, 16 do
    local sum = out[i] + s:byte(i) + carry
    out[i] = string.char(sum % 256)
    carry = math.floor(sum / 256)
  end
  return table.concat(out)
end

local function _pad16(s)
  local rem = #s % 16
  if rem == 0 then return "" end
  return string.rep("\0", 16 - rem)
end

function ChaCha20Poly1305Pure.poly1305_mac(msg, one_time_key)
  assert(type(one_time_key) == "string" and #one_time_key == 32, "Poly1305 one-time key must be 32 bytes")
  local r = _poly1305_limbs_from_le_bytes(_poly1305_clamp(one_time_key:sub(1, 16)))
  local h = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  local pos = 1
  while pos <= #msg do
    local n = _poly1305_block_limbs(msg:sub(pos, pos + 15))
    for i = 1, 10 do h[i] = h[i] + n[i] end
    h = _poly1305_mul_mod(h, r)
    pos = pos + 16
  end
  _poly1305_carry(h)
  if _poly1305_ge_p(h) then
    _poly1305_sub_p(h)
  end
  return _poly1305_add_s(h, one_time_key:sub(17, 32))
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

local _A24 = 121665 -- (486662-2)/4 for Curve25519 ladder

local floor = math.floor  -- localize for hot-loop performance
local _POW2 = {}
for _i = 0, 30 do _POW2[_i] = 2 ^ _i end

local function _fe_carry(c)
  local carry = 0
  local n = #c
  if n < _FE_LIMBS then n = _FE_LIMBS end
  for i = 1, n do
    local value = (c[i] or 0) + carry
    c[i] = value % _FE_BASE
    carry = floor(value / _FE_BASE)
  end
  while carry > 0 do
    n = n + 1
    c[n] = carry % _FE_BASE
    carry = floor(carry / _FE_BASE)
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

local function _fe_sub_p_in_place(c)
  local borrow = 0
  for i = 1, _FE_LIMBS do
    local value = (c[i] or 0) - _FE_P[i] - borrow
    if value < 0 then
      value = value + _FE_BASE
      borrow = 1
    else
      borrow = 0
    end
    c[i] = value
  end
  return c
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
    _fe_sub_p_in_place(c)
  end
  for i = 1, _FE_LIMBS do c[i] = c[i] or 0 end
  return c
end

local function _fp_add(a, b)
  local out = {}
  for i = 1, _FE_LIMBS do out[i] = (a[i] or 0) + (b[i] or 0) end
  return _fe_reduce(out)
end

local function _fp_add_into(out, a, b)
  for i = 1, _FE_LIMBS do out[i] = (a[i] or 0) + (b[i] or 0) end
  return out
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

local function _fp_sub_into(out, a, b)
  local borrow = 0
  for i = 1, _FE_LIMBS do
    local value = (a[i] or 0) + _FE_P[i] - (b[i] or 0) - borrow
    if value < 0 then
      value = value + _FE_BASE
      borrow = 1
    else
      borrow = 0
    end
    out[i] = value
  end
  return out
end

local _fp_mul_into
local function _fp_mul(a, b)
  local out = {}
  return _fp_mul_into(out, a, b)
end

function _fp_mul_into(out, a, b)
  local a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17 =
    a[1] or 0,a[2] or 0,a[3] or 0,a[4] or 0,a[5] or 0,a[6] or 0,a[7] or 0,a[8] or 0,a[9] or 0,a[10] or 0,a[11] or 0,a[12] or 0,a[13] or 0,a[14] or 0,a[15] or 0,a[16] or 0,a[17] or 0
  local b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15,b16,b17 =
    b[1] or 0,b[2] or 0,b[3] or 0,b[4] or 0,b[5] or 0,b[6] or 0,b[7] or 0,b[8] or 0,b[9] or 0,b[10] or 0,b[11] or 0,b[12] or 0,b[13] or 0,b[14] or 0,b[15] or 0,b[16] or 0,b[17] or 0
  local c1  = a1*b1
  local c2  = a1*b2+a2*b1
  local c3  = a1*b3+a2*b2+a3*b1
  local c4  = a1*b4+a2*b3+a3*b2+a4*b1
  local c5  = a1*b5+a2*b4+a3*b3+a4*b2+a5*b1
  local c6  = a1*b6+a2*b5+a3*b4+a4*b3+a5*b2+a6*b1
  local c7  = a1*b7+a2*b6+a3*b5+a4*b4+a5*b3+a6*b2+a7*b1
  local c8  = a1*b8+a2*b7+a3*b6+a4*b5+a5*b4+a6*b3+a7*b2+a8*b1
  local c9  = a1*b9+a2*b8+a3*b7+a4*b6+a5*b5+a6*b4+a7*b3+a8*b2+a9*b1
  local c10 = a1*b10+a2*b9+a3*b8+a4*b7+a5*b6+a6*b5+a7*b4+a8*b3+a9*b2+a10*b1
  local c11 = a1*b11+a2*b10+a3*b9+a4*b8+a5*b7+a6*b6+a7*b5+a8*b4+a9*b3+a10*b2+a11*b1
  local c12 = a1*b12+a2*b11+a3*b10+a4*b9+a5*b8+a6*b7+a7*b6+a8*b5+a9*b4+a10*b3+a11*b2+a12*b1
  local c13 = a1*b13+a2*b12+a3*b11+a4*b10+a5*b9+a6*b8+a7*b7+a8*b6+a9*b5+a10*b4+a11*b3+a12*b2+a13*b1
  local c14 = a1*b14+a2*b13+a3*b12+a4*b11+a5*b10+a6*b9+a7*b8+a8*b7+a9*b6+a10*b5+a11*b4+a12*b3+a13*b2+a14*b1
  local c15 = a1*b15+a2*b14+a3*b13+a4*b12+a5*b11+a6*b10+a7*b9+a8*b8+a9*b7+a10*b6+a11*b5+a12*b4+a13*b3+a14*b2+a15*b1
  local c16 = a1*b16+a2*b15+a3*b14+a4*b13+a5*b12+a6*b11+a7*b10+a8*b9+a9*b8+a10*b7+a11*b6+a12*b5+a13*b4+a14*b3+a15*b2+a16*b1
  local c17 = a1*b17+a2*b16+a3*b15+a4*b14+a5*b13+a6*b12+a7*b11+a8*b10+a9*b9+a10*b8+a11*b7+a12*b6+a13*b5+a14*b4+a15*b3+a16*b2+a17*b1
  local c18 = a2*b17+a3*b16+a4*b15+a5*b14+a6*b13+a7*b12+a8*b11+a9*b10+a10*b9+a11*b8+a12*b7+a13*b6+a14*b5+a15*b4+a16*b3+a17*b2
  local c19 = a3*b17+a4*b16+a5*b15+a6*b14+a7*b13+a8*b12+a9*b11+a10*b10+a11*b9+a12*b8+a13*b7+a14*b6+a15*b5+a16*b4+a17*b3
  local c20 = a4*b17+a5*b16+a6*b15+a7*b14+a8*b13+a9*b12+a10*b11+a11*b10+a12*b9+a13*b8+a14*b7+a15*b6+a16*b5+a17*b4
  local c21 = a5*b17+a6*b16+a7*b15+a8*b14+a9*b13+a10*b12+a11*b11+a12*b10+a13*b9+a14*b8+a15*b7+a16*b6+a17*b5
  local c22 = a6*b17+a7*b16+a8*b15+a9*b14+a10*b13+a11*b12+a12*b11+a13*b10+a14*b9+a15*b8+a16*b7+a17*b6
  local c23 = a7*b17+a8*b16+a9*b15+a10*b14+a11*b13+a12*b12+a13*b11+a14*b10+a15*b9+a16*b8+a17*b7
  local c24 = a8*b17+a9*b16+a10*b15+a11*b14+a12*b13+a13*b12+a14*b11+a15*b10+a16*b9+a17*b8
  local c25 = a9*b17+a10*b16+a11*b15+a12*b14+a13*b13+a14*b12+a15*b11+a16*b10+a17*b9
  local c26 = a10*b17+a11*b16+a12*b15+a13*b14+a14*b13+a15*b12+a16*b11+a17*b10
  local c27 = a11*b17+a12*b16+a13*b15+a14*b14+a15*b13+a16*b12+a17*b11
  local c28 = a12*b17+a13*b16+a14*b15+a15*b14+a16*b13+a17*b12
  local c29 = a13*b17+a14*b16+a15*b15+a16*b14+a17*b13
  local c30 = a14*b17+a15*b16+a16*b15+a17*b14
  local c31 = a15*b17+a16*b16+a17*b15
  local c32 = a16*b17+a17*b16
  local c33 = a17*b17
  out[1]=c1; out[2]=c2; out[3]=c3; out[4]=c4; out[5]=c5; out[6]=c6; out[7]=c7; out[8]=c8; out[9]=c9; out[10]=c10; out[11]=c11; out[12]=c12; out[13]=c13; out[14]=c14; out[15]=c15; out[16]=c16; out[17]=c17; out[18]=c18; out[19]=c19; out[20]=c20; out[21]=c21; out[22]=c22; out[23]=c23; out[24]=c24; out[25]=c25; out[26]=c26; out[27]=c27; out[28]=c28; out[29]=c29; out[30]=c30; out[31]=c31; out[32]=c32; out[33]=c33; out[34]=0
  return _fe_reduce(out)
end

local _fp_mul_small_into
local function _fp_mul_small(a, n)
  local out = {}
  return _fp_mul_small_into(out, a, n)
end

function _fp_mul_small_into(out, a, n)
  for i = 1, _FE_LIMBS do
    out[i] = (a[i] or 0) * n
  end
  for i = _FE_LIMBS + 1, #out do out[i] = nil end
  return _fe_reduce(out)
end

local _fp_sq_into
local function _fp_sq(a)
  local out = {}
  return _fp_sq_into(out, a)
end

function _fp_sq_into(out, a)
  local a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17 =
    a[1] or 0,a[2] or 0,a[3] or 0,a[4] or 0,a[5] or 0,a[6] or 0,a[7] or 0,a[8] or 0,a[9] or 0,a[10] or 0,a[11] or 0,a[12] or 0,a[13] or 0,a[14] or 0,a[15] or 0,a[16] or 0,a[17] or 0
  local c1  = a1*a1
  local c2  = 2*(a1*a2)
  local c3  = a2*a2+2*(a1*a3)
  local c4  = 2*(a1*a4+a2*a3)
  local c5  = a3*a3+2*(a1*a5+a2*a4)
  local c6  = 2*(a1*a6+a2*a5+a3*a4)
  local c7  = a4*a4+2*(a1*a7+a2*a6+a3*a5)
  local c8  = 2*(a1*a8+a2*a7+a3*a6+a4*a5)
  local c9  = a5*a5+2*(a1*a9+a2*a8+a3*a7+a4*a6)
  local c10 = 2*(a1*a10+a2*a9+a3*a8+a4*a7+a5*a6)
  local c11 = a6*a6+2*(a1*a11+a2*a10+a3*a9+a4*a8+a5*a7)
  local c12 = 2*(a1*a12+a2*a11+a3*a10+a4*a9+a5*a8+a6*a7)
  local c13 = a7*a7+2*(a1*a13+a2*a12+a3*a11+a4*a10+a5*a9+a6*a8)
  local c14 = 2*(a1*a14+a2*a13+a3*a12+a4*a11+a5*a10+a6*a9+a7*a8)
  local c15 = a8*a8+2*(a1*a15+a2*a14+a3*a13+a4*a12+a5*a11+a6*a10+a7*a9)
  local c16 = 2*(a1*a16+a2*a15+a3*a14+a4*a13+a5*a12+a6*a11+a7*a10+a8*a9)
  local c17 = a9*a9+2*(a1*a17+a2*a16+a3*a15+a4*a14+a5*a13+a6*a12+a7*a11+a8*a10)
  local c18 = 2*(a2*a17+a3*a16+a4*a15+a5*a14+a6*a13+a7*a12+a8*a11+a9*a10)
  local c19 = a10*a10+2*(a3*a17+a4*a16+a5*a15+a6*a14+a7*a13+a8*a12+a9*a11)
  local c20 = 2*(a4*a17+a5*a16+a6*a15+a7*a14+a8*a13+a9*a12+a10*a11)
  local c21 = a11*a11+2*(a5*a17+a6*a16+a7*a15+a8*a14+a9*a13+a10*a12)
  local c22 = 2*(a6*a17+a7*a16+a8*a15+a9*a14+a10*a13+a11*a12)
  local c23 = a12*a12+2*(a7*a17+a8*a16+a9*a15+a10*a14+a11*a13)
  local c24 = 2*(a8*a17+a9*a16+a10*a15+a11*a14+a12*a13)
  local c25 = a13*a13+2*(a9*a17+a10*a16+a11*a15+a12*a14)
  local c26 = 2*(a10*a17+a11*a16+a12*a15+a13*a14)
  local c27 = a14*a14+2*(a11*a17+a12*a16+a13*a15)
  local c28 = 2*(a12*a17+a13*a16+a14*a15)
  local c29 = a15*a15+2*(a13*a17+a14*a16)
  local c30 = 2*(a14*a17+a15*a16)
  local c31 = a16*a16+2*(a15*a17)
  local c32 = 2*(a16*a17)
  local c33 = a17*a17
  out[1]=c1; out[2]=c2; out[3]=c3; out[4]=c4; out[5]=c5; out[6]=c6; out[7]=c7; out[8]=c8; out[9]=c9; out[10]=c10; out[11]=c11; out[12]=c12; out[13]=c13; out[14]=c14; out[15]=c15; out[16]=c16; out[17]=c17; out[18]=c18; out[19]=c19; out[20]=c20; out[21]=c21; out[22]=c22; out[23]=c23; out[24]=c24; out[25]=c25; out[26]=c26; out[27]=c27; out[28]=c28; out[29]=c29; out[30]=c30; out[31]=c31; out[32]=c32; out[33]=c33; out[34]=0
  return _fe_reduce(out)
end

local function _fe_bit(v, bit_index)
  local limb = v[floor(bit_index / _FE_BITS) + 1] or 0
  return floor(limb / _POW2[bit_index % _FE_BITS]) % 2
end

local function _fp_inv(a)
  -- a^(p-2) where p-2 = 2^255-21, using addition chain: 254 sq + 11 mul
  -- instead of the naive 254 sq + 253 mul bit-by-bit approach.
  -- Key identity: 2^255-21 = 32*(2^250-1) + 11, so
  --   a^(p-2) = (a^(2^250-1))^32 * a^11
  local a2  = _fp_sq(a)             -- a^2
  local a4  = _fp_sq(a2)            -- a^4
  local a8  = _fp_sq(a4)            -- a^8
  local a9  = _fp_mul(a8, a)        -- a^9
  local a11 = _fp_mul(a9, a2)       -- a^11
  local a22 = _fp_sq(a11)           -- a^22
  local a31 = _fp_mul(a22, a9)      -- a^31 = a^(2^5-1)

  local t = _fp_sq(a31)             -- a^(2^6-2)
  t = _fp_sq(t); t = _fp_sq(t); t = _fp_sq(t); t = _fp_sq(t)
  local a10 = _fp_mul(t, a31)       -- a^(2^10-1)

  t = _fp_sq(a10)
  for _ = 1,  9 do t = _fp_sq(t) end
  local a20 = _fp_mul(t, a10)       -- a^(2^20-1)

  t = _fp_sq(a20)
  for _ = 1, 19 do t = _fp_sq(t) end
  local a40 = _fp_mul(t, a20)       -- a^(2^40-1)

  t = _fp_sq(a40)
  for _ = 1,  9 do t = _fp_sq(t) end
  local a50 = _fp_mul(t, a10)       -- a^(2^50-1)

  t = _fp_sq(a50)
  for _ = 1, 49 do t = _fp_sq(t) end
  local a100 = _fp_mul(t, a50)      -- a^(2^100-1)

  t = _fp_sq(a100)
  for _ = 1, 99 do t = _fp_sq(t) end
  local a200 = _fp_mul(t, a100)     -- a^(2^200-1)

  t = _fp_sq(a200)
  for _ = 1, 49 do t = _fp_sq(t) end
  t = _fp_mul(t, a50)               -- a^(2^250-1)

  -- Five more squarings: a^(2^255-32)
  t = _fp_sq(t); t = _fp_sq(t); t = _fp_sq(t); t = _fp_sq(t); t = _fp_sq(t)

  return _fp_mul(t, a11)            -- a^(2^255-32+11) = a^(2^255-21) = a^(p-2)
end

local function _fp_pow22523(z)
  -- z^(2^252-3), used by Ed25519 sqrt_ratio.
  local t0 = _fp_sq(z)
  local t1 = _fp_sq(t0)
  t1 = _fp_sq(t1)
  t1 = _fp_mul(z, t1)
  t0 = _fp_mul(t0, t1)
  t0 = _fp_sq(t0)
  t0 = _fp_mul(t1, t0)

  t1 = _fp_sq(t0)
  for _ = 1, 4 do t1 = _fp_sq(t1) end
  t0 = _fp_mul(t1, t0)

  t1 = _fp_sq(t0)
  for _ = 1, 9 do t1 = _fp_sq(t1) end
  t1 = _fp_mul(t1, t0)

  local t2 = _fp_sq(t1)
  for _ = 1, 19 do t2 = _fp_sq(t2) end
  t1 = _fp_mul(t2, t1)

  t1 = _fp_sq(t1)
  for _ = 1, 9 do t1 = _fp_sq(t1) end
  t0 = _fp_mul(t1, t0)

  t1 = _fp_sq(t0)
  for _ = 1, 49 do t1 = _fp_sq(t1) end
  t1 = _fp_mul(t1, t0)

  t2 = _fp_sq(t1)
  for _ = 1, 99 do t2 = _fp_sq(t2) end
  t1 = _fp_mul(t2, t1)

  t1 = _fp_sq(t1)
  for _ = 1, 49 do t1 = _fp_sq(t1) end
  t0 = _fp_mul(t1, t0)

  t0 = _fp_sq(t0)
  t0 = _fp_sq(t0)
  return _fp_mul(t0, z)
end

local function _le32_to_fe(s)
  local b = {s:byte(1, 32)}
  local out, acc, acc_bits, bi = {}, 0, 0, 1
  for i = 1, _FE_LIMBS do
    while acc_bits < _FE_BITS and bi <= 32 do
      acc = acc + (b[bi] or 0) * _POW2[acc_bits]
      acc_bits = acc_bits + 8
      bi = bi + 1
    end
    out[i] = acc % _FE_BASE
    acc = floor(acc / _FE_BASE)
    acc_bits = acc_bits - _FE_BITS
  end
  return _fe_reduce(out)
end

local function _fe_to_le32(v)
  local reduced = {}
  for i = 1, #v do reduced[i] = v[i] end
  v = _fe_reduce(reduced)
  local bytes, acc, acc_bits, bi = {}, 0, 0, 1
  for i = 1, _FE_LIMBS do
    acc = acc + (v[i] or 0) * _POW2[acc_bits]
    acc_bits = acc_bits + _FE_BITS
    while acc_bits >= 8 and bi <= 32 do
      bytes[bi] = string.char(acc % 256)
      acc = floor(acc / 256)
      acc_bits = acc_bits - 8
      bi = bi + 1
    end
  end
  while bi <= 32 do
    bytes[bi] = string.char(acc % 256)
    acc = floor(acc / 256)
    bi = bi + 1
  end
  return table.concat(bytes)
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

local _X16_PRIME = {
  [0] = 0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
  0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff,
}
local _X16_CURVE_CONST = { [0] = 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

local function _x16_carry(out)
  for i = 0, 15 do
    out[i] = out[i] + 0x10000
    local c = floor(out[i] / 0x10000)
    if i < 15 then
      out[i + 1] = out[i + 1] + c - 1
    else
      out[0] = out[0] + 38 * (c - 1)
    end
    out[i] = out[i] % 0x10000
  end
end

local function _x16_swap(a, b, bit)
  local inv = 1 - bit
  for i = 0, 15 do
    local ai, bi = a[i], b[i]
    a[i] = ai * inv + bi * bit
    b[i] = bi * inv + ai * bit
  end
end

local function _x16_unpack(out, s)
  local bytes = { s:byte(1, 32) }
  for i = 0, 15 do
    out[i] = (bytes[2 * i + 1] or 0) + (bytes[2 * i + 2] or 0) * 0x100
  end
  out[15] = out[15] % 0x8000
end

local function _x16_pack(a)
  local out, t, m = {}, {}, {}
  for i = 0, 15 do t[i] = a[i] end
  _x16_carry(t); _x16_carry(t); _x16_carry(t)
  for _ = 0, 1 do
    m[0] = t[0] - _X16_PRIME[0]
    for i = 1, 15 do
      m[i] = t[i] - _X16_PRIME[i] - (floor(m[i - 1] / 0x10000) % 2)
      m[i - 1] = m[i - 1] % 0x10000
    end
    local c = floor(m[15] / 0x10000) % 2
    _x16_swap(t, m, 1 - c)
  end
  for i = 0, 15 do
    out[2 * i + 1] = string.char(t[i] % 0x100)
    out[2 * i + 2] = string.char(floor(t[i] / 0x100))
  end
  return table.concat(out)
end

local function _x16_add(out, a, b)
  for i = 0, 15 do out[i] = a[i] + b[i] end
end

local function _x16_sub(out, a, b)
  for i = 0, 15 do out[i] = a[i] - b[i] end
end

local function _x16_mul(out, a, b, prod)
  prod = prod or {}
  for i = 0, 31 do prod[i] = 0 end
  for i = 0, 15 do
    local ai = a[i]
    for j = 0, 15 do
      prod[i + j] = prod[i + j] + ai * b[j]
    end
  end
  for i = 0, 14 do
    prod[i] = prod[i] + 38 * prod[i + 16]
  end
  for i = 0, 15 do out[i] = prod[i] end
  _x16_carry(out); _x16_carry(out)
end

local function _x16_inv(out, a)
  local prod = {}
  local a2, a4, a8, a9, a11, a22, a31 = {}, {}, {}, {}, {}, {}, {}
  local a10, a20, a40, a50, a100, a200, t = {}, {}, {}, {}, {}, {}, {}

  _x16_mul(a2, a, a, prod)
  _x16_mul(a4, a2, a2, prod)
  _x16_mul(a8, a4, a4, prod)
  _x16_mul(a9, a8, a, prod)
  _x16_mul(a11, a9, a2, prod)
  _x16_mul(a22, a11, a11, prod)
  _x16_mul(a31, a22, a9, prod)

  _x16_mul(t, a31, a31, prod)
  for _ = 1, 4 do _x16_mul(t, t, t, prod) end
  _x16_mul(a10, t, a31, prod)

  _x16_mul(t, a10, a10, prod)
  for _ = 1, 9 do _x16_mul(t, t, t, prod) end
  _x16_mul(a20, t, a10, prod)

  _x16_mul(t, a20, a20, prod)
  for _ = 1, 19 do _x16_mul(t, t, t, prod) end
  _x16_mul(a40, t, a20, prod)

  _x16_mul(t, a40, a40, prod)
  for _ = 1, 9 do _x16_mul(t, t, t, prod) end
  _x16_mul(a50, t, a10, prod)

  _x16_mul(t, a50, a50, prod)
  for _ = 1, 49 do _x16_mul(t, t, t, prod) end
  _x16_mul(a100, t, a50, prod)

  _x16_mul(t, a100, a100, prod)
  for _ = 1, 99 do _x16_mul(t, t, t, prod) end
  _x16_mul(a200, t, a100, prod)

  _x16_mul(t, a200, a200, prod)
  for _ = 1, 49 do _x16_mul(t, t, t, prod) end
  _x16_mul(t, t, a50, prod)

  for _ = 1, 5 do _x16_mul(t, t, t, prod) end
  _x16_mul(out, t, a11, prod)
end

-- Experimental 16-limb TweetNaCl-style X25519 backend.
function X25519Pure.mul(k_bytes, u_bytes)
  local x, a, b, c, d, e, f, scalar = {}, {}, {}, {}, {}, {}, {}, {}
  local prod = {}
  _x16_unpack(x, u_bytes)
  for i = 0, 15 do
    a[i], b[i], c[i], d[i] = 0, x[i], 0, 0
  end
  a[0], d[0] = 1, 1

  local kb = { k_bytes:byte(1, 32) }
  for i = 0, 30 do scalar[i] = kb[i + 1] end
  scalar[0] = scalar[0] - scalar[0] % 8
  scalar[31] = (kb[32] or 0) % 64 + 64

  for i = 254, 0, -1 do
    local bit = floor(scalar[floor(i / 8)] / _POW2[i % 8]) % 2
    _x16_swap(a, b, bit)
    _x16_swap(c, d, bit)
    _x16_add(e, a, c)
    _x16_sub(a, a, c)
    _x16_add(c, b, d)
    _x16_sub(b, b, d)
    _x16_mul(d, e, e, prod)
    _x16_mul(f, a, a, prod)
    _x16_mul(a, c, a, prod)
    _x16_mul(c, b, e, prod)
    _x16_add(e, a, c)
    _x16_sub(a, a, c)
    _x16_mul(b, a, a, prod)
    _x16_sub(c, d, f)
    _x16_mul(a, c, _X16_CURVE_CONST, prod)
    _x16_add(a, a, d)
    _x16_mul(c, c, a, prod)
    _x16_mul(a, d, f, prod)
    _x16_mul(d, b, x, prod)
    _x16_mul(b, e, e, prod)
    _x16_swap(a, b, bit)
    _x16_swap(c, d, bit)
  end

  _x16_inv(c, c)
  _x16_mul(a, a, c, prod)
  return _x16_pack(a)
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
local _ED_ZERO_FE = _fe_from_number(0)

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
  local b = {s:byte(1, #s)}
  local v, acc, acc_bits, bi = {}, 0, 0, 1
  local limb = 1
  while bi <= #b do
    while acc_bits < _FE_BITS and bi <= #b do
      acc = acc + (b[bi] or 0) * _POW2[acc_bits]
      acc_bits = acc_bits + 8
      bi = bi + 1
    end
    v[limb] = acc % _FE_BASE
    acc = floor(acc / _FE_BASE)
    acc_bits = acc_bits - _FE_BITS
    limb = limb + 1
  end
  if acc > 0 then v[limb] = acc end
  return _scalar_reduce(_fe_carry(v))
end

local function _scalar_to_le32(v)
  v = _scalar_reduce(v)
  local bytes, acc, acc_bits, bi = {}, 0, 0, 1
  for i = 1, #v do
    acc = acc + (v[i] or 0) * _POW2[acc_bits]
    acc_bits = acc_bits + _FE_BITS
    while acc_bits >= 8 and bi <= 32 do
      bytes[bi] = string.char(acc % 256)
      acc = floor(acc / 256)
      acc_bits = acc_bits - 8
      bi = bi + 1
    end
  end
  while bi <= 32 do
    bytes[bi] = string.char(acc % 256)
    acc = floor(acc / 256)
    bi = bi + 1
  end
  return table.concat(bytes)
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
  local T1, T2 = {}, {}
  local A = _fp_mul(_fp_sub_into(T1, P.Y, P.X), _fp_sub_into(T2, Q.Y, Q.X))
  local B = _fp_mul(_fp_add_into(T1, P.Y, P.X), _fp_add_into(T2, Q.Y, Q.X))
  local C = _fp_mul(_fp_mul(P.T, Q.T), _ED_2D)
  local ZZ = _fp_mul(P.Z, Q.Z)
  local D = _fp_add_into({}, ZZ, ZZ)
  local E = _fp_sub_into({}, B, A)
  local F = _fp_sub_into({}, D, C)
  local G = _fp_add_into({}, D, C)
  local H = _fp_add_into({}, B, A)
  return {
    X = _fp_mul(E, F),
    Y = _fp_mul(G, H),
    Z = _fp_mul(F, G),
    T = _fp_mul(E, H),
  }
end

local function _ed_point_double(P)
  local A = _fp_sq(P.X)
  local B = _fp_sq(P.Y)
  local Z2 = _fp_sq(P.Z)
  local C = _fp_add(Z2, Z2)
  local D = _fp_sub(_ED_ZERO_FE, A)
  local E = _fp_sub(_fp_sub(_fp_sq(_fp_add(P.X, P.Y)), A), B)
  local G = _fp_add(D, B)
  local F = _fp_sub(G, C)
  local H = _fp_sub(D, B)
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
    result = _ed_point_double(result)
    if _ed_scalar_bit(scalar, bit) == 1 then
      result = _ed_point_add(result, point)
    end
  end
  return result
end

local _ED_BASE_WINDOW = 5
local _ED_BASE_WINDOW_SIZE = 2 ^ _ED_BASE_WINDOW
local _ED_FIXED_TABLE_WINDOWS = math.ceil(256 / _ED_BASE_WINDOW)
local _ED_FIXED_TABLE_HEX_LEN = _ED_FIXED_TABLE_WINDOWS * _ED_BASE_WINDOW_SIZE * 4 * _FE_LIMBS * 4
local _ED_POINT_COORDS = { "X", "Y", "Z", "T" }
local _ED_BASE_TABLE = nil
local _ED_BASE_TABLE_PREWARMED = false

local function _ed_build_base_table()
  local table_by_window = {}
  local base = _ED_BASE
  for window = 1, _ED_FIXED_TABLE_WINDOWS do
    local multiples = {}
    multiples[0] = _ed_identity()
    multiples[1] = base
    for digit = 2, _ED_BASE_WINDOW_SIZE - 1 do
      multiples[digit] = _ed_point_add(multiples[digit - 1], base)
    end
    table_by_window[window] = multiples
    for _ = 1, _ED_BASE_WINDOW do
      base = _ed_point_double(base)
    end
  end
  return table_by_window
end

local function _ed_build_fixed_point_table(point)
  local table_by_window = {}
  local base = point
  for window = 1, _ED_FIXED_TABLE_WINDOWS do
    local multiples = {}
    multiples[0] = _ed_identity()
    multiples[1] = base
    for digit = 2, _ED_BASE_WINDOW_SIZE - 1 do
      multiples[digit] = _ed_point_add(multiples[digit - 1], base)
    end
    table_by_window[window] = multiples
    for _ = 1, _ED_BASE_WINDOW do
      base = _ed_point_double(base)
    end
  end
  return table_by_window
end

local function _ed_serialize_fixed_point_table(fixed_table)
  assert(type(fixed_table) == "table", "fixed point table is required")
  local out = {}
  for window = 1, _ED_FIXED_TABLE_WINDOWS do
    local multiples = assert(fixed_table[window], "fixed point table window missing")
    for digit = 0, _ED_BASE_WINDOW_SIZE - 1 do
      local point = assert(multiples[digit], "fixed point table digit missing")
      for _, coord_name in ipairs(_ED_POINT_COORDS) do
        local coord = assert(point[coord_name], "fixed point table coordinate missing")
        for limb = 1, _FE_LIMBS do
          out[#out + 1] = string.format("%04x", coord[limb] or 0)
        end
      end
    end
  end
  return table.concat(out)
end

local function _ed_deserialize_fixed_point_table(encoded)
  if type(encoded) ~= "string" or #encoded ~= _ED_FIXED_TABLE_HEX_LEN then
    return nil, "invalid Ed25519 fixed table length"
  end
  local pos = 1
  local table_by_window = {}
  for window = 1, _ED_FIXED_TABLE_WINDOWS do
    local multiples = {}
    for digit = 0, _ED_BASE_WINDOW_SIZE - 1 do
      local point = {}
      for _, coord_name in ipairs(_ED_POINT_COORDS) do
        local coord = {}
        for limb = 1, _FE_LIMBS do
          local chunk = encoded:sub(pos, pos + 3)
          local value = tonumber(chunk, 16)
          if value == nil or value >= _FE_BASE then
            return nil, "invalid Ed25519 fixed table limb"
          end
          coord[limb] = value
          pos = pos + 4
        end
        point[coord_name] = coord
      end
      multiples[digit] = point
    end
    table_by_window[window] = multiples
  end
  return table_by_window
end

local function _ed_point_neg(P)
  return {
    X = _fp_sub(_ED_ZERO_FE, P.X),
    Y = P.Y,
    Z = P.Z,
    T = _fp_sub(_ED_ZERO_FE, P.T),
  }
end

local function _ed_negate_fixed_point_table(fixed_table)
  local negated = {}
  for window = 1, #fixed_table do
    local src = fixed_table[window]
    local dst = {}
    for digit = 0, _ED_BASE_WINDOW_SIZE - 1 do
      dst[digit] = _ed_point_neg(src[digit])
    end
    negated[window] = dst
  end
  return negated
end

local function _ed_base_window_digit(scalar, window_index)
  local digit = 0
  local first_bit = (window_index - 1) * _ED_BASE_WINDOW
  for bit = 0, _ED_BASE_WINDOW - 1 do
    if _ed_scalar_bit(scalar, first_bit + bit) == 1 then
      digit = digit + 2 ^ bit
    end
  end
  return digit
end

local _ed_scalar_mult_fixed_table

local function _ed_scalar_mult_base(scalar)
  if not _ED_BASE_TABLE then
    _ED_BASE_TABLE = _ed_build_base_table()
    _ED_BASE_TABLE_PREWARMED = true
  end
  return _ed_scalar_mult_fixed_table(_ED_BASE_TABLE, scalar)
end

function _ed_scalar_mult_fixed_table(fixed_table, scalar)
  local result = _ed_identity()
  for window = 1, #fixed_table do
    local digit = _ed_base_window_digit(scalar, window)
    if digit ~= 0 then
      result = _ed_point_add(result, fixed_table[window][digit])
    end
  end
  return result
end

local function _ed_double_scalar_base_plus_fixed(base_scalar, fixed_table, fixed_scalar)
  if not _ED_BASE_TABLE then
    _ED_BASE_TABLE = _ed_build_base_table()
    _ED_BASE_TABLE_PREWARMED = true
  end
  local result = _ed_identity()
  local window_count = math.max(#_ED_BASE_TABLE, #fixed_table)
  for window = 1, window_count do
    local base_digit = _ed_base_window_digit(base_scalar, window)
    if base_digit ~= 0 then
      result = _ed_point_add(result, _ED_BASE_TABLE[window][base_digit])
    end
    local fixed_digit = _ed_base_window_digit(fixed_scalar, window)
    if fixed_digit ~= 0 then
      result = _ed_point_add(result, fixed_table[window][fixed_digit])
    end
  end
  return result
end

local function _ed_scalar_mult_window(point, scalar)
  local multiples = {}
  multiples[0] = _ed_identity()
  multiples[1] = point
  for digit = 2, _ED_BASE_WINDOW_SIZE - 1 do
    multiples[digit] = _ed_point_add(multiples[digit - 1], point)
  end

  local result = _ed_identity()
  local window_count = math.ceil(math.max(1, _scalar_bit_length(scalar)) / _ED_BASE_WINDOW)
  for window = window_count, 1, -1 do
    for _ = 1, _ED_BASE_WINDOW do
      result = _ed_point_double(result)
    end
    local digit = _ed_base_window_digit(scalar, window)
    if digit ~= 0 then
      result = _ed_point_add(result, multiples[digit])
    end
  end
  return result
end

local function _ed_point_equal(P, Q)
  return _fe_compare(_fp_mul(P.X, Q.Z), _fp_mul(Q.X, P.Z)) == 0 and
    _fe_compare(_fp_mul(P.Y, Q.Z), _fp_mul(Q.Y, P.Z)) == 0
end

local function _ed_sqrt_ratio(u, v)
  local v2 = _fp_sq(v)
  local v3 = _fp_mul(v2, v)
  local v7 = _fp_mul(_fp_sq(v2), v3)
  local x = _fp_mul(_fp_mul(u, v3), _fp_pow22523(_fp_mul(u, v7)))
  local check = _fp_mul(v, _fp_sq(x))
  if _fe_compare(check, u) ~= 0 then
    x = _fp_mul(x, _ED_SQRT_M1)
    check = _fp_mul(v, _fp_sq(x))
  end
  if _fe_compare(check, u) ~= 0 then
    return nil
  end
  return x
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
  local x = _ed_sqrt_ratio(u, v)
  if not x then return nil end
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
  return _ed_encode_point(_ed_scalar_mult_base(a))
end

function Ed25519Pure.expand_private_key(private_key)
  assert(type(private_key) == "string" and #private_key == 32, "Ed25519 private key must be 32 bytes")
  local h = _sha512_bytes(private_key)
  local a = _ed_clamped_scalar_from_hash(h)
  return {
    private_key = private_key,
    scalar = a,
    prefix = h:sub(33, 64),
    public_key = _ed_encode_point(_ed_scalar_mult_base(a)),
  }
end

function Ed25519Pure.prewarm()
  if _ED_BASE_TABLE_PREWARMED and _ED_BASE_TABLE then
    return false
  end
  _ED_BASE_TABLE = _ed_build_base_table()
  _ED_BASE_TABLE_PREWARMED = true
  return true
end

function Ed25519Pure.base_table_ready()
  return _ED_BASE_TABLE_PREWARMED and _ED_BASE_TABLE ~= nil
end

function Ed25519Pure.serialize_base_table()
  if not _ED_BASE_TABLE then
    Ed25519Pure.prewarm()
  end
  return _ed_serialize_fixed_point_table(_ED_BASE_TABLE)
end

function Ed25519Pure.restore_base_table(encoded)
  local fixed_table, err = _ed_deserialize_fixed_point_table(encoded)
  if not fixed_table then
    return false, err
  end
  local base = fixed_table[1] and fixed_table[1][1]
  if not base or _fe_compare(base.X, _ED_BASE.X) ~= 0 or _fe_compare(base.Y, _ED_BASE.Y) ~= 0 then
    return false, "Ed25519 fixed-base cache does not match base point"
  end
  _ED_BASE_TABLE = fixed_table
  _ED_BASE_TABLE_PREWARMED = true
  return true
end

function Ed25519Pure.sign(private_key, public_key, message)
  local h = _sha512_bytes(private_key)
  local a = _ed_clamped_scalar_from_hash(h)
  local prefix = h:sub(33, 64)
  local r = _scalar_from_le_bytes_mod(_sha512_bytes(prefix .. message))
  local R = _ed_encode_point(_ed_scalar_mult_base(r))
  local k = _scalar_from_le_bytes_mod(_sha512_bytes(R .. public_key .. message))
  local S = _scalar_add(r, _scalar_mul(k, a))
  return R .. _scalar_to_le32(S)
end

function Ed25519Pure.sign_expanded(expanded, message)
  assert(type(expanded) == "table", "expanded Ed25519 private key is required")
  assert(type(expanded.public_key) == "string" and #expanded.public_key == 32, "expanded Ed25519 public key is invalid")
  assert(type(expanded.prefix) == "string" and #expanded.prefix == 32, "expanded Ed25519 prefix is invalid")
  assert(type(expanded.scalar) == "table", "expanded Ed25519 scalar is invalid")
  local r = _scalar_from_le_bytes_mod(_sha512_bytes(expanded.prefix .. message))
  local R = _ed_encode_point(_ed_scalar_mult_base(r))
  local k = _scalar_from_le_bytes_mod(_sha512_bytes(R .. expanded.public_key .. message))
  local S = _scalar_add(r, _scalar_mul(k, expanded.scalar))
  return R .. _scalar_to_le32(S)
end

local function _ed_verify_internal(public_key, signature, message, collect_profile, decoded_public_key, fixed_public_table, negative_fixed_public_table)
  local profile = collect_profile and {} or nil
  if type(signature) ~= "string" or #signature ~= 64 then
    return false, profile
  end
  local A = decoded_public_key or _ed_decode_point(public_key)
  local R = _ed_decode_point(signature:sub(1, 32))
  if not A or not R then return false, profile end

  local S = _scalar_from_le_bytes_mod(signature:sub(33, 64))
  if _scalar_to_le32(S) ~= signature:sub(33, 64) then
    return false, profile
  end
  local k = _scalar_from_le_bytes_mod(_sha512_bytes(signature:sub(1, 32) .. public_key .. message))

  local ok
  if negative_fixed_public_table then
    local combined = _ed_double_scalar_base_plus_fixed(S, negative_fixed_public_table, k)
    ok = _ed_point_equal(combined, R)
  else
    local left = _ed_scalar_mult_base(S)

    local kA
    if fixed_public_table then
      kA = _ed_scalar_mult_fixed_table(fixed_public_table, k)
    else
      kA = _ed_scalar_mult_window(A, k)
    end
    local right = _ed_point_add(R, kA)

    ok = _ed_point_equal(left, right)
  end
  return ok, profile
end

function Ed25519Pure.verify(public_key, signature, message)
  local ok = _ed_verify_internal(public_key, signature, message, false)
  return ok
end

function Ed25519Pure.verify_profile(public_key, signature, message, decoded_public_key, fixed_public_table, negative_fixed_public_table)
  return _ed_verify_internal(public_key, signature, message, true, decoded_public_key, fixed_public_table, negative_fixed_public_table)
end

function Ed25519Pure.verify_cached(public_key, signature, message, decoded_public_key, fixed_public_table, negative_fixed_public_table)
  return _ed_verify_internal(public_key, signature, message, false, decoded_public_key, fixed_public_table, negative_fixed_public_table)
end

function Ed25519Pure.decode_public_key(public_key)
  return _ed_decode_point(public_key)
end

function Ed25519Pure.fixed_point_table(point)
  return _ed_build_fixed_point_table(point)
end

function Ed25519Pure.serialize_fixed_point_table(fixed_table)
  return _ed_serialize_fixed_point_table(fixed_table)
end

function Ed25519Pure.restore_fixed_point_table(encoded)
  return _ed_deserialize_fixed_point_table(encoded)
end

function Ed25519Pure.negate_fixed_point_table(fixed_table)
  return _ed_negate_fixed_point_table(fixed_table)
end

function SRP.sha512(data)
  return _sha512_bytes(data)
end

local function srp_xor_bytes(a, b)
  assert(#a == #b, "XOR operands must be equal length")
  local out = {}
  for i = 1, #a do
    out[i] = string.char(Bit32.bxor(a:byte(i), b:byte(i)))
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

  assert(#parts == 4, "credentials must be HAP credentials: ltpk:ltsk:atv_id:client_id")

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
  ed25519_public_point_cache = {},
  ed25519_private_key_cache = {},
}

OpenSSLCrypto.ED25519_TABLE_CACHE_VERSION = "ed25519-fixed-v2-window5-limb15"

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

OpenSSLCrypto._pregenerated_x25519_keypair = nil

function OpenSSLCrypto._pregen_x25519()
  local scalar = OpenSSLCrypto.random_bytes(32)
  OpenSSLCrypto._pregenerated_x25519_keypair = {
    private_key = scalar,
    public_key  = X25519Pure.mul(scalar, X25519Pure.BASE_POINT),
  }
end

function OpenSSLCrypto.ensure_x25519_keypair()
  if OpenSSLCrypto._pregenerated_x25519_keypair then
    return "ready"
  end
  OpenSSLCrypto._pregen_x25519()
  return "built"
end

function OpenSSLCrypto.generate_x25519_keypair()
  local cached = OpenSSLCrypto._pregenerated_x25519_keypair
  if cached then
    OpenSSLCrypto._pregenerated_x25519_keypair = nil
    -- Kick off background generation of the next keypair (best-effort, no-op if no C4)
    if has_c4() and type(SetTimer) == "function" then
      SetTimer("AppleTV_crypto_prewarm_x25519", 100, OpenSSLCrypto._pregen_x25519)
    end
    return cached
  end
  -- Fallback: generate synchronously
  local scalar = OpenSSLCrypto.random_bytes(32)
  local keypair = {
    private_key = scalar,
    public_key  = X25519Pure.mul(scalar, X25519Pure.BASE_POINT),
  }
  return keypair
end

function OpenSSLCrypto._derive_x25519(private_key, server_public_key)
  assert(type(private_key) == "string" and #private_key == 32,
    "X25519 private key must be 32 raw bytes")
  return X25519Pure.mul(private_key, server_public_key)
end

function OpenSSLCrypto._sign_ed25519(private_key_bytes, data, public_key)
  local expanded = OpenSSLCrypto._expanded_ed25519_private_key(private_key_bytes)
  if public_key and public_key ~= expanded.public_key then
    return Ed25519Pure.sign(private_key_bytes, public_key, data)
  end
  return Ed25519Pure.sign_expanded(expanded, data)
end

function OpenSSLCrypto._crypto_cache_state()
  Driver.state = Driver.state or Storage.load() or {}
  local cache = Driver.state.crypto_cache
  if type(cache) ~= "table" or cache.version ~= OpenSSLCrypto.ED25519_TABLE_CACHE_VERSION then
    cache = {
      version = OpenSSLCrypto.ED25519_TABLE_CACHE_VERSION,
      ed25519_public_tables = {},
      ed25519_private_keys = {},
    }
    Driver.state.crypto_cache = cache
  elseif type(cache.ed25519_public_tables) ~= "table" then
    cache.ed25519_public_tables = {}
  end
  if type(cache.ed25519_private_keys) ~= "table" then
    cache.ed25519_private_keys = {}
  end
  return cache
end

function OpenSSLCrypto._save_crypto_cache()
  if Driver.state and Driver.state.crypto_cache then
    Storage.save(Driver.state)
  end
end

function OpenSSLCrypto.prune_ed25519_public_table_cache(public_key_bytes)
  local cache = OpenSSLCrypto._crypto_cache_state()
  local keep_key = public_key_bytes and Bytes.hex(public_key_bytes) or nil
  local pruned = {}
  if keep_key and cache.ed25519_public_tables[keep_key] then
    pruned[keep_key] = cache.ed25519_public_tables[keep_key]
  end
  cache.ed25519_public_tables = pruned
  OpenSSLCrypto.ed25519_public_point_cache = {}
  OpenSSLCrypto._save_crypto_cache()
end

function OpenSSLCrypto.prune_ed25519_private_key_cache(private_key_bytes)
  local cache = OpenSSLCrypto._crypto_cache_state()
  local keep_key = private_key_bytes and Bytes.hex(private_key_bytes) or nil
  local pruned = {}
  if keep_key and cache.ed25519_private_keys[keep_key] then
    pruned[keep_key] = cache.ed25519_private_keys[keep_key]
  end
  cache.ed25519_private_keys = pruned
  OpenSSLCrypto.ed25519_private_key_cache = {}
  OpenSSLCrypto._save_crypto_cache()
end

function OpenSSLCrypto.restore_ed25519_base_table_cache()
  if Ed25519Pure.base_table_ready() then
    return true, "ready"
  end
  local cache = OpenSSLCrypto._crypto_cache_state()
  if type(cache.ed25519_base_table) ~= "string" then
    return false, "missing"
  end
  local ok, err = Ed25519Pure.restore_base_table(cache.ed25519_base_table)
  if not ok then
    Log.debug("crypto cache ignored: Ed25519 base table " .. tostring(err))
    cache.ed25519_base_table = nil
    OpenSSLCrypto._save_crypto_cache()
    return false, err
  end
  return true, "restored"
end

function OpenSSLCrypto.ensure_ed25519_base_table()
  local restored, restored_reason = OpenSSLCrypto.restore_ed25519_base_table_cache()
  if restored then
    return restored_reason
  end
  local built = Ed25519Pure.prewarm()
  local cache = OpenSSLCrypto._crypto_cache_state()
  if built or type(cache.ed25519_base_table) ~= "string" then
    cache.ed25519_base_table = Ed25519Pure.serialize_base_table()
    OpenSSLCrypto._save_crypto_cache()
    return built and "built" or "stored"
  end
  return "ready"
end

function OpenSSLCrypto._restore_ed25519_public_table_from_cache(public_key_bytes, key)
  local cache = OpenSSLCrypto._crypto_cache_state()
  local encoded = cache.ed25519_public_tables[key]
  if type(encoded) ~= "string" then
    return nil
  end

  local fixed_table, err = Ed25519Pure.restore_fixed_point_table(encoded)
  if not fixed_table then
    Log.debug("crypto cache ignored: Apple TV public key table " .. tostring(err))
    cache.ed25519_public_tables[key] = nil
    OpenSSLCrypto._save_crypto_cache()
    return nil
  end

  local point = fixed_table[1] and fixed_table[1][1]
  if not point or _ed_encode_point(point) ~= public_key_bytes then
    Log.debug("crypto cache ignored: Apple TV public key table key mismatch")
    cache.ed25519_public_tables[key] = nil
    OpenSSLCrypto._save_crypto_cache()
    return nil
  end

  return {
    point = point,
    fixed_table = fixed_table,
    negative_fixed_table = Ed25519Pure.negate_fixed_point_table(fixed_table),
    restored_from_cache = true,
  }
end

function OpenSSLCrypto.ensure_ed25519_public_table(public_key_bytes)
  assert(type(public_key_bytes) == "string" and #public_key_bytes == 32, "Ed25519 public key must be 32 bytes")
  local key = Bytes.hex(public_key_bytes)
  local entry = OpenSSLCrypto.ed25519_public_point_cache[key]
  if entry and entry.fixed_table and entry.negative_fixed_table then
    return "ready", entry
  end
  entry = OpenSSLCrypto._restore_ed25519_public_table_from_cache(public_key_bytes, key)
  if entry then
    OpenSSLCrypto.ed25519_public_point_cache[key] = entry
    return "restored", entry
  end
  local point = assert(Ed25519Pure.decode_public_key(public_key_bytes), "invalid Ed25519 public key")
  local fixed_table = Ed25519Pure.fixed_point_table(point)
  entry = {
    point = point,
    fixed_table = fixed_table,
    negative_fixed_table = Ed25519Pure.negate_fixed_point_table(fixed_table),
  }
  local cache = OpenSSLCrypto._crypto_cache_state()
  cache.ed25519_public_tables[key] = Ed25519Pure.serialize_fixed_point_table(fixed_table)
  OpenSSLCrypto._save_crypto_cache()
  OpenSSLCrypto.ed25519_public_point_cache[key] = entry
  return "built", entry
end

function OpenSSLCrypto._expanded_ed25519_private_key(private_key_bytes)
  assert(type(private_key_bytes) == "string" and #private_key_bytes == 32, "Ed25519 private key must be 32 bytes")
  local key = Bytes.hex(private_key_bytes)
  local expanded = OpenSSLCrypto.ed25519_private_key_cache[key]
  if not expanded then
    local cache = OpenSSLCrypto._crypto_cache_state()
    local persisted = cache.ed25519_private_keys[key]
    if type(persisted) == "table" and
      type(persisted.scalar) == "string" and #persisted.scalar == 64 and
      type(persisted.prefix) == "string" and #persisted.prefix == 64 and
      type(persisted.public_key) == "string" and #persisted.public_key == 64 then
      local ok, restored_or_err = pcall(function()
        return {
          private_key = private_key_bytes,
          scalar = _scalar_from_le_bytes_mod(Bytes.from_hex(persisted.scalar)),
          prefix = Bytes.from_hex(persisted.prefix),
          public_key = Bytes.from_hex(persisted.public_key),
        }
      end)
      if ok then
        expanded = restored_or_err
      else
        Log.debug("crypto cache ignored: controller Ed25519 signing key " .. tostring(restored_or_err))
        cache.ed25519_private_keys[key] = nil
      end
    end
    if not expanded then
      expanded = Ed25519Pure.expand_private_key(private_key_bytes)
      cache.ed25519_private_keys[key] = {
        scalar = Bytes.hex(_scalar_to_le32(expanded.scalar)),
        prefix = Bytes.hex(expanded.prefix),
        public_key = Bytes.hex(expanded.public_key),
      }
      OpenSSLCrypto._save_crypto_cache()
    end
    OpenSSLCrypto.ed25519_private_key_cache[key] = expanded
  end
  return expanded
end

function OpenSSLCrypto.ensure_ed25519_private_key(private_key_bytes)
  assert(type(private_key_bytes) == "string" and #private_key_bytes == 32, "Ed25519 private key must be 32 bytes")
  local key = Bytes.hex(private_key_bytes)
  if OpenSSLCrypto.ed25519_private_key_cache[key] then
    return "ready", OpenSSLCrypto.ed25519_private_key_cache[key]
  end
  local cache = OpenSSLCrypto._crypto_cache_state()
  local had_persisted = type(cache.ed25519_private_keys[key]) == "table"
  local expanded = OpenSSLCrypto._expanded_ed25519_private_key(private_key_bytes)
  return had_persisted and "restored" or "built", expanded
end

function OpenSSLCrypto._ed25519_public_key_cache_entry(public_key_bytes)
  assert(type(public_key_bytes) == "string" and #public_key_bytes == 32, "Ed25519 public key must be 32 bytes")
  local key = Bytes.hex(public_key_bytes)
  local entry = OpenSSLCrypto.ed25519_public_point_cache[key]
  if not entry then
    local _
    _, entry = OpenSSLCrypto.ensure_ed25519_public_table(public_key_bytes)
  end
  return entry
end

function OpenSSLCrypto._decoded_ed25519_public_key(public_key_bytes)
  return OpenSSLCrypto._ed25519_public_key_cache_entry(public_key_bytes).point
end

function OpenSSLCrypto._default_verify_ed25519(public_key_bytes, signature, data)
  local entry = OpenSSLCrypto._ed25519_public_key_cache_entry(public_key_bytes)
  return Ed25519Pure.verify_cached(public_key_bytes, signature, data,
    entry.point, entry.fixed_table, entry.negative_fixed_table)
end

OpenSSLCrypto._verify_ed25519 = OpenSSLCrypto._default_verify_ed25519

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

function OpenSSLCrypto.pair_verify_response(credentials, private_key, public_key, server_public_key, encrypted_data)
  local shared_secret = OpenSSLCrypto._derive_x25519(private_key, server_public_key)
  local session_key = OpenSSLCrypto.hkdf_sha512("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared_secret)
  local nonce = OpenSSLCrypto._hap_nonce("PV-Msg02")
  local decrypted = OpenSSLCrypto._chacha20_poly1305_decrypt(
    session_key,
    nonce,
    encrypted_data
  )
  local ok, decrypted_tlv_or_err = pcall(TLV8.decode, decrypted)
  if not ok then
    Log.error("Pair-Verify decrypted TLV decode failed: len=" .. tostring(#(decrypted or "")) ..
      " head=" .. Bytes.hex((decrypted or ""):sub(1, 32)) ..
      " tail=" .. Bytes.hex((decrypted or ""):sub(math.max(1, #(decrypted or "") - 31))) ..
      " encrypted_head=" .. Bytes.hex(encrypted_data:sub(1, 32)))
    error(decrypted_tlv_or_err, 2)
  end
  local decrypted_tlv = decrypted_tlv_or_err

  local identifier = decrypted_tlv[1]
  local signature = decrypted_tlv[10]
  assert(identifier == credentials.atv_id, "incorrect Apple TV Pair-Verify identifier")
  assert(signature, "Apple TV Pair-Verify signature missing")

  local device_info = server_public_key .. identifier .. public_key
  local verify_ok = OpenSSLCrypto._verify_ed25519(credentials.ltpk, signature, device_info)
  assert(verify_ok, "Apple TV Pair-Verify signature invalid")

  local controller_info = public_key .. credentials.client_id .. server_public_key
  if not credentials.controller_ltpk then
    local public_ok, expanded = pcall(OpenSSLCrypto._expanded_ed25519_private_key, credentials.ltsk)
    if public_ok then
      credentials.controller_ltpk = expanded.public_key
    end
  end
  local controller_signature = OpenSSLCrypto._sign_ed25519(credentials.ltsk, controller_info, credentials.controller_ltpk)
  local response_tlv = TLV8.encode_ordered({
    { 1, credentials.client_id },
    { 10, controller_signature },
  })

  local encrypted_response = OpenSSLCrypto._chacha20_poly1305_encrypt(session_key, OpenSSLCrypto._hap_nonce("PV-Msg03"), response_tlv)
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

function PairVerify.encode_hap_start(public_key)
  return TLV8.encode_ordered({
    { 6, string.char(0x01) },
    { 3, public_key },
  })
end

function PairVerify.encode_hap_next(encrypted_data)
  return TLV8.encode_ordered({
    { 6, string.char(0x03) },
    { 5, encrypted_data },
  })
end

function PairVerify.decode_hap_response(payload)
  local ok, tlv_or_err = pcall(TLV8.decode, payload)
  if not ok then
    Log.error("AirPlay Pair-Verify TLV decode failed: len=" .. tostring(#(payload or "")) ..
      " head=" .. Bytes.hex((payload or ""):sub(1, 32)))
    error(tlv_or_err, 2)
  end
  local tlv = tlv_or_err
  assert(not tlv[7], "Apple TV returned AirPlay Pair-Verify error")
  return tlv
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

function PairVerify:start_hap()
  local keypair = crypto_method(self.crypto, "generate_x25519_keypair")()
  assert(type(keypair) == "table" and type(keypair.public_key) == "string", "invalid X25519 keypair")
  self.keypair = keypair
  return PairVerify.encode_hap_start(keypair.public_key)
end

function PairVerify:finish_hap(response_body, output_info, input_info)
  assert(self.keypair, "pair verify has not started")
  local tlv = PairVerify.decode_hap_response(response_body)
  local server_public_key = tlv[3]
  local encrypted_data = tlv[5]
  assert(server_public_key and encrypted_data, "AirPlay Pair-Verify response missing public key or encrypted data")

  local encrypted_response, shared_secret = crypto_method(self.crypto, "pair_verify_response")(
    self.credentials,
    self.keypair.private_key,
    self.keypair.public_key,
    server_public_key,
    encrypted_data
  )

  self.shared_secret = shared_secret
  self.output_key = crypto_method(self.crypto, "hkdf_sha512")(
    "Control-Salt",
    output_info or "Control-Write-Encryption-Key",
    shared_secret
  )
  self.input_key = crypto_method(self.crypto, "hkdf_sha512")(
    "Control-Salt",
    input_info or "Control-Read-Encryption-Key",
    shared_secret
  )

  return PairVerify.encode_hap_next(encrypted_response), {
    output_key = self.output_key,
    input_key = self.input_key,
  }
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

function PairSetup:start_hap()
  Log.debug("AirPlay Pair-Setup M1 start: generating controller Ed25519 key and pairing id")
  local keypair = crypto_method(self.crypto, "generate_ed25519_keypair")()
  self.auth_private = keypair.private_key
  self.auth_public = keypair.public_key
  local uuid_bytes = crypto_method(self.crypto, "random_bytes")(16)
  local h = Bytes.hex(uuid_bytes)
  self.pairing_id = h:sub(1,8).."-"..h:sub(9,12).."-"..h:sub(13,16).."-"..h:sub(17,20).."-"..h:sub(21,32)
  self.state = "M1_SENT"
  Log.debug("AirPlay Pair-Setup M1 sent: public_key_len=" .. tostring(#self.auth_public) ..
    " pairing_id=" .. tostring(self.pairing_id))
  return TLV8.encode_ordered({
    { 0, string.char(0x00) },
    { 6, string.char(0x01) },
  })
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

function PairSetup:handle_m2_hap(payload)
  Log.debug("AirPlay Pair-Setup M2 received: payload_len=" .. tostring(#(payload or "")))
  assert(self.state == "M1_SENT", "unexpected M2 in state " .. self.state)
  local tlv = PairVerify.decode_hap_response(payload)
  local salt = tlv[2]
  local B_bytes = tlv[3]
  assert(salt and #salt == 16, "SRP salt must be 16 bytes, got " .. tostring(salt and #salt))
  assert(B_bytes and #B_bytes == 384, "SRP server public key must be 384 bytes")
  self._salt = salt
  self._B_bytes = B_bytes
  self.state = "M2_RECEIVED"
  Log.debug("AirPlay Pair-Setup M2 parsed: salt_len=" .. tostring(#salt) ..
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

function PairSetup:compute_m3_hap(pin)
  self:compute_m3(pin)
  return TLV8.encode_ordered({
    { 6, string.char(0x03) },
    { 3, self.A_bytes },
    { 4, self._M1 },
  })
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

function PairSetup:handle_m4_hap(payload)
  Log.debug("AirPlay Pair-Setup M4 received: payload_len=" .. tostring(#(payload or "")))
  assert(self.state == "M3_SENT", "unexpected M4 in state " .. self.state)
  local tlv = PairVerify.decode_hap_response(payload)
  local atv_M2 = tlv[4]
  assert(atv_M2 and #atv_M2 == 64, "server M4 proof must be 64 bytes")
  Log.debug("AirPlay Pair-Setup M4 progress: verifying server proof")
  assert(SRP.verify_M2(self.A_bytes, self._M1, self.K, atv_M2), "SRP M2 proof verification failed")
  Log.debug("AirPlay Pair-Setup M4 progress: server proof verified")
  self.session_key = crypto_method(self.crypto, "hkdf_sha512")(
    "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", self.K)
  self.state = "M4_VERIFIED"
  Log.debug("AirPlay Pair-Setup M4 verified: encryption key derived")
end

function PairSetup:compute_m5()
  Log.debug("Pair-Setup M5 compute started: signing controller identity")
  assert(self.state == "M4_VERIFIED", "must verify M4 before computing M5")
  local encrypted = self:_compute_m5_encrypted()
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

function PairSetup:_compute_m5_encrypted()
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
  return crypto_method(self.crypto, "encrypt")(self.session_key, inner_tlv, "", nonce)
end

function PairSetup:compute_m5_hap()
  assert(self.state == "M4_VERIFIED", "must verify M4 before computing M5")
  local encrypted = self:_compute_m5_encrypted()
  self.state = "M5_SENT"
  Log.debug("AirPlay Pair-Setup M5 sent: encrypted_len=" .. tostring(#encrypted))
  return TLV8.encode_ordered({
    { 6, string.char(0x05) },
    { 5, encrypted },
  })
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

function PairSetup:handle_m6_hap(payload)
  Log.debug("AirPlay Pair-Setup M6 received: payload_len=" .. tostring(#(payload or "")))
  assert(self.state == "M5_SENT", "unexpected M6 in state " .. self.state)
  local tlv = PairVerify.decode_hap_response(payload)
  local encrypted_data = tlv[5]
  assert(encrypted_data, "server M6 encrypted data missing")
  Log.debug("AirPlay Pair-Setup M6 progress: encrypted_len=" .. tostring(#encrypted_data) .. ", decrypting")
  local nonce = string.rep("\0", 4) .. "PS-Msg06"
  local decrypted = crypto_method(self.crypto, "decrypt")(self.session_key, encrypted_data, "", nonce)
  assert(decrypted, "M6 decrypt failed")
  Log.debug("AirPlay Pair-Setup M6 progress: decrypted_len=" .. tostring(#decrypted))
  local inner = TLV8.decode(decrypted)
  local atv_id = inner[1]
  local atv_ltpk = inner[3]
  assert(atv_id and atv_ltpk, "M6 response missing identifier or public key")
  local credentials_str = table.concat({
    Bytes.hex(atv_ltpk),
    Bytes.hex(self.auth_private),
    Bytes.hex(atv_id),
    Bytes.hex(self.pairing_id),
  }, ":")
  self.state = "PAIRED"
  Log.debug("AirPlay Pair-Setup M6 parsed: atv_id_len=" .. tostring(#atv_id) ..
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

local function enforce_buffer_limit(owner, field, max_bytes, label)
  local value = owner[field] or ""
  if max_bytes and max_bytes > 0 and #value > max_bytes then
    owner[field] = ""
    error(tostring(label or field) .. " exceeded " .. tostring(max_bytes) .. " bytes")
  end
  return value
end

local HAPSession = {}
HAPSession.FRAME_LENGTH = 1024
HAPSession.AUTH_TAG_LENGTH = 16
HAPSession.MAX_ENCRYPTED_BUFFER_BYTES = 65536

function HAPSession.new(output_key, input_key, crypto)
  return setmetatable({
    output_key = output_key,
    input_key = input_key,
    crypto = crypto or Crypto,
    out_counter = 0,
    in_counter = 0,
    encrypted_buffer = "",
  }, { __index = HAPSession })
end

function HAPSession:nonce(counter)
  return string.rep("\0", 4) .. Bytes.uint_le(counter, 8)
end

function HAPSession:encrypt(data)
  assert(type(data) == "string", "HAP plaintext must be a string")
  local out = {}
  local index = 1
  while index <= #data do
    local frame = data:sub(index, index + HAPSession.FRAME_LENGTH - 1)
    index = index + HAPSession.FRAME_LENGTH
    local length = Bytes.uint_le(#frame, 2)
    local nonce = self:nonce(self.out_counter)
    self.out_counter = self.out_counter + 1
    out[#out + 1] = length .. crypto_method(self.crypto, "encrypt")(self.output_key, frame, length, nonce)
  end
  return table.concat(out)
end

function HAPSession:decrypt(data)
  assert(type(data) == "string", "HAP ciphertext must be a string")
  self.encrypted_buffer = self.encrypted_buffer .. data
  enforce_buffer_limit(self, "encrypted_buffer", HAPSession.MAX_ENCRYPTED_BUFFER_BYTES, "HAP encrypted buffer")
  local out = {}

  while #self.encrypted_buffer >= 2 do
    local length = Bytes.read_u16le(self.encrypted_buffer, 1)
    local frame_end = 2 + length + HAPSession.AUTH_TAG_LENGTH
    if #self.encrypted_buffer < frame_end then
      break
    end

    local aad = self.encrypted_buffer:sub(1, 2)
    local encrypted = self.encrypted_buffer:sub(3, frame_end)
    local nonce = self:nonce(self.in_counter)
    self.in_counter = self.in_counter + 1
    out[#out + 1] = crypto_method(self.crypto, "decrypt")(self.input_key, encrypted, aad, nonce)
    self.encrypted_buffer = self.encrypted_buffer:sub(frame_end + 1)
  end

  return table.concat(out)
end

local Companion = {
  state = "DISCONNECTED",
  port = 49153,
  tx = 0,
  sent_messages = {},
  sent_messages_max = 100,
  pending_commands_max = 50,
  receive_buffer_max = 65536,
  watchdog_interval_ms = 60000,
  watchdog_stale_ms = 90000,
  credentials = nil,
  client = nil,
  app_list = {},
  current_app = nil,
  now_playing = {},
}

function Companion.record_sent_message(request)
  local messages = Companion.sent_messages
  if type(messages) ~= "table" then
    return
  end
  messages[#messages + 1] = request
  local max = tonumber(Companion.sent_messages_max) or 0
  if max <= 0 then
    Companion.sent_messages = {}
    return
  end
  while #messages > max do
    table.remove(messages, 1)
  end
end

local AirPlay = {
  port = nil,
  txt = {},
  credentials = nil,
  pair_setup = nil,
  pairing_active = false,
  control_client = nil,
  monitor_enabled = false,
  monitor_state = "Stopped",
  monitor_retry_ms = 15000,
  monitor_heartbeat_ms = 30000,
  monitor_stale_ms = 90000,
  receive_buffer_max = 65536,
  monitor_last_activity_ms = nil,
}

local BPlist = {}

function BPlist.bytes(data)
  assert(type(data) == "string", "bplist bytes value must be a string")
  return { __bplist_type = "bytes", data = data }
end

local function bplist_is_array(value)
  if type(value) ~= "table" then return false end
  local count = 0
  for key in pairs(value) do
    if type(key) ~= "number" or key < 1 or key ~= math.floor(key) then
      return false
    end
    count = count + 1
  end
  return count == #value
end

function BPlist.integer_object(value)
  assert(type(value) == "number" and value >= 0 and value == math.floor(value), "bplist integer must be unsigned")
  if value <= 0xFF then
    return string.char(0x10) .. Bytes.uint_be(value, 1)
  elseif value <= 0xFFFF then
    return string.char(0x11) .. Bytes.uint_be(value, 2)
  elseif value <= 0xFFFFFFFF then
    return string.char(0x12) .. Bytes.uint_be(value, 4)
  end
  return string.char(0x13) .. Bytes.uint_be(value, 8)
end

function BPlist.length_marker(prefix, length)
  if length < 15 then
    return string.char(prefix + length)
  end
  return string.char(prefix + 15) .. BPlist.integer_object(length)
end

function BPlist.encode(value)
  local objects = {}

  local function add(obj)
    objects[#objects + 1] = obj
    return #objects - 1
  end

  local function encode_object(obj)
    local value_type = type(obj)
    if value_type == "boolean" then
      return add(string.char(obj and 0x09 or 0x08))
    end
    if value_type == "number" then
      return add(BPlist.integer_object(obj))
    end
    if value_type == "string" then
      return add(BPlist.length_marker(0x50, #obj) .. obj)
    end
    if value_type == "table" then
      if obj.__bplist_type == "bytes" then
        return add(BPlist.length_marker(0x40, #(obj.data or "")) .. (obj.data or ""))
      end
      if bplist_is_array(obj) then
        local refs = {}
        for i = 1, #obj do
          refs[#refs + 1] = encode_object(obj[i])
        end
        local body = {}
        for _, ref in ipairs(refs) do
          body[#body + 1] = string.char(ref)
        end
        return add(BPlist.length_marker(0xA0, #refs) .. table.concat(body))
      end

      local keys = {}
      for key in pairs(obj) do
        assert(type(key) == "string", "bplist dictionary keys must be strings")
        keys[#keys + 1] = key
      end
      table.sort(keys)

      local key_refs = {}
      local value_refs = {}
      for _, key in ipairs(keys) do
        key_refs[#key_refs + 1] = encode_object(key)
        value_refs[#value_refs + 1] = encode_object(obj[key])
      end

      local body = {}
      for _, ref in ipairs(key_refs) do body[#body + 1] = string.char(ref) end
      for _, ref in ipairs(value_refs) do body[#body + 1] = string.char(ref) end
      return add(BPlist.length_marker(0xD0, #keys) .. table.concat(body))
    end
    error("unsupported bplist type: " .. tostring(value_type))
  end

  local top_object = encode_object(value)
  if #objects >= 256 then
    error("bplist encoder: " .. tostring(#objects) .. " objects exceeds 255-object limit (single-byte refs)")
  end

  local object_data = {}
  local offsets = {}
  local cursor = #"bplist00"
  for _, obj in ipairs(objects) do
    offsets[#offsets + 1] = cursor
    object_data[#object_data + 1] = obj
    cursor = cursor + #obj
  end

  local offset_int_size = cursor <= 0xFFFF and 2 or 4
  local offset_table = {}
  for _, offset in ipairs(offsets) do
    offset_table[#offset_table + 1] = Bytes.uint_be(offset, offset_int_size)
  end
  local offset_table_offset = cursor
  local trailer = string.rep("\0", 6) ..
    string.char(offset_int_size) ..
    string.char(1) ..
    Bytes.uint_be(#objects, 8) ..
    Bytes.uint_be(top_object, 8) ..
    Bytes.uint_be(offset_table_offset, 8)

  return "bplist00" .. table.concat(object_data) .. table.concat(offset_table) .. trailer
end

function BPlist.decode(data)
  assert(type(data) == "string" and data:sub(1, 8) == "bplist00", "not a binary plist")
  assert(#data >= 40, "truncated binary plist")

  local trailer = data:sub(#data - 31)
  local offset_int_size = trailer:byte(7)
  local object_ref_size = trailer:byte(8)
  local object_count = Bytes.read_uint_be(trailer, 9, 8)
  local top_object = Bytes.read_uint_be(trailer, 17, 8)
  local offset_table_offset = Bytes.read_uint_be(trailer, 25, 8)

  local offsets = {}
  for i = 0, object_count - 1 do
    offsets[i] = Bytes.read_uint_be(data, offset_table_offset + 1 + (i * offset_int_size), offset_int_size) + 1
  end

  local cache = {}
  local parse_object

  local function read_length(low, index)
    if low < 15 then
      return low, index
    end
    local marker = data:byte(index)
    assert(marker, "truncated bplist length")
    local kind = math.floor(marker / 0x10)
    local power = marker % 0x10
    assert(kind == 1, "extended bplist length must be integer")
    local size = 2 ^ power
    local value = Bytes.read_uint_be(data, index + 1, size)
    return value, index + 1 + size
  end

  local function read_ref(index)
    return Bytes.read_uint_be(data, index, object_ref_size), index + object_ref_size
  end

  parse_object = function(ref)
    if cache[ref] ~= nil then
      return cache[ref]
    end

    local index = offsets[ref]
    assert(index, "invalid bplist object reference")
    local marker = data:byte(index)
    assert(marker, "truncated bplist object")
    local kind = math.floor(marker / 0x10)
    local low = marker % 0x10
    index = index + 1

    local value
    if kind == 0 then
      if low == 0x8 then value = false
      elseif low == 0x9 then value = true
      else value = nil end
    elseif kind == 1 then
      value = Bytes.read_uint_be(data, index, 2 ^ low)
    elseif kind == 4 then
      local length
      length, index = read_length(low, index)
      value = BPlist.bytes(data:sub(index, index + length - 1))
    elseif kind == 5 then
      local length
      length, index = read_length(low, index)
      value = data:sub(index, index + length - 1)
    elseif kind == 6 then
      local length
      length, index = read_length(low, index)
      local chars = {}
      for i = 0, length - 1 do
        local code = Bytes.read_uint_be(data, index + (i * 2), 2)
        chars[#chars + 1] = code < 128 and string.char(code) or "?"
      end
      value = table.concat(chars)
    elseif kind == 0xA then
      local length
      length, index = read_length(low, index)
      value = {}
      cache[ref] = value
      for i = 1, length do
        local child_ref
        child_ref, index = read_ref(index)
        value[i] = parse_object(child_ref)
      end
      return value
    elseif kind == 0xD then
      local length
      length, index = read_length(low, index)
      local key_refs = {}
      local value_refs = {}
      for i = 1, length do
        key_refs[i], index = read_ref(index)
      end
      for i = 1, length do
        value_refs[i], index = read_ref(index)
      end
      value = {}
      cache[ref] = value
      for i = 1, length do
        value[tostring(parse_object(key_refs[i]))] = parse_object(value_refs[i])
      end
      return value
    else
      error("unsupported bplist marker 0x" .. string.format("%02x", marker))
    end

    cache[ref] = value
    return value
  end

  return parse_object(top_object)
end

function BPlist.describe(value, depth)
  depth = depth or 0
  if depth > 3 then return "..." end
  local value_type = type(value)
  if value_type == "nil" then return "nil" end
  if value_type == "boolean" or value_type == "number" then return tostring(value) end
  if value_type == "string" then
    local printable = value:gsub("[^%g ]", ".")
    if #printable > 80 then printable = printable:sub(1, 80) .. "..." end
    return '"' .. printable .. '"'
  end
  if value_type == "table" then
    if value.__bplist_type == "bytes" then
      return "bytes(" .. tostring(#(value.data or "")) .. ")=" .. Bytes.hex((value.data or ""):sub(1, 24))
    end
    local parts = {}
    if bplist_is_array(value) then
      for i = 1, math.min(#value, 8) do
        parts[#parts + 1] = BPlist.describe(value[i], depth + 1)
      end
      if #value > 8 then parts[#parts + 1] = "..." end
      return "[" .. table.concat(parts, ", ") .. "]"
    end
    local keys = {}
    for key in pairs(value) do keys[#keys + 1] = tostring(key) end
    table.sort(keys)
    for i = 1, math.min(#keys, 8) do
      local key = keys[i]
      parts[#parts + 1] = key .. "=" .. BPlist.describe(value[key], depth + 1)
    end
    if #keys > 8 then parts[#parts + 1] = "..." end
    return "{" .. table.concat(parts, ", ") .. "}"
  end
  return tostring(value)
end

local AirPlayHTTP = {}

function AirPlayHTTP.format_request(method, path, host, port, headers, body, protocol)
  method = method or "GET"
  path = path or "/"
  protocol = protocol or "HTTP/1.1"
  body = body or ""
  headers = headers or {}

  local ordered = {
    { "Host", tostring(host) .. ":" .. tostring(port) },
    { "User-Agent", headers["User-Agent"] or "AirPlay/550.10" },
    { "Connection", headers["Connection"] or "keep-alive" },
  }
  local seen = { Host = true, ["User-Agent"] = true, Connection = true }
  if body ~= "" or method == "POST" or method == "PUT" then
    ordered[#ordered + 1] = { "Content-Length", tostring(#body) }
    seen["Content-Length"] = true
  end
  for key, value in pairs(headers) do
    if not seen[key] then
      ordered[#ordered + 1] = { key, tostring(value) }
    end
  end

  local lines = { method .. " " .. path .. " " .. protocol }
  for _, header in ipairs(ordered) do
    lines[#lines + 1] = header[1] .. ": " .. header[2]
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = ""
  return table.concat(lines, "\r\n") .. body
end

function AirPlayHTTP.try_parse_response(buffer)
  local header_end = buffer:find("\r\n\r\n", 1, true)
  if not header_end then
    return nil, buffer
  end

  local header_block = buffer:sub(1, header_end - 1)
  local body_start = header_end + 4
  local first_line, rest = header_block:match("^([^\r\n]+)\r\n?(.*)$")
  if not first_line then
    return nil, nil
  end
  local protocol, status_text = first_line:match("^(%S+)%s+(.+)$")
  local status = tonumber((status_text or ""):match("^(%d+)")) or 0
  local headers = {}
  for line in tostring(rest):gmatch("([^\r\n]+)") do
    local key, value = line:match("^([^:]+):%s*(.*)$")
    if key then
      headers[key:lower()] = value
      headers[key] = value
    end
  end
  local content_length = tonumber(headers["content-length"] or headers["Content-Length"] or "0") or 0
  local response_end = body_start + content_length - 1
  if #buffer < response_end then
    return nil, buffer
  end

  return {
    protocol = protocol,
    status = status,
    status_text = status_text,
    headers = headers,
    body = buffer:sub(body_start, response_end),
    raw_headers = header_block,
  }, buffer:sub(response_end + 1)
end

function AirPlayHTTP.format_response(status, reason, headers, body, protocol)
  status = status or 200
  reason = reason or "OK"
  protocol = protocol or "HTTP/1.1"
  headers = headers or {}
  body = body or ""

  local lines = { protocol .. " " .. tostring(status) .. " " .. tostring(reason) }
  local has_content_length = false
  for key, value in pairs(headers) do
    if string.lower(tostring(key)) == "content-length" then
      has_content_length = true
    end
    lines[#lines + 1] = tostring(key) .. ": " .. tostring(value)
  end
  if not has_content_length then
    lines[#lines + 1] = "Content-Length: " .. tostring(#body)
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = ""
  return table.concat(lines, "\r\n") .. body
end

function AirPlayHTTP.try_parse_request(buffer)
  local header_end = buffer:find("\r\n\r\n", 1, true)
  if not header_end then
    return nil, buffer
  end

  local header_block = buffer:sub(1, header_end - 1)
  local body_start = header_end + 4
  local first_line, rest = header_block:match("^([^\r\n]+)\r\n?(.*)$")
  if not first_line then
    return nil, nil
  end
  local method, path, protocol = first_line:match("^(%S+)%s+(%S+)%s+(%S+)$")
  if not method then
    return nil, nil
  end
  local headers = {}
  for line in tostring(rest):gmatch("([^\r\n]+)") do
    local key, value = line:match("^([^:]+):%s*(.*)$")
    if key then
      headers[string.lower(key)] = value
      headers[key] = value
    end
  end
  local content_length = tonumber(headers["content-length"] or headers["Content-Length"] or "0") or 0
  local request_end = body_start + content_length - 1
  if #buffer < request_end then
    return nil, buffer
  end
  return {
    method = method,
    path = path,
    protocol = protocol,
    headers = headers,
    body = buffer:sub(body_start, request_end),
    raw_headers = header_block,
  }, buffer:sub(request_end + 1)
end

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
    TVRCSessionStart = { "ProtocolVersionKey" },
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
  local session = Companion.client and Companion.client.session
  local frame = session and session:encode_frame(CompanionFrame.E_OPACK, payload) or CompanionFrame.encode(CompanionFrame.E_OPACK, payload)
  return request, frame
end

function Companion.send_opack(identifier, content, message_type, options)
  if Companion.client and Companion.client.send_or_queue_opack then
    return Companion.client:send_or_queue_opack(identifier, content, message_type, options)
  end

  local request, frame = Companion.encode_opack_request(identifier, content, message_type)
  Companion.record_sent_message(request)

  Log.debug("queued Companion request " .. identifier)

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

function Companion.normalize_app_name(name)
  name = tostring(name or ""):lower()
  return (name:gsub("[^%w]", ""))
end

function Companion.looks_like_launch_identifier(value)
  value = tostring(value or "")
  if value == "" then return false end
  if value:match("^[%a][%w+.-]*:") then return true end
  return value:find(".", 1, true) ~= nil
end

function Companion.find_app_by_name(name)
  local normalized = Companion.normalize_app_name(name)
  if normalized == "" then return nil end

  local exact_match
  for _, app in ipairs(Companion.app_list_rows or {}) do
    if Companion.normalize_app_name(app.name) == normalized then
      if exact_match and exact_match ~= app.identifier then
        return nil, "multiple apps match name " .. tostring(name)
      end
      exact_match = app.identifier
    end
  end
  if exact_match then return exact_match end

  local fuzzy_match
  if #normalized >= 4 then
    for _, app in ipairs(Companion.app_list_rows or {}) do
      local app_name = Companion.normalize_app_name(app.name)
      local app_id = Companion.normalize_app_name(app.identifier)
      if (app_name ~= "" and (app_name:find(normalized, 1, true) or normalized:find(app_name, 1, true))) or
         (app_id ~= "" and app_id:find(normalized, 1, true))
      then
        if fuzzy_match and fuzzy_match ~= app.identifier then
          return nil, "multiple apps fuzzily match " .. tostring(name)
        end
        fuzzy_match = app.identifier
      end
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

  local title = content.title or content._title
  if not title and message._i == "NowPlaying" then
    title = content.name
  end
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

function Companion.button(name, state, options)
  local command = HID_COMMANDS[name]
  assert(command, "unsupported HID command: " .. tostring(name))
  return Companion.send_opack("_hidC", {
    _hidC = command,
    _hBtS = state or 2,
  }, 2, options)
end

function Companion.button_action(name, action, options)
  action = string.lower(tostring(action or "single"))
  if action == "singletap" or action == "tap" or action == "single" or action == "" then
    return { Companion.button(name, 1, options), Companion.button(name, 2, options) }
  end
  if action == "doubletap" or action == "double" then
    return {
      Companion.button(name, 1, options),
      Companion.button(name, 2, options),
      Companion.button(name, 1, options),
      Companion.button(name, 2, options),
    }
  end
  if action == "hold" or action == "longpress" or action == "long_press" then
    return { Companion.button(name, 1, options), Companion.button(name, 2, options) }
  end
  if action == "down" or action == "press" or action == "start" then
    return { Companion.button(name, 1, options) }
  end
  if action == "up" or action == "release" or action == "stop" then
    return { Companion.button(name, 2, options) }
  end
  error("unsupported HID action: " .. tostring(action))
end

local C4Driver
local C4MiniApps
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
    response_timeout_ms = options.response_timeout_ms or 30000,
    pending_commands = {},
    startup_steps = nil,
    startup_index = 0,
    startup_in_progress = false,
    post_session_started = false,
    tv_rc_session_xid = nil,
    last_rx_ms = nil,
    last_tx_ms = nil,
    session_active_since_ms = nil,
    injected_transport = options.transport ~= nil,
    connecting = false,
    connected = false,
    state = "DISCONNECTED",
    received_messages = {},
    on_state = options.on_state,
    on_message = options.on_message,
    on_paired = options.on_paired,
    on_pair_setup_m2 = options.on_pair_setup_m2,
    on_connection_refused = options.on_connection_refused,
  }, { __index = CompanionClient })
end

function CompanionClient:now_ms()
  if C4Driver and C4Driver.now_ms then
    return C4Driver.now_ms()
  end
  return (os.time() or 0) * 1000
end

function CompanionClient:mark_tx()
  self.last_tx_ms = self:now_ms()
end

function CompanionClient:mark_rx()
  self.last_rx_ms = self:now_ms()
end

function CompanionClient:clear_runtime_state(options)
  options = options or {}
  if self.tv_rc_session_xid and C4Driver and C4Driver.cancel_timer then
    C4Driver.cancel_timer("AppleTV_tv_rc_session_start_timeout")
  end
  self.connecting = false
  self.connected = false
  self.verifier = nil
  self.pair_setup = nil
  self.pending_pair_setup = false
  self.pending_pair_verify_keys = nil
  self.session = nil
  self.session_local_sid = nil
  self.session_remote_sid = nil
  self.session_start_xid = nil
  self.startup_steps = nil
  self.startup_index = 0
  self.startup_in_progress = false
  self.post_session_started = false
  self.tv_rc_session_xid = nil
  self.session_active_since_ms = nil
  self.buffer = ""
  self.pending_responses = {}
  if options.clear_pending_commands then
    self.pending_commands = {}
  end
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
  self:mark_tx()
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

function CompanionClient:close(options)
  options = options or {}
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
  self:clear_runtime_state({
    clear_pending_commands = options.clear_pending_commands ~= false,
  })
  self:set_state("DISCONNECTED")
end

function CompanionClient:dispose(options)
  self:close(options)
  self.credentials = nil
  self.crypto = nil
  self.host = nil
  self.port = nil
  self.transport = nil
  self.pending_commands = {}
  self.pending_responses = {}
  self.on_state = nil
  self.on_message = nil
  self.on_paired = nil
  self.on_pair_setup_m2 = nil
  self.on_connection_refused = nil
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
      self:mark_rx()
      local ok, err = pcall(function() self:receive(data) end)
      if not ok then
        Log.error("Companion receive failed: " .. tostring(err))
        if tcp_client.Close then
          pcall(function() tcp_client:Close() end)
        elseif tcp_client.close then
          pcall(function() tcp_client:close() end)
        end
        self.transport = nil
        self:clear_runtime_state({ clear_pending_commands = false })
        self:set_state("ERROR: " .. tostring(err))
        return
      end
      tcp_client:ReadUpTo(4096)
    end)
    :OnDisconnect(function(_, err_code, err_msg)
      Log.debug("Companion TCP disconnected: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      self:clear_runtime_state({ clear_pending_commands = false })
      self:set_state((err_code and err_code ~= 0) and ("DISCONNECTED: " .. tostring(err_msg)) or "DISCONNECTED")
    end)
    :OnError(function(_, err_code, err_msg)
      Log.error("Companion TCP error: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      self:clear_runtime_state({ clear_pending_commands = false })
      self:set_state("ERROR: " .. tostring(err_code) .. " " .. tostring(err_msg))
      if tostring(err_code) == "111" and self.on_connection_refused then
        self.on_connection_refused(self, err_code, err_msg)
      end
    end)
    :Connect(self.host, self.port)

  self.transport = client
  return self
end

function CompanionClient:on_connected(transport)
  self.transport = transport
  self.connecting = false
  self.connected = true
  self._port_rediscover_attempted = false
  self.last_rx_ms = nil
  self.last_tx_ms = nil
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
  if self.startup_in_progress or self.startup_steps then
    Log.debug("Companion startup already in progress")
    return
  end
  if self.state == "SESSION_ACTIVE" then
    Log.debug("Companion startup skipped: session already active")
    self:flush_pending_commands()
    return
  end
  self.startup_in_progress = true
  self.post_session_started = false
  self.startup_steps = {
    function() self:send_system_info() end,
    function() self:start_touch() end,
    function() self:start_session() end,
    function() self:start_tv_remote_control_session() end,
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
  self.startup_in_progress = false
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
    self.session_active_since_ms = self:now_ms()
    Log.debug("Companion session active, remote_sid=" .. tostring(self.session_remote_sid))
    self:send_next_startup_step()
  end)
  self.session_start_xid = request._x
  self:set_state("SESSION_STARTING")
end

function CompanionClient:finish_tv_remote_control_session(xid, reason)
  if self.tv_rc_session_xid ~= xid then
    return
  end
  self.tv_rc_session_xid = nil
  if C4Driver and C4Driver.cancel_timer then
    C4Driver.cancel_timer("AppleTV_tv_rc_session_start_timeout")
  end
  if reason and reason ~= "" then
    Log.debug("Companion TV RC session continuing: " .. tostring(reason))
  end
  self:flush_pending_commands({ priority_only = true })
  C4MiniApps.schedule_pending_launch_retry()
  self:send_next_startup_step()
end

function CompanionClient:start_tv_remote_control_session()
  local request
  request = self:send_opack("TVRCSessionStart", {
    ProtocolVersionKey = "1.2",
  }, 2, function(message)
    Log.debug("Companion TV RC session started")
    self:finish_tv_remote_control_session(message._x or request._x, "response")
  end, function(message)
    Log.debug("Companion TV RC session start failed; continuing startup")
    self:finish_tv_remote_control_session(message._x or request._x, "error")
  end)
  self.tv_rc_session_xid = request._x

  if has_c4() and type(SetTimer) == "function" then
    if C4Driver and C4Driver.cancel_timer then
      C4Driver.cancel_timer("AppleTV_tv_rc_session_start_timeout")
    end
    local ok, err = pcall(SetTimer, "AppleTV_tv_rc_session_start_timeout", 1500, function()
      self:finish_tv_remote_control_session(request._x, "timeout")
    end)
    if not ok then
      Log.debug("Companion TV RC session fallback timer unavailable: " .. tostring(err))
    end
  end
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
  self:mark_rx()
  self.buffer = self.buffer .. (data or "")
  enforce_buffer_limit(self, "buffer", Companion.receive_buffer_max, "Companion receive buffer")
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
    self.verifier = nil
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
  self:cleanup_pending_responses()
  local payload = Companion.encode_request_payload(request)
  local frame = self.session and self.session:encode_frame(CompanionFrame.E_OPACK, payload) or CompanionFrame.encode(CompanionFrame.E_OPACK, payload)
  if request._t == 2 then
    self.pending_responses[request._x] = {
      identifier = identifier,
      on_response = on_response,
      on_error = on_error,
      created_at_ms = self:now_ms(),
    }
  end
  self:send_raw(frame)
  return request, frame
end

function CompanionClient:cleanup_pending_responses(now_ms)
  now_ms = now_ms or self:now_ms()
  local timeout_ms = tonumber(self.response_timeout_ms) or 0
  if timeout_ms <= 0 then
    return 0
  end
  local expired = 0
  for xid, pending in pairs(self.pending_responses or {}) do
    local created_at = pending and pending.created_at_ms or now_ms
    if now_ms - created_at > timeout_ms then
      self.pending_responses[xid] = nil
      expired = expired + 1
      Log.debug("Companion pending response expired: xid=" .. tostring(xid) ..
        " identifier=" .. tostring(pending and pending.identifier))
    end
  end
  return expired
end

function CompanionClient:is_ready_for_commands()
  return self.state == "SESSION_ACTIVE" and self.session ~= nil
end

function CompanionClient:state_code()
  local state = tostring(self.state or "")
  return state:match("^([^:]+)") or state
end

function CompanionClient:needs_reconnect()
  local state = self:state_code()
  return state == "DISCONNECTED" or state == "ERROR"
end

function CompanionClient:queue_pending_command(item)
  self.pending_commands = self.pending_commands or {}
  if item.identifier == "_hidC" and type(item.content) == "table" then
    local hid_command = item.content._hidC
    local hid_state = item.content._hBtS
    if hid_command ~= nil and hid_state ~= nil then
      local removed = 0
      for i = #self.pending_commands, 1, -1 do
        local queued = self.pending_commands[i]
        local queued_content = queued and queued.content
        if queued and queued.identifier == "_hidC"
           and type(queued_content) == "table"
           and queued_content._hidC == hid_command
           and (queued_content._hBtS == hid_state or hid_state == 1)
        then
          table.remove(self.pending_commands, i)
          removed = removed + 1
        end
      end
      if removed > 0 then
        Log.debug("coalesced queued HID command: hid=" .. tostring(hid_command) ..
          " state=" .. tostring(hid_state) .. " removed=" .. tostring(removed))
      end
    end
  end
  self.pending_commands[#self.pending_commands + 1] = item
  local max = tonumber(Companion.pending_commands_max) or 0
  while max > 0 and #self.pending_commands > max do
    local dropped = table.remove(self.pending_commands, 1)
    Log.debug("dropped queued Companion request due to queue cap: " ..
      tostring(dropped and dropped.identifier or "unknown"))
  end
end

function CompanionClient:send_or_queue_opack(identifier, content, message_type, options)
  options = options or {}
  local request = Companion.build_request(identifier, content, message_type)
  Companion.record_sent_message(request)
  if self:is_ready_for_commands() then
    return self:send_opack(identifier, content, message_type, nil, nil, request)
  end
  Log.debug("queued Companion request until session active: " .. tostring(identifier))
  self:queue_pending_command({
    identifier = identifier,
    content = content,
    message_type = message_type,
    request = request,
    priority = options.priority == true,
  })
  if self:needs_reconnect() and not self.connecting then
    self:connect()
  end
  return request, nil
end

function CompanionClient:flush_pending_commands(options)
  options = options or {}
  if not self:is_ready_for_commands() then
    return
  end
  if #self.pending_commands == 0 then
    return
  end
  local queued = {}
  if options.priority_only then
    local remaining = {}
    for _, item in ipairs(self.pending_commands) do
      if item.priority then
        queued[#queued + 1] = item
      else
        remaining[#remaining + 1] = item
      end
    end
    self.pending_commands = remaining
  else
    queued = self.pending_commands
    self.pending_commands = {}
  end
  if #queued == 0 then
    return
  end
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

C4MiniApps = {
  PASSTHROUGH_PROXY = 5001,
  SWITCHER_PROXY = 5002,
  USES_DEDICATED_SWITCHER = true,
  MINIAPP_BINDING_START = 3101,
  MINIAPP_BINDING_END = 3125,
  MINIAPP_TYPE = "UM_APPLETV",
  aliases = {
    ["abC iView"] = "au.net.abc.ABCiView",
    ["amazon prime video"] = "com.amazon.aiv.AIVApp",
    ["apple tv"] = "com.apple.TVWatchList",
    ["apple tv+"] = "com.apple.TVWatchList",
    ["directv"] = "com.att.tv",
    ["disney plus"] = "com.disney.disneyplus",
    ["disney+"] = "com.disney.disneyplus",
    ["hbo max"] = "com.wbd.stream",
    ["hulu"] = "com.hulu.plus",
    ["max"] = "com.wbd.stream",
    ["pandora"] = "com.pandora",
    ["peacock"] = "com.peacocktv.peacock",
    ["peacock tv"] = "com.peacocktv.peacock",
    ["prime video"] = "com.amazon.aiv.AIVApp",
    ["tenplay"] = "com.networkten.epg",
    ["youtube"] = "com.google.ios.youtube",
  },
  bindings = {},
  pending_retry = nil,
  launch_retry_timer = "AppleTV_miniapp_launch_retry",
  launch_retry_delay_ms = 1500,
  launch_retry_window_ms = 5000,
  launch_debounce_ms = 1000,
  native_handoff_timer = "AppleTV_native_driver_handoff",
  native_handoff_delay_ms = 750,
  handoff_verify_delay_ms = 1000,
  active_handoff_timers = {},
  after_launch_property = "After Mini App Launch",
  native_driver_property = "Native Apple TV Driver",
  after_launch_return = "Return To This Driver",
  after_launch_native = "Select Native Apple TV Driver",
  native_driver_not_selected = "Not Selected",
  last_launch_id = nil,
  last_launch_at_ms = nil,
  power_off_debounce_ms = 1000,
  last_power_off_hid = nil,
  last_power_off_at_ms = nil,
  button_defaults = {
    MENU = "Home",
    GUIDE = "Menu",
    INFO = "Home",
    CANCEL = "Menu",
    OFF = "Do Nothing",
    RED = "Do Nothing",
    GREEN = "Do Nothing",
    YELLOW = "Do Nothing",
    BLUE = "Do Nothing",
  },
  button_properties = {
    OFF = "On Power Off",
    RED = "Red Button",
    GREEN = "Green Button",
    YELLOW = "Yellow Button",
    BLUE = "Blue Button",
  },
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
    return bound
  end

  if params then
    local service_id = params.SERVICE_ID or params.service_id or params.APP_ID or params.app_id
    local name = params.APP_NAME or params.app_name or params.NAME or params.name
    if service_id or name then
      return {
        service_id = service_id,
        name = name,
      }
    end
  end

  return nil
end

function C4MiniApps.alias_for(name)
  local normalized = Companion.normalize_app_name(name)
  if normalized == "" then return nil end
  for alias, bundle_id in pairs(C4MiniApps.aliases or {}) do
    if Companion.normalize_app_name(alias) == normalized then
      return bundle_id, alias
    end
  end
  if #normalized >= 4 then
    local fuzzy_match, fuzzy_alias
    for alias, bundle_id in pairs(C4MiniApps.aliases or {}) do
      local alias_norm = Companion.normalize_app_name(alias)
      if alias_norm:find(normalized, 1, true) or normalized:find(alias_norm, 1, true) then
        if fuzzy_match and fuzzy_match ~= bundle_id then
          return nil, nil, "multiple aliases match " .. tostring(name)
        end
        fuzzy_match = bundle_id
        fuzzy_alias = alias
      end
    end
    return fuzzy_match, fuzzy_alias
  end
  return nil
end

function C4MiniApps.resolve_launch_id(service)
  service = service or {}
  local service_id = service.service_id
  local name = service.name

  if Companion.looks_like_launch_identifier(service_id) then
    Log.debug("mini app provided launch id " .. tostring(service_id))
    return service_id
  end
  if Companion.looks_like_launch_identifier(name) then
    Log.debug("mini app provided launch id in name " .. tostring(name))
    return name
  end

  if service_id and service_id ~= "" and (not name or name == "") then
    name = service_id
    Log.debug("mini app service id appears to be app name: " .. tostring(service_id))
  end

  local dynamic_id, err = Companion.find_app_by_name(name)
  if dynamic_id then
    Log.debug("mini app resolved from app list: " .. tostring(name) .. " -> " .. tostring(dynamic_id))
    return dynamic_id
  end
  if err then
    Log.error("mini app app-list match failed: " .. tostring(err))
  end

  local alias_id, alias_name, alias_err = C4MiniApps.alias_for(name)
  if alias_id then
    Log.debug("mini app resolved from alias: " .. tostring(name) ..
      " -> " .. tostring(alias_name) .. " -> " .. tostring(alias_id))
    return alias_id
  end
  if alias_err then
    Log.error("mini app alias match failed: " .. tostring(alias_err))
  end

  return nil
end

function C4MiniApps.queue_retry(service, app_proxy_id)
  if not service or service._retried then
    return false
  end
  C4MiniApps.pending_retry = {
    service = {
      service_id = service.service_id,
      name = service.name,
      _retried = true,
    },
    app_proxy_id = app_proxy_id,
  }
  Log.debug("mini app unresolved; refreshing app list before retry: " ..
    tostring(service.name or service.service_id or "unknown"))
  if C4Driver and C4Driver.refresh_app_list then
    C4Driver.refresh_app_list()
    return true
  end
  return false
end

function C4MiniApps.now_ms()
  if C4Driver and C4Driver.now_ms then
    return C4Driver.now_ms()
  end
  return (os.time() or 0) * 1000
end

function C4MiniApps.is_duplicate_launch(launch_id)
  local now = C4MiniApps.now_ms()
  local last_at = C4MiniApps.last_launch_at_ms
  if C4MiniApps.last_launch_id == launch_id and last_at and
     (now - last_at) >= 0 and (now - last_at) < C4MiniApps.launch_debounce_ms
  then
    Log.debug("mini app duplicate launch suppressed " .. tostring(launch_id))
    return true
  end
  C4MiniApps.last_launch_id = launch_id
  C4MiniApps.last_launch_at_ms = now
  return false
end

function C4MiniApps.is_duplicate_power_off_action(hid)
  local now = C4MiniApps.now_ms()
  local last_at = C4MiniApps.last_power_off_at_ms
  if C4MiniApps.last_power_off_hid == hid and last_at and
     (now - last_at) >= 0 and (now - last_at) < C4MiniApps.power_off_debounce_ms
  then
    Log.debug("power-off duplicate action suppressed: " .. tostring(hid))
    return true
  end
  C4MiniApps.last_power_off_hid = hid
  C4MiniApps.last_power_off_at_ms = now
  return false
end

function C4MiniApps.native_driver_row(device_id, name)
  return tostring(name or ("Device " .. tostring(device_id))) .. " [" .. tostring(device_id) .. "]"
end

function C4MiniApps.parse_native_driver_selection(value)
  local text = tostring(value or "")
  if text == "" or text == C4MiniApps.native_driver_not_selected then
    return nil
  end
  local bracketed = text:match("%[(%d+)%]%s*$")
  return tonumber(bracketed or text)
end

function C4MiniApps.device_info_value(info, ...)
  if type(info) ~= "table" then
    return nil
  end
  for i = 1, select("#", ...) do
    local key = select(i, ...)
    local value = info[key]
    if value ~= nil and tostring(value) ~= "" then
      return value
    end
  end
  return nil
end

function C4MiniApps.same_device_id(left, right)
  local left_num = tonumber(left)
  local right_num = tonumber(right)
  if left_num and right_num then
    return left_num == right_num
  end
  return tostring(left) == tostring(right)
end

function C4MiniApps.device_display_name(device_id, info, fallback)
  local name = C4MiniApps.device_info_value(info, "name", "deviceName", "displayName", "device_display_name")
  if name then
    return tostring(name)
  end
  if has_c4() and C4.GetDeviceDisplayName then
    local ok, value = pcall(function() return C4:GetDeviceDisplayName(device_id) end)
    if ok and value and tostring(value) ~= "" then
      return tostring(value)
    end
  end
  return tostring(fallback or ("Device " .. tostring(device_id)))
end

function C4MiniApps.device_driver_filename(info)
  return tostring(C4MiniApps.device_info_value(info,
    "driverFileName", "driver_filename", "driverFilename", "filename", "fileName", "c4i", "driver") or "")
end

function C4MiniApps.normalized_driver_filename(filename)
  local text = tostring(filename or ""):gsub("\\", "/")
  local basename = text:match("([^/]+)$") or text
  return basename:lower()
end

function C4MiniApps.is_native_apple_tv_candidate(device_id, info, name)
  local own_id = has_c4() and C4.GetDeviceID and tonumber(C4:GetDeviceID()) or nil
  if own_id and tonumber(device_id) == own_id then
    return false
  end

  local driver_file = C4MiniApps.device_driver_filename(info)
  local driver_lower = C4MiniApps.normalized_driver_filename(driver_file)
  if driver_lower == "" then
    if tostring(name or ""):lower():find("apple", 1, true) then
      Log.debug("native Apple TV candidate skipped: no driver filename id=" ..
        tostring(device_id) .. " name=" .. tostring(name))
    end
    return false
  end
  if driver_lower:find("control4_apple_tv", 1, true) or driver_lower:find("app switcher", 1, true) then
    return false
  end
  return driver_lower == "appletv.c4z"
end

function C4MiniApps.refresh_native_apple_tv_drivers()
  local items = { C4MiniApps.native_driver_not_selected }
  if not (has_c4() and C4.GetDevices) then
    C4Driver.update_property_list(C4MiniApps.native_driver_property, items)
    Log.debug("native Apple TV driver list refresh skipped: C4.GetDevices unavailable")
    return items
  end

  local ok, devices = pcall(function() return C4:GetDevices({}) end)
  if not ok or type(devices) ~= "table" then
    C4Driver.update_property_list(C4MiniApps.native_driver_property, items)
    Log.error("native Apple TV driver list refresh failed: " .. tostring(devices))
    return items
  end

  local rows = {}
  for key, info in pairs(devices) do
    local device_id = tonumber(C4MiniApps.device_info_value(info, "id", "deviceId", "idDevice") or key)
    if device_id then
      local name = C4MiniApps.device_display_name(device_id, info, info)
      if C4MiniApps.is_native_apple_tv_candidate(device_id, info, name) then
        rows[#rows + 1] = {
          id = device_id,
          name = name,
          driver_file = C4MiniApps.device_driver_filename(info),
        }
      end
    end
  end

  table.sort(rows, function(a, b)
    return tostring(a.name):lower() < tostring(b.name):lower()
  end)

  for _, row in ipairs(rows) do
    items[#items + 1] = C4MiniApps.native_driver_row(row.id, row.name)
    Log.debug("native Apple TV driver candidate: id=" .. tostring(row.id) ..
      " name=" .. tostring(row.name) ..
      " driver=" .. tostring(row.driver_file))
  end

  C4Driver.update_property_list(C4MiniApps.native_driver_property, items)
  local selected = Properties and Properties[C4MiniApps.native_driver_property] or ""
  local selected_ok = selected == "" or selected == C4MiniApps.native_driver_not_selected
  for _, item in ipairs(items) do
    if selected == item then
      selected_ok = true
      break
    end
  end
  if not selected_ok then
    C4Driver.update_property(C4MiniApps.native_driver_property, C4MiniApps.native_driver_not_selected)
    Log.debug("native Apple TV driver selection reset; previous value no longer valid: " .. tostring(selected))
  end
  Log.debug("native Apple TV driver list refreshed: count=" .. tostring(#items - 1))
  return items
end

function C4MiniApps.select_native_apple_tv_after_launch(app_proxy_id)
  if not (has_c4() and C4.SendToDevice) then
    return false
  end
  if not app_proxy_id then
    Log.debug("mini app native handoff skipped: no app proxy id")
    return false
  end

  local selected = Properties and Properties[C4MiniApps.native_driver_property] or ""
  local native_device_id = C4MiniApps.parse_native_driver_selection(selected)
  if not native_device_id then
    Log.debug("mini app native handoff skipped: no native Apple TV driver selected")
    return false
  end
  local proxy_device_id = C4MiniApps.resolve_selectable_device_id(native_device_id)
  local passthrough_proxy_device_id = C4MiniApps.resolve_own_passthrough_device_id()
  local matched_rooms = {}

  for room_id, device_id in pairs(C4MiniApps.room_sources or {}) do
    if C4MiniApps.same_device_id(device_id, app_proxy_id) then
      matched_rooms[#matched_rooms + 1] = room_id
    end
  end
  if #matched_rooms == 0 then
    Log.debug("mini app native handoff found no room selected on app proxy " .. tostring(app_proxy_id))
    return false
  end

  for _, room_id in ipairs(matched_rooms) do
    local function reselect()
      C4MiniApps.active_handoff_timers[C4MiniApps.native_handoff_timer .. "_" .. tostring(room_id)] = nil
      local current_source = (C4MiniApps.room_sources or {})[room_id]
      local source_still_relevant = C4MiniApps.same_device_id(current_source, app_proxy_id) or
        (passthrough_proxy_device_id and C4MiniApps.same_device_id(current_source, passthrough_proxy_device_id))
      if not source_still_relevant then
        Log.debug("mini app native handoff skipped: room selection changed room=" ..
          tostring(room_id) .. " appProxy=" .. tostring(app_proxy_id) ..
          " current=" .. tostring(current_source))
        return
      end
      Log.debug("mini app native handoff selecting device " .. tostring(native_device_id) ..
        " in room " .. tostring(room_id) ..
        " nativeProxy=" .. tostring(proxy_device_id))
      C4:SendToDevice(room_id, "SELECT_VIDEO_DEVICE", {
        deviceid = native_device_id,
        DEVICE_ID = native_device_id,
      })
      C4MiniApps.verify_native_handoff(room_id, native_device_id, proxy_device_id)
    end

    if has_c4() and type(SetTimer) == "function" then
      local timer_name = C4MiniApps.native_handoff_timer .. "_" .. tostring(room_id)
      C4MiniApps.active_handoff_timers[timer_name] = true
      SetTimer(timer_name, C4MiniApps.native_handoff_delay_ms, reselect)
    else
      reselect()
    end
  end
  return true
end

function C4MiniApps.resolve_own_passthrough_device_id()
  if has_c4() and C4.GetBoundConsumerDevices and C4.GetDeviceID then
    local ok, consumers = pcall(function()
      return C4:GetBoundConsumerDevices(C4:GetDeviceID(), C4MiniApps.PASSTHROUGH_PROXY)
    end)
    if ok then
      local proxy_device_id = next(consumers or {})
      if proxy_device_id then
        return tonumber(proxy_device_id) or proxy_device_id
      end
    end
  end
  return nil
end

function C4MiniApps.resolve_selectable_device_id(driver_device_id)
  if has_c4() and C4.GetBoundConsumerDevices then
    local ok, consumers = pcall(function()
      return C4:GetBoundConsumerDevices(driver_device_id, C4MiniApps.PASSTHROUGH_PROXY)
    end)
    if ok then
      local proxy_device_id = next(consumers or {})
      if proxy_device_id then
        Log.debug("native Apple TV driver proxy resolved: driver=" ..
          tostring(driver_device_id) .. " proxy=" .. tostring(proxy_device_id))
        return tonumber(proxy_device_id) or proxy_device_id
      end
    else
      Log.debug("native Apple TV driver proxy lookup failed: driver=" ..
        tostring(driver_device_id) .. " err=" .. tostring(consumers))
    end
  end
  return driver_device_id
end

function C4MiniApps.verify_native_handoff(room_id, native_device_id, proxy_device_id)
  if not (has_c4() and C4.GetDeviceVariable) then
    return
  end

  local function verify()
    local ok, value = pcall(function()
      return C4:GetDeviceVariable(room_id, 1000)
    end)
    local selected = ok and tonumber(value) or nil
    if C4MiniApps.same_device_id(selected, native_device_id) then
      Log.debug("mini app native handoff verified: room=" .. tostring(room_id) ..
        " selected=" .. tostring(selected))
      return
    end
    if proxy_device_id and C4MiniApps.same_device_id(selected, proxy_device_id) then
      Log.debug("mini app native handoff verified via proxy: room=" .. tostring(room_id) ..
        " selected=" .. tostring(selected) ..
        " nativeDriver=" .. tostring(native_device_id))
      return
    end
    if proxy_device_id and not C4MiniApps.same_device_id(proxy_device_id, native_device_id)
        and has_c4() and C4.SendToDevice
    then
      Log.debug("mini app native handoff falling back to proxy " .. tostring(proxy_device_id) ..
        " in room " .. tostring(room_id) ..
        " nativeDriver=" .. tostring(native_device_id) ..
        " current=" .. tostring(value))
      C4:SendToDevice(room_id, "SELECT_VIDEO_DEVICE", {
        deviceid = proxy_device_id,
        DEVICE_ID = proxy_device_id,
      })
      C4MiniApps.verify_room_selection(room_id, proxy_device_id, "native handoff proxy fallback")
      return
    end
    Log.error("mini app native handoff did not select expected device: room=" ..
      tostring(room_id) ..
      " expected=" .. tostring(native_device_id) ..
      " proxy=" .. tostring(proxy_device_id) ..
      " actual=" .. tostring(value))
  end

  if has_c4() and type(SetTimer) == "function" then
    SetTimer("AppleTV_verify_native_handoff_" .. tostring(room_id),
      C4MiniApps.handoff_verify_delay_ms, verify)
  else
    verify()
  end
end

function C4MiniApps.verify_room_selection(room_id, expected_device_id, reason)
  if not (has_c4() and C4.GetDeviceVariable) then
    return
  end

  local function verify()
    local ok, value = pcall(function()
      return C4:GetDeviceVariable(room_id, 1000)
    end)
    local selected = ok and tonumber(value) or nil
    if selected == tonumber(expected_device_id) then
      Log.debug("mini app " .. tostring(reason or "handoff") ..
        " verified: room=" .. tostring(room_id) ..
        " selected=" .. tostring(selected))
    else
      Log.error("mini app " .. tostring(reason or "handoff") ..
        " did not select expected device: room=" .. tostring(room_id) ..
        " expected=" .. tostring(expected_device_id) ..
        " actual=" .. tostring(value))
    end
  end

  if has_c4() and type(SetTimer) == "function" then
    SetTimer("AppleTV_verify_handoff_" .. tostring(room_id),
      C4MiniApps.handoff_verify_delay_ms, verify)
  else
    verify()
  end
end

function C4MiniApps.after_launch_selection(app_proxy_id)
  if (Properties and Properties[C4MiniApps.after_launch_property] or C4MiniApps.after_launch_return) == C4MiniApps.after_launch_native then
    if C4MiniApps.select_native_apple_tv_after_launch(app_proxy_id) then
      return
    end
  end
  C4MiniApps.reselect_passthrough_if_needed(app_proxy_id)
end

function C4MiniApps.is_startup_launch_window()
  local client = Companion.client
  if not client then
    return false
  end
  if client.startup_in_progress then
    return true
  end
  local active_since = client.session_active_since_ms
  if not active_since then
    return false
  end
  local age = C4MiniApps.now_ms() - active_since
  return age >= 0 and age <= C4MiniApps.launch_retry_window_ms
end

function C4MiniApps.cancel_launch_retry()
  if C4Driver and C4Driver.cancel_timer then
    C4Driver.cancel_timer(C4MiniApps.launch_retry_timer)
  end
  C4MiniApps.pending_launch_retry_id = nil
end

function C4MiniApps.schedule_launch_retry(launch_id)
  if not C4MiniApps.is_startup_launch_window() then
    return false
  end
  if not (has_c4() and type(SetTimer) == "function") then
    return false
  end
  C4MiniApps.cancel_launch_retry()
  C4MiniApps.pending_launch_retry_id = launch_id
  local ok, err = pcall(SetTimer, C4MiniApps.launch_retry_timer, C4MiniApps.launch_retry_delay_ms, function()
    if C4MiniApps.pending_launch_retry_id ~= launch_id then
      return
    end
    C4MiniApps.pending_launch_retry_id = nil
    Log.debug("retry mini app launch after startup " .. tostring(launch_id))
    C4Driver.launch_app(launch_id)
  end)
  if not ok then
    C4MiniApps.pending_launch_retry_id = nil
    Log.debug("mini app launch retry timer unavailable: " .. tostring(err))
    return false
  end
  Log.debug("scheduled mini app launch retry " .. tostring(launch_id) ..
    " in " .. tostring(C4MiniApps.launch_retry_delay_ms) .. "ms")
  return true
end

function C4MiniApps.request_launch_retry(launch_id)
  if C4MiniApps.schedule_launch_retry(launch_id) then
    return true
  end
  C4MiniApps.pending_launch_retry_id = launch_id
  Log.debug("pending mini app launch retry after startup " .. tostring(launch_id))
  return false
end

function C4MiniApps.schedule_pending_launch_retry()
  local launch_id = C4MiniApps.pending_launch_retry_id
  if not launch_id then
    return false
  end
  return C4MiniApps.schedule_launch_retry(launch_id)
end

function C4MiniApps.launch_service(service, app_proxy_id, options)
  options = options or {}
  local launch_id = C4MiniApps.resolve_launch_id(service)
  if launch_id then
    if C4MiniApps.is_duplicate_launch(launch_id) then
      C4MiniApps.after_launch_selection(app_proxy_id)
      return nil
    end
    if C4MiniApps.pending_launch_retry_id and C4MiniApps.pending_launch_retry_id ~= launch_id then
      C4MiniApps.cancel_launch_retry()
    end
    Log.debug("launch mini app " .. launch_id)
    local request, frame = C4Driver.launch_app(launch_id)
    if not options.retry then
      C4MiniApps.request_launch_retry(launch_id)
    end
    C4MiniApps.after_launch_selection(app_proxy_id)
    return request, frame
  end
  if C4MiniApps.queue_retry(service, app_proxy_id) then
    return nil
  end
  Log.error("mini app selected without a resolvable Apple TV app id: " ..
    tostring(service and (service.name or service.service_id) or "unknown"))
  return nil
end

function C4MiniApps.retry_pending_launch()
  local pending = C4MiniApps.pending_retry
  if not pending then
    return
  end
  C4MiniApps.pending_retry = nil
  Log.debug("retrying pending mini app launch after app list refresh")
  C4MiniApps.launch_service(pending.service, pending.app_proxy_id)
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

function C4MiniApps.resolve_miniapp_service(binding_id, params)
  local bound = C4MiniApps.resolve_bound_minidriver(binding_id)
  local configured = C4MiniApps.resolve(binding_id, params)
  if not configured then
    return bound
  end
  if bound and bound.app_proxy_id then
    configured.app_proxy_id = configured.app_proxy_id or bound.app_proxy_id
    configured.app_device_id = configured.app_device_id or bound.app_device_id
  end
  return configured
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
  if not (has_c4() and C4.GetBoundConsumerDevices and C4.SendToDevice) then
    return
  end

  local passthrough_proxy_device_id = C4MiniApps.resolve_own_passthrough_device_id()
  if not passthrough_proxy_device_id then
    return
  end

  local function reselect()
    for room_id, device_id in pairs(C4MiniApps.room_sources or {}) do
      if device_id == app_proxy_id then
        C4:SendToDevice(room_id, "SELECT_VIDEO_DEVICE", {
          deviceid = passthrough_proxy_device_id,
          DEVICE_ID = passthrough_proxy_device_id,
        })
        C4MiniApps.verify_room_selection(room_id, passthrough_proxy_device_id, "return to this driver")
      end
    end
  end

  if has_c4() and type(SetTimer) == "function" then
    SetTimer("AppleTV_reselect_passthrough", 500, reselect)
  else
    reselect()
  end
end

function C4MiniApps.normalize_proxy_button(command, params)
  params = params or {}
  local action = params.ACTION or params.action or params.INPUT_ACTION or params.input_action
  if command:match("^START_") then
    action = "down"
    command = command:gsub("^START_", "")
  elseif command:match("^STOP_") then
    action = "up"
    command = command:gsub("^STOP_", "")
  elseif command:match("^END_") then
    action = "up"
    command = command:gsub("^END_", "")
  elseif params.BEGIN then
    action = "down"
  elseif params.DURATION then
    action = "up"
  end
  return command, action
end

function C4MiniApps.mapped_button_action(command, action)
  local property_name = C4MiniApps.button_properties[command] or (command .. " Button")
  local configured = Properties and Properties[property_name] or nil
  configured = configured or C4MiniApps.button_defaults[command]
  if not configured or configured == "" then
    return nil, nil, false
  end
  if configured == "Do Nothing" then
    return nil, nil, true
  end

  local mapped = {
    ["Home"] = { "HOME", nil },
    ["TV/Home"] = { "HOME", nil },
    ["Menu"] = { "MENU", nil },
    ["Back"] = { "MENU", nil },
    ["Guide"] = { "GUIDE", nil },
    ["Select"] = { "SELECT", nil },
    ["Play/Pause"] = { "PLAY_PAUSE", nil },
    ["Up"] = { "UP", nil },
    ["Down"] = { "DOWN", nil },
    ["Left"] = { "LEFT", nil },
    ["Right"] = { "RIGHT", nil },
  }
  local entry = mapped[configured]
  if not entry then
    Log.error("unknown " .. property_name .. " mapping: " .. tostring(configured))
    return nil, nil, true
  end
  return entry[1], action or entry[2], true
end

function C4MiniApps.handle_proxy_command(binding_id, command, params)
  if binding_id == nil or command == nil then
    return nil
  end

  params = params or {}

  if command == "BINDING_CHANGE_ACTION" or command == "CONNECT_OUTPUT" then
    return nil
  end

  if binding_id == C4MiniApps.SWITCHER_PROXY and command == "PASSTHROUGH" then
    binding_id = C4MiniApps.PASSTHROUGH_PROXY
    command = params.PASSTHROUGH_COMMAND
  end
  command, params._resolved_action = C4MiniApps.normalize_proxy_button(tostring(command or ""), params)

  if binding_id == C4MiniApps.SWITCHER_PROXY and command == "SET_INPUT" then
    local input = tonumber(params.INPUT)
    if input and C4MiniApps.is_binding(input) then
      local service = C4MiniApps.resolve_bound_minidriver(input) or C4MiniApps.bindings[input]
      if service then
        return C4MiniApps.launch_service(service, service.app_proxy_id)
      end
      Log.error("mini app selected without a " .. C4MiniApps.MINIAPP_TYPE .. " service id on input " .. tostring(input))
      return nil
    end
  end

  if C4MiniApps.is_binding(binding_id) then
    local service = C4MiniApps.resolve_miniapp_service(binding_id, params)
    if service then
      return C4MiniApps.launch_service(service, service.app_proxy_id)
    end
    Log.error("mini app selected without a service id on binding " .. tostring(binding_id))
    return nil
  end

  -- Power: ON scopes the metadata monitor to active room use.
  if command == "ON" then
    if not Companion.client or Companion.client.state == "DISCONNECTED" then
      C4Driver.connect_companion()
    end
    C4Driver.ensure_airplay_monitor_for_room("room on")
    return
  end
  if command == "OFF" then
    local mapped_hid, mapped_action, handled_mapping = C4MiniApps.mapped_button_action(command, params._resolved_action)
    if handled_mapping and mapped_hid then
      if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
        C4Driver.ensure_companion_client()
      end
      if not C4MiniApps.is_duplicate_power_off_action(mapped_hid) then
        Log.debug("power-off action queued: " .. tostring(mapped_hid))
        Companion.button_action(mapped_hid, mapped_action, { priority = true })
      end
    end
    C4Driver.stop_airplay_monitor("room off")
    return
  end

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

  local action = params._resolved_action

  local mapped_hid, mapped_action, handled_mapping = C4MiniApps.mapped_button_action(command, action)
  if handled_mapping then
    if mapped_hid then
      if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
        C4Driver.ensure_companion_client()
      end
      C4Driver.ensure_airplay_monitor_for_room("remote command")
      return Companion.button_action(mapped_hid, mapped_action)
    end
    return nil
  end

  local hid = remote_command[command]
  if hid then
    if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
      C4Driver.ensure_companion_client()
    end
    C4Driver.ensure_airplay_monitor_for_room("remote command")
    return Companion.button_action(hid, action)
  end

  Log.debug("unhandled proxy command " .. tostring(command))
  return nil
end

local AirPlayControlClient = {}
local AirPlayEventChannelClient = {}
local AirPlayDataChannelClient = {}

local PB = {}

function PB.varint(value)
  assert(type(value) == "number" and value >= 0, "protobuf varint must be unsigned")
  local out = {}
  repeat
    local byte = value % 128
    value = math.floor(value / 128)
    if value > 0 then byte = byte + 128 end
    out[#out + 1] = string.char(byte)
  until value == 0
  return table.concat(out)
end

function PB.key(field, wire_type)
  return PB.varint(field * 8 + wire_type)
end

function PB.field_varint(field, value)
  return PB.key(field, 0) .. PB.varint(value)
end

function PB.field_string(field, value)
  value = tostring(value or "")
  return PB.key(field, 2) .. PB.varint(#value) .. value
end

function PB.field_message(field, value)
  return PB.key(field, 2) .. PB.varint(#value) .. value
end

local _PB_POW2 = {}
for _i = 0, 63, 7 do _PB_POW2[_i] = 2 ^ _i end

function PB.read_varint(data, index)
  local shift = 0
  local value = 0
  while true do
    local b = data:byte(index)
    assert(b, "truncated protobuf varint")
    index = index + 1
    value = value + (b % 128) * _PB_POW2[shift]
    if b < 128 then
      return value, index
    end
    shift = shift + 7
    assert(shift <= 63, "protobuf varint too large")
  end
end

function PB.describe(data)
  local parts = {}
  local index = 1
  while index <= #data and #parts < 10 do
    local ok, key_or_err = pcall(PB.read_varint, data, index)
    if not ok then break end
    local key
    key, index = PB.read_varint(data, index)
    local field = math.floor(key / 8)
    local wire = key % 8
    if wire == 0 then
      local value
      value, index = PB.read_varint(data, index)
      parts[#parts + 1] = tostring(field) .. "=" .. tostring(value)
    elseif wire == 2 then
      local length
      length, index = PB.read_varint(data, index)
      local value = data:sub(index, index + length - 1)
      index = index + length
      local printable = value:gsub("[^%g ]", ".")
      if #printable > 48 then printable = printable:sub(1, 48) .. "..." end
      parts[#parts + 1] = tostring(field) .. "=\"" .. printable .. "\""
    else
      parts[#parts + 1] = tostring(field) .. "(wire=" .. tostring(wire) .. ")"
      break
    end
  end
  return table.concat(parts, " ")
end

local PB_MESSAGE_TYPES = {
  [1] = "SEND_COMMAND_MESSAGE",
  [2] = "SEND_COMMAND_RESULT_MESSAGE",
  [3] = "GET_STATE_MESSAGE",
  [4] = "SET_STATE_MESSAGE",
  [15] = "DEVICE_INFO_MESSAGE",
  [16] = "CLIENT_UPDATES_CONFIG_MESSAGE",
  [23] = "KEYBOARD_MESSAGE",
  [24] = "GET_KEYBOARD_SESSION_MESSAGE",
  [32] = "PLAYBACK_QUEUE_REQUEST_MESSAGE",
  [38] = "SET_CONNECTION_STATE_MESSAGE",
  [46] = "SET_NOW_PLAYING_CLIENT_MESSAGE",
  [47] = "SET_NOW_PLAYING_PLAYER_MESSAGE",
  [55] = "UPDATE_CLIENT_MESSAGE",
  [58] = "UPDATE_PLAYER_MESSAGE",
  [65] = "UPDATE_OUTPUT_DEVICE_MESSAGE",
  [72] = "SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE",
}

function PB.scan(data)
  local fields = {}
  local index = 1
  while index <= #data do
    local key
    key, index = PB.read_varint(data, index)
    local field = math.floor(key / 8)
    local wire = key % 8
    local value
    if wire == 0 then
      value, index = PB.read_varint(data, index)
    elseif wire == 1 then
      value = data:sub(index, index + 7)
      index = index + 8
    elseif wire == 2 then
      local length
      length, index = PB.read_varint(data, index)
      value = data:sub(index, index + length - 1)
      index = index + length
    elseif wire == 5 then
      value = data:sub(index, index + 3)
      index = index + 4
    else
      error("unsupported protobuf wire type " .. tostring(wire))
    end
    fields[#fields + 1] = { field = field, wire = wire, value = value }
  end
  return fields
end

function PB.first_field(data, field, wire)
  local ok, fields = pcall(PB.scan, data)
  if not ok then return nil end
  for _, item in ipairs(fields) do
    if item.field == field and (wire == nil or item.wire == wire) then
      return item.value
    end
  end
  return nil
end

function PB.string_field(data, field)
  return PB.first_field(data, field, 2)
end

function PB.varint_field(data, field)
  return PB.first_field(data, field, 0)
end

function PB.bool_text(value)
  if value == nil then return nil end
  return value == 0 and "false" or "true"
end

function PB.summarize_now_playing_client(data)
  if not data then return nil end
  local parts = {}
  local bundle = PB.string_field(data, 2)
  local parent = PB.string_field(data, 3)
  local display = PB.string_field(data, 7)
  if bundle then parts[#parts + 1] = "bundle=" .. bundle end
  if display then parts[#parts + 1] = "name=" .. display end
  if parent then parts[#parts + 1] = "parent=" .. parent end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.summarize_now_playing_player(data)
  if not data then return nil end
  local parts = {}
  local identifier = PB.string_field(data, 1)
  local display = PB.string_field(data, 2)
  local default = PB.bool_text(PB.varint_field(data, 3))
  if identifier then parts[#parts + 1] = "player=" .. identifier end
  if display then parts[#parts + 1] = "player_name=" .. display end
  if default then parts[#parts + 1] = "default=" .. default end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.summarize_player_path(data)
  if not data then return nil end
  local parts = {}
  local client = PB.summarize_now_playing_client(PB.first_field(data, 2, 2))
  local player = PB.summarize_now_playing_player(PB.first_field(data, 3, 2))
  if client then parts[#parts + 1] = client end
  if player then parts[#parts + 1] = player end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.summarize_content_metadata(data)
  if not data then return nil end
  local parts = {}
  local title = PB.string_field(data, 1)
  local subtitle = PB.string_field(data, 2)
  local album = PB.string_field(data, 6)
  local artist = PB.string_field(data, 7)
  local series = PB.string_field(data, 63)
  local service = PB.string_field(data, 76)
  if title then parts[#parts + 1] = "title=" .. title end
  if subtitle then parts[#parts + 1] = "subtitle=" .. subtitle end
  if artist then parts[#parts + 1] = "artist=" .. artist end
  if album then parts[#parts + 1] = "album=" .. album end
  if series then parts[#parts + 1] = "series=" .. series end
  if service then parts[#parts + 1] = "service=" .. service end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.summarize_now_playing_info(data)
  if not data then return nil end
  local parts = {}
  local album = PB.string_field(data, 1)
  local artist = PB.string_field(data, 2)
  local title = PB.string_field(data, 9)
  if title then parts[#parts + 1] = "title=" .. title end
  if artist then parts[#parts + 1] = "artist=" .. artist end
  if album then parts[#parts + 1] = "album=" .. album end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.copy_content_metadata(data, target)
  if not data or type(target) ~= "table" then return end
  local title = PB.string_field(data, 1)
  local album = PB.string_field(data, 6)
  local artist = PB.string_field(data, 7)
  if title and title ~= "" then target.title = title end
  if artist and artist ~= "" then target.artist = artist end
  if album and album ~= "" then target.album = album end
end

function PB.copy_playback_queue_metadata(data, target)
  if not data or type(target) ~= "table" then return end
  local ok, fields = pcall(PB.scan, data)
  if not ok then return end
  for _, item in ipairs(fields) do
    if item.field == 2 and item.wire == 2 then
      PB.copy_content_metadata(PB.first_field(item.value, 2, 2), target)
      if target.title or target.artist or target.album then
        return
      end
    end
  end
end

function PB.summarize_playback_queue(data)
  if not data then return nil end
  local parts = {}
  local location = PB.varint_field(data, 1)
  if location then parts[#parts + 1] = "location=" .. tostring(location) end
  local ok, fields = pcall(PB.scan, data)
  if ok then
    for _, item in ipairs(fields) do
      if item.field == 2 and item.wire == 2 then
        local item_id = PB.string_field(item.value, 1)
        local metadata = PB.summarize_content_metadata(PB.first_field(item.value, 2, 2))
        if item_id or metadata then
          local item_parts = {}
          if item_id then item_parts[#item_parts + 1] = "id=" .. item_id end
          if metadata then item_parts[#item_parts + 1] = metadata end
          parts[#parts + 1] = "item={" .. table.concat(item_parts, " ") .. "}"
          break
        end
      end
    end
  end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.summarize_state_like(data)
  if not data then return nil end
  local parts = {}
  local metadata = PB.summarize_content_metadata(PB.first_field(data, 1, 2))
  local queue = PB.summarize_playback_queue(PB.first_field(data, 3, 2))
  local display_id = PB.string_field(data, 4)
  local display_name = PB.string_field(data, 5)
  local state = PB.varint_field(data, 6)
  local path = PB.summarize_player_path(PB.first_field(data, 9, 2))
  if display_id then parts[#parts + 1] = "display_id=" .. display_id end
  if display_name then parts[#parts + 1] = "display=" .. display_name end
  if state then parts[#parts + 1] = "playback_state=" .. tostring(state) end
  if path then parts[#parts + 1] = "path={" .. path .. "}" end
  if metadata then parts[#parts + 1] = "metadata={" .. metadata .. "}" end
  if queue then parts[#parts + 1] = "queue={" .. queue .. "}" end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.summarize_device_info(data)
  if not data then return nil end
  local parts = {}
  local name = PB.string_field(data, 2)
  local model = PB.string_field(data, 3)
  local build = PB.string_field(data, 4)
  local app = PB.string_field(data, 5)
  local media_app = PB.string_field(data, 12)
  if name then parts[#parts + 1] = "name=" .. name end
  if model then parts[#parts + 1] = "model=" .. model end
  if build then parts[#parts + 1] = "build=" .. build end
  if app then parts[#parts + 1] = "app=" .. app end
  if media_app then parts[#parts + 1] = "media_app=" .. media_app end
  return #parts > 0 and table.concat(parts, " ") or nil
end

function PB.describe_protocol_message(data)
  local message_type = PB.varint_field(data, 1)
  local type_name = PB_MESSAGE_TYPES[message_type] or ("TYPE_" .. tostring(message_type))
  local parts = { type_name }
  local identifier = PB.string_field(data, 2)
  local error_code = PB.varint_field(data, 4)
  if identifier then parts[#parts + 1] = "id=" .. identifier end
  if error_code and error_code ~= 0 then parts[#parts + 1] = "error=" .. tostring(error_code) end

  local summary
  if message_type == 4 then
    summary = PB.summarize_state_like(PB.first_field(data, 9, 2))
  elseif message_type == 15 then
    summary = PB.summarize_device_info(PB.first_field(data, 20, 2))
  elseif message_type == 46 or message_type == 55 then
    local inner = PB.first_field(data, message_type == 46 and 50 or 59, 2)
    summary = PB.summarize_now_playing_client(PB.first_field(inner or "", 1, 2))
  elseif message_type == 47 or message_type == 58 then
    local inner = PB.first_field(data, message_type == 47 and 51 or 62, 2)
    summary = PB.summarize_player_path(PB.first_field(inner or "", 1, 2))
  elseif message_type == 72 then
    summary = PB.summarize_state_like(PB.first_field(data, 75, 2))
  end
  if summary then parts[#parts + 1] = summary end
  return table.concat(parts, " ")
end

function PB.extract_protocol_update(data)
  local message_type = PB.varint_field(data, 1)
  local update = {}

  local function copy_client(client)
    if not client then return end
    local bundle = PB.string_field(client, 2)
    local name = PB.string_field(client, 7)
    if bundle and bundle ~= "" then update.app_bundle = bundle end
    if name and name ~= "" then update.app_name = name end
  end

  local function copy_now_playing_info(info)
    if not info then return end
    local album = PB.string_field(info, 1)
    local artist = PB.string_field(info, 2)
    local title = PB.string_field(info, 9)
    if title and title ~= "" then update.title = title end
    if artist and artist ~= "" then update.artist = artist end
    if album and album ~= "" then update.album = album end
  end

  local function copy_state_like(state)
    if not state then return end
    copy_now_playing_info(PB.first_field(state, 1, 2))
    if not (update.title or update.artist or update.album) then
      PB.copy_playback_queue_metadata(PB.first_field(state, 3, 2), update)
    end
    local playback_state = PB.varint_field(state, 6)
    if playback_state ~= nil then update.playback_state = playback_state end
    local path = PB.first_field(state, 9, 2)
    if path then
      copy_client(PB.first_field(path, 2, 2))
    end
  end

  if message_type == 4 then
    copy_state_like(PB.first_field(data, 9, 2))
  elseif message_type == 46 or message_type == 55 then
    local inner = PB.first_field(data, message_type == 46 and 50 or 59, 2)
    copy_client(PB.first_field(inner or "", 1, 2))
  elseif message_type == 72 then
    copy_state_like(PB.first_field(data, 75, 2))
  end

  update.message_type = message_type
  if update.app_bundle or update.app_name or update.title or update.artist or update.album or update.playback_state ~= nil then
    return update
  end
  return nil
end

function PB.uuid(crypto)
  crypto = crypto or Crypto
  local h = Bytes.hex(crypto_method(crypto, "random_bytes")(16))
  return string.upper(h:sub(1, 8) .. "-" ..
    h:sub(9, 12) .. "-" ..
    h:sub(13, 16) .. "-" ..
    h:sub(17, 20) .. "-" ..
    h:sub(21, 32))
end

function PB.protocol_message(message_type, extension_field, extension_body, crypto, identifier)
  crypto = crypto or Crypto
  local out = {
    PB.field_varint(1, message_type),
    PB.field_varint(4, 0),
    PB.field_string(85, PB.uuid(crypto)),
  }
  if identifier then
    table.insert(out, 2, PB.field_string(2, identifier))
  end
  if extension_field and extension_body then
    out[#out + 1] = PB.field_message(extension_field, extension_body)
  end
  return table.concat(out)
end

function PB.device_info(client_id, crypto, identifier)
  local info = table.concat({
    PB.field_string(1, tostring(client_id or "Control4")),
    PB.field_string(2, "Control4"),
    PB.field_string(3, "iPhone"),
    PB.field_string(4, "20A"),
    PB.field_string(5, "com.apple.TVRemote"),
    PB.field_string(6, "344.28"),
    PB.field_varint(7, 1),
    PB.field_varint(8, 108),
    PB.field_varint(9, 1),
    PB.field_varint(10, 1),
    PB.field_string(12, "com.apple.TVMusic"),
    PB.field_varint(13, 1),
    PB.field_varint(14, 1),
    PB.field_varint(15, 1),
    PB.field_varint(17, 2),
    PB.field_varint(21, 1),
    PB.field_varint(22, 1),
  })
  return PB.protocol_message(15, 20, info, crypto, identifier)
end

function PB.set_connection_state(crypto)
  return PB.protocol_message(38, 42, PB.field_varint(1, 2), crypto)
end

function PB.client_updates_config(crypto, identifier)
  local config = table.concat({
    PB.field_varint(1, 1),
    PB.field_varint(2, 0),
    PB.field_varint(3, 1),
    PB.field_varint(4, 1),
    PB.field_varint(5, 1),
  })
  return PB.protocol_message(16, 21, config, crypto, identifier)
end

function PB.get_keyboard_session(crypto, identifier)
  return PB.protocol_message(24, nil, nil, crypto, identifier)
end

local DATA_HEADER_LENGTH = 32

function AirPlayDataChannelClient.new(options)
  options = options or {}
  return setmetatable({
    host = options.host,
    port = options.port,
    session = HAPSession.new(options.output_key, options.input_key, options.crypto or Crypto),
    crypto = options.crypto or Crypto,
    transport = options.transport,
    buffer = "",
    send_seqno = 0x100000000 + 1,
    client_id = options.client_id,
    startup_stage = "idle",
    on_connected = options.on_connected,
    on_activity = options.on_activity,
    on_error = options.on_error,
  }, { __index = AirPlayDataChannelClient })
end

function AirPlayDataChannelClient:connect()
  assert(type(self.host) == "string" and self.host ~= "", "AirPlay data host is required")
  assert(type(self.port) == "number", "AirPlay data port is required")
  self.closed = false

  if self.transport then
    if self.on_connected then self.on_connected(self) end
    return self
  end

  assert(has_c4() and C4.CreateTCPClient, "Control4 TCP client is not available")
  Log.debug("AirPlay data channel TCP connect requested: host=" .. tostring(self.host) ..
    " port=" .. tostring(self.port))
  local client
  client = C4:CreateTCPClient()
    :OnConnect(function(tcp_client)
      Log.debug("AirPlay data channel TCP connected")
      self.transport = tcp_client
      if self.on_connected then self.on_connected(self) end
      self:send_bootstrap()
      tcp_client:ReadUpTo(4096)
    end)
    :OnRead(function(tcp_client, data)
      Log.debug("AirPlay data channel TCP read: bytes=" .. tostring(#(data or "")))
      if self.on_activity then self.on_activity("read") end
      local ok, err = pcall(function() self:receive(data or "") end)
      if not ok then
        Log.error("AirPlay data channel receive failed: " .. tostring(err))
        if self.on_error then self.on_error(err) end
        self:close()
        return
      end
      tcp_client:ReadUpTo(4096)
    end)
    :OnDisconnect(function(_, err_code, err_msg)
      Log.debug("AirPlay data channel TCP disconnected: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      local on_error = self.on_error
      if not self.closed and on_error then on_error(err_msg or err_code or "disconnect") end
      if not self.closed then self:release_runtime_state(true) end
    end)
    :OnError(function(_, err_code, err_msg)
      Log.error("AirPlay data channel TCP error: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      local on_error = self.on_error
      if on_error then on_error(err_msg or err_code) end
      self:release_runtime_state(true)
    end)
    :Connect(self.host, self.port)
  self.transport = client
  return self
end

function AirPlayDataChannelClient:encode_message(message_type, command, seqno, payload)
  payload = payload or ""
  message_type = message_type .. string.rep("\0", math.max(0, 12 - #message_type))
  command = command .. string.rep("\0", math.max(0, 4 - #command))
  local seqno_bytes
  if type(seqno) == "string" then
    assert(#seqno == 8, "AirPlay data channel seqno bytes must be 8 bytes")
    seqno_bytes = seqno
  else
    seqno_bytes = Bytes.uint_be(seqno, 8)
  end
  local size = DATA_HEADER_LENGTH + #payload
  return Bytes.uint_be(size, 4) ..
    message_type:sub(1, 12) ..
    command:sub(1, 4) ..
    seqno_bytes ..
    Bytes.uint_be(0, 4) ..
    payload
end

function AirPlayDataChannelClient:send_payload(plist_payload)
  assert(self.transport, "AirPlay data channel is not connected")
  local frame = self:encode_message("sync", "comm", self.send_seqno, BPlist.encode(plist_payload))
  Log.debug("AirPlay data channel send frame: seqno=" .. tostring(self.send_seqno) ..
    " payload_len=" .. tostring(#frame - DATA_HEADER_LENGTH))
  self.send_seqno = self.send_seqno + 1
  return self.transport:Write(self.session:encrypt(frame))
end

function AirPlayDataChannelClient:send_protobuf(message)
  local payload = PB.varint(#message) .. message
  return self:send_payload({ params = { data = BPlist.bytes(payload) } })
end

function AirPlayDataChannelClient:send_bootstrap()
  local device_info_id = PB.uuid(self.crypto)
  self.startup_stage = "device_info_sent"
  Log.debug("AirPlay data channel bootstrap: sending MRP device info")
  self:send_protobuf(PB.device_info(self.client_id, self.crypto, device_info_id))
end

function AirPlayDataChannelClient:send_post_device_info_bootstrap()
  if self.startup_stage == "post_device_info_sent" then
    return
  end
  self.startup_stage = "post_device_info_sent"
  local updates_id = PB.uuid(self.crypto)
  local keyboard_id = PB.uuid(self.crypto)
  Log.debug("AirPlay data channel bootstrap: sending MRP connection state")
  self:send_protobuf(PB.set_connection_state(self.crypto))
  Log.debug("AirPlay data channel bootstrap: sending MRP client updates config")
  self:send_protobuf(PB.client_updates_config(self.crypto, updates_id))
  Log.debug("AirPlay data channel bootstrap: sending MRP keyboard session request")
  self:send_protobuf(PB.get_keyboard_session(self.crypto, keyboard_id))
end

function AirPlayDataChannelClient:send_heartbeat()
  Log.debug("AirPlay data channel heartbeat: sending MRP connection state")
  return self:send_protobuf(PB.set_connection_state(self.crypto))
end

function AirPlayDataChannelClient:send_reply(seqno)
  assert(self.transport, "AirPlay data channel is not connected")
  local frame = self:encode_message("rply", "\0\0\0\0", seqno, "")
  local seqno_log = type(seqno) == "string" and Bytes.hex(seqno) or tostring(seqno)
  Log.debug("AirPlay data channel send reply: seqno=" .. seqno_log)
  return self.transport:Write(self.session:encrypt(frame))
end

function AirPlayDataChannelClient:receive(data)
  local plaintext = self.session:decrypt(data)
  if plaintext == "" then return end
  self.buffer = self.buffer .. plaintext
  enforce_buffer_limit(self, "buffer", AirPlay.receive_buffer_max, "AirPlay data channel buffer")

  while #self.buffer >= DATA_HEADER_LENGTH do
    local size = Bytes.read_uint_be(self.buffer, 1, 4)
    if size < DATA_HEADER_LENGTH then
      local err = "AirPlay data channel invalid frame size=" .. tostring(size)
      Log.error(err .. ", closing")
      self.buffer = ""
      if self.on_error then self.on_error(err) end
      self:close()
      return
    end
    if #self.buffer < size then
      return
    end
    local frame = self.buffer:sub(1, size)
    self.buffer = self.buffer:sub(size + 1)
    local message_type = frame:sub(5, 16):gsub("%z+$", "")
    local command = frame:sub(17, 20):gsub("%z+$", "")
    local seqno_bytes = frame:sub(21, 28)
    local seqno = Bytes.read_uint_be(frame, 21, 8)
    local payload = frame:sub(DATA_HEADER_LENGTH + 1)
    self:handle_payload(message_type, seqno_bytes, payload)
  end
end

function AirPlayDataChannelClient:handle_payload(message_type, seqno, payload)
  if payload ~= "" then
    local ok, decoded = pcall(BPlist.decode, payload)
    if ok and type(decoded) == "table" then
      local data = decoded.params and decoded.params.data
      if type(data) == "table" and data.__bplist_type == "bytes" then
        local description = ""
        local ok_desc, value_or_err, next_index = pcall(PB.read_varint, data.data, 1)
        if ok_desc and value_or_err and next_index then
          local raw_message = data.data:sub(next_index, next_index + value_or_err - 1)
          local ok_protocol, protocol_description = pcall(PB.describe_protocol_message, raw_message)
          description = ok_protocol and protocol_description or PB.describe(raw_message)
          local ok_update, update = pcall(PB.extract_protocol_update, raw_message)
          if ok_update and update and C4Driver and C4Driver.handle_airplay_mrp_update then
            C4Driver.handle_airplay_mrp_update(update)
          end
          if PB.varint_field(raw_message, 1) == 15 then
            self:send_post_device_info_bootstrap()
          end
        end
        if description ~= "" and not description:match("^UPDATE_OUTPUT_DEVICE_MESSAGE") then
          Log.debug("AirPlay MRP: " .. description)
        end
      end
    end
  end
  if message_type == "sync" then
    self:send_reply(seqno)
  end
end

function AirPlayDataChannelClient:release_runtime_state(clear_callbacks)
  self.buffer = ""
  if self.session then
    self.session.encrypted_buffer = ""
  end
  self.session = nil
  self.transport = nil
  self.startup_stage = "closed"
  if clear_callbacks then
    self.on_connected = nil
    self.on_activity = nil
    self.on_error = nil
    self.crypto = nil
    self.client_id = nil
  end
end

function AirPlayDataChannelClient:close()
  self.closed = true
  if self.transport and self.transport.Close then
    self.transport:Close()
  elseif self.transport and self.transport.close then
    self.transport:close()
  end
  self:release_runtime_state(true)
end

function AirPlayEventChannelClient.new(options)
  options = options or {}
  return setmetatable({
    host = options.host,
    port = options.port,
    session = HAPSession.new(options.output_key, options.input_key, options.crypto or Crypto),
    transport = options.transport,
    buffer = "",
    closed = false,
    on_connected = options.on_connected,
    on_error = options.on_error,
  }, { __index = AirPlayEventChannelClient })
end

function AirPlayEventChannelClient:connect()
  assert(type(self.host) == "string" and self.host ~= "", "AirPlay event host is required")
  assert(type(self.port) == "number", "AirPlay event port is required")
  self.closed = false

  if self.transport then
    if self.on_connected then self.on_connected(self) end
    return self
  end

  assert(has_c4() and C4.CreateTCPClient, "Control4 TCP client is not available")
  Log.debug("AirPlay event channel TCP connect requested: host=" .. tostring(self.host) ..
    " port=" .. tostring(self.port))
  local client
  client = C4:CreateTCPClient()
    :OnConnect(function(tcp_client)
      Log.debug("AirPlay event channel TCP connected")
      self.transport = tcp_client
      if self.on_connected then self.on_connected(self) end
      tcp_client:ReadUpTo(4096)
    end)
    :OnRead(function(tcp_client, data)
      Log.debug("AirPlay event channel TCP read: bytes=" .. tostring(#(data or "")))
      local ok, err = pcall(function() self:receive(data or "") end)
      if not ok then
        Log.error("AirPlay event channel receive failed: " .. tostring(err))
        if self.on_error then self.on_error(err) end
        self:close()
        return
      end
      tcp_client:ReadUpTo(4096)
    end)
    :OnDisconnect(function(_, err_code, err_msg)
      Log.debug("AirPlay event channel TCP disconnected: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      local on_error = self.on_error
      if not self.closed and on_error then on_error(err_msg or err_code) end
      if not self.closed then self:release_runtime_state(true) end
    end)
    :OnError(function(_, err_code, err_msg)
      if self.closed then return end
      Log.error("AirPlay event channel TCP error: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      local on_error = self.on_error
      if on_error then on_error(err_msg or err_code) end
      self:release_runtime_state(true)
    end)
    :Connect(self.host, self.port)
  self.transport = client
  return self
end

function AirPlayEventChannelClient:send_response(cseq, server)
  if not self.transport then return nil end
  local headers = {
    ["Content-Length"] = "0",
    ["Audio-Latency"] = "0",
  }
  if cseq then headers["CSeq"] = tostring(cseq) end
  if server then headers["Server"] = tostring(server) end
  local response = AirPlayHTTP.format_response(200, "OK", headers, "", "RTSP/1.0")
  Log.debug("AirPlay event channel send response: cseq=" .. tostring(cseq))
  return self.transport:Write(self.session:encrypt(response))
end

function AirPlayEventChannelClient:receive(data)
  local plaintext = self.session:decrypt(data)
  if plaintext == "" then return end
  self.buffer = self.buffer .. plaintext
  enforce_buffer_limit(self, "buffer", AirPlay.receive_buffer_max, "AirPlay event channel buffer")

  while true do
    local request, rest = AirPlayHTTP.try_parse_request(self.buffer)
    if not request then
      if rest ~= nil then self.buffer = rest end
      return
    end
    self.buffer = rest
    Log.debug("AirPlay event channel request: method=" .. tostring(request.method) ..
      " path=" .. tostring(request.path) ..
      " cseq=" .. tostring(request.headers.CSeq or request.headers.cseq) ..
      " body_len=" .. tostring(#(request.body or "")))
    self:send_response(request.headers.CSeq or request.headers.cseq, request.headers.Server or request.headers.server)
  end
end

function AirPlayEventChannelClient:release_runtime_state(clear_callbacks)
  self.buffer = ""
  if self.session then
    self.session.encrypted_buffer = ""
  end
  self.session = nil
  self.transport = nil
  if clear_callbacks then
    self.on_connected = nil
    self.on_error = nil
  end
end

function AirPlayEventChannelClient:close()
  self.closed = true
  if self.transport and self.transport.Close then
    self.transport:Close()
  elseif self.transport and self.transport.close then
    self.transport:close()
  end
  self:release_runtime_state(true)
end

function AirPlayControlClient.new(options)
  options = options or {}
  return setmetatable({
    host = options.host,
    port = options.port or 7000,
    credentials = options.credentials,
    crypto = options.crypto or Crypto,
    transport = options.transport,
    verifier = nil,
    session = nil,
    raw_buffer = "",
    http_buffer = "",
    connecting = false,
    connected = false,
    closed = false,
    state = "DISCONNECTED",
    probe = options.probe or "info",
    rtsp_cseq = 0,
    rtsp_session_id = nil,
    rtsp_dacp_id = nil,
    rtsp_active_remote = nil,
    event_port = nil,
    data_port = nil,
    data_seed = nil,
    event_channel = nil,
    data_channel = nil,
    on_info = options.on_info,
    on_tunnel_setup = options.on_tunnel_setup,
    on_activity = options.on_activity,
    on_error = options.on_error,
    on_disconnect = options.on_disconnect,
    on_state = options.on_state,
  }, { __index = AirPlayControlClient })
end

function AirPlayControlClient:set_state(state)
  if self.state ~= state then
    Log.debug("AirPlay control state: " .. tostring(self.state) .. " -> " .. tostring(state))
    self.state = state
  end
  if self.on_state then
    self.on_state(state)
  end
end

function AirPlayControlClient:send_plain(method, path, body, headers)
  local request = AirPlayHTTP.format_request(method, path, self.host, self.port, headers, body, "HTTP/1.1")
  Log.debug("AirPlay control send plain: " .. tostring(method) .. " " .. tostring(path) ..
    " body_len=" .. tostring(#(body or "")))
  return self.transport:Write(request)
end

function AirPlayControlClient:send_encrypted(method, path, body, headers)
  assert(self.session, "AirPlay encrypted session is not ready")
  local request = AirPlayHTTP.format_request(method, path, self.host, self.port, headers, body, "HTTP/1.1")
  Log.debug("AirPlay control send encrypted: " .. tostring(method) .. " " .. tostring(path) ..
    " plain_len=" .. tostring(#request))
  return self.transport:Write(self.session:encrypt(request))
end

function AirPlayControlClient:random_u32()
  local bytes = crypto_method(self.crypto, "random_bytes")(4)
  return Bytes.read_uint_be(bytes, 1, 4)
end

function AirPlayControlClient:random_hex(bytes)
  return string.upper(Bytes.hex(crypto_method(self.crypto, "random_bytes")(bytes)))
end

function AirPlayControlClient:uuid()
  local h = Bytes.hex(crypto_method(self.crypto, "random_bytes")(16))
  return string.upper(h:sub(1, 8) .. "-" ..
    h:sub(9, 12) .. "-" ..
    h:sub(13, 16) .. "-" ..
    h:sub(17, 20) .. "-" ..
    h:sub(21, 32))
end

function AirPlayControlClient:rtsp_uri()
  if not self.rtsp_session_id then
    self.rtsp_session_id = self:random_u32()
  end
  return "rtsp://" .. tostring(self.host) .. "/" .. tostring(self.rtsp_session_id)
end

function AirPlayControlClient:send_rtsp(method, body, headers)
  self.rtsp_cseq = self.rtsp_cseq + 1
  self.rtsp_dacp_id = self.rtsp_dacp_id or self:random_hex(8)
  self.rtsp_active_remote = self.rtsp_active_remote or self:random_u32()

  headers = headers or {}
  headers["CSeq"] = tostring(self.rtsp_cseq)
  headers["DACP-ID"] = self.rtsp_dacp_id
  headers["Active-Remote"] = tostring(self.rtsp_active_remote)
  headers["Client-Instance"] = self.rtsp_dacp_id
  if body and body ~= "" then
    headers["Content-Type"] = headers["Content-Type"] or "application/x-apple-binary-plist"
  end

  local uri = self:rtsp_uri()
  local request = AirPlayHTTP.format_request(method, uri, self.host, self.port, headers, body or "", "RTSP/1.0")
  Log.debug("AirPlay RTSP send: method=" .. tostring(method) ..
    " cseq=" .. tostring(self.rtsp_cseq) ..
    " body_len=" .. tostring(#(body or "")))
  return self.transport:Write(self.session:encrypt(request))
end

function AirPlayControlClient:build_event_setup_plist()
  local txt = AirPlay.txt or {}
  return BPlist.encode({
    isRemoteControlOnly = true,
    osName = "tvOS",
    sourceVersion = "550.10",
    timingProtocol = "None",
    model = txt.model or "AppleTV",
    deviceID = txt.deviceid or txt.deviceID or "",
    osVersion = txt.osvers or "",
    osBuildVersion = txt.osbuild or "",
    macAddress = txt.deviceid or "",
    sessionUUID = self:uuid(),
    name = "Control4",
  })
end

function AirPlayControlClient:build_data_setup_plist()
  self.data_seed = self:random_u32()
  return BPlist.encode({
    streams = {
      {
        controlType = 2,
        channelID = self:uuid(),
        seed = self.data_seed,
        clientUUID = self:uuid(),
        type = 130,
        wantsDedicatedSocket = true,
        clientTypeUUID = "1910A70F-DBC0-4242-AF95-115DB30604E1",
      },
    },
  })
end

function AirPlayControlClient:derive_channel_key(salt, info)
  assert(self.verifier and self.verifier.shared_secret, "AirPlay Pair-Verify shared secret is not available")
  return crypto_method(self.crypto, "hkdf_sha512")(salt, info, self.verifier.shared_secret)
end

function AirPlayControlClient:open_event_channel()
  assert(self.event_port, "AirPlay event port is required")
  local output_key = self:derive_channel_key("Events-Salt", "Events-Read-Encryption-Key")
  local input_key = self:derive_channel_key("Events-Salt", "Events-Write-Encryption-Key")
  self.event_channel = AirPlayEventChannelClient.new({
    host = self.host,
    port = self.event_port,
    output_key = output_key,
    input_key = input_key,
    crypto = self.crypto,
    on_connected = function()
      self:set_state("RTSP_RECORD")
      self:send_rtsp("RECORD", "")
    end,
    on_error = function(err)
      if self.on_error then self.on_error(err) end
    end,
  })
  return self.event_channel:connect()
end

function AirPlayControlClient:open_data_channel()
  assert(self.data_port, "AirPlay data port is required")
  assert(self.data_seed, "AirPlay data seed is required")
  local output_key = self:derive_channel_key("DataStream-Salt" .. tostring(self.data_seed), "DataStream-Output-Encryption-Key")
  local input_key = self:derive_channel_key("DataStream-Salt" .. tostring(self.data_seed), "DataStream-Input-Encryption-Key")
  self.data_channel = AirPlayDataChannelClient.new({
    host = self.host,
    port = self.data_port,
    output_key = output_key,
    input_key = input_key,
    crypto = self.crypto,
    client_id = self.credentials and self.credentials.client_id,
    on_connected = function()
      self:set_state("DATA_CHANNEL_ACTIVE")
      if self.on_tunnel_setup then
        self.on_tunnel_setup({
          event_port = self.event_port,
          data_port = self.data_port,
          seed = self.data_seed,
        })
      end
    end,
    on_activity = function(reason)
      if self.on_activity then self.on_activity(reason) end
    end,
    on_error = function(err)
      if self.on_error then self.on_error(err) end
    end,
  })
  return self.data_channel:connect()
end

function AirPlayControlClient:connect(host, port)
  self.host = host or self.host
  self.port = port or self.port or 7000
  assert(type(self.host) == "string" and self.host ~= "", "Apple TV address is required")
  assert(self.credentials and self.credentials.type == "HAP", "AirPlay HAP credentials are required")
  self.closed = false

  if self.connecting then
    Log.debug("AirPlay control TCP connect already in progress")
    return self
  end
  if self.connected and self.transport then
    Log.debug("AirPlay control TCP already connected")
    return self
  end
  if self.transport then
    self:on_connected(self.transport)
    return self
  end

  assert(has_c4() and C4.CreateTCPClient, "Control4 TCP client is not available")
  Log.debug("AirPlay control TCP connect requested: host=" .. tostring(self.host) ..
    " port=" .. tostring(self.port))
  local client
  self.connecting = true
  client = C4:CreateTCPClient()
    :OnConnect(function(tcp_client)
      Log.debug("AirPlay control TCP connected")
      self:on_connected(tcp_client)
      tcp_client:ReadUpTo(4096)
    end)
    :OnRead(function(tcp_client, data)
      Log.debug("AirPlay control TCP read: bytes=" .. tostring(#(data or "")))
      local ok, err = pcall(function() self:receive(data or "") end)
      if not ok then
        Log.error("AirPlay control receive failed: " .. tostring(err))
        self:set_state("ERROR: " .. tostring(err))
        if self.on_error then self.on_error(err) end
        self:close()
        return
      end
      tcp_client:ReadUpTo(4096)
    end)
    :OnDisconnect(function(_, err_code, err_msg)
      Log.debug("AirPlay control TCP disconnected: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      self.connecting = false
      self.connected = false
      self:set_state("DISCONNECTED")
      local on_disconnect = self.on_disconnect
      if not self.closed and on_disconnect then on_disconnect(err_msg or err_code) end
      if not self.closed then self:release_runtime_state(false) end
    end)
    :OnError(function(_, err_code, err_msg)
      if self.closed then return end
      Log.error("AirPlay control TCP error: code=" .. tostring(err_code) ..
        " message=" .. tostring(err_msg))
      self.transport = nil
      self.connecting = false
      self.connected = false
      self:set_state("ERROR: " .. tostring(err_code) .. " " .. tostring(err_msg))
      local on_error = self.on_error
      if on_error then on_error(err_msg or err_code) end
      self:close()
    end)
    :Connect(self.host, self.port)
  self.transport = client
  return self
end

function AirPlayControlClient:release_runtime_state(clear_callbacks)
  if self.event_channel and self.event_channel.close then
    self.event_channel:close()
  end
  self.event_channel = nil
  if self.data_channel and self.data_channel.close then
    self.data_channel:close()
  end
  self.data_channel = nil
  self.raw_buffer = ""
  self.http_buffer = ""
  self.verifier = nil
  if self.session then
    self.session.encrypted_buffer = ""
  end
  self.session = nil
  self.transport = nil
  self.connecting = false
  self.connected = false
  self.rtsp_session_id = nil
  self.rtsp_dacp_id = nil
  self.rtsp_active_remote = nil
  self.event_port = nil
  self.data_port = nil
  self.data_seed = nil
  self.pending_control_keys = nil
  if clear_callbacks then
    self.on_info = nil
    self.on_tunnel_setup = nil
    self.on_activity = nil
    self.on_error = nil
    self.on_disconnect = nil
    self.on_state = nil
    self.credentials = nil
    self.crypto = nil
  end
end

function AirPlayControlClient:close()
  self.closed = true
  if self.transport and self.transport.Close then
    self.transport:Close()
  elseif self.transport and self.transport.close then
    self.transport:close()
  end
  self:release_runtime_state(true)
end

function AirPlayControlClient:on_connected(transport)
  self.transport = transport
  self.connecting = false
  self.connected = true
  self:set_state("PAIR_VERIFY_M1")
  self.verifier = PairVerify.new(self.credentials, self.crypto)
  self:send_plain("POST", "/pair-verify", self.verifier:start_hap(), {
    ["User-Agent"] = "AirPlay/550.10",
    ["X-Apple-HKP"] = "3",
    ["Content-Type"] = "application/octet-stream",
  })
end

function AirPlayControlClient:receive(data)
  if self.session then
    local plaintext = self.session:decrypt(data)
    if plaintext ~= "" then
      self.http_buffer = self.http_buffer .. plaintext
      enforce_buffer_limit(self, "http_buffer", AirPlay.receive_buffer_max, "AirPlay control HTTP buffer")
      self:process_http_buffer(true)
    end
    return
  end

  self.raw_buffer = self.raw_buffer .. data
  enforce_buffer_limit(self, "raw_buffer", AirPlay.receive_buffer_max, "AirPlay control raw buffer")
  self:process_http_buffer(false)
end

function AirPlayControlClient:process_http_buffer(encrypted)
  local buffer_name = encrypted and "http_buffer" or "raw_buffer"
  while true do
    local response, rest = AirPlayHTTP.try_parse_response(self[buffer_name])
    if not response then
      if rest ~= nil then self[buffer_name] = rest end
      return
    end
    self[buffer_name] = rest
    if encrypted then
      self:handle_encrypted_response(response)
    else
      self:handle_plain_response(response)
    end
  end
end

function AirPlayControlClient:handle_plain_response(response)
  if self.state == "PAIR_VERIFY_M1" then
    Log.debug("AirPlay control Pair-Verify M2 response: code=" .. tostring(response.status) ..
      " body_len=" .. tostring(#response.body) ..
      " body_head=" .. Bytes.hex(response.body:sub(1, 32)))
    assert(response.status >= 200 and response.status < 300, "AirPlay Pair-Verify M2 HTTP " .. tostring(response.status))
    local next_body, keys = self.verifier:finish_hap(response.body)
    self.pending_control_keys = keys
    self:set_state("PAIR_VERIFY_M3")
    self:send_plain("POST", "/pair-verify", next_body, {
      ["User-Agent"] = "AirPlay/550.10",
      ["X-Apple-HKP"] = "3",
      ["Content-Type"] = "application/octet-stream",
    })
    return
  end

  if self.state == "PAIR_VERIFY_M3" then
    Log.debug("AirPlay control Pair-Verify M4 response: code=" .. tostring(response.status) ..
      " body_len=" .. tostring(#response.body) ..
      " body_head=" .. Bytes.hex(response.body:sub(1, 32)))
    assert(response.status >= 200 and response.status < 300, "AirPlay Pair-Verify M4 HTTP " .. tostring(response.status))
    self.session = HAPSession.new(self.pending_control_keys.output_key, self.pending_control_keys.input_key, self.crypto)
    if self.probe == "tunnel_setup" then
      self:set_state("RTSP_EVENT_SETUP")
      self:send_rtsp("SETUP", self:build_event_setup_plist())
    else
      self:set_state("ENCRYPTED_INFO")
      self:send_encrypted("GET", "/info", "", {
        ["User-Agent"] = "AirPlay/550.10",
        ["Accept"] = "application/x-apple-binary-plist",
      })
    end
    return
  end

  Log.debug("AirPlay control unexpected plain response: code=" .. tostring(response.status))
end

function AirPlayControlClient:handle_encrypted_response(response)
  if self.state == "RTSP_EVENT_SETUP" then
    Log.debug("AirPlay RTSP event SETUP response: code=" .. tostring(response.status) ..
      " body_len=" .. tostring(#response.body) ..
      " body_head=" .. Bytes.hex(response.body:sub(1, 32)))
    assert(response.status >= 200 and response.status < 300, "AirPlay event SETUP HTTP " .. tostring(response.status))
    local body = BPlist.decode(response.body)
    self.event_port = body.eventPort or body.event_port
    Log.debug("AirPlay RTSP event channel discovered: eventPort=" .. tostring(self.event_port))
    self:set_state("EVENT_CHANNEL_CONNECTING")
    self:open_event_channel()
    return
  end

  if self.state == "RTSP_RECORD" then
    Log.debug("AirPlay RTSP RECORD response: code=" .. tostring(response.status) ..
      " body_len=" .. tostring(#response.body))
    assert(response.status >= 200 and response.status < 300, "AirPlay RECORD HTTP " .. tostring(response.status))
    self:set_state("RTSP_DATA_SETUP")
    self:send_rtsp("SETUP", self:build_data_setup_plist())
    return
  end

  if self.state == "RTSP_DATA_SETUP" then
    Log.debug("AirPlay RTSP data SETUP response: code=" .. tostring(response.status) ..
      " body_len=" .. tostring(#response.body) ..
      " body_head=" .. Bytes.hex(response.body:sub(1, 32)))
    assert(response.status >= 200 and response.status < 300, "AirPlay data SETUP HTTP " .. tostring(response.status))
    local body = BPlist.decode(response.body)
    local stream = body.streams and body.streams[1] or {}
    self.data_port = stream.dataPort or stream.data_port
    Log.debug("AirPlay RTSP data channel discovered: dataPort=" .. tostring(self.data_port) ..
      " seed=" .. tostring(self.data_seed))
    self:set_state("DATA_CHANNEL_CONNECTING")
    self:open_data_channel()
    return
  end

  if self.state == "ENCRYPTED_INFO" then
    Log.debug("AirPlay encrypted /info response: code=" .. tostring(response.status) ..
      " content_type=" .. tostring(response.headers["content-type"] or response.headers["Content-Type"] or "") ..
      " body_len=" .. tostring(#response.body) ..
      " body_head=" .. Bytes.hex(response.body:sub(1, 32)))
    self:set_state("ENCRYPTED_INFO_COMPLETE")
    if self.on_info then
      self.on_info(response)
    end
    return
  end

  Log.debug("AirPlay control unexpected encrypted response in state=" .. tostring(self.state) ..
    " code=" .. tostring(response.status))
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
    local ok, err = pcall(UpdateProperty, name, str_value)
    if not ok then
      Log.debug("UpdateProperty failed for " .. tostring(name) .. ": " .. tostring(err))
    end
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

function C4Driver.now_ms()
  if has_c4() and C4.GetTime then
    local ok, value = pcall(function() return C4:GetTime() end)
    if ok and type(value) == "number" then
      return value
    end
  end
  return (os.time() or 0) * 1000
end

function C4Driver.set_connection_state(value)
  C4Driver.set_companion_state(value)
end

function C4Driver.set_companion_state(value)
  Companion.state = value
  C4Driver.update_property("Connection State", value)
end

function C4Driver.set_airplay_monitor_state(value)
  AirPlay.monitor_state = value
end

function C4Driver.publish_current_app()
  C4Driver.update_property("Current App", Companion.render_current_app(Companion.current_app))
end

function C4Driver.publish_now_playing()
  C4Driver.update_property("Now Playing", Companion.render_now_playing(Companion.now_playing))
end

function C4Driver.publish_app_list()
  local rows = Companion.app_list_rows or {}
  C4Driver.update_property_list("Launch App", Companion.app_selector_items(rows))
end

function C4Driver.print_app_list()
  local rows = Companion.app_list_rows or {}
  if #rows == 0 then
    Log.output("App List: empty. Run Refresh App List first.")
    return false, "app list is empty"
  end
  Log.output("App List (" .. tostring(#rows) .. " apps)")
  for _, row in ipairs(rows) do
    Log.output("  " .. tostring(row.name or row.identifier or "") ..
      " | " .. tostring(row.identifier or ""))
  end
  return true
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
    C4MiniApps.retry_pending_launch()
  end
  if changed.current_app then
    C4Driver.publish_current_app()
  end
  if changed.now_playing then
    C4Driver.publish_now_playing()
  end
end

function C4Driver.handle_airplay_mrp_update(update)
  if type(update) ~= "table" then
    return
  end
  if update.app_bundle or update.app_name then
    local identifier = update.app_bundle or update.app_name
    local changed_app = not Companion.current_app or Companion.current_app.identifier ~= identifier
    Companion.current_app = {
      identifier = identifier,
      name = Companion.app_name_for_bundle(identifier) or update.app_name or identifier,
    }
    C4Driver.publish_current_app()
    if changed_app and not (update.title or update.artist or update.album) then
      Companion.now_playing = {}
      C4Driver.publish_now_playing()
    end
  end
  if update.title or update.artist or update.album then
    Companion.now_playing = {
      title = update.title,
      artist = update.artist,
      album = update.album,
    }
    C4Driver.publish_now_playing()
  end
end

function C4Driver.launch_app(bundle_id_or_url)
  if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
    C4Driver.ensure_companion_client()
  end
  C4Driver.ensure_airplay_monitor_for_room("launch app")
  local request, frame = Companion.launch_app(bundle_id_or_url)
  C4Driver.publish_current_app()
  return request, frame
end

function C4Driver.refresh_app_list()
  if Companion.credentials or (Driver.state and Driver.state.companion_credentials) then
    C4Driver.ensure_companion_client()
  end
  C4Driver.ensure_airplay_monitor_for_room("refresh app list")
  return Companion.fetch_apps()
end

function C4Driver.airplay_post(path, body, callback)
  local host = Properties and Properties["Apple TV Address"]
  local port = AirPlay.port or 7000
  local url = "http://" .. tostring(host) .. ":" .. tostring(port) .. tostring(path)
  if not (has_c4() and C4.urlPost) then
    Log.error("AirPlay HTTP POST requires Control4 HTTP client")
    return nil, "Control4 HTTP client unavailable"
  end
  local headers = {
    ["User-Agent"] = "AirPlay/320.20",
    ["Connection"] = "keep-alive",
    ["X-Apple-HKP"] = "3",
    ["Content-Type"] = "application/octet-stream",
  }
  return C4:urlPost(url, body or "", headers, false, callback)
end

function C4Driver.schedule_airplay_monitor_retry(reason)
  if not AirPlay.monitor_enabled then return end
  C4Driver.cancel_timer("AppleTV_airplay_monitor_watchdog")
  if not (has_c4() and type(SetTimer) == "function") then return end
  C4Driver.cancel_timer("AppleTV_airplay_monitor_retry")
  Log.debug("AirPlay monitor retry scheduled: " .. tostring(reason or "unknown") ..
    " in " .. tostring(AirPlay.monitor_retry_ms) .. "ms")
  local ok, err = pcall(SetTimer, "AppleTV_airplay_monitor_retry", AirPlay.monitor_retry_ms, function()
    if AirPlay.monitor_enabled then
      C4Driver.start_airplay_monitor("retry")
    end
  end)
  if not ok then
    Log.debug("AirPlay monitor retry timer unavailable: " .. tostring(err))
  end
end

function C4Driver.ensure_airplay_monitor_for_room(reason)
  if AirPlay.monitor_enabled then
    return
  end
  if not (AirPlay.credentials or (Driver.state and Driver.state.airplay_credentials)) then
    return
  end
  C4Driver.schedule_airplay_monitor_start(reason or "room active")
end

function C4Driver.mark_airplay_monitor_activity(reason)
  AirPlay.monitor_last_activity_ms = C4Driver.now_ms()
  if AirPlay.monitor_state ~= "ACTIVE" then
    C4Driver.set_airplay_monitor_state("ACTIVE")
  end
  if reason and reason ~= "" and reason ~= "read" then
    Log.debug("AirPlay monitor activity: " .. tostring(reason))
  end
end

function C4Driver.schedule_airplay_monitor_watchdog()
  if not AirPlay.monitor_enabled then return end
  if not (has_c4() and type(SetTimer) == "function") then return end
  C4Driver.cancel_timer("AppleTV_airplay_monitor_watchdog")
  local ok, err = pcall(SetTimer, "AppleTV_airplay_monitor_watchdog", AirPlay.monitor_heartbeat_ms, function()
    C4Driver.check_airplay_monitor_watchdog()
  end)
  if not ok then
    Log.debug("AirPlay monitor watchdog timer unavailable: " .. tostring(err))
  end
end

function C4Driver.check_airplay_monitor_watchdog()
  if not AirPlay.monitor_enabled then return end
  local client = AirPlay.control_client
  local data_channel = client and client.data_channel
  if not data_channel or not data_channel.transport then
    C4Driver.set_airplay_monitor_state("STALE")
    C4Driver.close_airplay_control_client("AirPlay monitor watchdog missing data channel")
    C4Driver.schedule_airplay_monitor_retry("watchdog missing data channel")
    return
  end

  local last_activity = AirPlay.monitor_last_activity_ms or 0
  local age = C4Driver.now_ms() - last_activity
  if last_activity > 0 and age > AirPlay.monitor_stale_ms then
    C4Driver.set_airplay_monitor_state("STALE")
    C4Driver.close_airplay_control_client("AirPlay monitor watchdog stale")
    C4Driver.schedule_airplay_monitor_retry("watchdog stale")
    return
  end

  local ok, err = pcall(function() data_channel:send_heartbeat() end)
  if not ok then
    C4Driver.set_airplay_monitor_state("FAILED")
    C4Driver.close_airplay_control_client("AirPlay monitor heartbeat failed")
    C4Driver.schedule_airplay_monitor_retry(err or "heartbeat failed")
    return
  end
  C4Driver.schedule_airplay_monitor_watchdog()
end

function C4Driver.start_airplay_monitor(reason)
  C4Driver.ensure_crypto_provider()
  local host = Properties and Properties["Apple TV Address"]
  if not host or host == "" then
    Log.error("Apple TV Address is required")
    return nil, "Apple TV Address is required"
  end

  local credentials = AirPlay.credentials or (Driver.state and Driver.state.airplay_credentials and Credentials.parse(Driver.state.airplay_credentials))
  if not credentials or credentials.type ~= "HAP" then
    Log.debug("AirPlay monitor skipped: AirPlay HAP credentials are not available")
    return nil, "AirPlay HAP credentials are required"
  end

  AirPlay.monitor_enabled = true
  C4Driver.cancel_timer("AppleTV_airplay_monitor_retry")
  C4Driver.cancel_timer("AppleTV_airplay_monitor_watchdog")

  local function start_monitor(port)
    C4Driver.close_airplay_control_client("starting AirPlay monitor")
    AirPlay.port = port or AirPlay.port or 7000
    AirPlay.monitor_last_activity_ms = C4Driver.now_ms()
    C4Driver.set_airplay_monitor_state("CONNECTING")
    AirPlay.control_client = AirPlayControlClient.new({
      host = host,
      port = AirPlay.port,
      credentials = credentials,
      crypto = Crypto,
      probe = "tunnel_setup",
      on_tunnel_setup = function(result)
        if result and result.data_port then
          Log.debug("AirPlay monitor active: dataPort=" .. tostring(result.data_port))
          C4Driver.mark_airplay_monitor_activity("tunnel ready")
          C4Driver.schedule_airplay_monitor_watchdog()
        else
          Log.debug("AirPlay monitor setup incomplete")
          C4Driver.set_airplay_monitor_state("SETUP_INCOMPLETE")
          C4Driver.schedule_airplay_monitor_retry("setup incomplete")
        end
      end,
      on_activity = function(activity_reason)
        C4Driver.mark_airplay_monitor_activity(activity_reason)
      end,
      on_disconnect = function(err)
        C4Driver.set_airplay_monitor_state("DISCONNECTED")
        C4Driver.schedule_airplay_monitor_retry(err or "disconnect")
      end,
      on_error = function(err)
        C4Driver.set_airplay_monitor_state("FAILED")
        C4Driver.schedule_airplay_monitor_retry(err or "error")
      end,
    })
    Log.debug("AirPlay monitor starting" .. (reason and (": " .. tostring(reason)) or ""))
    return AirPlay.control_client:connect(host, AirPlay.port)
  end

  if AirPlay.port then
    return start_monitor(AirPlay.port)
  end

  Log.debug("AirPlay monitor waiting for AirPlay port discovery")
  C4Driver.set_airplay_monitor_state("DISCOVERING")
  return MDNS.discover_airplay_info(host, function(info)
    if info and info.port then
      AirPlay.port = info.port
      AirPlay.txt = info.txt or {}
      start_monitor(info.port)
    else
      Log.debug("AirPlay monitor skipped: AirPlay service not discovered")
      C4Driver.set_airplay_monitor_state("NOT_FOUND")
      C4Driver.schedule_airplay_monitor_retry("AirPlay service not discovered")
    end
  end)
end

function C4Driver.stop_airplay_monitor(reason)
  AirPlay.monitor_enabled = false
  C4Driver.cancel_timer("AppleTV_airplay_monitor_start")
  C4Driver.cancel_timer("AppleTV_airplay_monitor_retry")
  C4Driver.cancel_timer("AppleTV_airplay_monitor_watchdog")
  C4Driver.close_airplay_control_client(reason or "stopping AirPlay monitor")
  C4Driver.set_airplay_monitor_state("STOPPED")
end

function C4Driver.schedule_airplay_monitor_start(reason)
  if not (AirPlay.credentials or (Driver.state and Driver.state.airplay_credentials)) then
    Log.debug("AirPlay monitor auto-start skipped: no AirPlay credentials")
    return
  end
  if not has_c4() then
    return
  end
  if type(SetTimer) == "function" then
    C4Driver.cancel_timer("AppleTV_airplay_monitor_start")
    C4Driver.set_airplay_monitor_state("SCHEDULED")
    local ok, err = pcall(SetTimer, "AppleTV_airplay_monitor_start", 2000, function()
      C4Driver.start_airplay_monitor(reason or "room active")
    end)
    if not ok then
      Log.debug("AirPlay monitor auto-start timer unavailable: " .. tostring(err))
      return
    end
    Log.debug("AirPlay monitor auto-start scheduled")
  else
    C4Driver.start_airplay_monitor(reason or "room active")
  end
end

function C4Driver.pair_airplay()
  C4Driver.ensure_pairing_crypto_ready()
  local host = Properties and Properties["Apple TV Address"]
  if not host or host == "" then
    Log.error("Apple TV Address is required")
    return nil, "Apple TV Address is required"
  end

  C4Driver.update_property("Pairing PIN", "")
  local function start_pairing(port)
    AirPlay.port = port or AirPlay.port or 7000
    AirPlay.pair_setup = PairSetup.new(Crypto)
    AirPlay.pairing_active = true
    AirPlay.credentials = nil

    Log.debug("AirPlay Pair-Setup PIN start requested: port=" .. tostring(AirPlay.port))
    return C4Driver.airplay_post("/pair-pin-start", "", function(_, _, pin_code, _, pin_error)
      if pin_error ~= nil then
        Log.error("AirPlay Pair-Setup PIN start failed: " .. tostring(pin_error))
        C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
        AirPlay.pairing_active = false
        return
      end
      Log.debug("AirPlay Pair-Setup PIN start response: code=" .. tostring(pin_code))

      local body = AirPlay.pair_setup:start_hap()
      Log.debug("AirPlay Pair-Setup M1 requested: payload_len=" .. tostring(#body))
      C4Driver.airplay_post("/pair-setup", body, function(_, response_body, response_code, response_headers, error_text)
        if error_text ~= nil then
          Log.error("AirPlay Pair-Setup M2 failed: " .. tostring(error_text))
          C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
          AirPlay.pairing_active = false
          return
        end

        response_body = response_body or ""
        local content_type = ""
        if type(response_headers) == "table" then
          content_type = response_headers["Content-Type"] or response_headers["content-type"] or ""
        end
        Log.debug("AirPlay Pair-Setup M2 response: code=" .. tostring(response_code) ..
          " content_type=" .. tostring(content_type) ..
          " body_len=" .. tostring(#response_body) ..
          " body_head=" .. Bytes.hex(response_body:sub(1, 32)))
        local code = tonumber(response_code) or 0
        if code < 200 or code >= 300 then
          C4Driver.update_property("Connection State", "AirPlay Pairing " .. tostring(response_code))
          AirPlay.pairing_active = false
          return
        end

        local ok, err = pcall(function() AirPlay.pair_setup:handle_m2_hap(response_body) end)
        if not ok then
          Log.error("AirPlay Pair-Setup M2 processing failed: " .. tostring(err))
          C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
          AirPlay.pairing_active = false
          return
        end
        C4Driver.update_property("Connection State", "Enter AirPlay PIN")
      end)
    end)
  end

  if AirPlay.port then
    return start_pairing(AirPlay.port)
  end

  Log.debug("AirPlay Pair-Setup waiting for AirPlay port discovery")
  return MDNS.discover_airplay_info(host, function(info)
    if info and info.port then
      AirPlay.port = info.port
      AirPlay.txt = info.txt or {}
      start_pairing(info.port)
    else
      Log.debug("AirPlay Pair-Setup skipped: AirPlay service not discovered")
      C4Driver.update_property("Connection State", "AirPlay Not Found")
    end
  end)
end

function C4Driver.airplay_pairing_submit_pin(pin)
  if not AirPlay.pair_setup or not AirPlay.pairing_active then
    return nil, "AirPlay pairing is not active"
  end

  local ok, m3_body_or_err = pcall(function() return AirPlay.pair_setup:compute_m3_hap(pin) end)
  if not ok then
    Log.error("AirPlay Pair-Setup M3 failed: " .. tostring(m3_body_or_err))
    C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
    AirPlay.pairing_active = false
    return nil, m3_body_or_err
  end

  local m3_body = m3_body_or_err
  Log.debug("AirPlay Pair-Setup M3 requested: payload_len=" .. tostring(#m3_body))
  return C4Driver.airplay_post("/pair-setup", m3_body, function(_, m4_body, m4_code, _, m4_error)
    if m4_error ~= nil then
      Log.error("AirPlay Pair-Setup M4 failed: " .. tostring(m4_error))
      C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
      AirPlay.pairing_active = false
      return
    end

    m4_body = m4_body or ""
    Log.debug("AirPlay Pair-Setup M4 response: code=" .. tostring(m4_code) ..
      " body_len=" .. tostring(#m4_body) ..
      " body_head=" .. Bytes.hex(m4_body:sub(1, 32)))
    local code = tonumber(m4_code) or 0
    if code < 200 or code >= 300 then
      C4Driver.update_property("Connection State", "AirPlay Pairing " .. tostring(m4_code))
      AirPlay.pairing_active = false
      return
    end

    local m5_ok, m5_body_or_err = pcall(function()
      AirPlay.pair_setup:handle_m4_hap(m4_body)
      return AirPlay.pair_setup:compute_m5_hap()
    end)
    if not m5_ok then
      Log.error("AirPlay Pair-Setup M5 failed: " .. tostring(m5_body_or_err))
      C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
      AirPlay.pairing_active = false
      return
    end

    local m5_body = m5_body_or_err
    Log.debug("AirPlay Pair-Setup M5 requested: payload_len=" .. tostring(#m5_body))
    C4Driver.airplay_post("/pair-setup", m5_body, function(_, m6_body, m6_code, _, m6_error)
      if m6_error ~= nil then
        Log.error("AirPlay Pair-Setup M6 failed: " .. tostring(m6_error))
        C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
        AirPlay.pairing_active = false
        return
      end

      m6_body = m6_body or ""
      Log.debug("AirPlay Pair-Setup M6 response: code=" .. tostring(m6_code) ..
        " body_len=" .. tostring(#m6_body) ..
        " body_head=" .. Bytes.hex(m6_body:sub(1, 32)))
      local final_code = tonumber(m6_code) or 0
      if final_code < 200 or final_code >= 300 then
        C4Driver.update_property("Connection State", "AirPlay Pairing " .. tostring(m6_code))
        AirPlay.pairing_active = false
        return
      end

      local credentials_ok, credentials_or_err = pcall(function()
        return AirPlay.pair_setup:handle_m6_hap(m6_body)
      end)
      if not credentials_ok then
        Log.error("AirPlay Pair-Setup M6 processing failed: " .. tostring(credentials_or_err))
        C4Driver.update_property("Connection State", "AirPlay Pairing Failed")
        AirPlay.pairing_active = false
        return
      end

      local canonical = Credentials.stringify(credentials_or_err)
      Driver.state = Driver.state or {}
      Driver.state.airplay_credentials = canonical
      AirPlay.credentials = credentials_or_err
      AirPlay.pairing_active = false
      OpenSSLCrypto.prune_ed25519_public_table_cache(credentials_or_err.ltpk)
      Storage.save(Driver.state)
      C4Driver.update_property("Pairing PIN", "")
      C4Driver.update_property("Connection State", "AirPlay Pairing Complete")
      Log.debug("AirPlay Pair-Setup complete, credentials saved")
    end)
  end)
end

function C4Driver.import_airplay_credentials(detail_string)
  assert(type(detail_string) == "string" and detail_string ~= "", "AirPlay credentials are required")
  local credentials = Credentials.parse(detail_string)
  local canonical = Credentials.stringify(credentials)

  Driver.state = Driver.state or {}
  Driver.state.airplay_credentials = canonical
  AirPlay.credentials = credentials
  OpenSSLCrypto.prune_ed25519_public_table_cache(credentials.ltpk)
  Storage.save(Driver.state)
  C4Driver.set_connection_state("AirPlay Credentials Imported")
  return credentials
end

function C4Driver.dispose_companion_client(client)
  client = client or Companion.client
  if not client then return end
  if client.dispose then
    client:dispose()
  elseif client.close then
    client:close()
  end
end

function C4Driver.load_persisted_airplay_credentials()
  local raw = Driver.state and Driver.state.airplay_credentials
  if not raw or raw == "" then
    return nil
  end

  local ok, credentials_or_err = pcall(Credentials.parse, raw)
  if not ok then
    Log.error("stored AirPlay credentials are invalid: " .. tostring(credentials_or_err))
    return nil
  end

  AirPlay.credentials = credentials_or_err
  Log.debug("AirPlay credentials loaded")
  return credentials_or_err
end

function C4Driver.launch_selected_app()
  local selection = Properties and (Properties["Launch App"] or Properties["Selected App"]) or ""
  local app_id, err = Companion.resolve_app_selection(selection)
  if not app_id then
    err = err or "select an app after refreshing the app list"
    Log.error("Launch App failed: " .. tostring(err))
    error(err)
  end
  return C4Driver.launch_app(app_id)
end

function C4Driver.import_credentials(detail_string)
  assert(type(detail_string) == "string" and detail_string ~= "", "Companion credentials are required")
  local credentials = Credentials.parse(detail_string)
  local canonical = Credentials.stringify(credentials)

  C4Driver.dispose_companion_client(Companion.client)
  Driver.state = Driver.state or {}
  Driver.state.companion_credentials = canonical
  Companion.credentials = credentials
  Companion.client = nil
  OpenSSLCrypto.prune_ed25519_private_key_cache(credentials.ltsk)
  Storage.save(Driver.state)
  C4Driver.set_connection_state("Credentials Imported")
  C4Driver.update_property("Pairing PIN", "")
  C4Driver.schedule_crypto_prewarm()
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
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_x25519")
  C4Driver.cancel_timer("AppleTV_companion_watchdog")
  OpenSSLCrypto._pregenerated_x25519_keypair = nil
  C4Driver.dispose_companion_client(Companion.client)
  Driver.state = Driver.state or {}
  Driver.state.companion_credentials = nil
  Driver.state.airplay_credentials = nil
  Driver.state.app_list = nil
  if type(Driver.state.crypto_cache) == "table" then
    Driver.state.crypto_cache.ed25519_public_tables = {}
    Driver.state.crypto_cache.ed25519_private_keys = {}
  end
  OpenSSLCrypto.ed25519_public_point_cache = {}
  OpenSSLCrypto.ed25519_private_key_cache = {}
  Companion.credentials = nil
  AirPlay.credentials = nil
  C4Driver.stop_airplay_monitor("reset pairing")
  Companion.client = nil
  Companion.app_list = {}
  Companion.app_list_rows = {}
  Companion.current_app = nil
  Companion.now_playing = {}
  Storage.save(Driver.state)
  C4Driver.update_property("Launch App", "")
  C4Driver.update_property_list("Launch App", { "" })
  C4Driver.update_property("Current App", "")
  C4Driver.update_property("Now Playing", "")
  C4Driver.update_property("Pairing PIN", "")
  C4Driver.set_connection_state("Disconnected")
end

function C4Driver.close_airplay_control_client(reason)
  if not AirPlay.control_client then return end
  if reason and reason ~= "" then
    Log.debug("AirPlay control closing existing session: " .. tostring(reason))
  end
  if AirPlay.control_client.close then
    AirPlay.control_client:close()
  end
  AirPlay.control_client = nil
end

function C4Driver.disconnect_companion()
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_x25519")
  C4Driver.cancel_timer("AppleTV_companion_watchdog")
  MDNS.close()
  OpenSSLCrypto._pregenerated_x25519_keypair = nil
  C4Driver.dispose_companion_client(Companion.client)
  C4Driver.stop_airplay_monitor("disconnect")
  Companion.client = nil
  C4Driver.set_connection_state("Disconnected")
end

function C4Driver.ensure_companion_client()
  if Companion.client then
    if Companion.client.needs_reconnect and Companion.client:needs_reconnect() then
      local host = Companion.client.host
      if MDNS.has_cached_port(host) then
        Companion.client.port = MDNS.cached_port(host)
        Companion.client:connect()
      else
        Log.debug("Companion reconnect waiting for Companion port discovery")
        MDNS.discover_companion_port(host, function(port)
          if not Companion.client then return end
          Companion.client.port = port or MDNS.DEFAULT_COMPANION_PORT
          Companion.client:connect()
        end)
      end
    end
    return Companion.client
  end
  return C4Driver.connect_companion()
end

function C4Driver.schedule_companion_watchdog()
  if not (has_c4() and type(SetTimer) == "function") then return end
  C4Driver.cancel_timer("AppleTV_companion_watchdog")
  local ok, err = pcall(SetTimer, "AppleTV_companion_watchdog", Companion.watchdog_interval_ms, function()
    C4Driver.check_companion_watchdog()
  end)
  if not ok then
    Log.debug("Companion watchdog timer unavailable: " .. tostring(err))
  end
end

function C4Driver.check_companion_watchdog()
  local client = Companion.client
  if not client then return end
  if client.cleanup_pending_responses then
    client:cleanup_pending_responses()
  end

  local state = tostring(client.state or "")
  local active = state == "READY" or state == "SESSION_ACTIVE" or state:match("^SESSION_")
  if active and client.transport then
    local now = C4Driver.now_ms()
    local last_activity = client.last_rx_ms or client.session_active_since_ms or client.last_tx_ms or 0
    local age = now - last_activity
    if last_activity > 0 and age > Companion.watchdog_stale_ms then
      Log.debug("Companion watchdog stale: state=" .. state .. " age_ms=" .. tostring(age))
      local ok, err = pcall(function()
        client:close({ clear_pending_commands = false })
      end)
      if not ok then
        Log.debug("Companion watchdog close failed: " .. tostring(err))
        client.transport = nil
        client:clear_runtime_state({ clear_pending_commands = false })
        client:set_state("DISCONNECTED")
      end
      C4Driver.set_connection_state("DISCONNECTED")
      if Companion.client == client and client.credentials and client.connect then
        local reconnect_ok, reconnect_err = pcall(function() client:connect() end)
        if not reconnect_ok then
          Log.debug("Companion watchdog reconnect failed: " .. tostring(reconnect_err))
        end
      end
      C4Driver.schedule_companion_watchdog()
      return
    end
  end

  C4Driver.schedule_companion_watchdog()
end

function C4Driver.start_companion_client(client, host, label)
  C4Driver.schedule_companion_watchdog()
  if MDNS.has_cached_port(host) then
    client.port = MDNS.cached_port(host)
    client:connect()
    return
  end

  Log.debug((label or "Companion") .. " waiting for Companion port discovery")
  MDNS.discover_companion_port(host, function(port)
    if Companion.client ~= client then return end
    client.port = port or MDNS.DEFAULT_COMPANION_PORT
    Log.debug((label or "Companion") .. " connecting after port discovery: port=" ..
      tostring(client.port))
    client:connect()
  end)
end

function C4Driver.build_companion_client(host, options)
  options = options or {}
  local label = options.label or "Companion"
  C4Driver.dispose_companion_client(Companion.client)
  local client = CompanionClient.new({
    host = host,
    port = MDNS.cached_port(host),
    credentials = options.credentials,
    crypto = Crypto,
    on_state = function(state)
      C4Driver.set_connection_state(state)
    end,
    on_message = function(message)
      C4Driver.handle_companion_message(message)
    end,
    on_connection_refused = function(refused_client)
      if refused_client._port_rediscover_attempted then
        Log.debug(label .. " TCP refused after rediscovery; not retrying again")
        return
      end
      refused_client._port_rediscover_attempted = true
      MDNS.invalidate(host)
      Log.debug(label .. " TCP refused; rediscovering Companion port")
      MDNS.discover_companion_port(host, function(port)
        if Companion.client ~= refused_client then return end
        refused_client.port = port or MDNS.DEFAULT_COMPANION_PORT
        Log.debug(label .. " retrying TCP connect after port discovery: port=" ..
          tostring(refused_client.port))
        refused_client:connect()
      end)
    end,
    on_pair_setup_m2 = options.on_pair_setup_m2,
    on_paired = options.on_paired,
  })
  Companion.client = client
  return client
end

function C4Driver.connect_companion()
  C4Driver.ensure_crypto_provider()
  local host = Properties and Properties["Apple TV Address"]
  local credentials = Companion.credentials or C4Driver.load_persisted_credentials()
  if not credentials then
    Log.error("pair this driver before connecting")
    error("pair this driver before connecting")
  end
  if Companion.client and not (Companion.client.needs_reconnect and Companion.client:needs_reconnect()) then
    Log.debug("Companion connect requested while client exists: state=" .. tostring(Companion.client.state))
    return Companion.client
  end

  local client = C4Driver.build_companion_client(host, {
    label = "Companion",
    credentials = credentials,
  })
  C4Driver.start_companion_client(client, host, "Companion")
  return client
end

function C4Driver.pair_companion()
  C4Driver.ensure_pairing_crypto_ready()
  local host = Properties and Properties["Apple TV Address"]
  if not host or host == "" then
    Log.error("set Apple TV Address before pairing")
    error("Apple TV Address is required for pairing")
  end
  C4Driver.update_property("Pairing PIN", "")
  local client = C4Driver.build_companion_client(host, {
    label = "Pair-Setup",
    on_pair_setup_m2 = function()
      C4Driver.set_connection_state("Enter PIN from Apple TV")
    end,
    on_paired = function(credentials)
      C4Driver.import_credentials(Credentials.stringify(credentials))
      Log.debug("Pair-Setup complete, credentials saved")
    end,
  })
  C4Driver.start_companion_client(client, host, "Pair-Setup")
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

local CRYPTO_PREWARM_STAGE_LABELS = {
  all = "All",
  base = "Ed25519 Base Table",
  controller = "Controller Signing Key",
  atv = "Apple TV Verify Table",
  x25519 = "X25519 Keypair",
}

function C4Driver.set_crypto_prewarm_status(value)
  C4Driver.update_property("Crypto Prewarm Status", value)
end

function C4Driver.prewarm_crypto_stage(stage)
  local stage_key = stage or "all"
  local label = CRYPTO_PREWARM_STAGE_LABELS[stage_key] or tostring(stage_key)
  Driver.crypto_prewarm_in_progress = Driver.crypto_prewarm_in_progress or {}
  for running_stage, running in pairs(Driver.crypto_prewarm_in_progress) do
    if running then
      local running_label = CRYPTO_PREWARM_STAGE_LABELS[running_stage] or tostring(running_stage)
      local status = "Skipped: " .. running_label .. " already running"
      C4Driver.set_crypto_prewarm_status(status)
      Log.output("Prewarm Crypto skipped: " .. tostring(running_label) .. " already running")
      return false, "already running"
    end
  end

  local credentials = Companion.credentials or C4Driver.load_persisted_credentials()
  if not credentials then
    local status = "Skipped: no pairing credentials"
    C4Driver.set_crypto_prewarm_status(status)
    Log.output("Prewarm Crypto skipped: pair Apple TV first")
    return false, "no pairing credentials"
  end
  Driver.crypto_prewarm_in_progress[stage_key] = true
  C4Driver.set_crypto_prewarm_status("Running: " .. label)
  Log.output("Prewarm Crypto started: " .. tostring(label))
  local results = {}
  local ok, err = pcall(function()
    if stage == nil or stage == "base" then
      Log.output("Prewarm Crypto: Ed25519 base table")
      local status = OpenSSLCrypto.ensure_ed25519_base_table()
      results[#results + 1] = "base=" .. tostring(status)
    end

    if stage == nil or stage == "controller" then
      Log.output("Prewarm Crypto: controller signing key")
      local status, expanded = OpenSSLCrypto.ensure_ed25519_private_key(credentials.ltsk)
      credentials.controller_ltpk = expanded.public_key
      results[#results + 1] = "controller=" .. tostring(status)
    end

    if stage == nil or stage == "atv" then
      Log.output("Prewarm Crypto: Apple TV verify table")
      local status = OpenSSLCrypto.ensure_ed25519_public_table(credentials.ltpk)
      results[#results + 1] = "atv=" .. tostring(status)
    end

    if stage == nil or stage == "x25519" then
      Log.output("Prewarm Crypto: X25519 keypair")
      local status = OpenSSLCrypto.ensure_x25519_keypair()
      results[#results + 1] = "x25519=" .. tostring(status)
    end
  end)
  Driver.crypto_prewarm_in_progress[stage_key] = nil
  if not ok then
    local status = "Failed: " .. label .. " - " .. tostring(err)
    C4Driver.set_crypto_prewarm_status(status)
    Log.output("Prewarm Crypto failed: " .. tostring(err))
    Log.error("crypto prewarm " .. tostring(stage_key) .. " failed: " .. tostring(err))
    return false, err
  end
  local result_text = table.concat(results, ", ")
  C4Driver.set_crypto_prewarm_status("Complete: " .. label ..
    " (" .. result_text .. ")")
  Log.output("Prewarm Crypto complete: " .. result_text)
  return true
end

function C4Driver.prewarm_crypto()
  local ok, err = C4Driver.prewarm_crypto_stage(nil)
  return ok, err
end

function C4Driver.schedule_crypto_prewarm()
  -- Crypto prewarm is intentionally installer-driven from Composer actions.
  -- The slow Ed25519 table builds can otherwise make driver upload/pairing feel hung.
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_all")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_base")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_controller")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_atv")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_x25519")
end

function C4Driver.cancel_timer(name)
  if type(CancelTimer) == "function" then
    pcall(CancelTimer, name)
  elseif has_c4() and C4.KillTimer then
    pcall(function() C4:KillTimer(name) end)
  end
end

function C4Driver.cancel_driver_timers()
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_all")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_base")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_controller")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_atv")
  C4Driver.cancel_timer("AppleTV_crypto_prewarm_x25519")
  C4Driver.cancel_timer("AppleTV_reselect_passthrough")
  C4Driver.cancel_timer(C4MiniApps.native_handoff_timer)
  for timer_name in pairs(C4MiniApps.active_handoff_timers or {}) do
    C4Driver.cancel_timer(timer_name)
  end
  C4MiniApps.active_handoff_timers = {}
  C4Driver.cancel_timer("AppleTV_mdns_timeout")
  C4Driver.cancel_timer("AppleTV_tv_rc_session_start_timeout")
  C4Driver.cancel_timer("AppleTV_companion_watchdog")
  C4Driver.cancel_timer("AppleTV_airplay_monitor_start")
  C4Driver.cancel_timer("AppleTV_airplay_monitor_retry")
  C4Driver.cancel_timer("AppleTV_airplay_monitor_watchdog")
  C4Driver.cancel_timer(C4MiniApps.launch_retry_timer)
  MDNS.close()
end

-- EC: Composer action and command dispatch (DCP normalises spaces→underscores and handles LUA_ACTION)
EC.LAUNCH_APP = function(params)
  return C4Driver.launch_app(params.BUNDLE_ID_OR_URL or params.bundle_id_or_url)
end
EC.REFRESH_APP_LIST = function()
  return C4Driver.refresh_app_list()
end
EC.PRINT_APP_LIST = function()
  return C4Driver.print_app_list()
end
EC.REFRESH_NATIVE_APPLE_TV_DRIVERS = function()
  return C4MiniApps.refresh_native_apple_tv_drivers()
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
EC.PREWARM_CRYPTO = function()
  return C4Driver.prewarm_crypto()
end
EC.START_AIRPLAY_MONITOR = function()
  return C4Driver.start_airplay_monitor("manual")
end
EC.STOP_AIRPLAY_MONITOR = function()
  return C4Driver.stop_airplay_monitor("manual")
end
EC.PAIR_AIRPLAY = function()
  return C4Driver.pair_airplay()
end
EC.IMPORT_COMPANION_CREDENTIALS = function(params)
  return C4Driver.import_credentials(params.CREDENTIALS or params.credentials or "")
end
EC.IMPORT_AIRPLAY_CREDENTIALS = function(params)
  return C4Driver.import_airplay_credentials(params.CREDENTIALS or params.credentials or "")
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
  C4Driver.update_property("Pairing PIN", "")
  C4Driver.set_crypto_prewarm_status("Idle")
  C4Driver.publish_app_list()
  C4MiniApps.refresh_native_apple_tv_drivers()
  C4Driver.load_persisted_credentials()
  C4Driver.load_persisted_airplay_credentials()
  Log.debug("driver init " .. Driver.VERSION)
end

function C4Driver.late_init()
  if C4MiniApps.USES_DEDICATED_SWITCHER then
    C4MiniApps.hide_proxy_in_all_rooms(C4MiniApps.SWITCHER_PROXY)
  end
  C4MiniApps.register_rooms()
  C4Driver.schedule_crypto_prewarm()
  Log.debug("driver late init")
end

function C4Driver.destroy()
  C4Driver.cancel_driver_timers()
  OpenSSLCrypto._pregenerated_x25519_keypair = nil
  C4Driver.dispose_companion_client(Companion.client)
  Companion.client = nil
  C4Driver.close_airplay_control_client("driver destroy")
  AirPlay.monitor_enabled = false
  Log.debug("driver destroyed")
end

-- OPC: Property change dispatch (DCP replaces spaces with underscores in the key)
OPC.Pairing_PIN = function(value)
  if value and value ~= "" then
    if AirPlay.pairing_active and AirPlay.pair_setup and AirPlay.pair_setup.state == "M2_RECEIVED" then
      local ok, err = pcall(function() C4Driver.airplay_pairing_submit_pin(value) end)
      if not ok then
        Log.error("AirPlay PIN submission failed: " .. tostring(err))
      end
    elseif Companion.client and Companion.client.state == "PAIR_SETUP_AWAITING_PIN" then
      local ok, err = pcall(function() Companion.client:pair_setup_submit_pin(value) end)
      if not ok then
        Log.error("PIN submission failed: " .. tostring(err))
      end
    end
  end
end

OPC.AirPlay_Credentials = function(value)
  if value and value ~= "" and
      (value ~= (Driver.state and Driver.state.airplay_credentials) or not AirPlay.credentials)
  then
    local ok, err = pcall(function() C4Driver.import_airplay_credentials(value) end)
    if not ok then
      Log.error("AirPlay credentials import failed: " .. tostring(err))
    end
  end
end

OPC.Debug_Mode = function(value)
  DEBUGPRINT = (value == "On")
end

-- OSE: System event dispatch (DCP parses the event name automatically)
OSE.OnPIP = function()
  C4MiniApps.register_rooms()
  C4MiniApps.refresh_native_apple_tv_drivers()
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
Driver.MDNS = MDNS
Driver.TLV8 = TLV8
Driver.OPACK = OPACK
Driver.BigInt = BigInt
Driver.SRP = SRP
Driver.CompanionFrame = CompanionFrame
Driver.CompanionSession = CompanionSession
Driver.HAPSession = HAPSession
Driver.ChaCha20Poly1305Pure = ChaCha20Poly1305Pure
Driver.CompanionClient = CompanionClient
Driver.Companion = Companion
Driver.AirPlay = AirPlay
Driver.AirPlayHTTP = AirPlayHTTP
Driver.AirPlayControlClient = AirPlayControlClient
Driver.BPlist = BPlist
Driver.PB = PB
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
