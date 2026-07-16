-- Test-only bit32 shim.
--
-- driver.lua requires a native bit library (bit32 or bit) and refuses to load
-- without one, because the pure-Lua substitute it used to fall back on was
-- ~30-47x slower and silently unusable. Control4's Director always supplies one,
-- and LuaJIT has `bit`, so this only matters for local runs under plain Lua 5.3+,
-- which has native bitwise operators but no bit32 table.
--
-- Building the table with load() keeps this file parseable by Lua 5.1, which
-- cannot compile `&`/`|`/`~`/`<<`/`>>` at all.
--
-- Load this before dofile("driver.lua").

if bit32 ~= nil or bit ~= nil then
  return
end

local compile = load or loadstring
local chunk = compile([[
  local function u32(v) return v & 0xFFFFFFFF end
  return {
    band   = function(a, b) return u32(math.floor(a) & math.floor(b)) end,
    bor    = function(a, b) return u32(math.floor(a) | math.floor(b)) end,
    bxor   = function(a, b) return u32(math.floor(a) ~ math.floor(b)) end,
    lshift = function(a, n) return u32(math.floor(a) << math.floor(n)) end,
    rshift = function(a, n) return u32(math.floor(a)) >> math.floor(n) end,
  }
]])

if not chunk then
  error("this Lua has neither a bit library (bit32/bit) nor native bitwise " ..
    "operators; run the tests under LuaJIT or Lua 5.3+")
end

bit32 = chunk()
