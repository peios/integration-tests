-- Reading the KMES ring through the guest's own probe, `revstrm`.
--
-- `revstrm --snapshot --pretty` drains what the ring holds and prints each
-- event as a header line and its payload beneath it. An event's payload is
-- a nested map (PGSS §6.4), and the pretty form prints a nested map as its
-- key followed by a colon, with its members indented beneath:
--
--   12:00:00.123456789  cpu0  #42       USR  peinit.job.ended
--       object:
--         job:
--           guid    0191f0a2-…
--           type    "service-main"
--       outcome:
--         success  true
--
-- `parse` turns that back into one flat table per event, keyed by the
-- dotted catalogue path (`object.job.guid`), so a test asks for a field by
-- the name the catalogue and the event viewer give it. Values are revstrm's
-- text with a string's quotes taken off: revstrm formats each value by the
-- type the installed catalogue declares (`/usr/share/evman`), so a
-- `bin.guid` is GUID text, a `bin.sid` SDDL, a `uint.time` RFC 3339, a
-- `uint.duration` `N ns (…)`, an `int.errno` `-N (text)`, a `uint.flags` the
-- flag names, and a scalar array `[a, b]`.

local M = {}

--- Strip the quotes revstrm puts round a string, undoing its two common
--- escapes. Anything else is returned as it is.
local function unquote(text)
    local inner = text:match('^"(.*)"$')
    if not inner then return text end
    return (inner:gsub('\\"', '"'):gsub("\\\\", "\\"))
end

--- The elements of an inline scalar array, `[a, "b"]`, unquoted. Splits on
--- `, ` outside quotes, which is enough for what peinit writes.
function M.array(text)
    if not text then return nil end
    local inner = text:match("^%[(.*)%]$")
    if not inner then return nil end
    local out, buf, quoted, i = {}, "", false, 1
    while i <= #inner do
        local c = inner:sub(i, i)
        if c == "\\" and quoted then
            buf = buf .. inner:sub(i, i + 1)
            i = i + 2
        else
            if c == '"' then quoted = not quoted end
            if c == "," and not quoted and inner:sub(i + 1, i + 1) == " " then
                out[#out + 1] = unquote(buf)
                buf = ""
                i = i + 2
            else
                buf = buf .. c
                i = i + 1
            end
        end
    end
    if buf ~= "" then out[#out + 1] = unquote(buf) end
    return out
end

--- Parse one payload block (the indented lines beneath a header) into a
--- flat table of dotted path → value text. A map shows as `path` → `true`
--- in `maps`, so a test can ask whether a map is present at all.
function M.fields(payload)
    local fields, maps, stack = {}, {}, {}
    for line in payload:gmatch("[^\r\n]+") do
        local pad, rest = line:match("^(%s*)(.-)%s*$")
        local depth = #pad
        while #stack > 0 and stack[#stack].depth >= depth do
            table.remove(stack)
        end
        local prefix = {}
        for _, frame in ipairs(stack) do prefix[#prefix + 1] = frame.key end
        local opener = rest:match("^([^%s]+):$")
        if opener then
            prefix[#prefix + 1] = opener
            maps[table.concat(prefix, ".")] = true
            stack[#stack + 1] = { depth = depth, key = opener }
        else
            local key, value = rest:match("^([^%s]+)%s%s+(.*)$")
            if key then
                prefix[#prefix + 1] = key
                fields[table.concat(prefix, ".")] = unquote(value)
            end
        end
    end
    return fields, maps
end

--- Every event in the ring whose type matches one of `globs`, oldest
--- first, as `{type, header, payload, fields, maps, index}`. Returns the
--- list and revstrm's whole output.
function M.snapshot(who, globs, opts)
    opts = opts or {}
    local flags = ""
    for _, glob in ipairs(globs or {}) do flags = flags .. " --type '" .. glob .. "'" end
    local r = who:run("revstrm --snapshot --pretty" .. flags, { timeout = opts.timeout or 60 })
    r:assert_ok()
    return M.parse(r.stdout), r.stdout
end

--- Parse revstrm's pretty output into events (see `snapshot`).
function M.parse(stdout)
    local out, current = {}, nil
    local function finish()
        if current then
            current.fields, current.maps = M.fields(current.payload)
        end
    end
    for line in stdout:gmatch("[^\r\n]+") do
        local kind = line:match("^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_%-]+%.[%w_%.%-]+)%s*$")
        if kind then
            finish()
            current = { type = kind, payload = "", index = #out + 1, header = line }
            out[#out + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    finish()
    return out
end

--- The value text at `path` in `event`, or nil when the field is absent.
function M.field(event, path)
    return event.fields[path]
end

--- Whether `event` has anything at `path`: a value, or a map.
function M.has(event, path)
    return event.fields[path] ~= nil or event.maps[path] == true
end

--- A GUID's text as the control channel shows it, lowercased and without
--- braces, for comparing a `bin.guid` from any reader with an id `svctl`
--- printed.
---
--- Takes revstrm's text (`0191…`, maybe braced), or an eventd row's value:
--- evctl's jsonl writes a payload `bin.guid` as `{"$binary": "<hex>"}`, the
--- sixteen bytes in PCDS order (the first three fields little-endian),
--- which this reads back as the canonical text.
function M.guid(value)
    if value == nil then return nil end
    local hex
    if type(value) == "table" then
        hex = value["$binary"]
    elseif type(value) == "string" and value:match("^%x+$") and #value == 32 then
        hex = value
    end
    if hex then
        if #hex ~= 32 then return nil end
        hex = hex:lower()
        local function bytes(from, to) return hex:sub(from * 2 + 1, to * 2) end
        local function reversed(from, to)
            local out = ""
            for i = to - 1, from, -1 do out = out .. hex:sub(i * 2 + 1, i * 2 + 2) end
            return out
        end
        return reversed(0, 4) .. "-" .. reversed(4, 6) .. "-" .. reversed(6, 8) .. "-"
            .. bytes(8, 10) .. "-" .. bytes(10, 16)
    end
    if type(value) ~= "string" then return nil end
    return (value:lower():gsub("^{", ""):gsub("}$", ""))
end

--- A SID's SDDL text, from revstrm's text (already SDDL) or an eventd
--- row's value: evctl's jsonl writes a `bin.sid` as `{"$binary": "<hex>"}`
--- of the binary SID (revision, sub-authority count, a 48-bit big-endian
--- authority, then 32-bit little-endian sub-authorities).
function M.sid(value)
    if type(value) == "string" then return value end
    if type(value) ~= "table" or type(value["$binary"]) ~= "string" then return nil end
    local hex = value["$binary"]
    local function byte(i) return tonumber(hex:sub(i * 2 + 1, i * 2 + 2), 16) end
    if #hex < 16 then return nil end
    local count = byte(1)
    if #hex ~= (8 + 4 * count) * 2 then return nil end
    local authority = 0
    for i = 2, 7 do authority = authority * 256 + byte(i) end
    local parts = { "S", tostring(byte(0)), tostring(authority) }
    for n = 0, count - 1 do
        local at = 8 + 4 * n
        parts[#parts + 1] = tostring(byte(at) + byte(at + 1) * 256
            + byte(at + 2) * 65536 + byte(at + 3) * 16777216)
    end
    return table.concat(parts, "-")
end

return M
