-- PKM §5.2.8 Names and Case — the syscall half of the null-byte rule:
-- a path or `reg_create_key`'s layer name is a C string, so a null byte
-- in it is the terminator, and nothing after it is read.
--
-- The way to see that nothing after the terminator is read is to put
-- something there the kernel would refuse if it did read it: invalid
-- UTF-8, which §5.2.8 makes EINVAL before any other work. A call that
-- succeeds with those bytes after the null never looked at them. The
-- control is the same bytes before the null, which are refused.
--
-- Belongs in data-names.test.lua beside "null bytes are rejected in
-- every string"; that file's "a null byte in reg_create_key's layer
-- name terminates it" case already holds the layer-name half and could
-- cite this anchor as well.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST = "Machine\\Software\\Test"
-- Bytes that are not UTF-8 in any position: 0xFF and 0xFE never occur.
local JUNK = "\xff\xfe"

local src = lcs.source(vm)
src:key(lcs.LAYERS_PATH .. "\\base", { sd = lcs.permissive_sd() })
src:key(TEST)
assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- The (name, layer) of each CREATE_ENTRY served since `mark`.
local function created_entries(mark)
    local out = {}
    for _, req in ipairs(src:served(lcs.OP.CREATE_ENTRY, mark)) do
        local name, at = string.unpack("<s4", req.payload, 17)
        out[#out + 1] = { name = name, layer = string.unpack("<s4", req.payload, at) }
    end
    return out
end

test("invalid UTF-8 inside a syscall path is refused — the control",
    { spec = "PKM *name.utf8.syscall-strings-end-at-the-null" }, function(t)
        local r = lcs.open_key(src, w, -1, TEST .. JUNK, lcs.RIGHT.KEY_READ)
        t:assert(r.ret < 0, "a path carrying the junk before its terminator is refused")
        t:assert_eq(r.errno, sys.E.INVAL,
            "with EINVAL, so the same bytes would be refused if they were read: "
            .. sys.errname(r.errno or 0))
        local c = lcs.create_key(src, w, { path = TEST .. "\\Ok", layer = "base" .. JUNK })
        t:assert(c.ret < 0, "and so is a layer name carrying it")
        t:assert_eq(c.errno, sys.E.INVAL,
            "with EINVAL: " .. sys.errname(c.errno or 0))
    end)

test("reg_open_key's path ends at the null byte and nothing after it is read",
    { spec = "PKM *name.utf8.syscall-strings-end-at-the-null" }, function(t)
        local mark = src:mark()
        local r = lcs.open_key(src, w, -1, TEST .. "\0" .. JUNK, lcs.RIGHT.KEY_READ)
        t:assert(r.ret >= 0,
            "invalid UTF-8 after the terminator is never validated: "
            .. sys.errname(r.errno or 0))
        if r.ret >= 0 then
            t:assert_eq(lcs.query_key_info(src, w, r.ret).name, "Test",
                "and the key opened is the one the path names up to the null")
            sys.close(w, r.ret)
        end
        -- More path after the terminator is not more path: a component
        -- that does not exist, past the null, is not looked up.
        local more = lcs.open_key(src, w, -1, TEST .. "\0\\Absent\\Deeper", lcs.RIGHT.KEY_READ)
        t:assert(more.ret >= 0,
            "components after the terminator are not walked: " .. sys.errname(more.errno or 0))
        if more.ret >= 0 then
            t:assert_eq(lcs.query_key_info(src, w, more.ret).name, "Test", "it is Test again")
            sys.close(w, more.ret)
        end
        local looked = {}
        for _, req in ipairs(src:served(lcs.OP.LOOKUP, mark)) do
            local name = lcs.lookup_name(req)
            if name then looked[#looked + 1] = name end
        end
        for _, n in ipairs(looked) do
            t:assert(n ~= "Absent" and n ~= "Deeper",
                "no lookup was made for a name past the null: " .. table.concat(looked, ","))
        end
    end)

test("reg_create_key's path ends at the null byte and nothing after it is read",
    { spec = "PKM *name.utf8.syscall-strings-end-at-the-null" }, function(t)
        local mark = src:mark()
        local c = lcs.create_key(src, w, { path = TEST .. "\\Cut\0" .. JUNK })
        t:assert(c.ret >= 0, "the create succeeds: " .. sys.errname(c.errno or 0))
        if c.ret >= 0 then
            t:assert_eq(c.disposition, lcs.CREATED_NEW, "creating a key")
            sys.close(w, c.ret)
        end
        local made = created_entries(mark)
        t:assert_eq(#made, 1, "one path entry was created")
        if made[1] then
            t:assert_eq(made[1].name, "Cut", "named by the bytes before the terminator only")
        end
        local back = lcs.open_key(src, w, -1, TEST .. "\\Cut", lcs.RIGHT.KEY_READ)
        t:assert(back.ret >= 0, "and it opens by that name: " .. sys.errname(back.errno or 0))
        if back.ret >= 0 then sys.close(w, back.ret) end
    end)

test("reg_create_key's layer name ends at the null byte and nothing after it is read",
    { spec = "PKM *name.utf8.syscall-strings-end-at-the-null" }, function(t)
        local mark = src:mark()
        local c = lcs.create_key(src, w, { path = TEST .. "\\InBase", layer = "base\0" .. JUNK })
        t:assert(c.ret >= 0,
            "invalid UTF-8 after the layer name's terminator is never validated: "
            .. sys.errname(c.errno or 0))
        if c.ret >= 0 then sys.close(w, c.ret) end
        local made = created_entries(mark)
        t:assert_eq(#made, 1, "one path entry was created")
        if made[1] then
            t:assert_eq(made[1].layer, "base", "in the layer the name names up to the null")
        end
    end)
