-- PKM §5.6.2 — the event records a watcher reads off a key fd: the
-- common header, the subtree fields, and what `read()` does with a
-- buffer that cannot hold everything queued.
--
-- These cases work on the raw bytes as well as on the decoded records,
-- because the header offsets are ABI.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"
local HDR = 8 -- total_len u32, event_type u16, name_len u16

local src = lcs.source(vm)
src:key(ROOT)
src:key(ROOT .. "\\A\\B")
src:key(ROOT .. "\\Records")
src:key(ROOT .. "\\Sizes")
src:key(ROOT .. "\\Blocking")
src:key(ROOT .. "\\Subtree\\A\\B")
src:key(ROOT .. "\\Bare\\Child")
src:key(lcs.LAYERS_PATH)
assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_nb(path, who)
    local r = lcs.open_key(src, who or w, -1, path, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. path .. ": " .. sys.errname(r.errno or 0))
    lcs.nonblock(who or w, r.ret)
    return r.ret
end

local function arm(t, fd, subtree, who)
    local n = lcs.notify(nil, who or w, fd, lcs.NOTIFY.ALL, subtree or false)
    t:assert_eq(n.ret, 0, "REG_IOC_NOTIFY arms: " .. sys.errname(n.errno or 0))
end

-- ---- the common header ------------------------------------------------

test("every record begins with total_len, event_type and name_len, little-endian",
    { spec = "PKM *watch.record.common-header-fields" }, function(t)
        local fd = open_nb(ROOT .. "\\Records")
        arm(t, fd)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local r = lcs.read_events(nil, w, fd, 4096)
        t:assert(r.ret > 0, "a record was read: " .. sys.errname(r.errno or 0))
        local raw = r.out_bufs[1]:sub(1, r.ret)
        local total_len, event_type, name_len = string.unpack("<I4I2I2", raw)
        t:assert_eq(total_len, HDR + #"Answer", "total_len at offset 0, four bytes")
        t:assert_eq(event_type, lcs.WATCH.VALUE_SET, "event_type at offset 4, two bytes")
        t:assert_eq(name_len, #"Answer", "name_len at offset 6, two bytes")
        t:assert_eq(raw:sub(HDR + 1, HDR + name_len), "Answer",
            "the UTF-8 name follows the header at offset 8")
        sys.close(w, fd)
    end)

test("the record's integers are little-endian",
    { spec = "PKM *watch.record.integers-are-little-endian" }, function(t)
        local fd = open_nb(ROOT .. "\\Records")
        arm(t, fd)
        lcs.set_value(src, w, fd, "Endian", lcs.TYPE.DWORD, lcs.dword(1))
        local r = lcs.read_events(nil, w, fd, 4096)
        local raw = r.out_bufs[1]:sub(1, r.ret)
        t:assert_eq(string.unpack("<I4", raw), HDR + #"Endian",
            "total_len read little-endian is the record length")
        t:assert(string.unpack(">I4", raw) ~= HDR + #"Endian",
            "and reading it big-endian does not give the record length")
        t:assert_eq(string.unpack("<I2", raw, 5), lcs.WATCH.VALUE_SET,
            "event_type read little-endian is the event code")
        t:assert_eq(string.unpack("<I2", raw, 7), #"Endian",
            "name_len read little-endian is the name length")
        sys.close(w, fd)
    end)

test("total_len covers the whole record and is how a consumer advances",
    { spec = "PKM *watch.record.total-len-covers-whole-record" }, function(t)
        local fd = open_nb(ROOT .. "\\Sizes")
        arm(t, fd)
        local names = { "Aa", "Bbb", "Cccc" }
        for i, n in ipairs(names) do
            lcs.set_value(src, w, fd, n, lcs.TYPE.DWORD, lcs.dword(i))
        end
        local r = lcs.read_events(nil, w, fd, 4096)
        local raw = r.out_bufs[1]:sub(1, r.ret)
        local at, seen = 1, {}
        while at <= #raw do
            local total_len, _, name_len = string.unpack("<I4I2I2", raw, at)
            t:assert_eq(total_len, HDR + name_len,
                "total_len counts the header and the name it carries")
            seen[#seen + 1] = raw:sub(at + HDR, at + HDR + name_len - 1)
            at = at + total_len -- the only safe way to reach the next record
        end
        t:assert_eq(at, #raw + 1, "advancing by total_len lands exactly on the end")
        t:assert_eq(#seen, 3, "and walked every record: " .. table.concat(seen, ","))
        sys.close(w, fd)
    end)

test("name_len and each component length are 16-bit fields",
    { spec = "PKM *watch.record.length-fields-are-16-bit" }, function(t)
        local fd = open_nb(ROOT .. "\\Sizes")
        local parent = open_nb(ROOT)
        arm(t, parent, true)
        local long = string.rep("N", 255) -- MaxPathComponentLength's default
        lcs.set_value(src, w, fd, long, lcs.TYPE.DWORD, lcs.dword(1))
        local r = lcs.read_events(nil, w, parent, 4096)
        local raw = r.out_bufs[1]:sub(1, r.ret)
        local total_len, _, name_len = string.unpack("<I4I2I2", raw)
        t:assert_eq(name_len, 255, "name_len holds a 255-byte name in its two bytes")
        t:assert(name_len <= 0xFFFF, "and is bounded by the 16-bit field")
        local depth, at = string.unpack("<I2", raw, HDR + name_len + 1)
        t:assert_eq(depth, 1, "path_depth is two bytes too")
        local clen = string.unpack("<I2", raw, at)
        t:assert_eq(clen, #"Sizes", "and each component carries a two-byte length")
        t:assert_eq(total_len, HDR + name_len + 2 + 2 + clen,
            "total_len accounts for every one of them")
        sys.close(w, parent); sys.close(w, fd)
    end)

test("future fields appended after path_components are skipped by total_len",
    { spec = "PKM *watch.record.appended-fields-are-skipped-by-total-len" }, function(t)
        -- The extension mechanism is that total_len comes first: a
        -- consumer that advances by it walks a stream of records
        -- correctly whether or not it understands every field, and
        -- compares total_len against what it parsed to find out.
        local fd = open_nb(ROOT .. "\\Sizes")
        local parent = open_nb(ROOT)
        arm(t, parent, true)
        for i = 1, 3 do
            lcs.set_value(src, w, fd, "Ext" .. i, lcs.TYPE.DWORD, lcs.dword(i))
        end
        local r = lcs.read_events(nil, w, parent, 4096)
        local raw = r.out_bufs[1]:sub(1, r.ret)
        local at, count = 1, 0
        while at <= #raw do
            local total_len, _, name_len = string.unpack("<I4I2I2", raw, at)
            local parsed = HDR + name_len
            local depth, p = string.unpack("<I2", raw, at + parsed)
            parsed = parsed + 2
            for _ = 1, depth do
                local clen; clen, p = string.unpack("<I2", raw, p)
                parsed = parsed + 2 + clen
                p = p + clen
            end
            t:assert_eq(total_len, parsed,
                "this version appends nothing after path_components, so " ..
                "total_len equals what a full parse consumed")
            count = count + 1
            at = at + total_len
        end
        t:assert_eq(count, 3, "and the cursor walked every record")
        t:assert_eq(at, #raw + 1, "landing exactly at the end")
        sys.close(w, parent); sys.close(w, fd)
    end)

-- ---- read() semantics -------------------------------------------------

test("read returns as many whole events as fit and dequeues only those",
    { spec = "PKM *watch.record.read-returns-whole-events-only" }, function(t)
        local fd = open_nb(ROOT .. "\\Records")
        arm(t, fd)
        local names = { "Aa", "Bbb", "Cccc" }
        for i, n in ipairs(names) do
            lcs.set_value(src, w, fd, n, lcs.TYPE.DWORD, lcs.dword(i))
        end
        local first_two = (HDR + #names[1]) + (HDR + #names[2])
        local r = lcs.read_events(nil, w, fd, first_two + 1)
        t:assert_eq(r.ret, first_two,
            "the third event did not fit and was not split: " .. tostring(r.ret))
        t:assert_eq(#r.events, 2, "two whole events came back")
        t:assert_eq(r.events[1].name, "Aa", "in queue order")
        t:assert_eq(r.events[2].name, "Bbb", "in queue order")
        local rest = lcs.read_events(nil, w, fd, 4096)
        t:assert_eq(#rest.events, 1, "and the third is still queued")
        t:assert_eq(rest.events[1].name, "Cccc", "intact")
        sys.close(w, fd)
    end)

test("only fully copied events are dequeued",
    { spec = "PKM *watch.record.only-fully-copied-events-dequeued" }, function(t)
        local fd = open_nb(ROOT .. "\\Records")
        arm(t, fd)
        lcs.set_value(src, w, fd, "Kept", lcs.TYPE.DWORD, lcs.dword(1))
        lcs.set_value(src, w, fd, "AlsoKept", lcs.TYPE.DWORD, lcs.dword(2))
        -- Room for the first record and one byte of the second.
        local r = lcs.read_events(nil, w, fd, HDR + #"Kept" + 1)
        t:assert_eq(r.ret, HDR + #"Kept", "the partial second event was not copied out")
        local rest = lcs.drain_events(w, fd)
        t:assert_eq(#rest, 1, "so it stayed queued: " .. lcs.event_summary(rest))
        t:assert_eq(rest[1].name, "AlsoKept", "whole, not truncated")
        t:assert_eq(rest[1].total_len, HDR + #"AlsoKept", "with its full length")
        sys.close(w, fd)
    end)

test("a buffer too small for the first queued event fails EINVAL",
    { spec = "PKM *watch.record.buffer-too-small-is-einval" }, function(t)
        local fd = open_nb(ROOT .. "\\Records")
        arm(t, fd)
        lcs.set_value(src, w, fd, "TooBig", lcs.TYPE.DWORD, lcs.dword(1))
        local size = HDR + #"TooBig"
        local r = lcs.read_events(nil, w, fd, size - 1)
        t:assert_eq(r.errno, sys.E.INVAL,
            "the buffer cannot hold even the first event, so read fails EINVAL")
        local again = lcs.read_events(nil, w, fd, size)
        t:assert_eq(again.ret, size, "a larger buffer makes progress")
        t:assert_eq(again.events[1].name, "TooBig", "the event was not lost")
        sys.close(w, fd)
    end)

test("read on an armed fd with an empty queue blocks, or is EAGAIN under O_NONBLOCK",
    { spec = "PKM *watch.record.empty-queue-blocks-or-eagain" }, function(t)
        -- The O_NONBLOCK half, on this file's worker.
        local nbfd = open_nb(ROOT .. "\\Blocking")
        arm(t, nbfd)
        local r = lcs.read_events(nil, w, nbfd, 4096)
        t:assert_eq(r.errno, sys.E.AGAIN, "an empty queue under O_NONBLOCK is EAGAIN")
        sys.close(w, nbfd)

        -- The blocking half needs a second worker: the read must still
        -- be outstanding while this one mutates through the source.
        local w2 = vm:spawn_worker()
        local o = lcs.open_key(src, w2, -1, ROOT .. "\\Blocking", lcs.KEY_ALL_ACCESS)
        t:assert(o.ret >= 0, "the second worker opens the key: " .. sys.errname(o.errno or 0))
        local n = lcs.notify(nil, w2, o.ret, lcs.NOTIFY.ALL, false)
        t:assert_eq(n.ret, 0, "and arms a watch on a blocking fd")
        local pending = lcs.read_events_async(w2, o.ret, 4096)
        local fd = open_nb(ROOT .. "\\Blocking")
        lcs.set_value(src, w, fd, "Wakes", lcs.TYPE.DWORD, lcs.dword(1))
        local got = pending:await()
        t:assert(got.ret > 0, "the blocked read returned once an event arrived: " ..
            sys.errname(got.errno or 0))
        t:assert_eq(got.events[1] and got.events[1].name, "Wakes",
            "with the record that woke it")
        sys.close(w, fd); sys.close(w2, o.ret)
        w2:kill(); w2:join()
    end)

-- ---- the subtree form -------------------------------------------------

test("a subtree watch's records carry the path from the watched key down",
    { spec = "PKM *watch.record.subtree-records-carry-relative-path" }, function(t)
        local watched = open_nb(ROOT .. "\\Subtree")
        arm(t, watched, true)
        local deep = open_nb(ROOT .. "\\Subtree\\A\\B")
        lcs.set_value(src, w, deep, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local r = lcs.read_events(nil, w, watched, 4096)
        local raw = r.out_bufs[1]:sub(1, r.ret)
        local total_len, etype, name_len = string.unpack("<I4I2I2", raw)
        t:assert_eq(etype, lcs.WATCH.VALUE_SET, "VALUE_SET")
        local depth, at = string.unpack("<I2", raw, HDR + name_len + 1)
        t:assert_eq(depth, 2, "path_depth follows the name")
        local comps = {}
        for _ = 1, depth do
            local clen; clen, at = string.unpack("<I2", raw, at)
            comps[#comps + 1] = raw:sub(at, at + clen - 1)
            at = at + clen
        end
        t:assert_eq(table.concat(comps, "/"), "A/B",
            "locating the changed key relative to the watched one")
        t:assert_eq(total_len, at - 1, "and total_len covers the appended fields")
        sys.close(w, deep); sys.close(w, watched)
    end)

test("path_depth counts components from the watched key, zero on the key itself",
    { spec = "PKM *watch.record.path-depth-counts-from-watched-key" }, function(t)
        local watched = open_nb(ROOT .. "\\Subtree")
        arm(t, watched, true)
        lcs.set_value(src, w, watched, "OnMe", lcs.TYPE.DWORD, lcs.dword(1))
        local own = lcs.drain_events(w, watched)
        t:assert_eq(#own, 1, "a change on the watched key: " .. lcs.event_summary(own))
        t:assert_eq(own[1].depth, 0, "path_depth zero means the watched key itself")
        t:assert_eq(#own[1].components, 0, "so it names no components")

        local a = open_nb(ROOT .. "\\Subtree\\A")
        lcs.set_value(src, w, a, "OnChild", lcs.TYPE.DWORD, lcs.dword(1))
        local one = lcs.drain_events(w, watched)
        t:assert_eq(one[1] and one[1].depth, 1, "one component down is depth 1")

        local b = open_nb(ROOT .. "\\Subtree\\A\\B")
        lcs.set_value(src, w, b, "OnGrandchild", lcs.TYPE.DWORD, lcs.dword(1))
        local two = lcs.drain_events(w, watched)
        t:assert_eq(two[1] and two[1].depth, 2, "two components down is depth 2")
        sys.close(w, a); sys.close(w, b); sys.close(w, watched)
    end)

test("path components are length-prefixed rather than joined with a separator",
    { spec = "PKM *watch.record.path-components-are-length-prefixed" }, function(t)
        -- A value name may contain a backslash, which is exactly why a
        -- concatenated path string would be ambiguous.
        local watched = open_nb(ROOT .. "\\Subtree")
        arm(t, watched, true)
        local a = open_nb(ROOT .. "\\Subtree\\A")
        local odd = "Wei\\rd"
        local s = lcs.set_value(src, w, a, odd, lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "a value name containing a backslash is accepted: " ..
            sys.errname(s.errno or 0))
        local r = lcs.read_events(nil, w, watched, 4096)
        local raw = r.out_bufs[1]:sub(1, r.ret)
        local _, _, name_len = string.unpack("<I4I2I2", raw)
        t:assert_eq(raw:sub(HDR + 1, HDR + name_len), odd,
            "the name is carried by length, backslash and all")
        local depth, at = string.unpack("<I2", raw, HDR + name_len + 1)
        t:assert_eq(depth, 1, "one component")
        local clen; clen, at = string.unpack("<I2", raw, at)
        t:assert_eq(clen, #"A", "each component is a u16 length")
        t:assert_eq(raw:sub(at, at + clen - 1), "A", "followed by that many UTF-8 bytes")
        sys.close(w, a); sys.close(w, watched)
    end)

test("OVERFLOW is the bare eight-byte record even on a subtree watch",
    { spec = "PKM *watch.record.overflow-is-always-the-bare-form" }, function(t)
        local watched = open_nb(ROOT .. "\\Bare")
        arm(t, watched, true)
        local layer_fd = assert(lcs.create_layer(src, w, "BareLayer", { precedence = 30 }))
        lcs.drain_events(w, watched)
        local d = lcs.delete_key(src, w, layer_fd, {})
        t:assert_eq(d.ret, 0, "deleting the layer: " .. sys.errname(d.errno or 0))
        local r = lcs.read_events(nil, w, watched, 4096)
        t:assert_eq(r.ret, HDR, "the whole record is eight bytes")
        local total_len, etype, name_len = string.unpack("<I4I2I2", r.out_bufs[1])
        t:assert_eq(etype, lcs.WATCH.OVERFLOW, "OVERFLOW")
        t:assert_eq(total_len, HDR, "total_len is the header alone")
        t:assert_eq(name_len, 0, "no name, and no path_depth after it")
        sys.close(w, layer_fd); sys.close(w, watched)
    end)

test("KEY_DELETED reaches a subtree watcher in the subtree form, with a path_depth",
    { spec = "PKM *watch.record.key-deleted-uses-the-subtree-form" }, function(t)
        local watched = open_nb(ROOT .. "\\Bare")
        arm(t, watched, true)
        local child = open_nb(ROOT .. "\\Bare\\Child")
        local d = lcs.delete_key(src, w, child, {})
        t:assert_eq(d.ret, 0, "deleting the child: " .. sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, watched)
        local key_deleted
        for _, e in ipairs(ev) do
            if e.type == lcs.WATCH.KEY_DELETED then key_deleted = e end
        end
        t:assert(key_deleted, "the subtree watcher was told the key went: " ..
            lcs.event_summary(ev))
        t:assert_eq(key_deleted.name, "", "KEY_DELETED still carries no name")
        t:assert_eq(key_deleted.depth, 1, "but it does carry a path_depth of its own")
        t:assert_eq(key_deleted.components[1], "Child", "locating the key that went")
        t:assert_eq(key_deleted.total_len, HDR + 2 + 2 + #"Child",
            "so the record is longer than the bare eight-byte form")
        sys.close(w, child); sys.close(w, watched)
    end)

test("an unrepresentable name or component length becomes an OVERFLOW instead",
    { spec = "PKM *watch.record.unrepresentable-length-becomes-overflow",
      covered_by = "kunit:pkm_lcs_kunit_key",
      skip = "name_len and each component length are 16-bit, and " ..
             "MaxPathComponentLength tops out at 1024 while " ..
             "MaxTotalPathLength tops out at 65535, so no key, value or " ..
             "layer name a source or a caller can produce reaches 65536 " ..
             "bytes; the substitution lives in lcs_core's " ..
             "plan_watch_event_record (WatchEventRecordPlan::OverflowInstead)" ..
             "; runs under pkm_lcs_kunit_watch_event_unrepresentable_length_is_overflow" },
    function(t) end)
