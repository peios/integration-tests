-- PKM §5.6.1 — the watch model: a persistent subscription on an open
-- key fd, its seven event types, and the filter categories that select
-- them.
--
-- Everything here is armed with `REG_IOC_NOTIFY` on a key fd and read
-- back with `read()`. Key fds come back blocking, so every fd a case
-- drains is put into O_NONBLOCK first (`lcs.nonblock`); an empty queue
-- then answers EAGAIN instead of wedging the worker.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local ROOT = "Machine\\Software\\Test"

-- One source for the file: a Machine hive, a higher-precedence layer
-- `high`, and the host-seeded fixtures whose layer shape cannot be
-- built through the syscalls (two different key objects at one name).
local src = lcs.source(vm)
src:key(ROOT)
src:seed_layer("high", { precedence = 10, enabled = true })

local unmask_key = src:key(ROOT .. "\\Unmask")
src:value(unmask_key, "Shadowed", lcs.TYPE.DWORD, lcs.dword(1))
src:tombstone(unmask_key, "Shadowed", "high")

local twins_key = src:key(ROOT .. "\\Twins")
src:key("Twins\\Twin", { root = twins_key })              -- base object
src:key("Twins\\Twin", { root = twins_key, layer = "high" }) -- a *different* object

local diff_key = src:key(ROOT .. "\\Diff")
src:value(diff_key, "Winner", lcs.TYPE.DWORD, lcs.dword(9), { layer = "high" })
src:value(diff_key, "Winner", lcs.TYPE.DWORD, lcs.dword(1))

local blanket_key = src:key(ROOT .. "\\Blanket")
src:value(blanket_key, "Alpha", lcs.TYPE.DWORD, lcs.dword(1))
src:value(blanket_key, "Beta", lcs.TYPE.DWORD, lcs.dword(2))

assert(src:register())
src:pump()

local w = vm:spawn_worker()

--- A fresh key under `Test`, opened non-blocking, so cases do not
--- share a key object.
local function fresh(name)
    local c = lcs.create_key(src, w, { path = ROOT .. "\\" .. name })
    assert(c.ret >= 0, "creating " .. name .. ": " .. sys.errname(c.errno or 0))
    lcs.nonblock(w, c.ret)
    return c.ret
end

--- An existing seeded key, opened non-blocking.
local function open_seeded(name)
    local r = lcs.open_watchable(src, w, -1, ROOT .. "\\" .. name, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. name .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

local function arm(t, fd, filter, subtree)
    local n = lcs.notify(nil, w, fd, filter, subtree or false)
    t:assert_eq(n.ret, 0, "REG_IOC_NOTIFY arms: " .. sys.errname(n.errno or 0))
    return n
end

-- ---- persistence, pollability, one watch per fd ----------------------

test("a watch stays armed until the fd closes, with no re-registration",
    { spec = "PKM *watch.model.persistent-until-fd-close" }, function(t)
        local fd = fresh("Persistent")
        arm(t, fd, lcs.NOTIFY.ALL)
        for i = 1, 3 do
            lcs.set_value(src, w, fd, "V" .. i, lcs.TYPE.DWORD, lcs.dword(i))
            local ev = lcs.drain_events(w, fd)
            t:assert_eq(#ev, 1, "write " .. i .. " delivered one record: " ..
                lcs.event_summary(ev))
            t:assert_eq(ev[1] and ev[1].name, "V" .. i,
                "and the watch was still armed without re-registering")
        end
        sys.close(w, fd)
    end)

test("an armed fd is pollable: EPOLLIN reports pending events",
    { spec = "PKM *watch.model.armed-fd-is-pollable" }, function(t)
        local fd = fresh("Pollable")
        arm(t, fd, lcs.NOTIFY.ALL)
        t:assert_eq(lcs.poll_revents(w, fd), 0, "no events pending, so no EPOLLIN")
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(lcs.poll_revents(w, fd) & 0x1, 0x1, "EPOLLIN reports the pending event")
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "and read() returns the structured record")
        t:assert_eq(lcs.poll_revents(w, fd), 0, "the queue is empty again")
        sys.close(w, fd)
    end)

test("each fd carries at most one watch, so a second arm replaces the first",
    { spec = "PKM *watch.model.one-watch-per-fd" }, function(t)
        local fd = fresh("OneWatch")
        arm(t, fd, lcs.NOTIFY.VALUE)
        arm(t, fd, lcs.NOTIFY.SUBKEY)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 0, "the first watch is gone, not held alongside the second: " ..
            lcs.event_summary(ev))
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "and the one watch on the fd is the second: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.SUBKEY_CREATED, "SUBKEY_CREATED")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("re-arming replaces the filter and the subtree flag and keeps the queue",
    { spec = "PKM *watch.model.rearm-replaces-filter-and-keeps-queue" }, function(t)
        local fd = fresh("Rearm")
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.set_value(src, w, fd, "Queued", lcs.TYPE.DWORD, lcs.dword(1))
        arm(t, fd, lcs.NOTIFY.SUBKEY)
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the queued event survived the re-arm: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].name, "Queued", "and it is the one that was queued")
        lcs.set_value(src, w, fd, "After", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(#lcs.drain_events(w, fd), 0,
            "the replacement filter no longer admits value events")
        sys.close(w, fd)
    end)

test("arming with a filter of zero disarms and discards every pending event",
    { spec = "PKM *watch.model.zero-filter-disarms-and-discards" }, function(t)
        local fd = fresh("ZeroFilter")
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.set_value(src, w, fd, "Doomed", lcs.TYPE.DWORD, lcs.dword(1))
        local n = lcs.notify(nil, w, fd, 0, false)
        t:assert_eq(n.ret, 0, "a filter of zero is accepted: " .. sys.errname(n.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 0, "the pending event was discarded: " .. lcs.event_summary(ev))
        lcs.set_value(src, w, fd, "After", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(#lcs.drain_events(w, fd), 0, "and the watch was removed")
        sys.close(w, fd)
    end)

-- ---- filter validation ----------------------------------------------

test("a filter containing an undefined bit is rejected",
    { spec = "PKM *watch.model.undefined-filter-bit-rejected" }, function(t)
        local fd = fresh("BadFilter")
        for _, filter in ipairs({ 0x08, 0x10, 0xFFFFFFFF, lcs.NOTIFY.ALL | 0x80 }) do
            local n = lcs.notify(nil, w, fd, filter, false)
            t:assert_eq(n.errno, sys.E.INVAL,
                ("filter 0x%x is outside REG_NOTIFY_ALL and is rejected"):format(filter))
        end
        sys.close(w, fd)
    end)

test("a subtree flag other than 0 or 1, or non-zero padding, is rejected",
    { spec = "PKM *watch.model.subtree-flag-must-be-zero-or-one" }, function(t)
        local fd = fresh("BadSubtree")
        for _, flag in ipairs({ 2, 3, 255 }) do
            local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, flag)
            t:assert_eq(n.errno, sys.E.INVAL, "subtree = " .. flag .. " is rejected")
        end
        local pad = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, 0, { pad = "\1\0\0" })
        t:assert_eq(pad.errno, sys.E.INVAL, "a non-zero padding byte is rejected the same way")
        sys.close(w, fd)
    end)

-- ---- the seven event types -------------------------------------------

test("VALUE_SET is code 1 and VALUE_DELETED code 2, both naming the value",
    { spec = "PKM *watch.model.event-value-set" }, function(t)
        local fd = fresh("ValueEvents")
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(42))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the write produced one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 1, "REG_WATCH_VALUE_SET is 1")
        t:assert_eq(ev[1].name, "Answer", "and its name field is the value name")
        sys.close(w, fd)
    end)

test("VALUE_DELETED fires when the last entry for a name goes away",
    { spec = "PKM *watch.model.event-value-deleted" }, function(t)
        local fd = fresh("ValueDeleted")
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(42))
        arm(t, fd, lcs.NOTIFY.ALL)
        local d = lcs.delete_value(src, w, fd, "Answer", {})
        t:assert_eq(d.ret, 0, "delete: " .. sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 2, "REG_WATCH_VALUE_DELETED is 2")
        t:assert_eq(ev[1].name, "Answer", "naming the value")
        sys.close(w, fd)
    end)

test("SUBKEY_CREATED is code 3 and SUBKEY_DELETED code 4, naming the subkey",
    { spec = "PKM *watch.model.event-subkey-created" }, function(t)
        local fd = fresh("SubkeyEvents")
        arm(t, fd, lcs.NOTIFY.ALL)
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        t:assert(c.ret >= 0, "create: " .. sys.errname(c.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the create produced one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 3, "REG_WATCH_SUBKEY_CREATED is 3")
        t:assert_eq(ev[1].name, "Child", "naming the subkey")
        local d = lcs.delete_key(src, w, c.ret, {})
        t:assert_eq(d.ret, 0, "delete: " .. sys.errname(d.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the delete produced one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 4, "REG_WATCH_SUBKEY_DELETED is 4")
        t:assert_eq(ev[1].name, "Child", "naming the subkey")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("SUBKEY_DELETED also covers a hiding entry appearing",
    { spec = "PKM *watch.model.event-subkey-deleted" }, function(t)
        local fd = fresh("HideChild")
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        arm(t, fd, lcs.NOTIFY.ALL)
        local h = lcs.hide_key(src, w, c.ret, { layer = "high" })
        t:assert_eq(h.ret, 0, "hide: " .. sys.errname(h.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the hide produced one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.SUBKEY_DELETED,
            "a child key became invisible, which is SUBKEY_DELETED")
        t:assert_eq(ev[1].name, "Child", "naming the subkey")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("SD_CHANGED is code 5 and carries an empty name",
    { spec = "PKM *watch.model.event-sd-changed" }, function(t)
        local fd = fresh("SdChanged")
        arm(t, fd, lcs.NOTIFY.ALL)
        local s = lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        t:assert_eq(s.ret, 0, "set_security: " .. sys.errname(s.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 5, "REG_WATCH_SD_CHANGED is 5")
        t:assert_eq(ev[1].name, "", "the watched key's descriptor changed; the name is empty")
        sys.close(w, fd)
    end)

test("KEY_DELETED is code 6, carries an empty name, and reaches the watched key",
    { spec = "PKM *watch.model.event-key-deleted" }, function(t)
        local fd = fresh("KeyDeleted")
        arm(t, fd, lcs.NOTIFY.ALL)
        local d = lcs.delete_key(src, w, fd, {})
        t:assert_eq(d.ret, 0, "delete: " .. sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 6, "REG_WATCH_KEY_DELETED is 6")
        t:assert_eq(ev[1].name, "", "the watched key itself went; the name is empty")
        sys.close(w, fd)
    end)

test("OVERFLOW is code 7 and carries an empty name",
    { spec = "PKM *watch.model.event-overflow" }, function(t)
        local fd = fresh("Overflow")
        arm(t, fd, lcs.NOTIFY.ALL)
        -- Deleting a layer is a recovery-dispatch operation (§5.6.3):
        -- every armed watch on the source is told its record is
        -- incomplete rather than being given an exact diff.
        local layer_fd = assert(lcs.create_layer(src, w, "Doomed", { precedence = 20 }))
        lcs.drain_events(w, fd)
        local d = lcs.delete_key(src, w, layer_fd, {})
        t:assert_eq(d.ret, 0, "deleting the layer key deletes the layer: " ..
            sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert(#ev >= 1, "an OVERFLOW arrived: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, 7, "REG_WATCH_OVERFLOW is 7")
        t:assert_eq(ev[1].name, "", "and it carries no name")
        sys.close(w, layer_fd); sys.close(w, fd)
    end)

test("the three no-name events carry no name at all",
    { spec = "PKM *watch.model.no-name-events-reject-a-name" }, function(t)
        local fd = fresh("NoName")
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        local layer_fd = assert(lcs.create_layer(src, w, "NoNameLayer", { precedence = 21 }))
        lcs.delete_key(src, w, layer_fd, {})
        lcs.delete_key(src, w, fd, {})
        local ev = lcs.drain_events(w, fd)
        local seen = {}
        for _, e in ipairs(ev) do
            seen[e.type] = true
            if e.type == lcs.WATCH.SD_CHANGED or e.type == lcs.WATCH.KEY_DELETED
                or e.type == lcs.WATCH.OVERFLOW then
                t:assert_eq(e.name, "",
                    (lcs.WATCH_NAME[e.type] or "?") .. " was emitted with no name")
                t:assert_eq(e.total_len, 8,
                    (lcs.WATCH_NAME[e.type] or "?") ..
                    " is the bare eight-byte record, so name_len is zero")
            end
        end
        t:assert(seen[lcs.WATCH.SD_CHANGED] and seen[lcs.WATCH.KEY_DELETED]
            and seen[lcs.WATCH.OVERFLOW],
            "all three no-name events were observed: " .. lcs.event_summary(ev))
        sys.close(w, layer_fd); sys.close(w, fd)
    end)

-- ---- filters ---------------------------------------------------------

test("the filter selects event categories, not individual event types",
    { spec = "PKM *watch.model.filter-selects-categories" }, function(t)
        -- REG_NOTIFY_VALUE admits both of the value events and neither
        -- of the subkey ones: the bit is a category, not a type.
        local fd = fresh("Categories")
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        arm(t, fd, lcs.NOTIFY.VALUE)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(2))
        lcs.delete_value(src, w, fd, "Answer", {})
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 2, "one bit admitted both value events and no subkey event: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.VALUE_SET, "VALUE_SET")
        t:assert_eq(ev[2] and ev[2].type, lcs.WATCH.VALUE_DELETED, "VALUE_DELETED")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("REG_NOTIFY_VALUE (0x01) admits VALUE_SET and VALUE_DELETED and nothing else",
    { spec = "PKM *watch.model.filter-value-admits-value-events" }, function(t)
        t:assert_eq(lcs.NOTIFY.VALUE, 0x01, "REG_NOTIFY_VALUE is 0x01")
        local fd = fresh("FilterValue")
        arm(t, fd, lcs.NOTIFY.VALUE)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "only the value event was admitted: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.VALUE_SET, "VALUE_SET")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("REG_NOTIFY_SUBKEY (0x02) admits SUBKEY_CREATED and SUBKEY_DELETED",
    { spec = "PKM *watch.model.filter-subkey-admits-subkey-events" }, function(t)
        t:assert_eq(lcs.NOTIFY.SUBKEY, 0x02, "REG_NOTIFY_SUBKEY is 0x02")
        local fd = fresh("FilterSubkey")
        arm(t, fd, lcs.NOTIFY.SUBKEY)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        lcs.delete_key(src, w, c.ret, {})
        lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 2, "both subkey events and nothing else: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.SUBKEY_CREATED, "SUBKEY_CREATED")
        t:assert_eq(ev[2] and ev[2].type, lcs.WATCH.SUBKEY_DELETED, "SUBKEY_DELETED")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("REG_NOTIFY_SD (0x04) admits SD_CHANGED",
    { spec = "PKM *watch.model.filter-sd-admits-sd-changed" }, function(t)
        t:assert_eq(lcs.NOTIFY.SD, 0x04, "REG_NOTIFY_SD is 0x04")
        local fd = fresh("FilterSd")
        arm(t, fd, lcs.NOTIFY.SD)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "only SD_CHANGED was admitted: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.SD_CHANGED, "SD_CHANGED")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("REG_NOTIFY_ALL (0x07) admits all three categories",
    { spec = "PKM *watch.model.filter-all-admits-all-three-categories" }, function(t)
        t:assert_eq(lcs.NOTIFY.ALL, 0x07, "REG_NOTIFY_ALL is 0x07")
        t:assert_eq(lcs.NOTIFY.ALL, lcs.NOTIFY.VALUE | lcs.NOTIFY.SUBKEY | lcs.NOTIFY.SD,
            "and it is exactly the three category bits")
        local fd = fresh("FilterAll")
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        lcs.set_security(src, w, fd, lcs.SI.DACL, lcs.permissive_sd())
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 3, "one of each category arrived: " .. lcs.event_summary(ev))
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("KEY_DELETED and OVERFLOW are delivered whatever the filter says",
    { spec = "PKM *watch.model.key-deleted-and-overflow-bypass-the-filter" }, function(t)
        -- A filter of SD alone admits no value or subkey event, and
        -- neither of these two is in any category.
        local doomed = fresh("BypassKey")
        arm(t, doomed, lcs.NOTIFY.SD)
        lcs.delete_key(src, w, doomed, {})
        local ev = lcs.drain_events(w, doomed)
        t:assert_eq(#ev, 1, "KEY_DELETED arrived under a filter that names no category for it: "
            .. lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.KEY_DELETED, "KEY_DELETED")
        sys.close(w, doomed)

        local fd = fresh("BypassOverflow")
        arm(t, fd, lcs.NOTIFY.SD)
        local layer_fd = assert(lcs.create_layer(src, w, "BypassLayer", { precedence = 22 }))
        lcs.drain_events(w, fd)
        lcs.delete_key(src, w, layer_fd, {})
        ev = lcs.drain_events(w, fd)
        t:assert(#ev >= 1, "OVERFLOW arrived under the same filter: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.OVERFLOW, "OVERFLOW")
        sys.close(w, layer_fd); sys.close(w, fd)
    end)

-- ---- what a watch observes -------------------------------------------

test("a watcher sees effective state change, not which layer won",
    { spec = "PKM *watch.model.reports-effective-state-not-layer-mechanics" }, function(t)
        -- `Unmask` holds a base value masked by a tombstone in `high`.
        -- Removing the tombstone surfaces the lower-precedence value:
        -- the watcher is told VALUE_SET, and nothing in the record
        -- names a layer.
        local fd = open_seeded("Unmask")
        arm(t, fd, lcs.NOTIFY.ALL)
        local before = lcs.query_value(src, w, fd, "Shadowed")
        t:assert_eq(before.errno, sys.E.NOENT, "the tombstone masks the value to start with")
        local d = lcs.delete_value(src, w, fd, "Shadowed", { layer = "high" })
        t:assert_eq(d.ret, 0, "removing the tombstone: " .. sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.VALUE_SET,
            "the value that surfaced underneath is reported as VALUE_SET")
        t:assert_eq(ev[1].name, "Shadowed", "named by the value, not by the layer")
        t:assert_eq(ev[1].total_len, 8 + #"Shadowed",
            "the record carries the name and nothing about layer mechanics")
        sys.close(w, fd)
    end)

test("events are computed by diffing effective state, so a masked deletion is silent",
    { spec = "PKM *watch.model.computed-by-diffing-effective-state" }, function(t)
        -- `Diff\Winner` is written in both layers and `high` wins.
        -- Removing the losing base entry changes no effective state,
        -- so the diff is empty and nothing is dispatched.
        local fd = open_seeded("Diff")
        arm(t, fd, lcs.NOTIFY.ALL)
        local d = lcs.delete_value(src, w, fd, "Winner", {})
        t:assert_eq(d.ret, 0, "the base-layer entry goes: " .. sys.errname(d.errno or 0))
        local q = lcs.query_value(src, w, fd, "Winner")
        t:assert_eq(q.data, lcs.dword(9), "the higher-precedence layer still wins")
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 0, "nothing effective changed, so nothing was dispatched: " ..
            lcs.event_summary(ev))
        sys.close(w, fd)
    end)

-- Kernel bug: REG_IOC_SET_VALUE dispatches VALUE_SET unconditionally on
-- the written name — key_fd.c sets `late_effect.event_type =
-- REG_WATCH_VALUE_SET` before the round trip and never compares
-- effective state before against after, unlike REG_IOC_DELETE_VALUE,
-- which derives the type from a snapshot diff
-- (pkm_lcs_key_fd_delete_value_watch_event_type). Observed: VALUE_SET
-- for a write that a higher-precedence layer completely masks.
test("a write that changes no effective state dispatches nothing",
    { spec = "PKM *watch.model.computed-by-diffing-effective-state",
      tags = { "known-bug" } }, function(t)
        local fd = open_seeded("Diff")
        lcs.set_value(src, w, fd, "Masked", lcs.TYPE.DWORD, lcs.dword(9),
            { layer = "high" })
        arm(t, fd, lcs.NOTIFY.ALL)
        local s = lcs.set_value(src, w, fd, "Masked", lcs.TYPE.DWORD, lcs.dword(2))
        t:assert_eq(s.ret, 0, "the base-layer write succeeds: " .. sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "Masked")
        t:assert_eq(q.data, lcs.dword(9), "the higher-precedence layer still wins")
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 0, "nothing effective changed, so nothing was dispatched: " ..
            lcs.event_summary(ev))
        sys.close(w, fd)
    end)

test("VALUE_SET fires on a write and on a tombstone being removed",
    { spec = "PKM *watch.model.value-set-fires-on-write-unmask-or-layer-deletion" },
    function(t)
        local fd = fresh("ValueSetCauses")
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "a write fires VALUE_SET: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.VALUE_SET, "VALUE_SET")

        local b = lcs.blanket_tombstone(src, w, fd, "high", true)
        t:assert_eq(b.ret, 0, "a blanket tombstone masks it: " .. sys.errname(b.errno or 0))
        lcs.drain_events(w, fd)
        local c = lcs.blanket_tombstone(src, w, fd, "high", false)
        t:assert_eq(c.ret, 0, "removing it: " .. sys.errname(c.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the unmasked value fires VALUE_SET: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.VALUE_SET, "VALUE_SET")
        t:assert_eq(ev[1].name, "Answer", "naming the value that became visible")
        sys.close(w, fd)
    end)

test("VALUE_DELETED fires when the last entry goes and when a blanket masks the name",
    { spec = "PKM *watch.model.value-deleted-fires-on-last-entry-gone-or-masked" },
    function(t)
        local fd = fresh("ValueDeletedCauses")
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.delete_value(src, w, fd, "Answer", {})
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the last entry going fires VALUE_DELETED: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.VALUE_DELETED, "VALUE_DELETED")

        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        lcs.drain_events(w, fd)
        local b = lcs.blanket_tombstone(src, w, fd, "high", true)
        t:assert_eq(b.ret, 0, "blanket: " .. sys.errname(b.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "a blanket masking the name fires VALUE_DELETED: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.VALUE_DELETED, "VALUE_DELETED")
        t:assert_eq(ev[1].name, "Answer", "naming the value")
        sys.close(w, fd)
    end)

-- Kernel bug: writing REG_TOMBSTONE over a lower-precedence value makes
-- the value unreadable (query answers ENOENT) but dispatches VALUE_SET
-- rather than VALUE_DELETED. The diff appears to be taken over the
-- layer's own entry rather than over effective state.
test("VALUE_DELETED fires when a tombstone masks every entry",
    { spec = "PKM *watch.model.value-deleted-fires-on-last-entry-gone-or-masked",
      tags = { "known-bug" } }, function(t)
        local fd = fresh("TombstoneMasks")
        lcs.set_value(src, w, fd, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        arm(t, fd, lcs.NOTIFY.ALL)
        local s = lcs.set_value(src, w, fd, "Answer", lcs.TYPE.TOMBSTONE, "",
            { layer = "high" })
        t:assert_eq(s.ret, 0, "writing the tombstone: " .. sys.errname(s.errno or 0))
        local q = lcs.query_value(src, w, fd, "Answer")
        t:assert_eq(q.errno, sys.E.NOENT, "the value is masked to a reader")
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "one record: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.VALUE_DELETED,
            "a tombstone masking every entry fires VALUE_DELETED")
        sys.close(w, fd)
    end)

test("subkey events cover a path entry appearing and being removed",
    { spec = "PKM *watch.model.subkey-events-cover-path-and-hiding-entries" }, function(t)
        local fd = fresh("PathEntries")
        arm(t, fd, lcs.NOTIFY.SUBKEY)
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the path entry appearing fires SUBKEY_CREATED: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.SUBKEY_CREATED, "SUBKEY_CREATED")
        lcs.delete_key(src, w, c.ret, {})
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the path entry being removed fires SUBKEY_DELETED: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.SUBKEY_DELETED, "SUBKEY_DELETED")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

-- Kernel bug: creating the hiding entry dispatches SUBKEY_DELETED, but
-- removing it dispatches nothing at all, even though the concealed key
-- is enumerable again immediately afterwards. Half of the "both halves
-- of the naming model" claim is missing. In
-- pkm_lcs_key_fd_delete_key_from_args_for_token the visibility events
-- are published only when `!post_lookup.target_still_named` — when the
-- *fd's own* GUID stopped being named at the path. Removing a hiding
-- entry leaves the fd's key named, so the branch is skipped.
test("removing a hiding entry that concealed a key fires SUBKEY_CREATED",
    { spec = "PKM *watch.model.subkey-events-cover-path-and-hiding-entries",
      tags = { "known-bug" } }, function(t)
        local fd = fresh("HidingEntries")
        local c = lcs.create_key(src, w, { parent_fd = fd, path = "Child" })
        arm(t, fd, lcs.NOTIFY.SUBKEY)
        local h = lcs.hide_key(src, w, c.ret, { layer = "high" })
        t:assert_eq(h.ret, 0, "hide: " .. sys.errname(h.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the hiding entry appearing fires SUBKEY_DELETED: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.SUBKEY_DELETED, "SUBKEY_DELETED")

        local d = lcs.delete_key(src, w, c.ret, { layer = "high" })
        t:assert_eq(d.ret, 0, "removing the hiding entry: " .. sys.errname(d.errno or 0))
        local back = lcs.enum_subkeys(src, w, fd, 0)
        t:assert_eq(back.name, "Child", "the concealed key is visible again")
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the hiding entry being removed fires SUBKEY_CREATED: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.SUBKEY_CREATED, "SUBKEY_CREATED")
        sys.close(w, c.ret); sys.close(w, fd)
    end)

test("replacing the key at a name with a different object is delete then create",
    { spec = "PKM *watch.model.key-replacement-is-delete-then-create" }, function(t)
        -- `Twins\Twin` names one key object in `base` and a different
        -- one in `high`. Removing the `high` path entry replaces the
        -- effective child with a different GUID at the same name.
        local fd = open_seeded("Twins")
        local before = lcs.open_key(src, w, fd, "Twin", lcs.KEY_ALL_ACCESS)
        t:assert(before.ret >= 0, "the high-layer twin resolves: " ..
            sys.errname(before.errno or 0))
        arm(t, fd, lcs.NOTIFY.SUBKEY)
        local d = lcs.delete_key(src, w, before.ret, { layer = "high" })
        t:assert_eq(d.ret, 0, "removing the winning path entry: " ..
            sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 2, "the diff says a key went and a key came: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1] and ev[1].type, lcs.WATCH.SUBKEY_DELETED, "SUBKEY_DELETED first")
        t:assert_eq(ev[2] and ev[2].type, lcs.WATCH.SUBKEY_CREATED, "then SUBKEY_CREATED")
        t:assert_eq(ev[1] and ev[1].name, "Twin", "both naming the same child name")
        t:assert_eq(ev[2] and ev[2].name, "Twin", "both naming the same child name")
        sys.close(w, before.ret); sys.close(w, fd)
    end)

-- ---- blanket tombstones ----------------------------------------------

test("a blanket tombstone expands to one event per value name",
    { spec = "PKM *watch.model.blanket-tombstone-expands-to-per-value-events" },
    function(t)
        local fd = open_seeded("Blanket")
        arm(t, fd, lcs.NOTIFY.ALL)
        local b = lcs.blanket_tombstone(src, w, fd, "high", true)
        t:assert_eq(b.ret, 0, "writing the blanket: " .. sys.errname(b.errno or 0))
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 2, "one VALUE_DELETED per name it newly masks: " ..
            lcs.event_summary(ev))
        local names = {}
        for _, e in ipairs(ev) do
            t:assert_eq(e.type, lcs.WATCH.VALUE_DELETED, "VALUE_DELETED")
            names[e.name] = true
        end
        t:assert(names.Alpha and names.Beta, "naming both masked values")

        local r = lcs.blanket_tombstone(src, w, fd, "high", false)
        t:assert_eq(r.ret, 0, "removing the blanket: " .. sys.errname(r.errno or 0))
        ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 2, "one VALUE_SET per name that became visible: " ..
            lcs.event_summary(ev))
        for _, e in ipairs(ev) do
            t:assert_eq(e.type, lcs.WATCH.VALUE_SET, "VALUE_SET")
        end
        sys.close(w, fd)
    end)

test("a watcher never learns that a blanket tombstone exists",
    { spec = "PKM *watch.model.blanket-tombstone-never-surfaces-as-such" }, function(t)
        local fd = fresh("BlanketOpaque")
        lcs.set_value(src, w, fd, "Only", lcs.TYPE.DWORD, lcs.dword(1))
        arm(t, fd, lcs.NOTIFY.ALL)
        lcs.blanket_tombstone(src, w, fd, "high", true)
        local ev = lcs.drain_events(w, fd)
        t:assert_eq(#ev, 1, "the per-value view is the only view: " .. lcs.event_summary(ev))
        for _, e in ipairs(ev) do
            t:assert(e.type >= 1 and e.type <= 7,
                "no event type outside the seven exists for a blanket")
            t:assert_eq(e.type, lcs.WATCH.VALUE_DELETED,
                "the blanket surfaces only as the per-value effect it had")
            t:assert_eq(e.name, "Only", "named by the value, never by the layer or the key")
        end
        sys.close(w, fd)
    end)
