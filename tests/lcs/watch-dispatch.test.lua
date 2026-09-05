-- PKM §5.6.3, first half — which armed watches hear about a mutation.
-- Dispatch is computed from the GUID on the fd and from the ancestor
-- chain captured when that fd was opened, never from a path string
-- resolved at the moment of the event.
--
-- The transaction batches, recovery dispatch and source restart of the
-- same article are in watch-dispatch-recovery.test.lua.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local SOFTWARE = "Machine\\Software"
local ROOT = SOFTWARE .. "\\Test"

local src = lcs.source(vm)
src:seed_param("MaxSubtreeWatchDepth", 0) -- the compiled-in default, made writable
src:seed_layer("high", { precedence = 10, enabled = true })
src:key(ROOT)
src:key(ROOT .. "\\Identity\\Other")
src:key(ROOT .. "\\Chain\\A\\B")
src:key(ROOT .. "\\Relative\\A\\B")
src:key(ROOT .. "\\Stale\\A\\B")
src:key(ROOT .. "\\Depth\\A\\B\\C")
src:key(ROOT .. "\\Costs\\A\\B\\C")
src:key(ROOT .. "\\Hidden\\Leaf")
src:key(ROOT .. "\\LinkTarget\\Deep")
src:symlink(ROOT .. "\\Link", ROOT .. "\\LinkTarget\\Deep")

-- Two different key objects at one name, one per layer: `high` wins.
local twins = src:key(ROOT .. "\\Twins")
local base_twin = src:key("Twins\\Twin", { root = twins })
local high_twin = src:key("Twins\\Twin", { root = twins, layer = "high" })

assert(src:register())
src:pump()

local w = vm:spawn_worker()

local function open_nb(path, parent_fd)
    local r = lcs.open_key(src, w, parent_fd or -1, path, lcs.KEY_ALL_ACCESS)
    assert(r.ret >= 0, "opening " .. path .. ": " .. sys.errname(r.errno or 0))
    lcs.nonblock(w, r.ret)
    return r.ret
end

local function arm(t, fd, subtree)
    local n = lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, subtree or false)
    t:assert_eq(n.ret, 0, "REG_IOC_NOTIFY arms: " .. sys.errname(n.errno or 0))
end

-- ---- a watch is bound to an object -----------------------------------

test("a watch is registered against the GUID on the fd it was armed through",
    { spec = "PKM *watch.dispatch.registered-against-the-fd-guid" }, function(t)
        local mine = open_nb(ROOT .. "\\Identity")
        local other = open_nb(ROOT .. "\\Identity\\Other")
        arm(t, mine)
        lcs.set_value(src, w, other, "Elsewhere", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, mine)
        t:assert_eq(#ev, 0, "a change to another object is not this watch's business: " ..
            lcs.event_summary(ev))
        lcs.set_value(src, w, mine, "Mine", lcs.TYPE.DWORD, lcs.dword(1))
        ev = lcs.drain_events(w, mine)
        t:assert_eq(#ev, 1, "a change to that object is: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "Mine", "naming the value that changed")
        sys.close(w, other); sys.close(w, mine)
    end)

test("dispatch is computed from identity, not from a path resolved at event time",
    { spec = "PKM *watch.dispatch.computed-from-identity-and-captured-ancestry" },
    function(t)
        -- Hiding the key makes its path stop resolving. The watch is
        -- registered against the object, so mutations through the fd
        -- that already exists still find it.
        local leaf = open_nb(ROOT .. "\\Hidden\\Leaf")
        arm(t, leaf)
        local h = lcs.hide_key(src, w, leaf, { layer = "high" })
        t:assert_eq(h.ret, 0, "hiding it: " .. sys.errname(h.errno or 0))
        local gone = lcs.open_key(src, w, -1, ROOT .. "\\Hidden\\Leaf", lcs.RIGHT.KEY_READ)
        t:assert_eq(gone.errno, sys.E.NOENT, "the path no longer resolves")
        lcs.drain_events(w, leaf)
        lcs.set_value(src, w, leaf, "StillMine", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, leaf)
        t:assert_eq(#ev, 1, "and the watch still hears about the object: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "StillMine", "no path was resolved to find it")
        -- Put the fixture back for the cases below.
        lcs.delete_key(src, w, leaf, { layer = "high" })
        sys.close(w, leaf)
    end)

test("a watch does not follow the path when a different key becomes visible there",
    { spec = "PKM *watch.dispatch.watch-does-not-follow-the-path" }, function(t)
        local parent = open_nb(ROOT .. "\\Twins")
        local winner = open_nb(ROOT .. "\\Twins\\Twin") -- the `high` object
        arm(t, winner)
        local d = lcs.delete_key(src, w, winner, { layer = "high" })
        t:assert_eq(d.ret, 0, "removing the winning path entry: " .. sys.errname(d.errno or 0))
        local told = lcs.drain_events(w, winner)
        t:assert_eq(#told, 1, "the watcher is told its key went: " .. lcs.event_summary(told))
        t:assert_eq(told[1].type, lcs.WATCH.KEY_DELETED, "KEY_DELETED")

        local now = open_nb(ROOT .. "\\Twins\\Twin") -- the `base` object
        lcs.set_value(src, w, now, "OnTheOtherObject", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, winner)
        t:assert_eq(#ev, 0,
            "the watch did not move to the key now at that path: " .. lcs.event_summary(ev))
        sys.close(w, now); sys.close(w, winner); sys.close(w, parent)
    end)

test("a watch on a key that later appears at a path receives nothing from the old one",
    { spec = "PKM *watch.dispatch.new-key-at-the-same-path-receives-nothing" }, function(t)
        -- The previous case removed the `high` entry, so `Twin` is the
        -- base object now; arm a watch on it and check the history of
        -- the object that used to hold the name does not reach it.
        local now = open_nb(ROOT .. "\\Twins\\Twin")
        arm(t, now)
        local old = lcs.open_key(src, w, -1, ROOT .. "\\Twins\\Twin", lcs.KEY_ALL_ACCESS)
        t:assert(old.ret >= 0, "reopening: " .. sys.errname(old.errno or 0))
        -- Re-create the `high` object over the name: the new watcher is
        -- on the base object and hears nothing about the other one.
        local h = lcs.create_key(src, w, { path = ROOT .. "\\Twins\\Twin", layer = "high" })
        local ev = lcs.drain_events(w, now)
        for _, e in ipairs(ev) do
            t:assert(e.type == lcs.WATCH.KEY_DELETED,
                "nothing but its own object's fate reaches this watch: " ..
                lcs.event_summary(ev))
        end
        if h.ret >= 0 then sys.close(w, h.ret) end
        sys.close(w, old.ret); sys.close(w, now)
    end)

test("hiding a watched key delivers KEY_DELETED but leaves the watch armed",
    { spec = "PKM *watch.dispatch.hiding-keeps-the-watch-armed" }, function(t)
        local leaf = open_nb(ROOT .. "\\Hidden\\Leaf")
        arm(t, leaf)
        local h = lcs.hide_key(src, w, leaf, { layer = "high" })
        t:assert_eq(h.ret, 0, "hiding it: " .. sys.errname(h.errno or 0))
        local ev = lcs.drain_events(w, leaf)
        t:assert_eq(#ev, 1, "KEY_DELETED was delivered: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].type, lcs.WATCH.KEY_DELETED, "KEY_DELETED")
        lcs.set_value(src, w, leaf, "WhileHidden", lcs.TYPE.DWORD, lcs.dword(1))
        ev = lcs.drain_events(w, leaf)
        t:assert_eq(#ev, 1, "the watch was not removed: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "WhileHidden", "it is still delivering")
        lcs.delete_key(src, w, leaf, { layer = "high" })
        sys.close(w, leaf)
    end)

test("events resume when the key reappears, with no re-emergence event",
    { spec = "PKM *watch.dispatch.events-resume-when-the-key-reappears" }, function(t)
        local leaf = open_nb(ROOT .. "\\Hidden\\Leaf")
        arm(t, leaf)
        lcs.hide_key(src, w, leaf, { layer = "high" })
        lcs.drain_events(w, leaf)
        local d = lcs.delete_key(src, w, leaf, { layer = "high" })
        t:assert_eq(d.ret, 0, "deleting the hiding layer's entry: " ..
            sys.errname(d.errno or 0))
        local back = lcs.open_key(src, w, -1, ROOT .. "\\Hidden\\Leaf", lcs.RIGHT.KEY_READ)
        t:assert(back.ret >= 0, "the key is at its original path again: " ..
            sys.errname(back.errno or 0))
        lcs.drain_events(w, leaf)
        lcs.set_value(src, w, leaf, "Resumed", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, leaf)
        t:assert_eq(#ev, 1, "events resume on the same watch: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].name, "Resumed", "with the same GUID behind it")
        sys.close(w, back.ret); sys.close(w, leaf)
    end)

test("there is no re-emergence event: the watcher simply sees the key active again",
    { spec = "PKM *watch.dispatch.no-re-emergence-event" }, function(t)
        local leaf = open_nb(ROOT .. "\\Hidden\\Leaf")
        arm(t, leaf)
        lcs.hide_key(src, w, leaf, { layer = "high" })
        local hidden = lcs.drain_events(w, leaf)
        t:assert_eq(#hidden, 1, "hiding delivered KEY_DELETED: " .. lcs.event_summary(hidden))
        local d = lcs.delete_key(src, w, leaf, { layer = "high" })
        t:assert_eq(d.ret, 0, "removing the hiding entry: " .. sys.errname(d.errno or 0))
        local ev = lcs.drain_events(w, leaf)
        t:assert_eq(#ev, 0, "no event marks the re-emergence itself: " ..
            lcs.event_summary(ev))
        sys.close(w, leaf)
    end)

-- ---- the ancestor chain ----------------------------------------------

test("an absolute open captures the ancestor chain the walk resolved",
    { spec = "PKM *watch.dispatch.ancestor-chain-captured-at-open" }, function(t)
        local watched = open_nb(ROOT .. "\\Chain")
        arm(t, watched, true)
        local deep = open_nb(ROOT .. "\\Chain\\A\\B")
        lcs.set_value(src, w, deep, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, watched)
        t:assert_eq(#ev, 1, "the subtree watch heard it: " .. lcs.event_summary(ev))
        t:assert_eq(ev[1].depth, 2, "through the chain the open retained")
        t:assert_eq(table.concat(ev[1].components, "/"), "A/B",
            "root GUID through parent GUID to the key itself")
        sys.close(w, deep); sys.close(w, watched)
    end)

test("a relative open copies the parent fd's chain and extends it",
    { spec = "PKM *watch.dispatch.relative-open-extends-the-parent-chain" }, function(t)
        -- The watch sits two levels above the fd the relative open
        -- started from, so only a copied-and-extended chain reaches it.
        local software = open_nb(SOFTWARE)
        arm(t, software, true)
        local parent = open_nb(ROOT .. "\\Relative")
        local relative = open_nb("A\\B", parent)
        lcs.drain_events(w, software)
        lcs.set_value(src, w, relative, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, software)
        t:assert_eq(#ev, 1, "the ancestor above the relative walk heard it: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].depth, 4, "the chain runs the whole way down")
        t:assert_eq(table.concat(ev[1].components, "/"), "Test/Relative/A/B",
            "the parent's components plus the ones the relative walk resolved")
        sys.close(w, relative); sys.close(w, parent); sys.close(w, software)
    end)

test("an open that followed a symlink records the chain of the resolved path",
    { spec = "PKM *watch.dispatch.symlink-open-records-the-resolved-chain" }, function(t)
        local target = open_nb(ROOT .. "\\LinkTarget")
        arm(t, target, true)
        local through_link = open_nb(ROOT .. "\\Link")
        lcs.set_value(src, w, through_link, "ViaLink", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, target)
        t:assert_eq(#ev, 1, "a watch on the target's parent hears it: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].depth, 1, "at the target's real position in the tree")
        t:assert_eq(ev[1].components[1], "Deep", "named by the target, not by the link")
        sys.close(w, through_link); sys.close(w, target)
    end)

test("a stale ancestor still receives subtree events from descendants opened through it",
    { spec = "PKM *watch.dispatch.stale-ancestor-still-receives-subtree-events" },
    function(t)
        local ancestor = open_nb(ROOT .. "\\Stale\\A")
        arm(t, ancestor, true)
        local deep = open_nb(ROOT .. "\\Stale\\A\\B")
        local h = lcs.hide_key(src, w, ancestor, { layer = "high" })
        t:assert_eq(h.ret, 0, "hiding the ancestor: " .. sys.errname(h.errno or 0))
        local gone = lcs.open_key(src, w, -1, ROOT .. "\\Stale\\A", lcs.RIGHT.KEY_READ)
        t:assert_eq(gone.errno, sys.E.NOENT, "the ancestor no longer resolves at its path")
        lcs.drain_events(w, ancestor)
        lcs.set_value(src, w, deep, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, ancestor)
        t:assert_eq(#ev, 1, "dispatch used the captured chain, not a re-resolution: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].depth, 1, "with the relative path it captured")
        t:assert_eq(ev[1].components[1], "B", "naming the descendant that changed")
        lcs.delete_key(src, w, ancestor, { layer = "high" })
        sys.close(w, deep); sys.close(w, ancestor)
    end)

-- ---- the algorithm ----------------------------------------------------

test("a watcher on the mutated key itself is queued the event at depth zero",
    { spec = "PKM *watch.dispatch.direct-watchers-receive-depth-zero" }, function(t)
        local direct = open_nb(ROOT .. "\\Chain\\A")
        local subtree_on_self = open_nb(ROOT .. "\\Chain\\A")
        arm(t, direct, false)
        arm(t, subtree_on_self, true)
        lcs.set_value(src, w, direct, "OnMe", lcs.TYPE.DWORD, lcs.dword(1))
        local bare = lcs.drain_events(w, direct)
        t:assert_eq(#bare, 1, "the direct watcher heard it: " .. lcs.event_summary(bare))
        t:assert_eq(bare[1].depth, nil,
            "a non-subtree watch's record carries no path fields at all")
        t:assert_eq(bare[1].total_len, 8 + #"OnMe", "just the header and the name")
        local zero = lcs.drain_events(w, subtree_on_self)
        t:assert_eq(#zero, 1, "the subtree watcher on the same key heard it: " ..
            lcs.event_summary(zero))
        t:assert_eq(zero[1].depth, 0, "with a path_depth of zero")
        sys.close(w, subtree_on_self); sys.close(w, direct)
    end)

test("subtree watchers receive the path from their key down to the changed one",
    { spec = "PKM *watch.dispatch.subtree-watchers-receive-the-relative-path" }, function(t)
        local top = open_nb(ROOT .. "\\Depth")
        local mid = open_nb(ROOT .. "\\Depth\\A")
        arm(t, top, true)
        arm(t, mid, true)
        local deep = open_nb(ROOT .. "\\Depth\\A\\B\\C")
        lcs.set_value(src, w, deep, "Answer", lcs.TYPE.DWORD, lcs.dword(1))
        local from_top = lcs.drain_events(w, top)
        t:assert_eq(#from_top, 1, "the higher watch heard it: " .. lcs.event_summary(from_top))
        t:assert_eq(table.concat(from_top[1].components, "/"), "A/B/C",
            "each ancestor gets the path from itself down to the changed key")
        local from_mid = lcs.drain_events(w, mid)
        t:assert_eq(#from_mid, 1, "so did the lower one: " .. lcs.event_summary(from_mid))
        t:assert_eq(table.concat(from_mid[1].components, "/"), "B/C",
            "sliced from the resolved path on the mutating fd")
        sys.close(w, deep); sys.close(w, mid); sys.close(w, top)
    end)

test("dispatch does no source I/O, however many watches it walks",
    { spec = "PKM *watch.dispatch.costs-o-depth-hash-lookups-and-no-source-io" },
    function(t)
        local deep = open_nb(ROOT .. "\\Costs\\A\\B\\C")
        local mark = src:mark()
        lcs.set_value(src, w, deep, "Unwatched", lcs.TYPE.DWORD, lcs.dword(1))
        local without = #src.log - mark + 1

        local watches = {}
        for _, path in ipairs({ SOFTWARE, ROOT, ROOT .. "\\Costs", ROOT .. "\\Costs\\A",
                                ROOT .. "\\Costs\\A\\B", ROOT .. "\\Costs\\A\\B\\C" }) do
            local fd = open_nb(path)
            arm(t, fd, true)
            watches[#watches + 1] = fd
        end
        mark = src:mark()
        lcs.set_value(src, w, deep, "Watched", lcs.TYPE.DWORD, lcs.dword(1))
        local with = #src.log - mark + 1
        t:assert_eq(with, without,
            "arming " .. #watches .. " watches up the chain added no RSI round trips: " ..
            with .. " vs " .. without)
        local delivered = 0
        for _, fd in ipairs(watches) do
            delivered = delivered + #lcs.drain_events(w, fd)
        end
        t:assert_eq(delivered, #watches, "and every one of them was still served")
        for _, fd in ipairs(watches) do sys.close(w, fd) end
        sys.close(w, deep)
    end)

test("dispatch runs under a single global registry lock",
    { spec = "PKM *watch.dispatch.serialised-under-the-global-registry-lock",
      covered_by = "kunit:",
      skip = "lock discipline is not observable from a guest: system-wide " ..
             "serialisation of dispatch has no user-visible consequence " ..
             "distinguishable from per-hive or per-source serialisation, " ..
             "and the batch-atomicity consequence that is observable is " ..
             "covered by watch.dispatch.commit-batch-queued-in-operation-" ..
             "order-without-interleaving; no KUnit case found — candidate " ..
             "for a new one" }, function(t) end)

-- ---- depth ------------------------------------------------------------
--
-- These two write MaxSubtreeWatchDepth, which is global, so they run
-- last and each restores the default of 0 before returning.

test("MaxSubtreeWatchDepth of 0 means unlimited",
    { spec = "PKM *watch.dispatch.depth-zero-means-unlimited" }, function(t)
        local params = open_nb(lcs.PARAMS_PATH)
        local q = lcs.query_value(src, w, params, "MaxSubtreeWatchDepth")
        t:assert_eq(q.data, lcs.dword(0), "the default is 0")
        local top = open_nb(ROOT .. "\\Depth")
        arm(t, top, true)
        local deep = open_nb(ROOT .. "\\Depth\\A\\B\\C")
        lcs.set_value(src, w, deep, "Unlimited", lcs.TYPE.DWORD, lcs.dword(1))
        local ev = lcs.drain_events(w, top)
        t:assert_eq(#ev, 1, "a change three levels down still arrives: " ..
            lcs.event_summary(ev))
        t:assert_eq(ev[1].depth, 3, "at its full depth")
        sys.close(w, deep); sys.close(w, top); sys.close(w, params)
    end)

test("a non-zero MaxSubtreeWatchDepth suppresses events whose path is longer",
    { spec = "PKM *watch.dispatch.depth-limit-suppresses-deeper-events" }, function(t)
        local params = open_nb(lcs.PARAMS_PATH)
        local top = open_nb(ROOT .. "\\Depth")
        arm(t, top, true)
        local one = open_nb(ROOT .. "\\Depth\\A")
        local two = open_nb(ROOT .. "\\Depth\\A\\B")

        local s = lcs.set_value(src, w, params, "MaxSubtreeWatchDepth",
            lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "setting the limit to 1: " .. sys.errname(s.errno or 0))
        lcs.drain_events(w, top)

        lcs.set_value(src, w, two, "TooDeep", lcs.TYPE.DWORD, lcs.dword(1))
        local deeper = lcs.drain_events(w, top)
        t:assert_eq(#deeper, 0, "a path of 2 is longer than the limit and is suppressed: "
            .. lcs.event_summary(deeper))
        lcs.set_value(src, w, one, "InRange", lcs.TYPE.DWORD, lcs.dword(1))
        local within = lcs.drain_events(w, top)
        t:assert_eq(#within, 1, "a path of 1 is within it and arrives: " ..
            lcs.event_summary(within))
        t:assert_eq(within[1].depth, 1, "at depth 1")

        local back = lcs.set_value(src, w, params, "MaxSubtreeWatchDepth",
            lcs.TYPE.DWORD, lcs.dword(0))
        t:assert_eq(back.ret, 0, "restoring the default: " .. sys.errname(back.errno or 0))
        lcs.drain_events(w, top)
        lcs.set_value(src, w, two, "AgainDeep", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(#lcs.drain_events(w, top), 1, "and the limit is off again")
        sys.close(w, two); sys.close(w, one); sys.close(w, top); sys.close(w, params)
    end)
