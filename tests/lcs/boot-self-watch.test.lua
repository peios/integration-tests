-- PKM §5.10.4 — the internal self-watch: what it drives, how it is
-- armed, and why the callback is not the atomicity boundary.
--
-- An internal watch has no fd, so nothing can read its queue: what a
-- guest sees of it is what it *does*. Every case here reads the RSI
-- traffic the source was asked for. A self-configuration re-read is an
-- `RSI_QUERY_VALUES` against the `Machine\System\Registry` key that
-- LCS makes for itself, arriving after the mutation it reacted to and
-- before the syscall that made the mutation returns; a layer metadata
-- refresh is the same against a layer's metadata key; a bootstrap
-- refresh re-entry is the whole `System` → `Registry` → `Layers` →
-- `KMES` → `Network` walk running again.
--
-- Every case brings its own source through `with_machine`, all sharing
-- one Machine root GUID: a Down slot keeps its hive identity (§5.8.2),
-- so a second root for the same name would be ESTALE, while the same
-- root lets each case seed a database of its own. The wrapper closes
-- the source however the case ends, because a case that raised with
-- the hive still claimed would leave every later one EEXIST.
--
-- Two things outlive a source and are shared by the whole file: the
-- layer table (a refresh that finds no Layers key leaves it alone) and
-- the active configuration. So each case names a layer nobody else
-- names, and writes the parameters it depends on rather than assuming
-- a default.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()
local MACHINE_ROOT = lcs.guid()

local KMES_PATH = "Machine\\System\\KMES"
local NETWORK_PATH = "Machine\\System\\Network"
local PORTS_PATH = NETWORK_PATH .. "\\TcpIp\\PortReservations"

--- Run `fn(src, w)` against a Machine source seeded by `seed`, with a
--- worker of its own, closing both however the case ends.
local function with_machine(seed, fn)
    local src = lcs.source(vm, { hives = {
        { name = "Machine", root = MACHINE_ROOT } } })
    src:key("Machine\\Software\\Test")
    if seed then seed(src) end
    assert(src:register())
    src:pump()
    local w = vm:spawn_worker()
    local ok, err = pcall(fn, src, w)
    w:kill(); w:join()
    src:close()
    if not ok then error(err, 0) end
end

--- The RSI ops a source was asked for, LOOKUPs carrying their name.
local function traffic(src, from)
    local out = {}
    for i = from or 1, #src.log do
        local e = src.log[i]
        local name = lcs.lookup_name(e)
        out[#out + 1] = (lcs.OP_NAME[e.op] or tostring(e.op))
            .. (name and ("(" .. name .. ")") or "")
    end
    return table.concat(out, " ")
end

--- How many RSI_QUERY_VALUES were asked against one key since `from`.
--- A write to a key makes one itself; a second is LCS reading the key
--- back for its own purposes.
local function reads_of(src, from, guid)
    return #src:served(lcs.OP.QUERY_VALUES, from, guid)
end

--- Open a key, asserting it opened.
local function open(t, src, w, path, mask)
    local r = lcs.open_key(src, w, -1, path, mask or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

-- ---- what the watch is ----------------------------------------------

test("the internal watch has no fd, no granted access mask and no filter",
    { spec = "PKM *self-watch.no-fd-mask-or-filter" }, function(t)
        -- The write below goes through an fd that carries KEY_SET_VALUE
        -- and nothing else: no KEY_NOTIFY, and REG_IOC_NOTIFY was never
        -- called on it, so no filter of any kind selects this event.
        -- LCS reads its configuration back all the same.
        with_machine(function(s) s:key(lcs.PARAMS_PATH) end, function(src, w)
            local reg_guid = src:lookup(lcs.PARAMS_PATH)
            local fd = open(t, src, w, lcs.PARAMS_PATH, lcs.RIGHT.SET_VALUE)
            local mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, fd, "MaxKeyDepth", lcs.TYPE.DWORD,
                lcs.dword(1024)).ret, 0, "a parameter is written")
            t:assert(reads_of(src, mark, reg_guid) >= 2,
                "and LCS read the key back for itself: " .. traffic(src, mark))
            -- There is no fd behind the watch that drove it, and no mask
            -- either: this fd could not have armed one if it wanted to.
            t:assert_eq(lcs.notify(nil, w, fd, lcs.NOTIFY.ALL, false).errno,
                sys.E.ACCES,
                "the fd that made the change holds no KEY_NOTIFY and could arm none")
            sys.close(w, fd)
        end)
    end)

test("the internal watch is not subject to NotificationQueueSize",
    { spec = "PKM *self-watch.exempt-from-notification-queue-size" },
    function(t)
        -- Sixteen entries is the smallest queue a watcher may have, and
        -- nobody ever read()s an internal watch, so a queue behind one
        -- would be permanently full after sixteen events. Thirty
        -- unrelated writes go first; the thirty-first is the parameter,
        -- and it takes effect.
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:seed_param("NotificationQueueSize", 16)
        end, function(src, w)
            local reg = open(t, src, w, lcs.PARAMS_PATH)
            local test_fd = open(t, src, w, "Machine\\Software\\Test")
            -- A real watcher on the same key, for the contrast.
            t:assert_eq(lcs.notify(nil, w, reg, lcs.NOTIFY.ALL, false).ret, 0,
                "a key-fd watcher is armed on the same key")
            for i = 1, 30 do
                lcs.set_value(src, w, reg, "Filler" .. i, lcs.TYPE.DWORD,
                    lcs.dword(i))
            end
            local queued = lcs.read_events(nil, w, reg)
            t:assert_eq(#queued.events, 16,
                "the key-fd watcher's queue held its sixteen and overflowed")
            local mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, reg, "MaxValueSize",
                lcs.TYPE.DWORD, lcs.dword(4096)).ret, 0,
                "the thirty-first write is a parameter")
            t:assert(reads_of(src, mark, src:lookup(lcs.PARAMS_PATH)) >= 2,
                "and the internal watch still drove a re-read")
            local over = lcs.set_value(src, w, test_fd, "Over", lcs.TYPE.BINARY,
                string.rep("x", 8192))
            t:assert_eq(over.errno, sys.E.NOSPC,
                "which hot-swapped: no queue behind the internal watch had filled")
            sys.close(w, test_fd); sys.close(w, reg)
        end)
    end)

test("the internal watch is not subject to MaxSubtreeWatchDepth",
    { spec = "PKM *self-watch.exempt-from-depth-and-burst-limits" },
    function(t)
        -- Internal collection happens before the depth test. The
        -- Machine-root fallback is armed (Layers, KMES, Network are all
        -- absent), MaxSubtreeWatchDepth is one, and a key created four
        -- components below the hive root still re-enters the refresh.
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:seed_param("MaxSubtreeWatchDepth", 1)
            s:key("Machine\\Deep\\Down\\Here")
        end, function(src, w)
            local parent = open(t, src, w, "Machine\\Deep\\Down\\Here")
            local mark = src:mark()
            local made = lcs.create_key(src, w,
                { parent_fd = parent, path = "Leaf" })
            t:assert(made.ret >= 0, "a key four below the hive root is created: "
                .. sys.errname(made.errno or 0))
            local after = traffic(src, mark)
            t:assert(after:match("LOOKUP%(Registry%)"),
                "and the fallback delivered the event from depth four: " .. after)
            sys.close(w, made.ret); sys.close(w, parent)
        end)
    end)

test("the internal watch is not subject to the transaction burst suppressor",
    { spec = "PKM *self-watch.exempt-from-depth-and-burst-limits",
      covered_by = "kunit:pkm_lcs_kunit_transaction",
      skip = "the burst half of the claim cannot be told apart from inside a " ..
             "guest: any one admitted event of a commit drives a full re-read " ..
             "of the configuration key, which already sees the committed " ..
             "state, so a suppressor that dropped every event after the first " ..
             "256 would leave exactly the same configuration in force as no " ..
             "suppressor at all; the depth half is the live case above" ..
             "; runs under pkm_lcs_kunit_transaction_watch_burst_spares_the_internal_watch" },
    function(t) end)

test("each internal target admits only the event types it cares about",
    { spec = "PKM *self-watch.admits-event-types-per-target" }, function(t)
        -- Every kernel-read key exists, so the arming is purely
        -- targeted: no Machine-root fallback is armed, and a subkey
        -- creation that no target admits drives nothing at all.
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:key(lcs.LAYERS_PATH)
            s:key(KMES_PATH)
            s:key(PORTS_PATH)
        end, function(src, w)
            local reg_guid = src:lookup(lcs.PARAMS_PATH)
            local reg = open(t, src, w, lcs.PARAMS_PATH)

            -- Configuration subtree: value events on the watched key.
            local mark = src:mark()
            lcs.set_value(src, w, reg, "MaxKeyDepth", lcs.TYPE.DWORD,
                lcs.dword(256))
            t:assert(reads_of(src, mark, reg_guid) >= 2,
                "a value event on the configuration key is admitted")

            -- A subkey event on the same key is not a value event.
            mark = src:mark()
            local sub = lcs.create_key(src, w, { parent_fd = reg, path = "Sub" })
            t:assert(sub.ret >= 0, "a subkey of the configuration key is created")
            t:assert_eq(reads_of(src, mark, reg_guid), 0,
                "and SUBKEY_CREATED on it is not admitted: " .. traffic(src, mark))

            -- Nor is a value event one component below it.
            mark = src:mark()
            lcs.set_value(src, w, sub.ret, "MaxKeyDepth", lcs.TYPE.DWORD,
                lcs.dword(64))
            t:assert_eq(reads_of(src, mark, reg_guid), 0,
                "and a value event at depth 1 is not admitted either")

            -- Layer metadata: subkey events at depth 0, value events at
            -- depth 1, and nothing deeper.
            local layers = open(t, src, w, lcs.LAYERS_PATH)
            mark = src:mark()
            local admit = lcs.create_key(src, w,
                { parent_fd = layers, path = "AdmitLayer" })
            t:assert(admit.ret >= 0, "a layer metadata key is created")
            t:assert(traffic(src, mark):match("QUERY_VALUES"),
                "SUBKEY_CREATED at depth 0 under Layers is admitted: "
                    .. traffic(src, mark))
            local admit_guid = src:lookup(lcs.LAYERS_PATH .. "\\AdmitLayer")
            mark = src:mark()
            lcs.set_value(src, w, admit.ret, "Precedence", lcs.TYPE.DWORD,
                lcs.dword(5))
            t:assert(reads_of(src, mark, admit_guid) >= 2,
                "a value event at depth 1 under Layers is admitted")
            local deeper = lcs.create_key(src, w,
                { parent_fd = admit.ret, path = "Deeper" })
            mark = src:mark()
            lcs.set_value(src, w, deeper.ret, "Precedence", lcs.TYPE.DWORD,
                lcs.dword(6))
            t:assert_eq(reads_of(src, mark, admit_guid), 0,
                "and a value event at depth 2 is not: " .. traffic(src, mark))

            sys.close(w, deeper.ret); sys.close(w, admit.ret)
            sys.close(w, layers); sys.close(w, sub.ret); sys.close(w, reg)
        end)
    end)

-- ---- what it drives --------------------------------------------------

test("a change under Machine\\System\\Registry re-reads and validates the parameters",
    { spec = "PKM *self-watch.drives.parameter-re-read" }, function(t)
        with_machine(function(s) s:key(lcs.PARAMS_PATH) end, function(src, w)
            local reg = open(t, src, w, lcs.PARAMS_PATH)
            local mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, reg, "MaxTotalPathLength",
                lcs.TYPE.DWORD, lcs.dword(1024)).ret, 0,
                "MaxTotalPathLength is written")
            t:assert(reads_of(src, mark, src:lookup(lcs.PARAMS_PATH)) >= 2,
                "the change triggered a re-read of the key")
            local parts = { "Machine" }
            for _ = 1, 5 do parts[#parts + 1] = string.rep("a", 255) end
            local over = lcs.open_key(src, w, -1, table.concat(parts, "\\"),
                lcs.RIGHT.KEY_READ)
            t:assert_eq(over.errno, sys.E.NAMETOOLONG,
                "and the re-read value was validated and put in force")
            sys.close(w, reg)
        end)
    end)

test("SUBKEY_CREATED and SUBKEY_DELETED under Layers\\ add and remove layers, except base",
    { spec = "PKM *self-watch.drives.layer-lifecycle-from-subkey-events" },
    function(t)
        with_machine(function(s) s:key(lcs.LAYERS_PATH) end, function(src, w)
            local layers = open(t, src, w, lcs.LAYERS_PATH)
            local test_fd = open(t, src, w, "Machine\\Software\\Test")

            local absent = lcs.set_value(src, w, test_fd, "Early",
                lcs.TYPE.DWORD, lcs.dword(1), { layer = "LifeLayer" })
            t:assert_eq(absent.errno, sys.E.NOENT,
                "a layer that has no metadata key does not exist")
            local made = lcs.create_key(src, w,
                { parent_fd = layers, path = "LifeLayer" })
            t:assert(made.ret >= 0, "the metadata key is created")
            local present = lcs.set_value(src, w, test_fd, "Now",
                lcs.TYPE.DWORD, lcs.dword(1), { layer = "LifeLayer" })
            t:assert_eq(present.ret, 0,
                "and SUBKEY_CREATED added the layer: "
                    .. sys.errname(present.errno or 0))

            t:assert_eq(lcs.delete_key(src, w, made.ret, {}).ret, 0,
                "the metadata key is deleted")
            local gone = lcs.set_value(src, w, test_fd, "Gone", lcs.TYPE.DWORD,
                lcs.dword(1), { layer = "LifeLayer" })
            t:assert_eq(gone.errno, sys.E.NOENT,
                "and SUBKEY_DELETED removed the layer")

            -- base is the static constant of §5.3.2: its metadata key
            -- may come and go, and the layer is neither added nor taken
            -- away by it.
            local base = lcs.create_key(src, w, { parent_fd = layers, path = "base" })
            t:assert(base.ret >= 0, "a Layers\\base key is created")
            t:assert_eq(lcs.set_value(src, w, test_fd, "InBase", lcs.TYPE.DWORD,
                lcs.dword(1)).ret, 0, "and base still writes")
            t:assert_eq(lcs.delete_key(src, w, base.ret, {}).ret, 0,
                "the base metadata key is deleted again")
            t:assert_eq(lcs.set_value(src, w, test_fd, "StillBase",
                lcs.TYPE.DWORD, lcs.dword(2)).ret, 0,
                "and base is still there: the lifecycle events for it are ignored")

            sys.close(w, base.ret); sys.close(w, made.ret)
            sys.close(w, test_fd); sys.close(w, layers)
        end)
    end)

test("a third internal watch on Machine\\System\\KMES picks up KMES's parameters",
    { spec = "PKM *self-watch.drives.kmes-configuration" }, function(t)
        with_machine(function(s) s:key(KMES_PATH) end, function(src, w)
            t:assert(traffic(src):match("LOOKUP%(KMES%)"),
                "the bootstrap resolved Machine\\System\\KMES")
            local kmes_guid = src:lookup(KMES_PATH)
            local fd = open(t, src, w, KMES_PATH)
            local mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, fd, "MaxEventSize",
                lcs.TYPE.DWORD, lcs.dword(4096)).ret, 0,
                "a value is written under it")
            t:assert(reads_of(src, mark, kmes_guid) >= 2,
                "and the change was noticed and the key re-read: "
                    .. traffic(src, mark))
            sys.close(w, fd)
        end)
    end)

-- ---- the callback is not the atomicity boundary ----------------------

test("the callback identifies dirty layers and publishes nothing itself",
    { spec = "PKM *self-watch.callback-does-not-publish" }, function(t)
        -- Everything a published layer needs — the table entry, the
        -- metadata key GUID and the cached descriptor — comes from a
        -- bounded refresh that reads the metadata key from the source.
        -- If the callback published, the layer would appear without LCS
        -- ever having read what it consists of.
        with_machine(function(s) s:key(lcs.LAYERS_PATH) end, function(src, w)
            local layers = open(t, src, w, lcs.LAYERS_PATH)
            local mark = src:mark()
            local made = lcs.create_key(src, w,
                { parent_fd = layers, path = "PublishLayer" })
            t:assert(made.ret >= 0, "a layer metadata key is created")
            local guid = src:lookup(lcs.LAYERS_PATH .. "\\PublishLayer")
            t:assert(#src:served(lcs.OP.READ_KEY, mark, guid) >= 1,
                "LCS read the metadata key's own record — its descriptor: "
                    .. traffic(src, mark))
            t:assert(reads_of(src, mark, guid) >= 1,
                "and its values, precedence and enabled state among them")
            local test_fd = open(t, src, w, "Machine\\Software\\Test")
            t:assert_eq(lcs.set_value(src, w, test_fd, "In", lcs.TYPE.DWORD,
                lcs.dword(1), { layer = "PublishLayer" }).ret, 0,
                "only then is the layer published, entry and descriptor together")
            sys.close(w, test_fd); sys.close(w, made.ret); sys.close(w, layers)
        end)
    end)

test("no source round trip happens while the watch-map or layer-table locks are held",
    { spec = "PKM *self-watch.no-source-round-trip-under-locks" }, function(t)
        -- The refresh runs after the mutating operation commits and
        -- before the syscall returns, and outside the publication
        -- locks. Hold its round trip: the mutation has already been
        -- accepted by the source, the syscall has not returned, and
        -- unrelated work goes on regardless.
        with_machine(function(s) s:key(lcs.PARAMS_PATH) end, function(src, w)
            local w2 = vm:spawn_worker()
            local ok, err = pcall(function()
                local reg_guid = src:lookup(lcs.PARAMS_PATH)
                local reg = open(t, src, w, lcs.PARAMS_PATH)
                local seen = 0
                src:intercept(lcs.OP.QUERY_VALUES, function(_, req)
                    if req.payload:sub(1, 16) == reg_guid then
                        seen = seen + 1
                        if seen == 2 then return lcs.HOLD end
                    end
                    return nil
                end)
                local pending = lcs.set_value_async(w, reg,
                    "MaxPathComponentLength", lcs.TYPE.DWORD, lcs.dword(64))
                src:pump()
                t:assert_eq(#src:held_ids(), 1,
                    "the mutation committed and LCS's own re-read is in flight")
                -- Locks are not held across it: another caller walks the
                -- same hive and opens a key while the round trip is out.
                local other = lcs.open_key(src, w2, -1,
                    "Machine\\Software\\Test", lcs.KEY_ALL_ACCESS)
                t:assert(other.ret >= 0,
                    "an unrelated open completes while the refresh is outstanding: "
                        .. sys.errname(other.errno or 0))
                -- And the syscall has not returned: nothing is published.
                local before = lcs.open_key(src, w2, -1,
                    "Machine\\" .. string.rep("a", 100), lcs.RIGHT.KEY_READ)
                t:assert_eq(before.errno, sys.E.NOENT,
                    "the new value is not in force while the refresh is in flight")
                src:intercept(lcs.OP.QUERY_VALUES, nil)
                src:release(src:held_ids()[1])
                t:assert_eq(pending:await().ret, 0, "the syscall then returns")
                local after = lcs.open_key(src, w2, -1,
                    "Machine\\" .. string.rep("a", 100), lcs.RIGHT.KEY_READ)
                t:assert_eq(after.errno, sys.E.NAMETOOLONG,
                    "and the refresh, having run before it returned, has published")
                sys.close(w2, other.ret)
                sys.close(w, reg)
            end)
            src:intercept(lcs.OP.QUERY_VALUES, nil)
            w2:kill(); w2:join()
            if not ok then error(err, 0) end
        end)
    end)

-- ---- arming ----------------------------------------------------------

test("at bootstrap the GUIDs are resolved through RSI_LOOKUP and targeted watches armed",
    { spec = "PKM *self-watch.arming.targeted-via-rsi-lookup" }, function(t)
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:key(lcs.LAYERS_PATH)
        end, function(src, w)
            local walk = traffic(src)
            t:assert(walk:match("LOOKUP%(System%) LOOKUP%(Registry%)"),
                "Machine\\System\\Registry was resolved component by component: "
                    .. walk)
            t:assert(walk:match("LOOKUP%(Registry%) LOOKUP%(Layers%)"),
                "and Machine\\System\\Registry\\Layers under it: " .. walk)
            -- Targeted: a change to either key reaches LCS.
            local reg_guid = src:lookup(lcs.PARAMS_PATH)
            local reg = open(t, src, w, lcs.PARAMS_PATH)
            local mark = src:mark()
            lcs.set_value(src, w, reg, "MaxKeyDepth", lcs.TYPE.DWORD,
                lcs.dword(256))
            t:assert(reads_of(src, mark, reg_guid) >= 2,
                "the configuration watch is armed on the resolved GUID")
            local layers = open(t, src, w, lcs.LAYERS_PATH)
            mark = src:mark()
            local made = lcs.create_key(src, w,
                { parent_fd = layers, path = "TargetLayer" })
            t:assert(made.ret >= 0, "a layer metadata key is created")
            t:assert(reads_of(src, mark,
                src:lookup(lcs.LAYERS_PATH .. "\\TargetLayer")) >= 1,
                "and the layer metadata watch on its own")
            sys.close(w, made.ret); sys.close(w, layers); sys.close(w, reg)
        end)
    end)

test("with neither key present the fallback is armed on the Machine hive root",
    { spec = "PKM *self-watch.arming.fallback-on-machine-root" }, function(t)
        -- An empty database: nothing to arm a targeted watch on, so the
        -- watch that exists is the one on the hive root, and it is what
        -- notices seed restore creating the subtree.
        with_machine(nil, function(src, w)
            t:assert(not traffic(src):match("QUERY_VALUES"),
                "the bootstrap found no key to read: " .. traffic(src))
            local mark = src:mark()
            local made = lcs.create_key(src, w, { path = "Machine\\Seeded" })
            t:assert(made.ret >= 0, "a subkey is created under the hive root: "
                .. sys.errname(made.errno or 0))
            t:assert(traffic(src, mark):match("LOOKUP%(System%)"),
                "and the fallback noticed it: " .. traffic(src, mark))
            sys.close(w, made.ret)
        end)
    end)

test("the fallback event re-enters the whole bootstrap refresh",
    { spec = "PKM *self-watch.arming.fallback-event-re-enters-refresh" },
    function(t)
        with_machine(nil, function(src, w)
            local sysk = lcs.create_key(src, w, { path = "Machine\\System" })
            t:assert(sysk.ret >= 0, "Machine\\System is created")
            local mark = src:mark()
            local reg = lcs.create_key(src, w,
                { parent_fd = sysk.ret, path = "Registry" })
            t:assert(reg.ret >= 0, "and Machine\\System\\Registry under it")
            local after = traffic(src, mark)
            t:assert(after:match("LOOKUP%(Registry%).*QUERY_VALUES"),
                "the whole refresh re-entered and resolved the specific GUID: "
                    .. after)
            -- Targeted watches were armed by the re-entry: the next
            -- change to the key reaches LCS without another fallback.
            local reg_guid = src:lookup(lcs.PARAMS_PATH)
            mark = src:mark()
            lcs.set_value(src, w, reg.ret, "MaxKeyDepth", lcs.TYPE.DWORD,
                lcs.dword(256))
            t:assert(reads_of(src, mark, reg_guid) >= 2,
                "and the targeted watch it armed is live: " .. traffic(src, mark))
            sys.close(w, reg.ret); sys.close(w, sysk.ret)
        end)
    end)

test("what is armed is a mixed superset: targeted where they exist, plus the fallback",
    { spec = "PKM *self-watch.arming.mixed-superset" }, function(t)
        -- Registry exists, Layers does not. The spec-level description
        -- says the fallback is armed *instead of* the targeted ones;
        -- what the kernel arms is both, and both work.
        with_machine(function(s) s:key(lcs.PARAMS_PATH) end, function(src, w)
            local reg_guid = src:lookup(lcs.PARAMS_PATH)
            local reg = open(t, src, w, lcs.PARAMS_PATH)
            local mark = src:mark()
            lcs.set_value(src, w, reg, "MaxKeyDepth", lcs.TYPE.DWORD,
                lcs.dword(256))
            t:assert(reads_of(src, mark, reg_guid) >= 2,
                "the targeted watch on the Registry key that exists is armed")
            mark = src:mark()
            local made = lcs.create_key(src, w, { path = "Machine\\Elsewhere" })
            t:assert(made.ret >= 0, "a key is created elsewhere under the hive root")
            t:assert(traffic(src, mark):match("LOOKUP%(Layers%)"),
                "and the Machine-root fallback is armed alongside it, still "
                    .. "looking for the key that is missing: " .. traffic(src, mark))
            sys.close(w, made.ret); sys.close(w, reg)
        end)
    end)

test("the same arming covers every key the kernel reads for itself",
    { spec = "PKM *self-watch.arming.covers-every-kernel-read-key" }, function(t)
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:key(lcs.LAYERS_PATH)
            s:key(KMES_PATH)
            s:key(PORTS_PATH)
        end, function(src, w)
            local walk = traffic(src)
            for _, name in ipairs({ "Registry", "Layers", "KMES", "Network",
                                    "TcpIp", "PortReservations" }) do
                t:assert(walk:match("LOOKUP%(" .. name .. "%)"),
                    name .. " is discovered in the same refresh: " .. walk)
            end
            -- And each got its own targeted watch.
            local kmes = open(t, src, w, KMES_PATH)
            local mark = src:mark()
            lcs.set_value(src, w, kmes, "MaxEventSize", lcs.TYPE.DWORD,
                lcs.dword(4096))
            t:assert(reads_of(src, mark, src:lookup(KMES_PATH)) >= 2,
                "the KMES configuration watch is armed")
            local ports = open(t, src, w, PORTS_PATH)
            mark = src:mark()
            lcs.set_value(src, w, ports, "Reserved", lcs.TYPE.DWORD, lcs.dword(1))
            t:assert(reads_of(src, mark, src:lookup(PORTS_PATH)) >= 2,
                "the port reservation table watch is armed")
            sys.close(w, ports); sys.close(w, kmes)
        end)
    end)

test("the network policy watch is the one depth-unbounded, every-mutation watch",
    { spec = "PKM *self-watch.arming.policy-watch-is-depth-unbounded" },
    function(t)
        -- Rules are keys and exceptions are subkeys, so anything written
        -- anywhere beneath Machine\System\Network may be policy: value
        -- and subkey events at any depth re-walk it. The configuration
        -- watches admit nothing below their own key at all.
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:key(NETWORK_PATH .. "\\Rules\\Inbound\\Exception")
        end, function(src, w)
            local deep = open(t, src, w,
                NETWORK_PATH .. "\\Rules\\Inbound\\Exception")
            local mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, deep, "Action", lcs.TYPE.DWORD,
                lcs.dword(1)).ret, 0,
                "a value is written three below the policy key")
            t:assert(traffic(src, mark):match("ENUM_CHILDREN"),
                "and the policy subtree is re-walked: " .. traffic(src, mark))
            mark = src:mark()
            local child = lcs.create_key(src, w,
                { parent_fd = deep, path = "Deeper" })
            t:assert(child.ret >= 0, "a subkey is created four below it")
            t:assert(traffic(src, mark):match("ENUM_CHILDREN"),
                "and that is re-walked too: " .. traffic(src, mark))
            sys.close(w, child.ret); sys.close(w, deep)
        end)
    end)

test("a refresh that fails before arming arms the Machine-root fallback alone",
    { spec = "PKM *self-watch.arming.failed-refresh-arms-fallback-alone" },
    function(t)
        -- A stage can fail transiently. If the refresh simply returned,
        -- no watch would exist and no kernel-read key would load for the
        -- life of the boot.
        with_machine(function(s)
            s:key(lcs.PARAMS_PATH)
            s:key(lcs.LAYERS_PATH)
        end, function(src, w)
            src:intercept(lcs.OP.LOOKUP, function(_, req)
                if lcs.lookup_name(req) == "System" then
                    return lcs.STATUS.STORAGE_ERROR, ""
                end
                return nil
            end)
            local mark = #src.log
            assert(src:resume())
            src:pump()
            t:assert_eq(traffic(src, mark + 1), "LOOKUP(System)",
                "the very first stage failed and the refresh stopped there")
            src:intercept(lcs.OP.LOOKUP, nil)

            local w2 = vm:spawn_worker()
            local ok, err = pcall(function()
                mark = src:mark()
                local made = lcs.create_key(src, w2, { path = "Machine\\Retry" })
                t:assert(made.ret >= 0, "a subkey is created under the hive root")
                local after = traffic(src, mark)
                t:assert(after:match("LOOKUP%(Registry%)")
                    and after:match("LOOKUP%(Layers%)"),
                    "the fallback armed alone re-entered the refresh, which then "
                        .. "armed the targeted watches: " .. after)
                sys.close(w2, made.ret)
            end)
            w2:kill(); w2:join()
            if not ok then error(err, 0) end
        end)
    end)

test("the failure and the fallback arm are both traced by lcs:lcs_bootstrap_refresh",
    { spec = "PKM *self-watch.arming.failure-is-traced" }, function(t)
        with_machine(function(s) s:key(lcs.PARAMS_PATH) end, function(src, w)
            src:intercept(lcs.OP.LOOKUP, function(_, req)
                if lcs.lookup_name(req) == "System" then
                    return lcs.STATUS.STORAGE_ERROR, ""
                end
                return nil
            end)
            local started, err = hooks.trace_start(vm, "lcs/lcs_bootstrap_refresh")
            t:assert(started, "tracing starts on lcs:lcs_bootstrap_refresh: "
                .. tostring(err))
            assert(src:resume())
            src:pump()
            local lines = hooks.trace_stop(vm, "lcs/lcs_bootstrap_refresh")
            src:intercept(lcs.OP.LOOKUP, nil)
            t:assert(lines, "the trace buffer reads back")
            local failure, arm
            for _, l in ipairs(lines) do
                if l:match("stage=registry") and l:match("ret=%-%d") then
                    failure = l
                end
                if l:match("stage=self%-watch") and l:match("ret=0") then
                    arm = l
                end
            end
            t:assert(failure, "the failing stage is traced with its error: "
                .. table.concat(lines, " | "))
            t:assert(arm, "and so is the fallback arm that follows it: "
                .. table.concat(lines, " | "))
        end)
    end)
