-- PKM §2.8 — the kernel's emission policy: the generated table of kernel
-- event types, the cached enabled mask, the walk of Machine\Generic\Events,
-- the watch that keeps it current, and the seed that ships with the kernel.
--
-- What a guest can see of the policy is what the kernel asks the registry
-- for. No kernel emitter consults the mask yet, so a switched-off type is
-- still written and the mask itself cannot be read from outside; every
-- claim about the mask runs under KUnit (pkm_lcs_kunit_kmes). What is live
-- here is the walk: the RSI traffic a Lua-served Machine hive is asked for
-- at bootstrap and after a change, read from the source's log.
--
-- Every case brings its own source through `with_machine`, sharing one
-- Machine root GUID (a Down slot keeps its hive identity, §5.8.2). Each
-- seeds every other key the kernel reads for itself, so the self-watch is
-- targeted and no machine-root fallback re-runs the bootstrap inside a
-- write being counted — except the one case about that fallback.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("vpolicy", "kernel-only"):boot()
local MACHINE_ROOT = lcs.guid()

local EVENTS_PATH = "Machine\\Generic\\Events"
local KMES_PATH = "Machine\\System\\KMES"
local PORTS_PATH = "Machine\\System\\Network\\TcpIp\\PortReservations"

--- Seed every kernel-read key but the emission policy.
local function seed_other_kernel_keys(s)
    s:key(lcs.PARAMS_PATH)
    s:key(lcs.LAYERS_PATH)
    s:key(KMES_PATH)
    s:key(PORTS_PATH)
end

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

--- How many RSI_QUERY_VALUES were asked against one key since `from`. A
--- walk of the policy begins with one against the Events key.
local function reads_of(src, from, guid)
    return #src:served(lcs.OP.QUERY_VALUES, from, guid)
end

local function open(t, src, w, path)
    local r = lcs.open_key(src, w, -1, path, lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

-- ---- the seed ---------------------------------------------------------

test("the kernel's seed creates Events with Enabled = 1",
    { spec = "PKM *policy.seed-enables-at-root" }, function(t)
        -- Shipped by the kernel package, inert until an image names it:
        -- the kernel-only image names nothing, so it is read as a file.
        local doc = json.decode(vm:read_file("/usr/share/regim/event-policy.reg"))
        t:assert(doc and doc.keys, "the seed is a batch document")
        local events, generic
        for _, k in ipairs(doc.keys) do
            if k.path == EVENTS_PATH then events = k end
            if k.path == "Machine\\Generic" then generic = k end
        end
        t:assert(generic, "it creates Machine\\Generic")
        t:assert(events, "and Machine\\Generic\\Events beneath it")
        local enabled
        for _, v in ipairs(events.values or {}) do
            if v.name == "Enabled" then enabled = v end
        end
        t:assert(enabled, "which holds Enabled")
        t:assert_eq(enabled.type, "dword", "as a REG_DWORD")
        t:assert_eq(enabled.data, 1, "of 1")
    end)

-- ---- bootstrap ----------------------------------------------------------

test("the bootstrap finds Events and walks the kernel's roots beneath it",
    { spec = "PKM *policy.discovered-at-bootstrap" }, function(t)
        with_machine(function(s)
            seed_other_kernel_keys(s)
            local ev = s:key(EVENTS_PATH)
            s:value(ev, "Enabled", lcs.TYPE.DWORD, lcs.dword(1))
            s:key(EVENTS_PATH .. "\\kacs")
        end, function(src, w)
            local walk = traffic(src)
            t:assert(walk:match("LOOKUP%(Generic%) LOOKUP%(Events%)"),
                "Machine\\Generic\\Events is discovered: " .. walk)
            t:assert(reads_of(src, 1, src:lookup(EVENTS_PATH)) >= 1,
                "and its Enabled is read: " .. walk)
        end)
    end)

test("the walk looks only where a kernel type's path goes",
    { spec = "PKM *policy.walk-follows-kernel-types" }, function(t)
        with_machine(function(s)
            seed_other_kernel_keys(s)
            s:key(EVENTS_PATH .. "\\kacs")
            -- A vendor's subtree beside the kernel's: nothing a kernel
            -- type's path passes through.
            s:key(EVENTS_PATH .. "\\org\\jellyfin")
        end, function(src, w)
            local walk = traffic(src)
            for _, root in ipairs({ "kacs", "kmes", "lcs", "ntfe", "stratafs" }) do
                t:assert(walk:match("LOOKUP%(" .. root .. "%)"),
                    "the root " .. root .. " is looked up: " .. walk)
            end
            t:assert(walk:match("LOOKUP%(audit%)"),
                "beneath kacs, which exists, its children are: " .. walk)
            t:assert(reads_of(src, 1, src:lookup(EVENTS_PATH .. "\\kacs")) >= 1,
                "and kacs's own Enabled is read")
            t:assert(not walk:match("LOOKUP%(org%)"),
                "a vendor root is never asked for: " .. walk)
        end)
    end)

test("a missing key ends the walk beneath it",
    { spec = "PKM *policy.missing-key-ends-walk" }, function(t)
        -- Events exists with no root beneath it: one query, then one
        -- lookup per root, and nothing below any of them.
        with_machine(function(s)
            seed_other_kernel_keys(s)
            s:key(EVENTS_PATH)
        end, function(src, w)
            local walk = traffic(src)
            t:assert(walk:match("LOOKUP%(stratafs%)"),
                "the last root is looked up: " .. walk)
            for _, below in ipairs({ "audit", "caap", "config", "buffer",
                                     "verdict", "file", "mutation" }) do
                t:assert(not walk:match("LOOKUP%(" .. below .. "%)"),
                    below .. " is not asked for beneath a missing root: " .. walk)
            end
        end)
    end)

test("Events created later is noticed by the machine-root fallback",
    { spec = "PKM *policy.discovered-at-bootstrap" }, function(t)
        -- No Machine\Generic at registration: the fallback watch stays
        -- armed for it. Creating Events, two levels below Machine, re-runs
        -- the bootstrap, which walks it and arms its own watch.
        with_machine(seed_other_kernel_keys, function(src, w)
            local generic = lcs.create_key(src, w, { path = "Machine\\Generic" })
            t:assert(generic.ret >= 0, "Machine\\Generic is created: "
                .. sys.errname(generic.errno or 0))
            local mark = src:mark()
            local made = lcs.create_key(src, w,
                { parent_fd = generic.ret, path = "Events" })
            t:assert(made.ret >= 0, "Machine\\Generic\\Events is created: "
                .. sys.errname(made.errno or 0))
            sys.close(w, generic.ret)
            local events_guid = src:lookup(EVENTS_PATH)
            t:assert(events_guid, "the source holds it")
            t:assert(reads_of(src, mark, events_guid) >= 1,
                "and the re-run bootstrap walked it: " .. traffic(src, mark))

            mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, made.ret, "Enabled",
                lcs.TYPE.DWORD, lcs.dword(0)).ret, 0, "Enabled = 0 is written")
            t:assert(reads_of(src, mark, events_guid) >= 2,
                "and its own watch re-walks it: " .. traffic(src, mark))
            sys.close(w, made.ret)
        end)
    end)

-- ---- noticing a change -------------------------------------------------

test("a change beneath a kernel root is walked within the debounce window",
    { spec = "PKM *policy.change-applies-within-50ms-plus-one-walk" },
    function(t)
        -- `set_value` serves the source until it has been quiet for
        -- 100 ms. The walk is scheduled 50 ms after the write's watch
        -- event, so it arrives inside that window: the change is read
        -- back within about 50 ms plus the walk, never a second.
        with_machine(function(s)
            seed_other_kernel_keys(s)
            s:key(EVENTS_PATH .. "\\kacs")
        end, function(src, w)
            local events_guid = src:lookup(EVENTS_PATH)
            local kacs = open(t, src, w, EVENTS_PATH .. "\\kacs")
            local mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, kacs, "Enabled", lcs.TYPE.DWORD,
                lcs.dword(0)).ret, 0, "kacs Enabled = 0 is written")
            t:assert_eq(reads_of(src, mark, events_guid), 1,
                "and exactly one walk read it back: " .. traffic(src, mark))
            sys.close(w, kacs)
        end)
    end)

test("the watch passes on only what can change a kernel type",
    { spec = "PKM *policy.watch-filtered-to-kernel-roots" }, function(t)
        with_machine(function(s)
            seed_other_kernel_keys(s)
            s:key(EVENTS_PATH .. "\\kacs")
        end, function(src, w)
            local events_guid = src:lookup(EVENTS_PATH)
            local events = open(t, src, w, EVENTS_PATH)

            -- A vendor key appearing under Events, and Enabled set on it.
            local mark = src:mark()
            local vendor = lcs.create_key(src, w,
                { parent_fd = events, path = "org\\jellyfin" })
            t:assert(vendor.ret >= 0, "a vendor key is created")
            t:assert_eq(lcs.set_value(src, w, vendor.ret, "Enabled",
                lcs.TYPE.DWORD, lcs.dword(0)).ret, 0, "and switched off")
            t:assert_eq(reads_of(src, mark, events_guid), 0,
                "neither re-walks the kernel's policy: " .. traffic(src, mark))

            -- A value under a kernel root that is not Enabled.
            local kacs = open(t, src, w, EVENTS_PATH .. "\\kacs")
            mark = src:mark()
            t:assert_eq(lcs.set_value(src, w, kacs, "Comment", lcs.TYPE.DWORD,
                lcs.dword(7)).ret, 0, "another value is written under kacs")
            t:assert_eq(reads_of(src, mark, events_guid), 0,
                "and decides nothing: " .. traffic(src, mark))

            -- A kernel root appearing, in any case.
            mark = src:mark()
            local ntfe = lcs.create_key(src, w,
                { parent_fd = events, path = "NTFE" })
            t:assert(ntfe.ret >= 0, "a kernel root is created")
            t:assert(reads_of(src, mark, events_guid) >= 1,
                "and that is walked: " .. traffic(src, mark))

            sys.close(w, ntfe.ret); sys.close(w, kacs)
            sys.close(w, vendor.ret); sys.close(w, events)
        end)
    end)

-- ---- what runs under KUnit -------------------------------------------

test("the kernel's event types are generated from its fragments",
    { spec = "PKM *policy.closed-kernel-type-table",
      covered_by = "build:pkm/tools/gen-kmes-event-table.py",
      skip = "the table is compiled in and has no outward form; " ..
             "`gen-kmes-event-table.py --check` fails the build when " ..
             "kmes/event_types.h or event_types.rs differs from the " ..
             "evman fragments" }, function(t) end)

test("the policy is one enabled bit per kernel type",
    { spec = "PKM *policy.mask-one-bit-per-type",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "the mask is not readable from outside and no emitter " ..
             "consults it yet; runs under " ..
             "pkm_lcs_kunit_kmes_event_policy_resolution_table and " ..
             "pkm_lcs_kunit_kmes_event_policy_essential_fold" },
    function(t) end)

test("an essential type never consults the policy",
    { spec = "PKM *policy.essential-never-consults",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "needs a mask with every bit clear, which only a kernel-side " ..
             "caller can publish; runs under " ..
             "pkm_lcs_kunit_kmes_event_policy_essential_fold" },
    function(t) end)

test("before the first walk the tier decides",
    { spec = "PKM *policy.early-boot-tier-defaults",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "the mask in force before any source registers has no " ..
             "outward sign while no emitter consults it; runs under " ..
             "pkm_lcs_kunit_kmes_event_policy_early_boot_defaults" },
    function(t) end)

test("no Events key means tier defaults",
    { spec = "PKM *policy.absent-key-is-tier-defaults",
      covered_by = "kunit:pkm_lcs_kunit_source",
      skip = "observing the mask needs a kernel-side vantage; runs under " ..
             "pkm_lcs_kunit_source_bootstrap_refresh_machine_hive_success, " ..
             "whose hive has no Machine\\Generic" }, function(t) end)

test("only a REG_DWORD of 0 or 1 is a setting",
    { spec = "PKM *policy.enabled-dword-only",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "an ignored value changes no mask, and the mask is not " ..
             "readable from outside; runs under " ..
             "pkm_lcs_kunit_kmes_event_policy_enabled_values" },
    function(t) end)

test("the deepest Enabled on a type's path decides",
    { spec = "PKM *policy.resolution",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "PGSS §6.9's example tree and its variants, for every kernel " ..
             "type; runs under " ..
             "pkm_lcs_kunit_kmes_event_policy_resolution_table" },
    function(t) end)

test("a walk publishes the mask it computes",
    { spec = "PKM *policy.walk-publishes",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "the published mask is not readable from outside; runs under " ..
             "pkm_lcs_kunit_kmes_event_policy_walk_publishes" },
    function(t) end)

test("a failed walk keeps the mask in force",
    { spec = "PKM *policy.failed-walk-keeps-mask",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "needs a mask other than the defaults in force before the " ..
             "walk, which only a kernel-side caller can publish; runs " ..
             "under pkm_lcs_kunit_kmes_event_policy_failed_walk_keeps_mask" },
    function(t) end)
