-- PKM §5.10.1–§5.10.2 — the bootstrap problem and the boot sequence.
--
-- The three circular dependencies and the three rules that break them,
-- and what happens from PKM initialisation to a registered source.
--
-- Two guests. `virgin` never has a source registered against it, which
-- is the only way to observe "before any source registers": an empty
-- routing table and the compiled-in defaults with nothing to have
-- configured them. `vm` carries the sources; every case there registers
-- its own, all sharing one Machine root GUID because a Down slot keeps
-- its hive identity (§5.8.2) and a second root for the same name would
-- be ESTALE.
--
-- The operational parameters themselves are in boot-parameters, the
-- internal watch that drives the transition in boot-self-watch.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()
local virgin = provium:vm("virgin", "kernel-only"):boot()

-- One root for every Machine hive in this file: see the header.
local MACHINE_ROOT = lcs.guid()

--- A Machine source of this file's own, seeded by `fn`, registered and
--- pumped. Returns the source.
local function machine(seed, o)
    o = o or {}
    local src = lcs.source(vm, { hives = {
        { name = "Machine", root = MACHINE_ROOT, sd = o.sd },
    } })
    if seed then seed(src) end
    assert(src:register(o))
    if not o.no_pump then src:pump() end
    return src
end

--- The RSI op names a source was asked for, LOOKUPs carrying the name
--- they asked about: "LOOKUP(System) QUERY_VALUES ...".
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

test("LCS runs on compiled-in defaults from the moment PKM initialises",
    { spec = "PKM *boot.defaults-active-from-init" }, function(t)
        -- No source has ever registered against this guest, so nothing
        -- can have configured anything. The compiled-in
        -- MaxPathComponentLength of 255 (§5.10.3) is nevertheless being
        -- enforced: 255 bytes is walked, 256 is refused before the walk.
        local w = virgin:spawn_worker()
        local ok = lcs.open_key(nil, w, -1,
            "Machine\\" .. string.rep("a", 255), lcs.RIGHT.KEY_READ)
        t:assert_eq(ok.errno, sys.E.NOENT,
            "a 255-byte component is within the compiled-in limit and is walked")
        local too_long = lcs.open_key(nil, w, -1,
            "Machine\\" .. string.rep("a", 256), lcs.RIGHT.KEY_READ)
        t:assert_eq(too_long.errno, sys.E.NAMETOOLONG,
            "a 256-byte component exceeds the compiled-in 255 and is refused")
        -- And a syscall that needs no source at all is answered, rather
        -- than waiting for a configuration that will never arrive.
        local txn, errno = lcs.begin_transaction(w)
        t:assert(txn, "reg_begin_transaction answers with no source registered: "
            .. sys.errname(errno or 0))
        if txn then sys.close(w, txn) end
        w:kill(); w:join()
    end)

test("there is no waiting-for-configuration state: registration never blocks on it",
    { spec = "PKM *boot.no-waiting-for-configuration-state" }, function(t)
        -- The first attempt to read configuration happens after a
        -- source has registered. Hold every lookup the refresh makes:
        -- REG_SRC_REGISTER has already returned, and unrelated syscalls
        -- keep being answered while the refresh sits unanswered.
        local src = lcs.source(vm, { hives = {
            { name = "Machine", root = MACHINE_ROOT } } })
        src:key("Machine\\System\\Registry")
        src:intercept(lcs.OP.LOOKUP, function() return lcs.HOLD end)
        local ok, err = src:register()
        t:assert(ok, "REG_SRC_REGISTER returns without waiting for configuration: "
            .. tostring(err))
        src:pump()
        t:assert(#src:held_ids() > 0,
            "the refresh's first lookup is still unanswered")

        local w = vm:spawn_worker()
        local txn = lcs.begin_transaction(w)
        t:assert(txn, "and LCS still answers syscalls while it is unanswered")
        if txn then sys.close(w, txn) end
        w:kill(); w:join()

        src:intercept(lcs.OP.LOOKUP, nil)
        for _, id in ipairs(src:held_ids()) do src:release(id) end
        src:close()
    end)

test("before any source registers, every operation naming a hive is ENOENT",
    { spec = "PKM *boot.empty-routing-table-enoent" }, function(t)
        -- The routing table is empty, which is not a state: it is a
        -- table with nothing in it, and a name it does not hold is
        -- simply absent.
        local w = virgin:spawn_worker()
        local open = lcs.open_key(nil, w, -1, "Machine\\Software\\Test",
            lcs.RIGHT.KEY_READ)
        t:assert_eq(open.errno, sys.E.NOENT, "reg_open_key on Machine is ENOENT")
        local create = lcs.create_key(nil, w, { path = "Machine\\Software\\New" })
        t:assert_eq(create.errno, sys.E.NOENT, "reg_create_key on Machine is ENOENT")
        local users = lcs.open_key(nil, w, -1, "Users\\Somebody",
            lcs.RIGHT.KEY_READ)
        t:assert_eq(users.errno, sys.E.NOENT, "and on Users, the other name LCS knows")
        local unknown = lcs.open_key(nil, w, -1, "Widget\\Thing",
            lcs.RIGHT.KEY_READ)
        t:assert_eq(unknown.errno, sys.E.NOENT,
            "a hive nobody ever backed is the same ENOENT: routing is entirely dynamic")
        w:kill(); w:join()
    end)

test("configuration arriving is a hot-swap in place, not a restart",
    { spec = "PKM *boot.hot-swap-not-restart" }, function(t)
        -- A source registers with no Machine\System\Registry at all,
        -- runs on the defaults, and the key appears afterwards. LCS
        -- swaps the values in place: the fds and the source registration
        -- that existed before the swap are the same ones after it.
        local src = machine(function(s) s:key("Machine\\Software\\Test") end)
        local w = vm:spawn_worker()
        local before = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.KEY_ALL_ACCESS)
        t:assert(before.ret >= 0, "a key opens on the compiled-in defaults: "
            .. sys.errname(before.errno or 0))
        local held_fd = before.ret
        local big = lcs.set_value(src, w, held_fd, "Big", lcs.TYPE.BINARY,
            string.rep("x", 8192))
        t:assert_eq(big.ret, 0, "and an 8 KiB value fits the default MaxValueSize")

        local sysk = lcs.create_key(src, w, { path = "Machine\\System" })
        local reg = lcs.create_key(src, w,
            { parent_fd = sysk.ret, path = "Registry" })
        t:assert(reg.ret >= 0, "Machine\\System\\Registry is created: "
            .. sys.errname(reg.errno or 0))
        local swap = lcs.set_value(src, w, reg.ret, "MaxValueSize",
            lcs.TYPE.DWORD, lcs.dword(4096))
        t:assert_eq(swap.ret, 0, "and MaxValueSize is written")

        -- Swapped in place: the same fd, opened before the swap, now
        -- refuses what the new value forbids and still serves what it
        -- allows. Nothing was restarted or re-initialised.
        local after = lcs.set_value(src, w, held_fd, "Big2", lcs.TYPE.BINARY,
            string.rep("x", 8192))
        t:assert_eq(after.errno, sys.E.NOSPC,
            "the fd held across the swap is bound by the new MaxValueSize")
        local small = lcs.set_value(src, w, held_fd, "Small", lcs.TYPE.BINARY,
            string.rep("x", 100))
        t:assert_eq(small.ret, 0, "and is otherwise untouched: no fd was invalidated")
        t:assert(src.registered and not src.eof,
            "the source is still registered: LCS did not restart or re-register it")

        sys.close(w, reg.ret); sys.close(w, sysk.ret); sys.close(w, held_fd)
        w:kill(); w:join()
        src:close()
    end)

test("LCS's only requirement of a source is the device and RSI",
    { spec = "PKM *boot.source-dependencies-not-lcs-concern" }, function(t)
        -- This source is a bare worker holding /dev/pkm_registry: no
        -- filesystem of its own, no service, no dependency of any kind.
        -- LCS neither asks about one nor offers a way to declare one —
        -- every request it makes is one of the eighteen RSI verbs.
        local src = machine(function(s) s:key("Machine\\Software\\Test") end)
        local w = vm:spawn_worker()
        local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0, "it serves a key open: " .. sys.errname(r.errno or 0))
        t:assert(#src.log > 0, "having been asked at least one question")
        for _, e in ipairs(src.log) do
            t:assert(lcs.OP_NAME[e.op],
                "LCS asked only RSI ops, never about a dependency: op 0x"
                    .. string.format("%04x", e.op))
        end
        sys.close(w, r.ret)
        w:kill(); w:join()
        src:close()
    end)

test("the normal boot sequence: TCB-gated device, registration, sequence, base layer",
    { spec = "PKM *boot.normal-sequence" }, function(t)
        -- /dev/pkm_registry is registered without consulting
        -- configuration, and SeTcbPrivilege is checked at open.
        token.as_principal(t, virgin, {}, function(w2)
            local fd, e = sys.open(w2, lcs.DEVICE, sys.O.RDWR)
            t:assert(not fd, "an ordinary principal cannot open " .. lcs.DEVICE)
            t:assert_eq(e, sys.E.ACCES, "the TCB check at open refuses it")
            if fd then sys.close(w2, fd) end
        end)

        -- REG_SRC_REGISTER carries hive names, root GUIDs and the max
        -- persisted sequence; LCS advances next_sequence to max + 1.
        local src = machine(function(s) s:key("Machine\\Software\\Test") end,
            { max_sequence = 4242 })
        local w = vm:spawn_worker()
        local fd = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.KEY_ALL_ACCESS).ret
        t:assert(fd >= 0, "the registered hive routes to the source")
        local s = lcs.set_value(src, w, fd, "First", lcs.TYPE.DWORD, lcs.dword(1))
        t:assert_eq(s.ret, 0, "a write succeeds")
        local q = lcs.query_value(src, w, fd, "First")
        t:assert_eq(q.sequence, 4243,
            "next_sequence was advanced to max persisted + 1")
        -- The base layer exists in memory: a write that names no layer
        -- lands in it, with no layer metadata anywhere in the database.
        t:assert_eq(q.layer, "base", "and the write landed in the base layer")
        -- Bootstrap refresh queued: the source was asked to resolve
        -- Machine\System on registration.
        t:assert(traffic(src):match("LOOKUP%(System%)"),
            "the bootstrap refresh was queued and resolved Machine\\System")
        sys.close(w, fd)
        w:kill(); w:join()
        src:close()
    end)

test("the bootstrap refresh runs on a workqueue after REG_SRC_REGISTER returns",
    { spec = "PKM *boot.refresh-on-workqueue-after-register" }, function(t)
        -- Registration cannot have waited for the refresh: the refresh's
        -- very first request is still unanswered when the ioctl has
        -- already returned 0, and the source is free to start answering
        -- ordinary traffic in the meantime.
        local src = lcs.source(vm, { hives = {
            { name = "Machine", root = MACHINE_ROOT } } })
        src:key("Machine\\Software\\Test")
        src:intercept(lcs.OP.LOOKUP, function(_, req)
            if lcs.lookup_name(req) == "System" then return lcs.HOLD end
            return nil
        end)
        local ok = src:register()
        t:assert(ok, "REG_SRC_REGISTER returned")
        src:pump()
        local held = src:held_ids()
        t:assert(#held > 0,
            "with the refresh's first lookup still held: registration did not block on it")

        src:intercept(lcs.OP.LOOKUP, nil)
        local w = vm:spawn_worker()
        local r = lcs.open_key(src, w, -1, "Machine\\Software\\Test",
            lcs.KEY_ALL_ACCESS)
        t:assert(r.ret >= 0,
            "and a source that has registered answers immediately: "
                .. sys.errname(r.errno or 0))
        sys.close(w, r.ret)
        w:kill(); w:join()
        for _, id in ipairs(held) do src:release(id) end
        src:close()
    end)

test("the refresh is triggered by a global hive named Machine, case-insensitively",
    { spec = "PKM *boot.refresh-triggered-by-machine-hive" }, function(t)
        -- A hive by any other name is registered and routed, and no
        -- refresh is queued for it: routing is dynamic, but Machine and
        -- Users are the two names the kernel itself knows.
        local other = lcs.source(vm, { hives = {
            { name = "Widget" }, { name = "Users" } } })
        other:key("Widget\\Thing")
        other:key("Users\\Somebody\\Software")
        assert(other:register())
        other:pump()
        t:assert_eq(#other.log, 0,
            "registering Widget and Users queues no bootstrap refresh")

        -- Users is known, though, as the target of CurrentUser rewriting
        -- (§5.2.1): the walk routes to the Users hive root.
        local w = vm:spawn_worker()
        local mark = other:mark()
        lcs.open_key(other, w, -1, "CurrentUser\\Software", lcs.RIGHT.KEY_READ)
        local users_root = other.roots["users"]
        local routed = false
        for _, e in ipairs(other:served(lcs.OP.LOOKUP, mark, users_root)) do
            routed = routed or e ~= nil
        end
        t:assert(routed, "CurrentUser\\ was rewritten onto the Users hive root")
        w:kill(); w:join()
        other:close()

        -- The name is matched case-insensitively in the kernel.
        local cased = lcs.source(vm, { hives = {
            { name = "mAcHiNe", root = MACHINE_ROOT } } })
        cased:key("mAcHiNe\\System\\Registry")
        assert(cased:register())
        cased:pump()
        t:assert(traffic(cased):match("LOOKUP%(Registry%)"),
            "a hive named mAcHiNe triggers the refresh: the match is case-insensitive")
        cased:close()

        -- A *global* hive: a private Machine is a different hive in a
        -- different scope and is not LCS's own configuration.
        local scope = lcs.guid()
        local private = lcs.source(vm, { hives = {
            { name = "Machine", private = true, scope = scope } } })
        private:key("Machine\\System\\Registry", { root = private.hives[1].root })
        assert(private:register())
        private:pump()
        t:assert_eq(#private.log, 0,
            "a private hive named Machine queues no refresh: the trigger is the global one")
        private:close()
    end)

test("first boot keeps the compiled-in defaults, and seed restore re-runs the refresh",
    { spec = "PKM *boot.first-boot-retains-defaults" }, function(t)
        -- An empty source: root key records and nothing else. LCS
        -- resolves Machine\System\Registry, does not find it, and
        -- retains the defaults rather than failing or waiting.
        local src = machine(function(s) s:key("Machine\\Software\\Test") end)
        t:assert(traffic(src):match("LOOKUP%(System%)"),
            "the refresh looked for Machine\\System")
        t:assert(not traffic(src):match("QUERY_VALUES"),
            "found nothing to read, and read no configuration")

        -- MaxPathComponentLength is this case's parameter, and no other
        -- case in this file writes it: what is in force is still the
        -- compiled-in 255 of §5.10.3.
        local w = vm:spawn_worker()
        local walked = lcs.open_key(src, w, -1,
            "Machine\\" .. string.rep("a", 255), lcs.RIGHT.KEY_READ)
        t:assert_eq(walked.errno, sys.E.NOENT,
            "and the compiled-in MaxPathComponentLength of 255 is what is in force")

        -- Seed restore populates Machine\: the fallback subtree watch
        -- fires and LCS re-runs the whole bootstrap refresh, resolving
        -- the specific GUIDs and hot-swapping the seed values.
        local mark = src:mark()
        local sysk = lcs.create_key(src, w, { path = "Machine\\System" })
        local reg = lcs.create_key(src, w,
            { parent_fd = sysk.ret, path = "Registry" })
        t:assert(reg.ret >= 0, "Machine\\System\\Registry appears: "
            .. sys.errname(reg.errno or 0))
        local after = traffic(src, mark)
        t:assert(after:match("LOOKUP%(Registry%).*QUERY_VALUES"),
            "the fallback watch re-entered the refresh, which resolved and read it: "
                .. after)
        local swap = lcs.set_value(src, w, reg.ret, "MaxPathComponentLength",
            lcs.TYPE.DWORD, lcs.dword(64))
        t:assert_eq(swap.ret, 0, "the seed value is written")
        local now = lcs.open_key(src, w, -1,
            "Machine\\" .. string.rep("a", 100), lcs.RIGHT.KEY_READ)
        t:assert_eq(now.errno, sys.E.NAMETOOLONG,
            "and validated and hot-swapped: the seeded MaxPathComponentLength is in force")

        sys.close(w, reg.ret); sys.close(w, sysk.ret)
        w:kill(); w:join()
        src:close()
    end)
