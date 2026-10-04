-- loregd §1.1 (Overview) — where loregd sits, and the invariants the whole
-- manual rests on.
--
-- Most of this chapter is architectural prose. The parts that are reachable
-- from a guest are proven against a real second loregd serving PtState (the
-- helpers/loregd harness) and against the image's own boot registryd; the
-- parts that are wire-direction or trust-boundary facts a caller never sees
-- are homed on the loregd Go unit tests that assert them, with the closed
-- guest route noted at each stub.
--
-- The daemon is booted once at file scope and shared by every non-reboot
-- case. The sequence-number case reboots (power_cut + vm:reset), so it comes
-- last; the disk is mediated for it.

local loregd = require("helpers.loregd")
local lcs = require("helpers.lcs")
local sys = require("helpers.sys")

local KEY = loregd.KEY -- PtState\Durable

local vm = loregd.boot({ name = "loregd-overview", mediated = true })
local disk = vm:disk("hive")
loregd.format(vm)
loregd.mount(vm)
local proc = loregd.start(vm)

-- ==== reachable: serving, and the source-agnostic kernel ================

-- §1.1: "It holds one or more registry hives in SQLite databases and serves
-- them to the kernel's registry subsystem over the Registry Source Interface
-- (RSI)." A key round-trips through the kernel to our loregd, and the file
-- backing the hive is a SQLite database.
--
-- §1.1: "Any process that implements the RSI contract can serve as a registry
-- source, and the kernel is source-agnostic." Our PtState source is a process
-- the test launched itself — not the image's boot registryd, not started from
-- any service definition — and the kernel routes to it exactly as it routes to
-- the boot source's Machine hive.
test("loregd holds a hive in SQLite and serves it over RSI, as any RSI process may", {
    spec = "loregd *overview.loregd-holds-hives-in-sqlite-and-serves-them-over-rsi" ..
        " *overview.any-process-implementing-rsi-can-be-a-registry-source",
}, function(t)
    -- Round-trip through the kernel: create, write, read back.
    loregd.new_key(vm, KEY):assert_ok()
    loregd.set(vm, KEY, "RoundTrip", "dword:42"):assert_ok()
    local r, v = loregd.get(vm, KEY, "RoundTrip")
    r:assert_ok()
    t:assert_eq(v, "42",
        "a value set on our hive read back through the kernel — loregd served " ..
        "the hive over RSI")

    -- The hive is backed by a SQLite database file. Its first 15 bytes are
    -- the SQLite format-3 magic (before the trailing NUL of the 16-byte
    -- header string).
    local head = vm:run("head -c 15 '" .. loregd.HIVE_FILE .. "'")
    head:assert_ok()
    t:assert_eq(head.stdout, "SQLite format 3",
        "the file backing the hive is a SQLite database: " .. head.stdout)

    -- Source-agnostic kernel: the boot registryd serves Machine, our
    -- self-launched process serves PtState, and the same `reg` path reaches
    -- both. loregd is not architecturally special — any RSI process is a
    -- source.
    t:assert(not loregd.exited(vm, proc:pid()),
        "our PtState source is a live process the test launched")
    t:assert_eq(vm:run("reg info PtState").exit_code, 0,
        "the kernel routes to our self-launched RSI process for PtState")
    t:assert_eq(vm:run("reg info Machine").exit_code, 0,
        "and to the separate boot source for Machine — the kernel is agnostic " ..
        "about which process implements RSI for a hive")
end)

-- ==== reachable: the boot source ========================================

-- §1.1: "It is the source that provides the `Machine\` and `Users\` hives at
-- boot, which puts it on the critical path to a running system." Observed
-- against the image's own registryd (loregd), with no second daemon involved:
-- both boot hives resolve on a running system.
test("loregd provides the Machine and Users hives at boot",
    { spec = "loregd *overview.loregd-provides-the-machine-and-users-hives-at-boot" },
    function(t)
        local m = vm:run("reg info Machine")
        t:assert_eq(m.exit_code, 0,
            "the boot registryd serves the Machine hive: " .. m.stderr)
        local u = vm:run("reg info Users")
        t:assert_eq(u.exit_code, 0,
            "and the Users hive — loregd provides both at boot, on the critical " ..
            "path to a running system: " .. u.stderr)
    end)

-- ==== reachable (package): what the loregd package installs =============

-- §1.1: "The `dev.peios.loregd` package installs the daemon, its `registryd`
-- role provider, and the protected empty state directory." The role provider
-- IS the daemon binary: the package declares `[provides] registryd` bound to
-- /usr/sbin/loregd, and the composer materialises the
-- /usr/sbin/registryd -> /usr/sbin/loregd role symlink. Checked against the
-- installed image.
test("the loregd package installs the daemon and its registryd role provider",
    { spec = "loregd *overview.the-loregd-package-installs-the-daemon-and-its-role-provider" },
    function(t)
        t:assert_eq(vm:run("test -x /usr/sbin/loregd").exit_code, 0,
            "the daemon binary is installed at /usr/sbin/loregd")

        -- The registryd role provider: /usr/sbin/registryd resolves to the
        -- loregd binary (the composed role symlink).
        t:assert_eq(vm:run("test -e /usr/sbin/registryd").exit_code, 0,
            "the registryd role provider is present at /usr/sbin/registryd")
        local reg_target = vm:run("readlink -f /usr/sbin/registryd")
        local loregd_target = vm:run("readlink -f /usr/sbin/loregd")
        t:assert_eq(reg_target.stdout, loregd_target.stdout,
            "the registryd role provider resolves to the loregd daemon: " ..
            "registryd -> " .. reg_target.stdout ..
            " vs loregd -> " .. loregd_target.stdout)

        t:assert_eq(vm:run("test -d /var/state/loregd").exit_code, 0,
            "the package-owned protected state directory /var/state/loregd exists")
    end)

-- §1.1: "peinit owns the compiled-in Phase-1 service definition, so Loregd
-- does not ship a second service seed that could compete with it." A service
-- seed would apply as a registry entry under Machine\System\Services; but
-- registryd bootstraps the registry and so can never be an entry in it, and
-- loregd ships nothing under the /usr/share/regim seed directory. Observed:
-- there is no registryd service key, and no loregd/registryd seed file.
test("loregd ships no service seed of its own",
    { spec = "loregd *overview.loregd-ships-no-service-seed-of-its-own" },
    function(t)
        local ls = vm:run("reg ls 'Machine\\System\\Services' --keys-only")
        t:assert_eq(ls.exit_code, 0,
            "the services key enumerates: " .. ls.stderr)
        t:assert(not ls.stdout:lower():find("registryd", 1, true),
            "registryd is not a registry service entry — its definition is " ..
            "compiled into peinit, not seeded, so nothing competes with it: " ..
            ls.stdout)

        -- No loregd/registryd seed shipped under the seed directory. (Other
        -- packages legitimately ship seeds there; loregd ships none.) A seed
        -- that defined the service would name its key; other seeds mention
        -- registryd in their comments, which is not a definition.
        local grep = vm:run([[grep -rlF -e 'Services\\registryd' -e 'Services\\loregd' /usr/share/regim 2>/dev/null]])
        t:assert_eq(grep.stdout:gsub("%s+$", ""), "",
            "loregd ships no service seed under /usr/share/regim: " .. grep.stdout)
    end)

-- ==== reachable: where loregd sits (the trust boundary, observably) ======

-- §1.1: "The registry is split across a trust boundary. The kernel side owns
-- the namespace ... it holds no storage of its own. The source side owns bytes
-- on disk and answers questions about them." Observed as the split it names:
-- the source is an ordinary unprivileged userspace process whose storage is
-- bytes in an on-disk file, reached only across the kernel's registry device.
test("the registry is split across a trust boundary: a userspace source owning " ..
     "bytes on disk, reached across the kernel device", {
    spec = "loregd *overview.the-registry-is-split-across-a-trust-boundary",
}, function(t)
    -- The source side: an ordinary userspace process, not the kernel.
    local exe = vm:run("readlink -f /proc/" .. proc:pid() .. "/exe")
    t:assert_eq((exe.stdout:gsub("%s+$", "")), "/usr/sbin/loregd",
        "the source is a userspace process running the loregd binary: " .. exe.stdout)

    -- It owns bytes on disk: the hive's data is a file on our disk.
    t:assert_eq(vm:run("test -f '" .. loregd.HIVE_FILE .. "'").exit_code, 0,
        "the source owns bytes on disk — the hive is an on-disk file")

    -- The kernel side is reached only across its registry device: that is the
    -- boundary the source registers over, and the namespace lives behind it.
    t:assert_eq(vm:run("test -c " .. lcs.DEVICE).exit_code, 0,
        "the kernel exposes " .. lcs.DEVICE .. ", the boundary the source " ..
        "registers across and the caller resolves the namespace through")
end)

-- ==== unit-cited: wire-direction invariants a caller never sees =========

-- §1.1: "loregd stores; it does not decide. It never resolves layers, never
-- filters results by visibility, and never applies a security descriptor ...
-- The security descriptors in its tables are opaque payload to it."
--
-- Route closed: access checks, layer resolution and visibility filtering are
-- all the kernel's, applied before any result reaches a caller — so a guest
-- can never observe loregd storing an SD it does not interpret, nor returning
-- the unresolved multi-layer entries the kernel picks a winner from.
-- TestWriteKeySD writes an arbitrary 3-byte blob (0xAABBCC — not a valid SD)
-- and reads it back byte-identical: loregd stores the descriptor as opaque
-- payload and never applies it. (TestEnumChildrenDeterministicOrder shows the
-- other half: a name present in two layers is returned carrying both entries,
-- unresolved, for the kernel to decide.)
test("loregd stores; it does not decide", {
    spec = "loregd *overview.loregd-stores-it-does-not-decide",
    skip = true,
    covered_by = "go:loregd internal/handler::TestWriteKeySD",
}, function() end)

-- §1.1: "GUIDs come from the kernel. loregd does not mint key identities. It
-- records the GUID it is given, and uses it as the primary key."
--
-- Route closed: the RSI_CREATE_KEY GUID is chosen by the kernel before loregd
-- ever sees the request, and `reg` exposes no key GUID to a caller (reg info
-- carries subkey/value counts and flags, never a GUID; loregd has no
-- QUERY_KEY_INFO handler), so a guest cannot observe that the identity
-- originated kernel-side. TestCreateKey supplies a GUID on the wire and
-- asserts loregd stores exactly that GUID as the key's primary key — it mints
-- none of its own.
test("guids come from the kernel", {
    spec = "loregd *overview.guids-come-from-the-kernel",
    skip = true,
    covered_by = "go:loregd internal/handler::TestCreateKey",
}, function() end)

-- ==== reachable (reboot): the kernel allocates sequence numbers ==========

-- §1.1: "Sequence numbers come from the kernel. loregd stores them and reports
-- the maximum it holds at registration, but never allocates one." Observed
-- across a reboot: loregd reports its stored maximum at registration and the
-- kernel resumes allocation ABOVE it, so a write made after the reboot carries
-- a sequence strictly greater than one committed before it. Were loregd the
-- allocator (or did it not report the max), a fresh kernel would restart the
-- counter and the post-reboot write could reuse or precede the earlier value.
--
-- Reboots (power_cut + vm:reset), so this case is last.
local function seq_of(key, name)
    local r = vm:run("reg get '" .. key .. "' " .. name .. " --json")
    r:assert_ok()
    local s = r.stdout:match('"sequence"%s*:%s*(%d+)')
    return tonumber(s), r.stdout
end

test("sequence numbers come from the kernel: loregd reports its max and the " ..
     "kernel resumes above it", {
    spec = "loregd *overview.sequence-numbers-come-from-the-kernel",
}, function(t)
    loregd.new_key(vm, [[PtState\Seq]]):assert_ok()
    loregd.set(vm, [[PtState\Seq]], "Before", "dword:1"):assert_ok()
    local before, before_json = seq_of([[PtState\Seq]], "Before")
    t:assert(before ~= nil, "the committed value carries a kernel sequence: " .. before_json)

    disk:power_cut()
    vm:reset()
    loregd.mount(vm, t)
    loregd.start(vm, t)

    -- A fresh write after the reboot. loregd reported max=`before` at
    -- registration and the kernel resumes from there.
    loregd.set(vm, [[PtState\Seq]], "After", "dword:2"):assert_ok()
    local after, after_json = seq_of([[PtState\Seq]], "After")
    t:assert(after ~= nil, "the post-reboot value carries a kernel sequence: " .. after_json)

    t:assert(after > before,
        "the post-reboot write's sequence (" .. tostring(after) .. ") is greater " ..
        "than the pre-reboot value's (" .. tostring(before) .. "): loregd reported " ..
        "its maximum at registration and the kernel resumed allocation above it, " ..
        "rather than either party restarting the counter")
end)
