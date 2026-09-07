-- peinit TRM §2.4 — boot-time path provisioning: the registry-backed way
-- a filesystem object that belongs to no service comes to exist, with the
-- descriptor it is supposed to have, before anything that uses it starts.
--
-- Everything here rides on one boot. Provisioning is a single pass over
-- the child keys of `Machine\System\Init\ProvisionedPaths`, each entry is
-- independent of every other, and the pass leaves two kinds of evidence
-- behind: the filesystem, and a console line per entry that did not
-- apply. So one seed carrying a dozen entries — good ones, ones that must
-- fail, ones that must not even be attempted — exercises the whole
-- chapter, and each test below reads its own entry's outcome out of that
-- one boot. Entries are applied in sorted key order and cannot see each
-- other, so no test here depends on another's entry.
--
-- The seed is applied by the image's own `10-apply-seeds.sh` at Phase 1
-- step 7; provisioning is step 8. So the entries are in the registry
-- before peinit reads them, which is the only reason a test can choose
-- them at all.
--
-- Two things about the paths chosen. `/run` is a tmpfs peinit mounts in
-- Phase 1, so an entry under it is created fresh on every boot and cannot
-- be confused with something the image ships. `/lcl` is real root, which
-- is where the two entries that need a pre-existing object of a
-- particular type point: `/lcl/policy` is a directory the image ships,
-- and `/lcl/pt-keepme.txt` is a file this test stages.
--
-- The required-entry case is not here. It ends in recovery rather than a
-- Phase 2, so it cannot share a boot with anything; it lives in
-- boot-provisioning-required.test.lua.

local peinit = require("helpers.peinit")
peinit.claim(1)

--- `O:SY G:SY D:(A;;GA;;;SY)` as the self-relative bytes a registry
--- binary value carries (MS-DTYP 2.4.6): the 20-byte header with the
--- control word and four offsets, the owner and group SIDs, then a DACL
--- of exactly one ACE.
---
--- Written out rather than built, because a `Security` value is bytes and
--- nothing in the image turns SDDL into them. One ACE is the whole point:
--- the built-in default has three, so a path carrying this one could not
--- have got its descriptor from the default.
local SYSTEM_ONLY = table.concat({
    "01 00 04 80",                                     -- revision, sbz, SELF_RELATIVE|DACL_PRESENT
    "14 00 00 00 20 00 00 00 00 00 00 00 2c 00 00 00", -- owner, group, sacl (none), dacl offsets
    "01 01 00 00 00 00 00 05 12 00 00 00",             -- owner  S-1-5-18
    "01 01 00 00 00 00 00 05 12 00 00 00",             -- group  S-1-5-18
    "02 00 1c 00 01 00 00 00",                         -- ACL: revision 2, 28 bytes, one ACE
    "00 00 14 00 00 00 00 10",                         -- ACE: allow, 20 bytes, mask 0x10000000
    "01 01 00 00 00 00 00 05 12 00 00 00",             -- ACE trustee S-1-5-18
}, " ")

--- The built-in default, as the chapter states it and as peinit's own
--- `DEFAULT_PROVISIONED_PATH_SDDL` spells it, verbatim.
---
--- This is what comes back from a path peinit *stamped* — one that was
--- already there and was opened rather than created.
local DEFAULT_SDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;FR;;;BU)"

--- The same descriptor as it comes back from a path peinit *created*.
---
--- `GA` reads back as `FA` because a creator descriptor's generic rights
--- are mapped to the object type's specific rights as the object is
--- made, while `fd_set_sd` on an existing object stores what it is
--- given. Same descriptor, two renderings, and which one a test sees
--- says which branch of `ensure_file`/`ensure_directory` ran — so the
--- distinction is load-bearing rather than cosmetic.
local DEFAULT_SDDL_CREATED = "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

local function entry(name, values)
    return { path = [[Machine\System\Init\ProvisionedPaths\]] .. name, values = values }
end

local function dir(name, path, extra)
    local values = {
        { name = "Kind", type = "sz", data = "directory" },
        { name = "Path", type = "sz", data = path },
    }
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return entry(name, values)
end

local function file(name, path, extra)
    local values = {
        { name = "Kind", type = "sz", data = "file" },
        { name = "Path", type = "sz", data = path },
    }
    for _, v in ipairs(extra or {}) do values[#values + 1] = v end
    return entry(name, values)
end

local KEEPME = "/lcl/pt-keepme.txt"
local KEEPME_BODY = "provisioning must not touch this\n"

local vm = peinit.boot({
    name = "provisioned",
    files = peinit.merge(
        { ["lcl/pt-keepme.txt"] = KEEPME_BODY },
        peinit.seed("zz-pt-provision", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Init]] },
            { path = [[Machine\System\Init\ProvisionedPaths]] },

            -- The two that simply work, one of each Kind.
            dir("pt-dir", "/run/pt-dir"),
            file("pt-file", "/run/pt-file"),

            -- Carries a value peinit has no field for.
            dir("pt-unknown", "/run/pt-unknown", {
                { name = "Nonsense", type = "sz", data = "not a field" },
            }),

            -- Carries its own descriptor, and one that cannot be decoded.
            dir("pt-supplied", "/run/pt-supplied", {
                { name = "Security", type = "binary", data = SYSTEM_ONLY },
            }),
            dir("pt-badsd", "/run/pt-badsd", {
                { name = "Security", type = "binary", data = "de ad be ef" },
            }),

            -- An object that is already there, of the right type: opened,
            -- not created.
            file("pt-keep", KEEPME),

            -- Already there, of the wrong type, in both directions.
            file("pt-wrongtype-file", "/lcl/policy"),
            dir("pt-wrongtype-dir", KEEPME),

            -- Parent does not exist, and peinit does not make one.
            dir("pt-noparent", "/run/pt-absent/child"),

            -- Malformed three ways, and two of them say Required=1.
            entry("pt-nokind", {
                { name = "Path", type = "sz", data = "/run/pt-nokind" },
                { name = "Required", type = "dword", data = 1 },
            }),
            dir("pt-relative", "relative/path", {
                { name = "Required", type = "dword", data = 1 },
            }),
            entry("pt-badkind", {
                { name = "Kind", type = "sz", data = "socket" },
                { name = "Path", type = "sz", data = "/run/pt-badkind" },
            }),
        })
    ),
})

local LOG = vm:console():read_log()

--- The console line peinit writes for an entry that decoded but did not
--- apply. `Required=0`, so it is a warning and the boot carries on.
local function failure_line(name)
    return LOG:match("peinit warning: provisioned path " .. name .. " at ([^\r\n]+)")
end

--- The console line for an entry that never got as far as being applied,
--- because the entry itself did not decode.
local function ignored_line(name)
    return LOG:match("peinit warning: provisioned path " .. name .. " ignored: ([^\r\n]+)")
end

local function sddl(path)
    local r = vm:run("sd show --sddl " .. path)
    r:assert_ok()
    return (r.stdout:match("(O:[^\r\n]+)"))
end

test("provisioning runs after registryd is serving and before Phase 2 is planned",
    { spec = "peinit *provision.runs-after-registryd-and-before-phase-2" },
    function(t)
        -- The console is the only record of an ordering, and provisioning
        -- announces itself only through the entries that failed — which
        -- is why the seed above deliberately contains some. Positions in
        -- the log, not line numbers: peinit interleaves nothing else here
        -- but the autorun summaries.
        local registryd = LOG:find("peinit: phase1 registryd started", 1, true)
        local phase2 = LOG:find("peinit: phase2 boot starting", 1, true)
        t:assert(registryd and phase2 and registryd < phase2,
            "the boot reached both marks in order")

        -- Every entry that produced a line produced it in the window.
        -- `pt-noparent` is the one asserted on because it is the entry
        -- whose failure is entirely peinit's own doing.
        local at = LOG:find("peinit warning: provisioned path pt%-noparent")
        t:assert(at, "the failing entry was reported: " .. LOG:sub(-600))
        t:assert(at > registryd,
            "provisioning came after registryd was serving, which is what makes the entries readable")
        t:assert(at < phase2,
            "and before Phase 2 was planned, which is what makes them usable by the first service")
    end)

test("each child key under ProvisionedPaths is one entry, and a value peinit has no field for is ignored",
    {
        spec = {
            "peinit *provision.each-child-key-is-an-entry",
            "peinit *provision.unknown-values-are-ignored",
        },
    },
    function(t)
        -- The seed named twelve child keys; the registry has them as
        -- siblings under the one parent, alongside the image's own.
        local listing = vm:run([[reg ls 'Machine\System\Init\ProvisionedPaths' --keys-only]])
        listing:assert_ok()
        for _, name in ipairs({ "pt-dir", "pt-file", "pt-unknown", "pt-supplied", "pt-badsd",
                                "pt-keep", "pt-wrongtype-file", "pt-wrongtype-dir",
                                "pt-noparent", "pt-nokind", "pt-relative", "pt-badkind" }) do
            t:assert(listing.stdout:find(name, 1, true),
                name .. " is a child key of the provisioning root: " .. listing.stdout)
        end

        -- One key, one entry: each of those keys got its own outcome —
        -- a path of its own, or a console line naming it. Nothing was
        -- merged and nothing was skipped for being a sibling of a
        -- broken one.
        t:assert_eq(vm:stat("/run/pt-dir").entry_type, "directory", "pt-dir applied")
        t:assert_eq(vm:stat("/run/pt-unknown").entry_type, "directory", "pt-unknown applied")
        t:assert(failure_line("pt%-noparent"), "pt-noparent reported on its own")
        t:assert(ignored_line("pt%-badkind"), "pt-badkind reported on its own")

        -- And `Nonsense` on pt-unknown neither failed the entry nor
        -- produced a complaint: an unrecognised value is passed over.
        t:assert(not LOG:find("Nonsense", 1, true),
            "peinit said nothing about the value it has no field for: " .. LOG:sub(-600))
        t:assert(not failure_line("pt%-unknown") and not ignored_line("pt%-unknown"),
            "and the entry carrying it applied like any other")
    end)

test("Kind decides what is ensured, and an entry with no Security gets the built-in default",
    {
        spec = {
            "peinit *provision.kind-decides-what-is-ensured",
            "peinit *provision.the-built-in-default-descriptor",
        },
    },
    function(t)
        t:assert_eq(vm:stat("/run/pt-dir").entry_type, "directory",
            "Kind=directory ensured a directory")
        t:assert_eq(vm:stat("/run/pt-file").entry_type, "file",
            "Kind=file ensured a regular file")

        -- SYSTEM and Administrators full control, ordinary users read.
        -- Both were created by this pass, so the generic rights read back
        -- mapped; the stamped rendering is asserted on the pre-existing
        -- file in the truncation test below.
        for _, path in ipairs({ "/run/pt-dir", "/run/pt-file" }) do
            t:assert_eq(sddl(path), DEFAULT_SDDL_CREATED,
                path .. " carries the built-in default descriptor")
        end
    end)

test("a path that exists with a different file type fails the entry, and an optional entry is fail-soft",
    {
        spec = {
            "peinit *provision.a-type-mismatch-fails-the-entry",
            "peinit *provision.an-optional-entry-is-fail-soft",
        },
    },
    function(t)
        -- Both directions. `/lcl/policy` is a directory the image ships
        -- and the entry asks for a file; `/lcl/pt-keepme.txt` is the file
        -- this test staged and the entry asks for a directory.
        local as_file = failure_line("pt%-wrongtype%-file")
        t:assert(as_file and as_file:find("/lcl/policy", 1, true),
            "Kind=file on an existing directory failed: " .. tostring(as_file))
        local as_dir = failure_line("pt%-wrongtype%-dir")
        t:assert(as_dir and as_dir:find(KEEPME, 1, true),
            "Kind=directory on an existing regular file failed: " .. tostring(as_dir))

        -- Fail-soft: neither entry carries Required, so peinit logged and
        -- carried on. The boot reaching Phase 2 at all is the assertion —
        -- `peinit.boot` above waited for it.
        t:assert(LOG:find("peinit: phase2 boot complete", 1, true),
            "the boot proceeded past two failed optional entries")
        t:assert(not LOG:find("entering recovery", 1, true),
            "and did not go to recovery: " .. LOG:sub(-600))
    end)

test("an existing file is opened rather than created, so provisioning never truncates one",
    { spec = "peinit *provision.an-existing-file-is-never-truncated" },
    function(t)
        -- The entry applied — it is in neither failure list — so the
        -- surviving contents are the contents of a file peinit opened,
        -- not of one it declined to touch.
        t:assert(not failure_line("pt%-keep") and not ignored_line("pt%-keep"),
            "the entry naming an existing file applied")
        t:assert_eq(vm:read_file(KEEPME), KEEPME_BODY,
            "and the file still holds every byte it held before the boot")

        -- What the entry did do is stamp the descriptor, which is the
        -- evidence that it was opened rather than passed over — and it
        -- is the stamped rendering, not the created one, which is the
        -- same statement made a second way.
        t:assert_eq(sddl(KEEPME), DEFAULT_SDDL,
            "the descriptor was applied to the file that was already there")
    end)

test("peinit does not create parent directories",
    { spec = "peinit *provision.parents-are-not-created" },
    function(t)
        local reported = failure_line("pt%-noparent")
        t:assert(reported and reported:find("/run/pt-absent/child", 1, true),
            "the entry failed: " .. tostring(reported))
        t:assert(reported:find("parent", 1, true),
            "and peinit named the parent as the reason rather than a bare errno: " .. reported)

        -- Neither the missing parent nor the child was created.
        t:assert(not vm:run("sd show /run/pt-absent"):ok(),
            "the parent peinit refused to create is not there")
        t:assert(not vm:run("sd show /run/pt-absent/child"):ok(),
            "and neither is the entry's own path")
    end)

test("a supplied descriptor is applied, and one that cannot be decoded fails the entry",
    {
        spec = {
            "peinit *provision.a-supplied-descriptor-is-applied",
            "peinit *provision.a-bad-descriptor-fails-the-entry",
        },
    },
    function(t)
        -- One ACE, and it is the one the seed named. The built-in default
        -- has three, so this cannot be the default by accident.
        t:assert_eq(sddl("/run/pt-supplied"), "O:SYG:SYD:(A;;FA;;;SY)",
            "the descriptor the entry carried is the one on the path")

        -- A descriptor peinit cannot decode fails the entry before the
        -- path is touched, rather than falling back to the default —
        -- which would create the object with rights nobody asked for.
        local reported = failure_line("pt%-badsd")
        t:assert(reported and reported:find("/run/pt-badsd", 1, true),
            "the entry with the malformed descriptor failed: " .. tostring(reported))
        t:assert(not vm:run("sd show /run/pt-badsd"):ok(),
            "and its path was not created with some other descriptor instead")
    end)

test("a malformed entry is logged and skipped whatever Required says",
    { spec = "peinit *provision.a-malformed-entry-is-skipped-whatever-required-says" },
    function(t)
        -- Three ways to be malformed: no Kind, a Kind that names nothing,
        -- and a Path that is not absolute.
        t:assert(ignored_line("pt%-nokind"), "a missing Kind was reported as ignored")
        t:assert(ignored_line("pt%-badkind"), "an unrecognised Kind was reported as ignored")
        t:assert(ignored_line("pt%-relative"), "a relative Path was reported as ignored")

        -- Two of the three carry Required=1. A required entry that FAILS
        -- is recovery; a required entry that does not decode is not,
        -- because Required marks a path as essential rather than making
        -- a broken declaration more dangerous than a missing one.
        t:assert(LOG:find("peinit: phase2 boot complete", 1, true),
            "the boot proceeded despite two malformed Required=1 entries")
        t:assert(not LOG:find("required provisioned path", 1, true),
            "and peinit never treated one as a required failure: " .. LOG:sub(-600))

        -- Skipped means skipped: nothing was created for them.
        t:assert(not vm:run("sd show /run/pt-nokind"):ok(),
            "the entry with no Kind produced no path")
        t:assert(not vm:run("sd show /run/pt-badkind"):ok(),
            "and neither did the one whose Kind names nothing")
    end)
