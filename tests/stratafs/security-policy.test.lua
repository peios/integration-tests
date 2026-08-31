-- PKM §4.6.3, §4.6.4, §4.6.5, §4.8 and §4.A — descriptors on copy-up,
-- the mount policy class, audit, and the consolidated failure modes.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()

local FULL_SD = kacs.SI.OWNER | kacs.SI.GROUP | kacs.SI.DACL

local function copying(t, name, body, entries)
    stratafs.with(vm, name, {
        { name = "dest", flags = { "create" } },
        { name = "src", flags = { "ro" }, entries = entries or { f = "original" } },
    }, body)
end

test("a copy-up carries the source's descriptor whole",
    { spec = "PKM *security.copy-up-descriptor-preserved" }, function(t)
        -- Owner, group, discretionary list, system list and integrity
        -- label alike, as a copy of the source bytes rather than
        -- anything reconstructed field by field.
        copying(t, "sd-preserved", function(s)
            local marked = kacs.grant_all_but(kacs.RIGHT.WRITE_ATTRIBUTES)
            local r = kacs.set_sd(vm, s:in_stratum("src", "f"), marked)
            t:assert_eq(r.ret, 0, "the source is given a distinctive " ..
                "descriptor: " .. sys.errname(r.errno))
            local before = kacs.get_sd(vm, s:in_stratum("src", "f"), FULL_SD)
            t:assert(before, "which reads back")

            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write copies it up")

            t:assert_eq(kacs.get_sd(vm, s:in_stratum("dest", "f"), FULL_SD),
                before, "and the copy carries it byte for byte")
        end)
    end)

test("a copied-up object never receives an inherited descriptor",
    { spec = "PKM *security.copy-up-never-inherits-descriptor" }, function(t)
        -- Ordinary creation in a create stratum inherits from its
        -- parent; copy-up preserves. There is no path on which a
        -- copied-up object receives an inherited descriptor.
        copying(t, "sd-no-inherit", function(s)
            -- Give the create stratum's root a descriptor of its own,
            -- so that anything inheriting from it is recognisable.
            local r = kacs.set_sd(vm, s:in_stratum("dest"),
                kacs.grant(kacs.ALL_RIGHTS))
            t:assert_eq(r.ret, 0, "the create stratum is marked: " ..
                sys.errname(r.errno))
            local source_sd = kacs.get_sd(vm, s:in_stratum("src", "f"), FULL_SD)

            -- An ordinary creation there does inherit.
            t:assert(stratafs.try_create(vm, s:join("created"), "x"),
                "an ordinary creation succeeds")
            local inherited = kacs.get_sd(vm, s:in_stratum("dest", "created"),
                FULL_SD)
            t:assert(inherited, "and has an inherited descriptor")

            -- The copy-up does not.
            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "and a write copies the other up")
            local copied = kacs.get_sd(vm, s:in_stratum("dest", "f"), FULL_SD)
            t:assert_eq(copied, source_sd,
                "the copy carries the source's descriptor")
            t:assert_neq(copied, inherited,
                "and not the one an ordinary creation there would inherit")
        end)
    end)

test("the copy's descriptor owner is the source's, not the caller's",
    { spec = "PKM *security.copy-up-descriptor-owner-is-source" }, function(t)
        -- Ownership therefore does not record who created the copy and
        -- cannot be relied on to; the audit record is where that is.
        copying(t, "sd-owner", function(s)
            local owner_before = kacs.get_sd(vm, s:in_stratum("src", "f"),
                kacs.SI.OWNER)
            t:assert(owner_before, "the source has a descriptor owner")

            kacs.as_dacl_bound(t, vm, function(worker)
                local fd = sys.open(worker, s:join("f"), sys.O.RDWR)
                t:assert(fd, "a caller other than the owner opens it")
                t:assert_eq(sys.write(worker, fd, "modified").ret, 8,
                    "and writes, copying up")
                sys.close(worker, fd)
            end)

            t:assert_eq(kacs.get_sd(vm, s:in_stratum("dest", "f"), kacs.SI.OWNER),
                owner_before,
                "the copy's descriptor owner is the source's")
        end)
    end)

test("what is pinned is the provider's effective descriptor",
    { spec = "PKM *security.copy-up-pins-effective-descriptor" }, function(t)
        -- Reaching the object through the mount at all requires a real
        -- descriptor under the deny-missing class, so the effective
        -- value and the stored one coincide — which is what makes the
        -- synthesising case unreachable in practice.
        copying(t, "sd-effective", function(s)
            local effective = kacs.get_sd(vm, s:join("f"), FULL_SD)
            local stored = kacs.get_sd(vm, s:in_stratum("src", "f"), FULL_SD)
            t:assert(effective and stored, "both read")
            t:assert_eq(effective, stored,
                "the effective descriptor is the stored one")

            t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                "the write copies it up")
            t:assert_eq(kacs.get_sd(vm, s:in_stratum("dest", "f"), FULL_SD),
                effective, "and the copy carries exactly that value")
        end)
    end)

-- FACS refuses every raw write to the canonical attribute, so a
-- corrupt or unreadable source descriptor cannot be planted; the
-- copy-up-begin fail point (§4.A.2) stands in for one, failing the
-- phase at the moment the source descriptor is read — before any
-- staging exists. EIO is the probe errno precisely because §4.6.3
-- notes no real failure on this path produces it: an EIO coming back
-- is provably the injected one, propagated unaltered.
test("a descriptor that cannot be replicated fails the operation",
    { spec = "PKM *security.copy-up-descriptor-failure-fails-operation" },
    function(t)
        copying(t, "sd-fail", function(s)
            t:assert(hooks.fail(vm, "copy-up-begin", sys.E.IO),
                "the fail point arms")
            local ok, err = pcall(function()
                local fd = sys.open(vm, s:join("f"), sys.O.WRONLY)
                t:assert(fd, "the open succeeds; routing happens per write")
                local r = sys.write(vm, fd, "modified")
                sys.close(vm, fd)
                t:assert(r.ret < 0, "the write that needs the copy-up fails")
                t:assert_eq(r.errno, sys.E.IO,
                    "carrying the copy-up's failure: " .. sys.errname(r.errno))

                -- The phase failed before the destination was created:
                -- nothing was staged, published, or half-written.
                t:assert_eq(#vm:listdir(s:in_stratum("dest")), 0,
                    "the create stratum is untouched")
                t:assert_eq(vm:read_file(s:join("f")), "original",
                    "and the merged view still provides the source")

                -- The one-shot is spent; the operation as a whole is
                -- repeatable and now succeeds.
                t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                    "the same write succeeds once the failure is spent")
            end)
            hooks.clear(vm, "copy-up-begin")
            if not ok then error(err, 0) end
        end)
    end)

test("a stratafs mount carries the deny-missing policy class",
    { spec = "PKM *security.mount-policy-is-deny-missing" }, function(t)
        -- Derived from the filesystem magic, not from an
        -- administrative choice.
        stratafs.with(vm, "policy-class", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local fd = sys.open(vm, s.at, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the mount root opens")
            local policy, errno = kacs.get_mount_policy(vm, fd)
            sys.close(vm, fd)
            t:assert(policy, "its mount policy reads: " ..
                sys.errname(errno or 0))
            t:assert_eq(policy, kacs.MOUNT_POLICY.DENY_MISSING,
                "and is the deny-missing class")
        end)
    end)

test("a stratafs mount's policy cannot be set to anything",
    { spec = "PKM *security.mount-policy-cannot-be-set" }, function(t)
        -- Every class that could actually change the mount's policy is
        -- refused, so the guarantee §4.6.4 rests on holds: a stratafs
        -- mount cannot be moved off the deny-missing class.
        stratafs.with(vm, "policy-set", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local fd = sys.open(vm, s.at, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the mount root opens")

            for name, policy in pairs({
                ["deny-missing itself"] = kacs.MOUNT_POLICY.DENY_MISSING,
                ["the ephemeral synthesising class"] =
                    kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
                ["the persistent synthesising class"] =
                    kacs.MOUNT_POLICY.SYNTHESIZE_PERSISTENT,
            }) do
                local r = kacs.set_mount_policy(vm, fd, policy)
                t:assert_neq(r.ret, 0, "setting it to " .. name .. " is refused")
                t:assert_eq(r.errno, sys.E.OPNOTSUPP,
                    "with EOPNOTSUPP: " .. sys.errname(r.errno))
            end

            t:assert_eq(kacs.get_mount_policy(vm, fd),
                kacs.MOUNT_POLICY.DENY_MISSING, "and the class is unchanged")
            sys.close(vm, fd)
        end)
    end)

-- PEI-586. §4.6.4 says the stratafs-magic test runs before the set path
-- validates its arguments. It does not: `UNMANAGED` — a real class, and
-- the one §4.6.4 spends a paragraph explaining must never apply here —
-- is refused with EINVAL, as are out-of-range values and an oversized
-- argsize. Only values that pass validation reach the EOPNOTSUPP.
test("the policy is refused for every class, whatever the argument",
    { spec = "PKM *security.mount-policy-cannot-be-set",
      tags = { "known-bug" } }, function(t)
        stratafs.with(vm, "policy-set-order", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local fd = sys.open(vm, s.at, sys.O.RDONLY | sys.O.DIRECTORY)
            t:assert(fd, "the mount root opens")

            local r = kacs.set_mount_policy(vm, fd, kacs.MOUNT_POLICY.UNMANAGED)
            t:assert_neq(r.ret, 0, "setting it to unmanaged is refused")
            t:assert_eq(r.errno, sys.E.OPNOTSUPP,
                "with EOPNOTSUPP, because the filesystem is checked before " ..
                "the argument: " .. sys.errname(r.errno))

            local out = kacs.set_mount_policy(vm, fd, 99)
            t:assert_eq(out.errno, sys.E.OPNOTSUPP,
                "and so is a value out of range: " .. sys.errname(out.errno))
            sys.close(vm, fd)
        end)
    end)

test("merging never widens access",
    { spec = "PKM *security.merge-never-widens-access" }, function(t)
        -- The divergence from direct access is always in the refusing
        -- direction: an object reachable through its stratum path is
        -- never made more reachable by being merged.
        stratafs.with(vm, "never-widens", {
            { name = "top", flags = { "create" }, entries = { shut = "hidden" } },
            { name = "bot", entries = { shut = "the one below" } },
        }, function(s)
            local r = kacs.set_sd(vm, s:in_stratum("top", "shut"), kacs.deny_all())
            t:assert_eq(r.ret, 0, "the provider is closed: " ..
                sys.errname(r.errno))
            kacs.set_sd(vm, s:in_stratum("bot", "shut"), kacs.grant(kacs.ALL_RIGHTS))

            kacs.as_dacl_bound(t, vm, function(worker)
                -- Refused through the mount...
                local fd, errno = sys.open(worker, s:join("shut"), sys.O.RDONLY)
                t:assert(fd == nil, "the merged path is refused")
                t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))

                -- ...and merging did not make the readable object below
                -- reachable under that name either.
                local direct = sys.open(worker, s:in_stratum("bot", "shut"),
                    sys.O.RDONLY)
                t:assert(direct,
                    "while the lower object is readable by its own path")
                if direct then sys.close(worker, direct) end
            end)
        end)
    end)


-- §4.6.5's audit records are covered in audit.test.lua, which reads
-- them out of the KMES ring.

test("the option-only mount checks precede every path check",
    { spec = "PKM *failure.mount.option-checks-precede-path-checks" }, function(t)
        -- §4.8 consolidates this; §4.2.3 is authoritative for it. The
        -- point is that a malformed or invalid option string is
        -- reported whatever the paths are, so the validity conditions
        -- cannot be used as an oracle for what exists.
        local s = stratafs.scenario(vm, "failure-ordering", {
            { name = "real", entries = { f = "x" } },
        }, { mount = false })
        local missing = s.root .. "/definitely-absent"
        local file = s.root .. "/a-regular-file"
        vm:write_file(file, "x")

        local cases = {
            ["an empty stack over absent paths"] = "strata=",
            ["two create strata, both absent"] =
                "strata=" .. missing .. "+create:" .. missing .. "2+create",
            ["create and ro on a regular file"] = "strata=" .. file .. "+create+ro",
            ["an unknown flag on an absent path"] = "strata=" .. missing .. "+nope",
            ["a relative path"] = "strata=relative/path",
        }
        local n = 0
        for why, data in pairs(cases) do
            n = n + 1
            local r = stratafs.try_mount(vm, { at = s.root .. "/m" .. n, data = data })
            t:assert_neq(r.ret, 0, why .. " is refused")
            t:assert_eq(r.errno, sys.E.INVAL,
                why .. " gives EINVAL before any path is touched, not " ..
                sys.errname(r.errno))
        end
    end)

test("the superblock magic is the one the constants name",
    { spec = "PKM *const.magic-alias-shared-with-kacs" }, function(t)
        -- STRATAFS_MAGIC is an alias for STRATAFS_SUPER_MAGIC, and it
        -- is what statfs reports.
        stratafs.with(vm, "const-magic", {
            { name = "only", flags = { "create" }, entries = { f = "x" } },
        }, function(s)
            local fs = sys.statfs(vm, s.at)
            t:assert(fs, "statfs answers")
            t:assert_eq(fs.type, 0x53545241,
                "with STRATAFS_MAGIC — ASCII `STRA`")
        end)
    end)

test("the filesystem is built in, not loadable",
    { spec = "PKM *const.build-kconfig-option" }, function(t)
        -- CONFIG_STRATAFS_FS is a boolean, so stratafs is linked into
        -- vmlinux and registered by an fs_initcall. There is no module
        -- to load and nothing that could fail to load.
        local filesystems = vm:read_file("/proc/filesystems")
        t:assert_contains(filesystems, "nodev\tstratafs",
            "the type is registered from boot")

        -- Nothing loaded it: this VM has no module loader and no
        -- modules at all.
        local ok, modules = pcall(function()
            return vm:read_file("/proc/modules")
        end)
        if ok then
            t:assert_eq(modules, "",
                "and no module is loaded, stratafs included")
        end
    end)

test("every stack-wide configuration error collapses to EINVAL",
    { spec = "PKM *const.config-errors-collapse-to-einval" }, function(t)
        -- stratafs-core distinguishes five cases; the C boundary does
        -- not, so the distinction is not observable to a caller.
        -- §4.2.1 covers the same ground from the flag side.
        local s = stratafs.scenario(vm, "const-einval", {
            { name = "a" }, { name = "b" },
        }, { mount = false })
        local a, b = s:in_stratum("a"), s:in_stratum("b")
        local seventeen = {}
        for i = 1, 17 do seventeen[i] = a end

        local cases = {
            ["an empty stack"] = "strata=",
            ["more than sixteen strata"] = "strata=" .. table.concat(seventeen, ":"),
            ["an unrecognised flag bit"] = "strata=" .. a .. "+nosuchflag",
            ["create carried twice"] = "strata=" .. a .. "+create:" .. b .. "+create",
            ["create and ro on one stratum"] = "strata=" .. a .. "+create+ro",
        }
        local n = 0
        for why, data in pairs(cases) do
            n = n + 1
            local r = stratafs.try_mount(vm, { at = s.root .. "/c" .. n, data = data })
            t:assert_eq(r.errno, sys.E.INVAL,
                why .. " is EINVAL, indistinguishable from the rest: " ..
                sys.errname(r.errno))
        end
    end)

-- Four of §4.A's constants are source-level invariants: that the
-- appendix is generated rather than written, that the marker struct has
-- a given layout, and that two sets of discriminants agree between the
-- C and Rust halves. None has a runtime surface for a conformance VM to
-- observe — they are checks on the build, and belong to whatever
-- verifies the generator's output against the headers.

test("the constants appendix is generated from the headers",
    { spec = "PKM *const.generated-from-source",
      covered_by = "ci:regenerate-and-diff",
      skip = "a CI check: regenerate the appendix and expect no diff. Not " ..
             "a property of a running kernel" },
    function(t) t:fail("no runtime surface") end)

test("the staging marker is a packed 24-byte little-endian struct",
    { spec = "PKM *const.stage-marker-layout",
      covered_by = "gen-stratafs-abi",
      skip = "covered by the constants generator, which measures the " ..
             "struct by compiling a probe against the real header — " ..
             "stronger than anything a VM can assert" },
    function(t) t:fail("no runtime surface") end)

test("the routing discriminants match between C and Rust",
    { spec = "PKM *const.route-discriminants-match-rust",
      covered_by = "kunit:stratafs_kunit_routing",
      skip = "covered by KUnit: stratafs_kunit_routing calls " ..
             "stratafs_rust_route_existing and compares its return against " ..
             "the C enumerators, which is this claim" },
    function(t) t:fail("no runtime surface") end)

test("stratafs-core's flag bits match the C ones",
    { spec = "PKM *const.core-flag-bits-match-c",
      covered_by = "kunit:stratafs-core",
      skip = "a build-time invariant between the C and Rust halves; " ..
             "belongs to a static assert or a KUnit case beside " ..
             "stratafs_kunit_routing, not to a running VM" },
    function(t) t:fail("no runtime surface") end)

