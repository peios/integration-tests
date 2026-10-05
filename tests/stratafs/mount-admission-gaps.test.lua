-- PKM §4.2.3 — entitlement is decided in two passes. The first resolves
-- and stats every stratum, and an EACCES from any of them is the
-- answer, whatever an earlier stratum reported; only when every stratum
-- has passed entitlement does the second pass apply the type, duplicate
-- and depth conditions.
--
-- Entitlement is both halves of the first pass: the path walk (traverse
-- rights) and the attribute read, which goes through the checking
-- vfs_getattr and so demands FILE_READ_ATTRIBUTES on the stratum
-- directory itself. The cases here put a second-pass condition before
-- an entitlement failure of each kind and expect the entitlement
-- failure, with the same stack minus that failure as the control.
--
-- Belongs in mount-admission.test.lua after "entitlement is decided for
-- the whole stack before any validity condition" (PEI-263), which holds
-- the non-directory and absent cases against a traverse failure under
-- the evaluation-order anchor.

local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")
local kacs = require("helpers.kacs")

local vm = provium:vm("v", "kernel-only"):boot()

local base = stratafs.scenario(vm, "admission-gaps", {
    { name = "a", entries = { a = "a" } },
    { name = "b", entries = { b = "b" } },
}, { mount = false })
local A = base:in_stratum("a")

local function mount_as(who, at, data)
    sys.mkdir(who, at)
    return sys.mount(who, {
        source = "stratafs", target = at, fstype = "stratafs", data = data,
    })
end

--- `mount_as`, then unmount if it unexpectedly succeeded, so a passing
--- refusal case leaves nothing behind.
local function try(who, at, data)
    local r = mount_as(who, at, data)
    if r.ret == 0 then sys.umount(who, at, 0) end
    return r
end

-- A directory no caller may traverse, with a directory behind it.
local SHUT = base.root .. "/shut"
vm:mkdir(SHUT .. "/inner", { parents = true })
assert(kacs.set_sd(vm, SHUT, kacs.deny_all()).ret == 0, "the barrier descriptor")

-- A directory the caller can reach and traverse, but whose attributes
-- it may not read.
local NOATTR = base.root .. "/noattr"
vm:mkdir(NOATTR, { parents = true })
assert(kacs.set_sd(vm, NOATTR, kacs.grant_all_but(kacs.RIGHT.READ_ATTRIBUTES)).ret == 0,
    "the no-attributes descriptor")

-- A regular file, for the type condition.
local FILE = base.root .. "/a-regular-file"
vm:write_file(FILE, "x")

test("an unreachable stratum after a duplicate pair is EACCES, not EINVAL",
    { spec = "PKM *mount.entitlement-is-decided-in-two-passes" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local dup = try(worker, base.root .. "/m-dup",
                "strata=" .. A .. ":" .. A)
            t:assert(dup.ret ~= 0, "the control: a duplicate pair alone is refused")
            t:assert_eq(dup.errno, sys.E.INVAL, "EINVAL: " .. sys.errname(dup.errno))

            local r = try(worker, base.root .. "/m-dup-shut",
                "strata=" .. A .. ":" .. A .. ":" .. SHUT .. "/inner")
            t:assert(r.ret ~= 0, "the pair followed by an unreachable stratum is refused")
            t:assert_eq(r.errno, sys.E.ACCES,
                "the duplicate is a second-pass condition, so the third stratum's "
                .. "EACCES is the answer, not " .. sys.errname(r.errno))
        end)
    end)

test("a stratum whose attributes the caller may not read fails entitlement",
    { spec = "PKM *mount.entitlement-is-decided-in-two-passes" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            -- The control for the descriptor: the caller can reach it.
            local fd = sys.open(worker, NOATTR, sys.O.PATH)
            t:assert(fd, "the directory resolves for the caller")
            if fd then sys.close(worker, fd) end

            local r = try(worker, base.root .. "/m-noattr", "strata=" .. NOATTR)
            t:assert(r.ret ~= 0, "mounting it is refused")
            t:assert_eq(r.errno, sys.E.ACCES,
                "with EACCES, from the checked attribute read: " .. sys.errname(r.errno))
        end)
    end)

test("an attribute-read refusal after a non-directory is EACCES, not ENOTDIR",
    { spec = "PKM *mount.entitlement-is-decided-in-two-passes" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local notdir = try(worker, base.root .. "/m-file-a",
                "strata=" .. FILE .. ":" .. A)
            t:assert(notdir.ret ~= 0, "the control: a regular file then a good stratum is refused")
            t:assert_eq(notdir.errno, sys.E.NOTDIR,
                "ENOTDIR: " .. sys.errname(notdir.errno))

            local r = try(worker, base.root .. "/m-file-noattr",
                "strata=" .. FILE .. ":" .. NOATTR)
            t:assert(r.ret ~= 0, "a regular file then an unreadable stratum is refused")
            t:assert_eq(r.errno, sys.E.ACCES,
                "the second stratum's entitlement failure wins over the first's type: "
                .. sys.errname(r.errno))
        end)
    end)

test("the answer is the same wherever in the stack the entitlement failure sits",
    { spec = "PKM *mount.entitlement-is-decided-in-two-passes" }, function(t)
        kacs.as_dacl_bound(t, vm, function(worker)
            local stacks = {
                ["first"] = SHUT .. "/inner:" .. FILE .. ":" .. A,
                ["middle"] = FILE .. ":" .. SHUT .. "/inner:" .. A,
                ["last"] = FILE .. ":" .. A .. ":" .. SHUT .. "/inner",
            }
            for where, strata in pairs(stacks) do
                local r = try(worker, base.root .. "/m-pos-" .. where, "strata=" .. strata)
                t:assert(r.ret ~= 0, "an unreachable stratum " .. where .. " is refused")
                t:assert_eq(r.errno, sys.E.ACCES,
                    "EACCES with it " .. where .. ", not " .. sys.errname(r.errno))
            end
        end)
    end)
