-- Copy-up: what the staged object inherits from the object it replaces.
--
-- PKM §4.5.2. These are the cases stratafs KUnit cannot reach — copy-up
-- needs a real mount stack, a provider that will not accept the write,
-- and a caller whose credentials differ from the source's.

local stratafs = require("helpers.stratafs")
local sys = require("helpers.sys")

local vm = provium:vm("v", "kernel-only"):boot()

-- PEI-256 / PEI-485 case 4. The highest-value case of the seven: the
-- fix depends on the mount's resolution credential carrying CAP_CHOWN,
-- which nothing had exercised. If it does not, the chown fails and
-- takes the whole copy-up down with it — so this asserts the write
-- *succeeds* before it asserts anything about ownership. A test that
-- only compared uids would pass a kernel that had turned a metadata
-- divergence into a hard write failure.
test("copy-up preserves the POSIX owner of the object it copies",
    { spec = "PKM *copy-up.posix-ownership-preserved" }, function(t)
        stratafs.with(vm, "copy-up-owner", {
            { name = "upper", flags = { "create" } },
            { name = "lower", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
        -- Give the source to a uid that is not the caller's, so the
        -- staged copy beginning owned by the caller is observable.
        local OWNER_UID, OWNER_GID = 4242, 4243
        local chown = sys.chown(vm, s:in_stratum("lower", "f"), OWNER_UID, OWNER_GID)
        t:assert_eq(chown.ret, 0, "chown the source: " .. sys.errname(chown.errno))

        local before = sys.stat(vm, s:join("f"))
        t:assert_eq(before.uid, OWNER_UID, "the merged view reports the source's owner")

        -- Writing through the mount routes to a copy-up, because the
        -- provider carries `ro` and will not accept the modification.
        vm:write_file(s:join("f"), "rewritten")

        local copy = sys.stat(vm, s:in_stratum("upper", "f"))
        t:assert(copy ~= nil, "the write produced a copy in the create stratum")
        t:assert_eq(vm:read_file(s:join("f")), "rewritten",
            "and the write landed — a failed chown would have aborted the copy-up")
        t:assert_eq(vm:read_file(s:in_stratum("lower", "f")), "original",
            "the read-only provider was not modified in place")
        t:assert_eq(copy.uid, OWNER_UID, "the copy keeps the source's uid")
        t:assert_eq(copy.gid, OWNER_GID, "and its gid")
        t:assert_neq(copy.uid, 0, "and is not the calling task's, which is root here")
        end)
    end)

-- The same rule from the other side: where the caller already owns the
-- source there is no chown to make, and the copy must still be correct.
-- This is the branch `!uid_eq(...)` skips, which the case above never
-- enters.
test("copy-up of an object the caller already owns needs no chown",
    { spec = "PKM *copy-up.posix-ownership-preserved" }, function(t)
        stratafs.with(vm, "copy-up-owner-same", {
            { name = "upper", flags = { "create" } },
            { name = "lower", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
        local source = sys.stat(vm, s:in_stratum("lower", "f"))
        vm:write_file(s:join("f"), "rewritten")

        local copy = sys.stat(vm, s:in_stratum("upper", "f"))
        t:assert(copy ~= nil, "the write produced a copy")
        t:assert_eq(copy.uid, source.uid, "ownership is unchanged")
        t:assert_eq(copy.gid, source.gid, "in both fields")
        end)
    end)
