-- PKM §4.6.5 — the two classes of stratafs event that carry
-- information which cannot be recovered from the filesystem
-- afterwards.
--
-- These are emitted through KACS's kernel-only emitter into a KMES
-- ring and never reach the filesystem interface the rest of these
-- tests drive, so helpers/kmes reads the ring directly.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")

local vm = provium:vm("v", "kernel-only"):boot()

local COPY_UP = "STRATAFS_COPY_UP"
local REFUSED = "STRATAFS_MUTATION_REFUSED"

local function only(t, events, event_type, why)
    local matching = kmes.of_type(events, event_type)
    t:assert_eq(#matching, 1, (why or event_type) ..
        ": exactly one record, got " .. #matching)
    return matching[1]
end

test("every copy-up emits a record, successful or not",
    { spec = "PKM *audit.copy-up-always-emitted" }, function(t)
        -- Recording it matters because §4.6.3 preserves the source's
        -- descriptor, so nothing about the resulting object records who
        -- caused it to exist.
        stratafs.with(vm, "audit-copy-up", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                t:assert(stratafs.try_write(vm, s:join("f"), "modified"),
                    "the write copies up")
            end)

            local e = only(t, events, COPY_UP, "a successful copy-up")
            t:assert_eq(e.origin, kmes.ORIGIN.KACS,
                "emitted through KACS's kernel-only emitter")
            local p = e.payload
            t:assert(p, "with a decodable payload")
            t:assert_eq(p.path, "/f", "the relative path, slash-prefixed")
            t:assert_eq(p.provider_index, 1, "the stratum copied from")
            t:assert_eq(p.provider_stratum, s:in_stratum("src"), "and its path")
            t:assert_eq(p.create_index, 0, "the stratum copied into")
            t:assert_eq(p.create_stratum, s:in_stratum("dest"), "and its path")
            t:assert_eq(p.result_errno, 0, "and a zero result")

            -- The caller's identity is deliberately not among the keys:
            -- it is in the envelope, once, for every event.
            t:assert(p.uid == nil and p.token == nil and p.caller == nil,
                "and no identity key, which the envelope carries instead")
        end)
    end)

test("a failed copy-up emits a record carrying its errno",
    { spec = "PKM *audit.copy-up-always-emitted" }, function(t)
        -- Successful or not, and the failure is carried as a negative
        -- errno in the same six keys. The reachable failure is §4.5.2's
        -- staleness rule: two descriptors on one object, the first
        -- copies it up, and the second's write then finds its object is
        -- no longer the provider.
        stratafs.with(vm, "audit-copy-up-fail", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local first = sys.open(vm, s:join("f"), sys.O.RDWR)
                local second = sys.open(vm, s:join("f"), sys.O.RDWR)
                t:assert(first and second, "two descriptors open")
                t:assert_eq(sys.write(vm, first, "modified").ret, 8,
                    "the first writes, copying up")
                local w = sys.write(vm, second, "second!!")
                sys.close(vm, first); sys.close(vm, second)
                t:assert_eq(w.errno, sys.E.STALE,
                    "and the second is ESTALE: " .. sys.errname(w.errno))
            end)

            local records = kmes.of_type(events, COPY_UP)
            t:assert_eq(#records, 2,
                "both copy-ups are recorded, the one that worked and the " ..
                "one that did not")
            t:assert_eq(records[1].payload.result_errno, 0,
                "the first with a zero result")
            t:assert_eq(records[2].payload.result_errno, -sys.E.STALE,
                "and the second with its errno")
            t:assert_eq(records[2].payload.path, "/f",
                "naming the same path")
            t:assert_eq(records[2].payload.provider_stratum, s:in_stratum("src"),
                "and the same provider")
        end)
    end)

test("every record is stamped with the causing task's tokens",
    { spec = "PKM *audit.events-stamped-with-effective-token" }, function(t)
        -- KMES stamps the effective, true and process token GUIDs onto
        -- every event header at ring-write time, and because copy-up
        -- runs in the caller's own context those are the caller's.
        stratafs.with(vm, "audit-token", {
            { name = "dest", flags = { "create" } },
            { name = "src", flags = { "ro" },
              entries = { by_agent = "a", by_worker = "w" } },
        }, function(s)
            kacs.set_sd(vm, s:in_stratum("src", "by_worker"),
                kacs.grant(kacs.ALL_RIGHTS))

            local mine = kmes.recording(t, vm, function()
                t:assert(stratafs.try_write(vm, s:join("by_agent"), "modified"),
                    "the agent causes one")
            end)
            local a = only(t, mine, COPY_UP, "the agent's copy-up")

            for _, field in ipairs({ "effective_token", "true_token",
                                     "process_guid" }) do
                t:assert_eq(#a[field], 16, field .. " is a 16-byte GUID")
                t:assert_neq(a[field], kmes.NULL_GUID,
                    field .. " is not the null GUID — identity was available")
            end

            -- A different task causes the next one, and the envelope
            -- says so.
            local theirs = kmes.recording(t, vm, function()
                local worker = vm:spawn_worker()
                local ok, err = pcall(function()
                    local fd = sys.open(worker, s:join("by_worker"), sys.O.RDWR)
                    t:assert(fd, "the worker opens it")
                    t:assert_eq(sys.write(worker, fd, "modified").ret, 8,
                        "and writes, copying up")
                    sys.close(worker, fd)
                end)
                worker:kill(); worker:join()
                if not ok then error(err, 0) end
            end)
            local b = only(t, theirs, COPY_UP, "the worker's copy-up")

            t:assert_neq(b.process_guid, a.process_guid,
                "a different process is recorded for a different causer")
            t:assert_eq(b.payload.path, "/by_worker",
                "and the payload names what it copied")
        end)
    end)

test("a mutation refused by the mount's arrangement emits a record",
    { spec = "PKM *audit.arrangement-refusal-emitted" }, function(t)
        stratafs.with(vm, "audit-refusal", {
            { name = "only", flags = { "ro" }, entries = { f = "original" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local ok, errno = stratafs.try_write(vm, s:join("f"), "modified")
                t:assert(not ok and errno == sys.E.ROFS,
                    "the write is refused with EROFS")
            end)

            local e = only(t, events, REFUSED, "an EROFS write")
            local p = e.payload
            t:assert_eq(p.path, "/f", "the path")
            t:assert_eq(p.operation, "write", "the operation name")
            t:assert_eq(p.provider_index, 0, "the provider index")
            t:assert_eq(p.provider_stratum, s:in_stratum("only"),
                "the provider stratum's path")
            t:assert_eq(p.result_errno, -sys.E.ROFS, "the errno")
            t:assert_eq(p.deferred, false, "and whether it was deferred")
        end)
    end)

test("a refusal before a provider is known names none",
    { spec = "PKM *audit.arrangement-refusal-emitted" }, function(t)
        -- Creation, tmpfile, the heads of link and rename. They report
        -- a provider index of -1 and a provider_stratum of msgpack nil,
        -- so a reader can tell "no provider was involved" from "the
        -- provider's path is empty". The two fields agree.
        stratafs.with(vm, "audit-no-provider", {
            { name = "only", flags = { "ro" }, entries = { anchor = "a" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local ok, errno = stratafs.try_create(vm, s:join("new"), "x")
                t:assert(not ok and errno == sys.E.ROFS,
                    "creation with no create stratum is refused")
            end)

            local e = only(t, events, REFUSED, "a creation refusal")
            t:assert_eq(e.payload.provider_index, -1,
                "the provider index is -1")
            t:assert_eq(e.payload.provider_stratum, nil,
                "and the provider stratum is msgpack nil, not an empty string")
        end)
    end)

test("an access-check refusal emits no stratafs record",
    { spec = "PKM *audit.arrangement-refusal-emitted" }, function(t)
        -- EACCES is deliberately absent from the arrangement list: a
        -- refusal produced by an access check is audited by the
        -- mechanism that performed it, and stratafs does not duplicate
        -- those records.
        stratafs.with(vm, "audit-eacces", {
            { name = "only", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            local r = kacs.set_sd(vm, s:in_stratum("only", "d/f"),
                kacs.grant_all_but(kacs.RIGHT.WRITE_DATA))
            t:assert_eq(r.ret, 0, "the object refuses writes: " ..
                sys.errname(r.errno))

            local events = kmes.recording(t, vm, function()
                kacs.as_dacl_bound(t, vm, function(worker)
                    local fd, errno = sys.open(worker, s:join("d", "f"),
                        sys.O.WRONLY)
                    t:assert(fd == nil, "the caller cannot open it for writing")
                    t:assert_eq(errno, sys.E.ACCES, sys.errname(errno))
                end)
            end)

            t:assert_eq(#kmes.of_type(events, REFUSED), 0,
                "and stratafs emits no refusal record for it")
            t:assert_eq(#kmes.of_type(events, COPY_UP), 0,
                "nor a copy-up record")
        end)
    end)

test("a deferred deletion refused by the arrangement is audited",
    { spec = "PKM *audit.arrangement-refusal-emitted" }, function(t)
        -- Rollbacks and deferred refusals are audited under the same
        -- event with the deferred flag set.
        stratafs.with(vm, "audit-deferred-erofs", {
            { name = "dest", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local fd = kacs.open(vm, s:join("d", "f"),
                    { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
                t:assert(fd, "the descriptor is armed")
                t:assert(sys.set_immutable(vm, s:in_stratum("dest", "d/f"), true),
                    "and the entry then becomes immutable")
                sys.close(vm, fd)
                sys.set_immutable(vm, s:in_stratum("dest", "d/f"), false)
            end)

            t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) ~= nil,
                "the deletion was refused and the object left in place")

            local e = only(t, events, REFUSED, "a refused deferred deletion")
            t:assert_eq(e.payload.deferred, true, "with the deferred flag set")
            t:assert_eq(e.payload.operation, "unlink", "naming the operation")
            t:assert_eq(e.payload.path, "/d/f", "and the path")
            t:assert_eq(e.payload.result_errno, -sys.E.ROFS,
                "and carrying the errno nobody was left to receive")
        end)
    end)

-- PEI-588. §4.6.5 makes this an explicit exception to the EACCES
-- exclusion, because a deferred deletion's error reaches nobody: the
-- descriptor's owner may be gone by the time it runs. The exception is
-- not implemented — an arrangement refusal is audited (the sibling case
-- above), an access-check refusal produces an empty ring.
test("a refused deferred deletion is audited on any non-zero result",
    { spec = "PKM *audit.deferred-deletion-audited-on-any-error",
      tags = { "known-bug" } }, function(t)
        stratafs.with(vm, "audit-deferred", {
            { name = "dest", flags = { "create" }, entries = { ["d/f"] = "x" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                local fd = kacs.open(vm, s:join("d", "f"),
                    { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
                t:assert(fd, "the descriptor is armed")
                local r = kacs.set_sd(vm, s:in_stratum("dest", "d"),
                    kacs.deny_all())
                t:assert_eq(r.ret, 0, "the stratum's directory is then closed: " ..
                    sys.errname(r.errno))
                sys.close(vm, fd)
            end)

            t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) ~= nil,
                "the deletion was refused and the object left in place")

            local e = only(t, events, REFUSED,
                "a deferred deletion refused by an access check")
            t:assert_eq(e.payload.deferred, true, "with the deferred flag set")
            t:assert_neq(e.payload.result_errno, 0,
                "carrying the non-zero result")
        end)
    end)

test("resolution, revalidation and enumeration emit no records",
    { spec = "PKM *audit.lookup-not-audited" }, function(t)
        -- They occur on every path operation, they reveal nothing the
        -- resulting access check does not, and recording them would
        -- produce volume out of all proportion. There is no audit call
        -- anywhere in the lookup path.
        stratafs.with(vm, "audit-lookup", {
            { name = "top", flags = { "create" },
              entries = { ["d/x"] = "x", f = "f" } },
            { name = "bot", entries = { ["d/y"] = "y", f = "shadowed" } },
        }, function(s)
            local events = kmes.recording(t, vm, function()
                -- Resolution, at depth and across strata.
                for _ = 1, 20 do
                    sys.stat(vm, s:join("d", "x"))
                    sys.stat(vm, s:join("d", "y"))
                    sys.stat(vm, s:join("f"))
                    sys.stat(vm, s:join("does", "not", "exist"))
                end
                -- Enumeration, of a merged directory and of the root.
                for _ = 1, 10 do
                    vm:listdir(s:join("d"))
                    vm:listdir(s.at)
                end
                -- Reads, which route nothing.
                for _ = 1, 10 do vm:read_file(s:join("f")) end
                -- And the origin attribute, which resolves afresh.
                for _ = 1, 10 do sys.getxattr(vm, s:join("d"), "system.stratafs.origin") end
            end)

            t:assert_eq(#events, 0,
                "nothing was recorded across " ..
                "eighty resolutions, twenty enumerations, ten reads and " ..
                "ten origin reads")
        end)
    end)
