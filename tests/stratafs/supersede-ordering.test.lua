local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")
local hooks = require("helpers.hooks")
local vm = provium:vm("supersede-ordering", "kernel-only"):boot()

test("supersede requires a writable create-stratum source and the same parent",
    { spec = "PKM *create.supersede-source-and-parent-restrictions",
      covered_by = "kunit:stratafs_supersede",
      skip = "native open constructs this arrangement itself; " ..
             "stratafs_kunit_supersede_source_and_parent_guards calls the " ..
             "real internal entry with wrong-stratum, read-only and different-parent " ..
             "sources plus a valid-arrangement control" },
    function(t) t:fail("requires the kernel-internal supersede entry") end)

local function arrangement(where)
    local create = { name = "dest", flags = { "create" }, entries = { d = stratafs.DIR } }
    local old = { name = "old", entries = { ["d/f"] = "original" } }
    local fallback = { name = "fallback", entries = { ["d/f"] = "fallback" } }
    if where == "same" then
        create.entries["d/f"] = "original"
        return { create, fallback }, "dest"
    elseif where == "above" then
        return { old, create, fallback }, "old"
    end
    return { create, old, fallback }, "old"
end

local function no_temporary(t, s)
    for _, entry in ipairs(vm:listdir(s:in_stratum("dest", "d"))) do
        t:assert(not entry.name:match("^%.kacs%-super%."), "no supersede temporary remains")
    end
end

local function start_supersede(worker, path)
    local how = string.pack("<I4I4I4I4I8I4I4",
        kacs.RIGHT.READ_DATA | kacs.RIGHT.WRITE_DATA | kacs.RIGHT.DELETE,
        kacs.DISPOSITION.SUPERSEDE, 0, 0, 0, 0, 0)
    return worker:syscall_async(kacs.SYS.OPEN, {
        args = { sys.AT_FDCWD, 0, 0, 32, 0 },
        bufs = { sys.cstr(path), how, string.rep("\0", 4) }, ptrs = { 1, 2, 4 },
    })
end

for _, where in ipairs({ "below", "above", "same" }) do
    test("publication failure preserves the original " .. where .. " the create stratum",
        { spec = "PKM *create.supersede-is-not-atomic" }, function(t)
            local stack, old = arrangement(where)
            stratafs.with(vm, "publish-fails-" .. where, stack, function(s)
                t:assert(hooks.fail(vm, "supersede-publish", sys.E.IO))
                local ok, err = pcall(function()
                    local fd, e = kacs.open(vm, s:join("d/f"),
                        { disposition = kacs.DISPOSITION.SUPERSEDE })
                    if fd then sys.close(vm, fd) end
                    t:assert(not fd and e == sys.E.IO, "publication failure reaches the caller")
                    t:assert_eq(vm:read_file(s:in_stratum(old, "d/f")), "original")
                    t:assert_eq(vm:read_file(s:join("d/f")), "original",
                        "failure never exposes the unrelated fallback")
                    t:assert_eq(vm:read_file(s:in_stratum("fallback", "d/f")), "fallback")
                    if where ~= "same" then
                        t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) == nil)
                    end
                    no_temporary(t, s)
                end)
                hooks.clear(vm, "supersede-publish")
                if not ok then error(err, 0) end
            end)
        end)
end

for _, where in ipairs({ "below", "above" }) do
    test("both providers exist before supersede removes the original " .. where,
        { spec = "PKM *create.supersede-is-not-atomic" }, function(t)
            local stack, old = arrangement(where)
            stratafs.with(vm, "coexist-" .. where, stack, function(s)
                t:assert(hooks.hold(vm, "supersede-remove"))
                local worker = vm:spawn_worker()
                local ok, err = pcall(function()
                    local pending = start_supersede(worker, s:join("d/f"))
                    t:assert(hooks.await_waiting(vm, "supersede-remove"))
                    -- The outer rename holds its merged-parent lock. Observe
                    -- the backing names directly without waiting on that lock.
                    t:assert_eq(vm:read_file(s:in_stratum(old, "d/f")), "original")
                    t:assert_eq(vm:read_file(s:in_stratum("dest", "d/f")), "",
                        "the replacement is published before removing the original")
                    t:assert(hooks.clear(vm, "supersede-remove"))
                    local r = pending:await()
                    t:assert(r.ret >= 0, "supersede completes: " .. sys.errname(r.errno))
                    t:assert_eq(sys.write(worker, r.ret, "replacement").ret, 11)
                    sys.close(worker, r.ret)
                    t:assert(sys.stat(vm, s:in_stratum(old, "d/f")) == nil)
                    t:assert_eq(vm:read_file(s:join("d/f")), "replacement")
                    no_temporary(t, s)
                end)
                hooks.clear(vm, "supersede-remove")
                worker:kill(); worker:join()
                if not ok then error(err, 0) end
            end)
        end)

    test("removal failure rolls back the newly published object with original " .. where,
        { spec = "PKM *create.supersede-is-not-atomic" }, function(t)
            local stack, old = arrangement(where)
            stratafs.with(vm, "remove-fails-" .. where, stack, function(s)
                t:assert(hooks.fail(vm, "supersede-remove", sys.E.IO))
                local ok, err = pcall(function()
                    local events = kmes.recording(t, vm, function()
                        local fd, e = kacs.open(vm, s:join("d/f"),
                            { disposition = kacs.DISPOSITION.SUPERSEDE })
                        if fd then sys.close(vm, fd) end
                        t:assert(not fd and e == sys.E.IO, "the removal error reaches the caller")
                    end)
                    local failures = kmes.of_type(events, "stratafs.mutation.refused")
                    t:assert_eq(#failures, 1)
                    t:assert_eq(failures[1].payload.operation.name, "supersede-removal")
                    t:assert_eq(failures[1].payload.outcome.errno, -sys.E.IO)
                    t:assert_eq(vm:read_file(s:in_stratum(old, "d/f")), "original")
                    t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) == nil,
                        "cleanup follows the published name, not the old temporary name")
                    t:assert_eq(vm:read_file(s:join("d/f")), "original")
                    no_temporary(t, s)
                end)
                hooks.clear(vm, "supersede-remove")
                if not ok then error(err, 0) end
            end)
        end)

    test("a failed cleanup retains both providers with original " .. where,
        { spec = "PKM *create.supersede-is-not-atomic" }, function(t)
            local stack, old = arrangement(where)
            stratafs.with(vm, "cleanup-fails-" .. where, stack, function(s)
                t:assert(hooks.hold(vm, "supersede-remove"))
                local worker = vm:spawn_worker()
                local original = s:in_stratum(old, "d/f")
                local replacement = s:in_stratum("dest", "d/f")
                local ok, err = pcall(function()
                    local events = kmes.recording(t, vm, function()
                        local pending = start_supersede(worker, s:join("d/f"))
                        t:assert(hooks.await_waiting(vm, "supersede-remove"))
                        t:assert(sys.set_immutable(vm, original, true))
                        t:assert(sys.set_immutable(vm, replacement, true))
                        t:assert(hooks.clear(vm, "supersede-remove"))
                        local r = pending:await()
                        if r.ret >= 0 then sys.close(worker, r.ret) end
                        t:assert(r.ret < 0 and r.errno == sys.E.PERM,
                            "failed removal still reaches the caller when cleanup fails too")
                    end)
                    local removal, cleanup = 0, 0
                    for _, e in ipairs(kmes.of_type(events, "stratafs.mutation.refused")) do
                        if e.payload.operation.name == "supersede-removal" then
                            removal = removal + 1
                            t:assert_eq(e.payload.outcome.errno, -sys.E.PERM)
                        elseif e.payload.operation.name == "unlink" and e.payload.outcome.deferred then
                            cleanup = cleanup + 1
                            t:assert_eq(e.payload.outcome.errno, -sys.E.ROFS,
                                "the immutable replacement fails StrataFS's writable-stratum gate")
                        end
                    end
                    t:assert_eq(removal, 1, "the original failure is audited")
                    t:assert_eq(cleanup, 1, "the failed rollback is audited separately")
                    t:assert_eq(vm:read_file(original), "original")
                    t:assert_eq(vm:read_file(replacement), "")
                    t:assert_eq(vm:read_file(s:join("d/f")), where == "above" and "original" or "",
                        "ordinary precedence selects between the two retained names")
                    no_temporary(t, s)
                end)
                hooks.clear(vm, "supersede-remove")
                worker:kill(); worker:join()
                sys.set_immutable(vm, original, false)
                sys.set_immutable(vm, replacement, false)
                if not ok then error(err, 0) end
            end)
        end)

    test("cleanup preserves a concurrent create-stratum replacement with original " .. where,
        { spec = "PKM *create.supersede-is-not-atomic" }, function(t)
            local stack, old = arrangement(where)
            stratafs.with(vm, "cleanup-race-" .. where, stack, function(s)
                t:assert(hooks.hold(vm, "supersede-remove"))
                local worker = vm:spawn_worker()
                local original = s:in_stratum(old, "d/f")
                local replacement = s:in_stratum("dest", "d/f")
                local ok, err = pcall(function()
                    local pending = start_supersede(worker, s:join("d/f"))
                    t:assert(hooks.await_waiting(vm, "supersede-remove"))
                    t:assert(sys.set_immutable(vm, original, true))
                    t:assert_eq(sys.rename(vm, replacement, replacement .. "-saved").ret, 0)
                    vm:write_file(replacement, "concurrent create-stratum replacement")
                    t:assert(hooks.clear(vm, "supersede-remove"))
                    local r = pending:await()
                    if r.ret >= 0 then sys.close(worker, r.ret) end
                    t:assert(r.ret < 0 and r.errno == sys.E.PERM)
                    t:assert_eq(vm:read_file(original), "original")
                    t:assert_eq(vm:read_file(replacement), "concurrent create-stratum replacement",
                        "cleanup never removes a different inode at the published path")
                    t:assert_eq(vm:read_file(replacement .. "-saved"), "",
                        "the moved published inode also survives")
                    no_temporary(t, s)
                end)
                hooks.clear(vm, "supersede-remove")
                worker:kill(); worker:join()
                sys.set_immutable(vm, original, false)
                if not ok then error(err, 0) end
            end)
        end)

    test("a raced provider replacement survives supersede with original " .. where,
        { spec = "PKM *create.supersede-is-not-atomic" }, function(t)
            local stack, old = arrangement(where)
            stratafs.with(vm, "raced-provider-" .. where, stack, function(s)
                t:assert(hooks.hold(vm, "supersede-remove"))
                local worker = vm:spawn_worker()
                local ok, err = pcall(function()
                    local pending = start_supersede(worker, s:join("d/f"))
                    t:assert(hooks.await_waiting(vm, "supersede-remove"))
                    local raw = s:in_stratum(old, "d/f")
                    t:assert_eq(sys.rename(vm, raw, raw .. "-saved").ret, 0)
                    vm:write_file(raw, "concurrent replacement")
                    t:assert(hooks.clear(vm, "supersede-remove"))
                    local r = pending:await()
                    if r.ret >= 0 then sys.close(worker, r.ret) end
                    t:assert(r.ret < 0 and r.errno == sys.E.STALE,
                        "the original-provider identity check refuses a different inode")
                    t:assert_eq(vm:read_file(raw), "concurrent replacement")
                    t:assert_eq(vm:read_file(raw .. "-saved"), "original")
                    t:assert(sys.stat(vm, s:in_stratum("dest", "d/f")) == nil)
                    t:assert_eq(vm:read_file(s:join("d/f")), "concurrent replacement")
                    no_temporary(t, s)
                end)
                hooks.clear(vm, "supersede-remove")
                worker:kill(); worker:join()
                if not ok then error(err, 0) end
            end)
        end)
end
