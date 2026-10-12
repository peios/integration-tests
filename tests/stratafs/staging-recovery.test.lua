-- PEI-1455 / PEI-485: a real post-crash marker cannot be manufactured through
-- userspace xattr calls. The offline image supplies it without relaxing FACS.
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")
local image = require("helpers.image")
local hooks = require("helpers.hooks")
local vm = provium:vm("staging-recovery", "kernel-only"):boot()

local function with_image(t, case, entry, body)
    local at = "/orphan-" .. case
    local release = image.mount(t, vm, {
        name = case, host_image = "../fixtures/staging-orphans.img",
        fstype = "ext2", at = at,
        policy = kacs.MOUNT_POLICY.SYNTHESIZE_EPHEMERAL,
    })
    local merged = at .. "-merged"
    local mounted = false
    local ok, err = pcall(function()
        -- Merged access needs a stored descriptor. Materialize exactly the
        -- DACL the provider already synthesizes, without broadening access.
        for _, suffix in ipairs({ "", "/" .. case, "/" .. case .. "/" .. entry }) do
            local path = at .. "/upper" .. suffix
            local sd = kacs.get_sd(vm, path)
            t:assert(sd, "provider has an effective descriptor")
            t:assert_eq(kacs.set_sd(vm, path, sd).ret, 0, "store the existing DACL")
        end
        stratafs.mount(vm, { at = merged, strata = {
            { path = at .. "/upper", flags = { "create" } },
        } })
        mounted = true
        local raw = at .. "/upper/" .. case .. "/" .. entry
        t:assert(sys.stat(vm, raw), "the fixture entry exists before recovery")
        body(merged .. "/" .. case, raw)
    end)
    if mounted then stratafs.umount(vm, merged) end
    release()
    if not ok then error(err, 0) end
end

for _, case in ipairs({ "orphan-file", "orphan-dir" }) do
    test("a staging-prefix lookup physically recovers " .. case,
        { spec = "PKM *resolution.staging-prefix-triggers-recovery" }, function(t)
            with_image(t, case, ".stratafs-stage-dead", function(merged, raw)
                local st, errno = sys.stat(vm, merged .. "/ordinary-missing")
                t:assert(not st and errno == sys.E.NOENT)
                t:assert(sys.stat(vm, raw), "an ordinary lookup leaves the orphan in place")

                -- A different, absent staging name must scan the entire parent;
                -- neither enumeration nor a lookup of the orphan itself occurs.
                st, errno = sys.stat(vm, merged .. "/.stratafs-stage-probe")
                t:assert(not st and errno == sys.E.NOENT)
                st, errno = sys.stat(vm, raw)
                t:assert(not st and errno == sys.E.NOENT,
                    "lookup physically removed the dead owner's backing entry")
            end)
        end)
end

for _, bound_mounter in ipairs({ false, true }) do
    test("recovery needs no list grant to " .. (bound_mounter and "mounter or caller" or "caller"),
        { spec = "PKM *security.staging-recovery-uses-mounter" }, function(t)
            with_image(t, "orphan-file", ".stratafs-stage-dead", function(merged, raw)
                local parent = raw:match("^(.*)/[^/]+$")
                t:assert_eq(kacs.set_sd(vm, parent,
                    kacs.grant_all_but(kacs.RIGHT.LIST_DIRECTORY)).ret, 0)
                kacs.as_dacl_bound(t, vm, function(worker)
                    local fd, errno = kacs.open(worker, parent, {
                        access = kacs.RIGHT.LIST_DIRECTORY,
                        options = kacs.CREATE_OPT.DIRECTORY,
                    })
                    if fd then sys.close(worker, fd) end
                    t:assert(not fd and errno == sys.E.ACCES,
                        "ordinary directory reads are denied to this principal")
                    local observer = "/recovery-bound-mounter"
                    local mounted = false
                    local ok, err = pcall(function()
                        if bound_mounter then
                            stratafs.mount(worker, { at = observer, strata = {
                                { path = parent:match("^(.*)/[^/]+$"), flags = { "create" } },
                            } })
                            mounted = true
                            merged = observer .. "/orphan-file"
                        end
                        local st, e = sys.stat(worker, merged .. "/.stratafs-stage-probe")
                        t:assert(not st and e == sys.E.NOENT)
                        st, e = sys.stat(vm, raw)
                        t:assert(not st and e == sys.E.NOENT,
                            "the scoped recovery scan removed the orphan without LIST_DIRECTORY")
                    end)
                    if mounted then stratafs.umount(worker, observer) end
                    if not ok then error(err, 0) end
                end)
            end)
        end)
end

test("a refused emptiness check does not remove orphans",
    { spec = "PKM *remove.rmdir-staging-recovery" }, function(t)
        with_image(t, "orphan-file", ".stratafs-stage-dead", function(merged, raw)
            local parent = raw:match("^(.*)/[^/]+$")
            -- Keep traversal and deletion allowed: the refused right is
            -- specifically the list access required by the emptiness scan.
            t:assert_eq(kacs.set_sd(vm, parent,
                kacs.grant_all_but(kacs.RIGHT.LIST_DIRECTORY)).ret, 0)
            kacs.as_dacl_bound(t, vm, function(worker)
                local r = sys.unlink(worker, merged, sys.AT_REMOVEDIR)
                t:assert_eq(r.errno, sys.E.ACCES, "access is checked before recovery")
            end)
            t:assert(sys.stat(vm, raw), "the refused caller did not trigger deletion")
        end)
    end)

test("rmdir preserves a real named stage owned by another live mount",
    { spec = "PKM *remove.rmdir-staging-recovery" }, function(t)
        stratafs.with(vm, "live-owner", {
            { name = "dest", flags = { "create" }, entries = { d = stratafs.DIR } },
            { name = "src", flags = { "ro" }, entries = { ["d/child"] = stratafs.DIR } },
        }, function(s)
            t:assert(hooks.hold(vm, "copy-up-publish"), "hold a named directory stage")
            local worker = vm:spawn_worker()
            local observer = s.root .. "/observer"
            local observed = false
            local ok, err = pcall(function()
                local pending = worker:syscall_async(sys.NR.fchownat, {
                    args = { sys.AT_FDCWD, 0, 4242, 4243, 0 },
                    bufs = { sys.cstr(s:join("d/child")) }, ptrs = { 1 },
                })
                t:assert(hooks.await_waiting(vm, "copy-up-publish"), "copy-up is staged")
                local names = vm:listdir(s:in_stratum("dest", "d"))
                t:assert_eq(#names, 1, "one real named stage exists")
                t:assert(names[1].name:match("^%.stratafs%-stage%-"), "it has the stage prefix")
                local stage = s:in_stratum("dest", "d", names[1].name)
                stratafs.mount(vm, { at = observer, strata = {
                    { path = s.path.dest, flags = { "create" } },
                } })
                observed = true
                local r = sys.unlink(vm, observer .. "/d", sys.AT_REMOVEDIR)
                t:assert_eq(r.errno, sys.E.NOTEMPTY, "a live owner's stage prevents removal")
                t:assert(sys.stat(vm, stage), "recovery left the live stage intact")
                t:assert(hooks.clear(vm, "copy-up-publish"))
                t:assert_eq(pending:await().ret, 0, "the original copy-up still publishes")
                t:assert(sys.stat(vm, s:in_stratum("dest", "d/child")))
            end)
            hooks.clear(vm, "copy-up-publish")
            if observed then stratafs.umount(vm, observer) end
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
    end)

for _, case in ipairs({ "orphan-file", "orphan-dir" }) do
    test("rmdir recovers " .. case .. " without a prior enumeration",
        { spec = "PKM *remove.rmdir-staging-recovery" }, function(t)
            with_image(t, case, ".stratafs-stage-dead", function(merged, raw)
                local r = sys.unlink(vm, merged, sys.AT_REMOVEDIR)
                t:assert_eq(r.ret, 0, "rmdir recovers the dead owner: " .. sys.errname(r.errno))
                local st, e = sys.stat(vm, raw)
                t:assert(not st and e == sys.E.NOENT, "the orphan was physically removed")
            end)
        end)
end

test("enumeration recognizes the same valid dead-owner marker",
    { spec = "PKM *copy-up.orphan-recovery-checks-marker" }, function(t)
        with_image(t, "orphan-file", ".stratafs-stage-dead", function(merged, raw)
            t:assert_eq(#vm:listdir(merged), 0, "enumeration recovers the orphan")
            local st, e = sys.stat(vm, raw)
            t:assert(not st and e == sys.E.NOENT, "recovery deleted the underlying entry")
            t:assert_eq(sys.unlink(vm, merged, sys.AT_REMOVEDIR).ret, 0)
        end)
    end)

for _, row in ipairs({
    { "unmarked", ".stratafs-stage-unmarked" },
    { "short-marker", ".stratafs-stage-short" },
    { "bad-magic", ".stratafs-stage-magic" },
    { "bad-version", ".stratafs-stage-version" },
    { "bad-size", ".stratafs-stage-size" },
    { "published", "ordinary" },
}) do
    test("rmdir preserves " .. row[1],
        { spec = "PKM *remove.rmdir-staging-recovery" }, function(t)
            with_image(t, row[1], row[2], function(merged, raw)
                local r = sys.unlink(vm, merged, sys.AT_REMOVEDIR)
                t:assert_eq(r.errno, sys.E.NOTEMPTY, "unproven or published entries remain")
                t:assert(sys.stat(vm, raw), "the underlying entry was not removed")
            end)
        end)
end
