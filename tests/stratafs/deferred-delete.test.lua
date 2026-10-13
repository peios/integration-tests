-- PEI-1457 / PEI-1444: close-time deletion must tolerate an already-removed target
-- without ever deleting a replacement at its old path.
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")
local vm = provium:vm("v", "kernel-only"):boot()

for _, mode in ipairs({ "missing-name", "missing-parent", "blocked-parent", "replacement", "moved-parent" }) do
    test("deferred deletion quietly tolerates " .. mode,
        { spec = "PKM *create.deferred-delete-already-gone-succeeds" }, function(t)
            stratafs.with(vm, "deferred-" .. mode, {
                { name = "dest", flags = { "create" } },
                { name = "src", entries = { ["d/f"] = "original" } },
            }, function(s)
                local raw = s:in_stratum("src", "d/f")
                local before = sys.stat(vm, raw)
                local fd = kacs.open(vm, s:join("d/f"),
                    { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
                t:assert(fd, "arm the original object")
                local ok, err = pcall(function()
                    if mode == "moved-parent" then
                        t:assert_eq(sys.rename(vm, s:in_stratum("src", "d"),
                            s:in_stratum("src", "moved")).ret, 0, "move the original parent away")
                    else
                        t:assert_eq(sys.unlink(vm, raw).ret, 0, "remove the original backing name")
                    end
                    if mode == "missing-parent" or mode == "blocked-parent" then
                        t:assert_eq(sys.unlink(vm, s:in_stratum("src", "d"),
                            sys.AT_REMOVEDIR).ret, 0, "remove its parent")
                        if mode == "blocked-parent" then
                            vm:write_file(s:in_stratum("src", "d"), "parent replacement")
                        end
                    elseif mode == "replacement" then
                        vm:write_file(raw, "replacement")
                        t:assert_neq(sys.stat(vm, raw).ino, before.ino,
                            "the replacement is a different live inode")
                    end
                    local events = kmes.recording(t, vm, function()
                        t:assert_eq(sys.close(vm, fd).ret, 0, "final close succeeds")
                        fd = nil
                    end)
                    for _, e in ipairs(kmes.of_type(events, "stratafs.mutation.refused")) do
                        t:log("refused " .. e.payload.operation.name .. " errno=" ..
                            tostring(e.payload.outcome.errno) .. " path=" ..
                            e.payload.object.file["path-relative"])
                    end
                    t:assert_eq(#kmes.of_type(events, "stratafs.mutation.refused"), 0,
                        "already-gone is success, not an audited failure")
                    if mode == "moved-parent" then
                        t:assert_eq(vm:read_file(s:in_stratum("src", "moved/f")), "original",
                            "the old path is gone, but the relocated object remains intact")
                    elseif mode == "replacement" then
                        t:assert_eq(vm:read_file(raw), "replacement",
                            "the different inode is never deleted")
                    elseif mode == "blocked-parent" then
                        t:assert_eq(vm:read_file(s:in_stratum("src", "d")),
                            "parent replacement", "the replacement parent is untouched")
                    else
                        local gone, errno = sys.stat(vm, raw)
                        t:assert(not gone and errno == sys.E.NOENT, "the old path remains absent")
                    end
                end)
                if fd then sys.close(vm, fd) end
                if not ok then error(err, 0) end
            end)
        end)
end

test("a merged parent masking a live backing target is still audited",
    { spec = "PKM *create.deferred-delete-already-gone-succeeds" }, function(t)
        stratafs.with(vm, "deferred-masked-parent", {
            { name = "dest", flags = { "create" } },
            { name = "src", entries = { ["d/f"] = "original" } },
        }, function(s)
            local fd = kacs.open(vm, s:join("d/f"),
                { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "arm the lower target")
            vm:write_file(s:in_stratum("dest", "d"), "masks the lower directory")
            local events = kmes.recording(t, vm, function()
                t:assert_eq(sys.close(vm, fd).ret, 0)
            end)
            local refused = kmes.of_type(events, "stratafs.mutation.refused")
            t:assert_eq(#refused, 1, "a still-live target must not be classified as gone")
            t:assert_eq(refused[1].payload.outcome.errno, -sys.E.NOTDIR,
                "the merged parent's non-directory error is retained")
            t:assert_eq(refused[1].payload.outcome.deferred, true)
            t:assert_eq(vm:read_file(s:in_stratum("src", "d/f")), "original",
                "the failed deletion leaves the original target intact")
            t:assert_eq(vm:read_file(s:in_stratum("dest", "d")), "masks the lower directory",
                "the masking object is untouched too")
        end)
    end)
