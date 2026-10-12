-- PEI-485 / PEI-255: exercise the foreign-entry scan with a genuine
-- named copy-up stage registered to this mount, not a prefix lookalike.
local sys = require("helpers.sys")
local stratafs = require("helpers.stratafs")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()

test("directory rename ignores its mount's live stage but not a lookalike",
    { spec = "PKM *rename.directory-source-must-not-strand-entries" }, function(t)
        stratafs.with(vm, "rename-live-stage", {
            { name = "provider", entries = { ["d/mine"] = "kept" } },
            { name = "dest", flags = { "create" }, entries = { d = stratafs.DIR } },
            { name = "src", flags = { "ro" }, entries = { ["d/child"] = stratafs.DIR } },
        }, function(s)
            t:assert(hooks.hold(vm, "copy-up-publish"), "hold publication")
            local worker = vm:spawn_worker()
            local ok, err = pcall(function()
                -- Directory copy-up uses a named stage; regular files
                -- use anonymous tmpfiles and cannot exercise this scan.
                local pending = worker:syscall_async(sys.NR.fchownat, {
                    args = { sys.AT_FDCWD, 0, 4242, 4243, 0 },
                    bufs = { sys.cstr(s:join("d/child")) }, ptrs = { 1 },
                })
                t:assert(hooks.await_waiting(vm, "copy-up-publish"),
                    "the real copy-up is staged before publication")
                local entries = vm:listdir(s:in_stratum("dest", "d"))
                t:assert_eq(#entries, 1, "exactly one named stage exists")
                t:assert(entries[1].name:match("^%.stratafs%-stage%-"),
                    "the entry has the kernel's staging name")
                local stage = s:in_stratum("dest", "d/" .. entries[1].name)
                t:assert(sys.stat(vm, stage).is_dir, "the stage is a directory")

                -- The lower child's ordinary name must have a match in
                -- the provider; otherwise it independently causes EXDEV.
                -- Add that match only after copy-up has reached its hook.
                t:assert_eq(sys.mkdir(vm, s:in_stratum("provider", "d/child")).ret,
                    0, "cover the lower child's ordinary name")
                local lookalike = s:in_stratum("dest", "d/.stratafs-stage-lookalike")
                vm:write_file(lookalike, "ordinary entry")
                local denied = sys.rename(vm, s:join("d"), s:join("moved"))
                t:assert_eq(denied.errno, sys.E.XDEV,
                    "an unregistered prefix lookalike is a foreign entry")
                t:assert_eq(vm:read_file(s:in_stratum("provider", "d/mine")),
                    "kept", "the refused rename leaves the provider intact")
                t:assert_eq(sys.unlink(vm, lookalike).ret, 0, "remove the control entry")

                local renamed = sys.rename(vm, s:join("d"), s:join("moved"))
                t:assert_eq(renamed.ret, 0,
                    "the tracked stage does not prevent rename: " .. sys.errname(renamed.errno))
                t:assert_eq(vm:read_file(s:in_stratum("provider", "moved/mine")),
                    "kept", "the provider directory actually moved")
                t:assert(sys.stat(vm, stage) ~= nil, "rename leaves the live stage intact")

                t:assert(hooks.clear(vm, "copy-up-publish"), "release the held copy-up")
                t:assert_eq(pending:await().ret, 0, "the held operation completes")
                t:assert(sys.stat(vm, stage) == nil, "completion removes the staging name")
            end)
            hooks.clear(vm, "copy-up-publish")
            worker:kill(); worker:join()
            if not ok then error(err, 0) end
        end)
    end)
