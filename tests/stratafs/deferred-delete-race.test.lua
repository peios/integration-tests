local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local kmes = require("helpers.kmes")
local stratafs = require("helpers.stratafs")
local vm = provium:vm("deferred-delete-race", "kernel-only", { cpus = 2 }):boot()

test("an external unlink racing final close completes without a refusal audit",
    { spec = "PKM *create.deferred-delete-already-gone-succeeds" }, function(t)
        stratafs.with(vm, "deferred-race", {
            { name = "only", flags = { "create" }, entries = { d = stratafs.DIR } },
        }, function(s)
            local owner = vm:spawn_worker()
            local remover = vm:spawn_worker()
            local external_wins, close_wins = 0, 0
            local ok, err = pcall(function()
                local events = kmes.recording(t, vm, function()
                    for i = 1, 32 do
                        local relative = "d/f" .. i
                        local raw = s:in_stratum("only", relative)
                        vm:write_file(raw, "original")
                        local fd, e = kacs.open(owner, s:join(relative),
                            { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
                        t:assert(fd, "the owner alone arms the descriptor: " .. sys.errname(e or 0))
                        local close, unlink
                        local function start_close()
                            return owner:syscall_async(sys.NR.close, { args = { fd } })
                        end
                        local function start_unlink()
                            return remover:syscall_async(sys.NR.unlinkat, {
                                args = { sys.AT_FDCWD, 0, 0 },
                                bufs = { sys.cstr(raw) }, ptrs = { 1 },
                            })
                        end
                        -- Submit both without awaiting either, alternating the
                        -- launch order. The second worker never owns the fd.
                        if i % 2 == 0 then
                            close, unlink = start_close(), start_unlink()
                        else
                            unlink, close = start_unlink(), start_close()
                        end
                        t:assert_eq(close:await().ret, 0)
                        local r = unlink:await()
                        t:assert(r.ret == 0 or r.errno == sys.E.NOENT,
                            "the competing remover either wins or finds the promised deletion complete")
                        if r.ret == 0 then external_wins = external_wins + 1
                        else close_wins = close_wins + 1 end
                        local st, errno = sys.stat(vm, raw)
                        t:assert(not st and errno == sys.E.NOENT)
                    end
                end)
                t:assert_eq(#kmes.of_type(events, "stratafs.mutation.refused"), 0,
                    "neither ordering is an audited deletion failure")
                t:log("external unlink wins=" .. external_wins .. ", final close wins=" .. close_wins)
            end)
            owner:kill(); owner:join()
            remover:kill(); remover:join()
            if not ok then error(err, 0) end
        end)
    end)
