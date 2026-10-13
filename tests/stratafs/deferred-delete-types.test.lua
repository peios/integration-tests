-- PEI-1444: only regular files can carry deferred deletion.
local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local stratafs = require("helpers.stratafs")
local vm = provium:vm("v", "kernel-only"):boot()

test("deferred deletion accepts regular files and refuses directory and FIFO arms",
    { spec = "PKM *create.deferred-delete-non-directories" }, function(t)
        stratafs.with(vm, "deferred-types", {
            { name = "only", flags = { "create" }, entries = { f = "file", d = stratafs.DIR } },
        }, function(s)
            t:assert_eq(sys.mknod(vm, s:join("fifo"), sys.S_IFIFO | tonumber("600", 8)).ret, 0)
            for _, name in ipairs({ "d", "fifo" }) do
                local fd, errno = kacs.open(vm, s:join(name), {
                    access = kacs.RIGHT.READ_DATA | kacs.RIGHT.DELETE |
                        (name == "fifo" and kacs.RIGHT.WRITE_DATA or 0),
                    options = kacs.CREATE_OPT.DELETE_ON_CLOSE,
                })
                if fd then sys.close(vm, fd) end
                t:assert(fd == nil, name .. " cannot be armed")
                t:assert_eq(errno, sys.E.OPNOTSUPP, name .. " fails the object-type gate")
                t:assert(sys.stat(vm, s:in_stratum("only", name)), "the refused object survives")
            end
            local fd, errno = kacs.open(vm, s:join("f"),
                { options = kacs.CREATE_OPT.DELETE_ON_CLOSE })
            t:assert(fd, "a managed regular file can be armed: " .. sys.errname(errno or 0))
            t:assert_eq(sys.close(vm, fd).ret, 0)
            t:assert(sys.stat(vm, s:in_stratum("only", "f")) == nil,
                "the positive control is deleted at final close")
        end)
    end)
