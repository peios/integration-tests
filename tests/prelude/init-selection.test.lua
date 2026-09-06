-- Area E, second half, and area F: choosing an init, and giving up.
--
-- By the time prelude reaches phase 8 it is standing inside the new root
-- with nothing left to do but replace itself. It has a list of paths to
-- try — whatever `init=` named, then the fallback chain — and it works
-- down it until an execve takes. Claims E11-E16.
--
-- If anything before that went wrong, prelude does not limp: it says so,
-- re-reads the command line for the debug knobs, and halts the machine.
-- Claims F1-F5. A test for one of those asserts on the console text that
-- comes back in the boot's failure, because there is no agent left to
-- ask — which is itself the point.
--
-- The lever throughout is a hook that mounts the root and then rearranges
-- what prelude will find in it (`prelude.root_hook`). Phase 8 is prelude
-- alone, so the only way to steer it is to change the root it is about
-- to look at.

local prelude = require("helpers.prelude")

--- The text of the last line prelude itself printed, tag stripped. The
--- guest console is CRLF, so the carriage return comes off the end.
local function last_prelude_line(log)
    local last
    for msg in log:gmatch("%[[^%]\r\n]*%] prelude: ([^\r\n]*)") do last = msg end
    return last
end

test("an init= that exists is exec'd, and the fallback chain is never reached",
    { spec = "prelude init.cmdline-value-precedes-the-chain" }, function(t)
        -- A second copy of the agent, at a name nothing else would find.
        -- prelude puts the cmdline value at the head of the candidate
        -- list, so this one is tried before /bin/peinit2 — which is
        -- still sitting there, executable, and never touched.
        local vm = provium:vm("named-init", "prelude")
        vm:boot({
            kernel_cmdline_append = "init=/bin/pt-alt-init",
            files = prelude.files({
                hooks = { root = { body = prelude.root_hook("root",
                    "cp -a /mnt/rootfs/bin/peinit2 /mnt/rootfs/bin/pt-alt-init") } },
            }),
        })
        local log = vm:console():read_log()

        t:assert(log:find("target init from cmdline: /bin/pt-alt-init", 1, true),
            "prelude read the init= value: " .. log:sub(-600))
        t:assert(log:find("exec /bin/pt-alt-init", 1, true),
            "and exec'd it")
        t:assert(not log:find("exec /bin/peinit2", 1, true),
            "the first of the fallbacks was never tried, though it is present and executable")
        t:assert_eq(vm:read_file("/proc/1/cmdline"), "/bin/pt-alt-init\0",
            "PID 1 is the init the command line named")
    end)

test("an init= that does not exist falls through to the chain rather than failing the boot",
    { spec = { "prelude init.cmdline-value-precedes-the-chain",
               "prelude init.absent-candidate-is-skipped" } }, function(t)
        -- The cmdline value goes FIRST but does not replace the chain:
        -- prelude appends the whole of it behind whatever init= named, so
        -- naming something absent costs one skipped candidate and
        -- nothing else.
        local vm = provium:vm("bad-init", "prelude")
        vm:boot({ kernel_cmdline_append = "init=/bin/there-is-no-such-init" })
        local log = vm:console():read_log()

        t:assert(log:find("target init from cmdline: /bin/there-is-no-such-init", 1, true),
            "prelude took the init= value: " .. log:sub(-600))
        t:assert(log:find("skip /bin/there-is-no-such-init: not present", 1, true),
            "found nothing there, and said which candidate it was passing over")
        t:assert(log:find("exec /bin/peinit2", 1, true),
            "then carried on into the fallback chain")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "and the boot completed on the first fallback")
    end)

test("the fallback chain is tried in order, each absent candidate named as it is passed over",
    { spec = { "prelude init.fallback-chain-order",
               "prelude init.absent-candidate-is-skipped" } }, function(t)
        -- Put the only init at the LAST name in the chain. Reaching it
        -- means prelude walked past the other three, in order, and said
        -- so each time.
        local vm = provium:vm("chain", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { root = { body = prelude.root_hook("root",
                "mv /mnt/rootfs/bin/peinit2 /mnt/rootfs/bin/sh") } },
        }) })
        local log = vm:console():read_log()

        local at = {}
        for i, path in ipairs({ "/bin/peinit2", "/sbin/init", "/bin/init" }) do
            at[i] = log:find("skip " .. path .. ": not present", 1, true)
            t:assert(at[i], "prelude skipped " .. path .. ": " .. log:sub(-700))
        end
        t:assert(at[1] < at[2] and at[2] < at[3],
            "the chain is /bin/peinit2, /sbin/init, /bin/init, /bin/sh, in that order")
        t:assert(log:find("exec /bin/sh", 1, true),
            "and the last of the four is where it stopped")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "sh",
            "PID 1 is the init found at the end of the chain")
    end)

test("with the first candidate present, nothing is skipped",
    { spec = "prelude init.absent-candidate-is-skipped" }, function(t)
        -- The other half of the same behaviour: the skip line is a
        -- report about a candidate prelude passed over, not a step it
        -- takes on every boot.
        local vm = provium:vm("no-skips", "prelude"):boot()
        local log = vm:console():read_log()

        t:assert(log:find("exec /bin/peinit2", 1, true),
            "prelude exec'd the head of the chain: " .. log:sub(-600))
        t:assert(not log:find("skip /", 1, true),
            "and skipped nothing, because it never looked past the first candidate")
    end)

test("the init prelude execs gets its own path as argv and TERM=linux as its whole environment",
    { spec = "prelude init.argv-and-environment" }, function(t)
        local vm = provium:vm("argv-env", "prelude"):boot()

        local cmdline = vm:read_file("/proc/1/cmdline")
        t:assert_eq(cmdline, "/bin/peinit2\0",
            "argv is one element, the path prelude exec'd: " .. (cmdline:gsub("%z", "\\0")))

        local environ = vm:read_file("/proc/1/environ")
        t:assert_eq(environ, "TERM=linux\0",
            "and the environment holds TERM and nothing else: " .. (environ:gsub("%z", "\\0")))
    end)

test("a candidate that is present but cannot be exec'd is reported and the next one tried",
    { spec = "prelude init.failed-exec-tries-the-next" }, function(t)
        -- `Path::exists` is true for a file carrying no execute mark, so
        -- prelude does not skip it — it tries the execve, and the kernel
        -- is what refuses. The distinction matters: this path reports an
        -- execve failure rather than "not present", and carries on.
        --
        -- The unrunnable copy is made by shell redirection, which creates
        -- the file without the execute mark. Peios ships no `chmod` —
        -- access is the security descriptor's business — and `mkexec`,
        -- the tool that sets the mark, cannot take it away.
        local vm = provium:vm("bad-exec", "prelude")
        vm:boot({ files = prelude.files({
            hooks = { root = { body = prelude.root_hook("root", table.concat({
                "rm -f /mnt/rootfs/bin/peinit2",
                "cat /fixtures/rootfs/bin/peinit2 > /mnt/rootfs/bin/peinit2",
                "mkdir -p /mnt/rootfs/sbin",
                "cp -a /fixtures/rootfs/bin/peinit2 /mnt/rootfs/sbin/init",
            }, "\n")) } },
        }) })
        local log = vm:console():read_log()

        t:assert(not log:find("skip /bin/peinit2", 1, true),
            "the unexecutable file is present, so it is not skipped: " .. log:sub(-700))
        local tried = log:find("exec /bin/peinit2", 1, true)
        local failed = log:find("execve /bin/peinit2 failed:", 1, true)
        local next_one = log:find("exec /sbin/init", 1, true)
        t:assert(tried and failed and tried < failed,
            "prelude tried it and reported the execve failure: " .. log:sub(-700))
        t:assert(next_one and failed < next_one,
            "then moved on to the next candidate in the chain")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "init",
            "and the boot completed on that one")
    end)

test("a root with no candidate anywhere in the chain ends the boot",
    { spec = "prelude init.no-candidate-ends-the-boot" }, function(t)
        local vm = provium:vm("no-init", "prelude")
        local err = prelude.boot_halts(t, vm, { files = prelude.files({
            hooks = { root = { body = prelude.root_hook("root",
                "rm -f /mnt/rootfs/bin/peinit2") } },
        }) })

        for _, path in ipairs({ "/bin/peinit2", "/sbin/init", "/bin/init", "/bin/sh" }) do
            t:assert(err:find("skip " .. path .. ": not present", 1, true),
                "prelude passed over " .. path .. ": " .. err:sub(-700))
        end
        t:assert(err:find("boot failed: no init candidate executable", 1, true),
            "and having exhausted the list, refused the boot: " .. err:sub(-700))
        t:assert(err:find("halting system", 1, true),
            "then halted, with the root mounted and the pivot already done")
    end)

test("a failure is reported as a failure, naming what went wrong",
    { spec = "prelude halt.failure-is-logged" }, function(t)
        local vm = provium:vm("failed-tag", "prelude")
        local err = prelude.boot_halts(t, vm, { kernel_cmdline_append = "pt.mount-root=fail" })

        t:assert(err:find(
            "[FAILED] prelude: boot failed: hook /usr/libexec/prelude/hooks.d/pt-mount-root.sh: " ..
            "exited with status 1", 1, true),
            "the one line every refused boot ends with carries the FAILED tag and the error: " ..
            err:sub(-700))
    end)

test("rd.shell is honoured, though nothing before the failure ever looked for it",
    { spec = { "prelude halt.cmdline-is-reread-for-the-debug-knobs",
               "prelude halt.rd-shell-opens-a-shell-first" } }, function(t)
        -- prelude reads /proc/cmdline once during the boot, for quiet,
        -- colour, init= and rd.break. `rd.shell` is not among them: the
        -- only code that looks for that token runs after the failure, on
        -- a fresh read. So a shell opening here is the re-read, observed.
        local vm = provium:vm("reread", "prelude")
        local err = prelude.boot_halts(t, vm,
            { kernel_cmdline_append = "pt.mount-root=fail rd.shell" })

        t:assert(err:find(
            "rd.shell: boot failed: hook /usr/libexec/prelude/hooks.d/pt-mount-root.sh: " ..
            "exited with status 1 (exit to halt)", 1, true),
            "the shell announced itself, quoting the failure and saying what exiting does: " ..
            err:sub(-700))
        t:assert(err:find("can't access tty", 1, true),
            "and the shell is really running — the boot is paused in it, not halted")
    end)

test("the re-read cannot reach /proc once the kernel filesystems have moved, so rd.shell is inert there",
    { spec = "prelude halt.cmdline-is-reread-for-the-debug-knobs" }, function(t)
        -- The re-read is a plain open of /proc/cmdline, and by phase 5
        -- prelude has already moved /proc out of the root it is still
        -- standing in. The read fails, the cmdline reads as empty, and
        -- every debug knob silently stops working for exactly the
        -- failures — the handoff ones — that are hardest to reproduce.
        local vm = provium:vm("reread-late", "prelude")
        local err = prelude.boot_halts(t, vm, {
            kernel_cmdline_append = "rd.shell",
            files = prelude.files({
                hooks = { root = { body = prelude.root_hook("root", "rmdir /mnt/rootfs/sys") } },
            }),
        })

        t:assert(err:find("mount-move /proc -> /mnt/rootfs/proc", 1, true),
            "/proc had already been moved out of the old root: " .. err:sub(-700))
        t:assert(err:find("boot failed: mount-move /sys:", 1, true),
            "and the boot then failed")
        t:assert(not err:find("rd.shell:", 1, true),
            "rd.shell was on the command line but no shell opened: the re-read found nothing")
        t:assert(err:find("halting system", 1, true),
            "the machine halted instead")
    end)

test("a refused boot ends by halting the machine",
    { spec = "prelude halt.syncs-and-halts" }, function(t)
        local vm = provium:vm("halts", "prelude")
        local err = prelude.boot_halts(t, vm, { kernel_cmdline_append = "pt.topology=fail:70" })

        t:assert(err:find("[      ] prelude: halting system", 1, true),
            "prelude said it was halting: " .. err:sub(-700))
        t:assert_eq(last_prelude_line(err), "halting system",
            "and that is the last thing it ever says")
        t:assert(err:find("reboot: System halted", 1, true),
            "the kernel then halted the system, which is RB_HALT_SYSTEM and not a reset")
    end)

test("a boot that succeeds never comes back to prelude at all",
    { spec = "prelude halt.success-never-returns" }, function(t)
        local vm = provium:vm("no-return", "prelude"):boot()
        local log = vm:console():read_log()

        t:assert_eq(last_prelude_line(log), "exec /bin/peinit2",
            "the exec is the last word prelude has: " .. log:sub(-600))
        t:assert(not log:find("boot failed", 1, true), "no failure was reported")
        t:assert(not log:find("halting system", 1, true), "and nothing halted the machine")

        -- The exec replaced prelude rather than starting something
        -- beside it: PID 1 still holds the process prelude was, under
        -- the init's name and with the init's argv.
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "PID 1 is the init, not prelude waiting on it")
        t:assert_eq(vm:read_file("/proc/1/cmdline"), "/bin/peinit2\0",
            "and carries the init's own command line")
    end)
