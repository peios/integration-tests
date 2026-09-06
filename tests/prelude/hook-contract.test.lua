-- The hook contract's second half: what prelude hands a hook, and what a
-- hook may say back.
--
-- Everything a hook receives comes from one `fork` + `execve` in
-- `spawn_and_wait` — a two-variable environment, an argv of one element,
-- no pipe on either output stream — and everything it can say comes back
-- through one `waitpid` status, which `run_one_hook` and `wait_failure`
-- decode into exactly three non-failure outcomes and a failure for
-- everything else.
--
-- The console is the oracle on both sides. A hook's own report line
-- (`pt|<hook>|env=…|argc=…`) says what it was handed; prelude's log line
-- says what prelude made of what it said back. For the codes prelude
-- refuses, the machine halts and the console arrives in `vm:boot()`'s
-- error instead.

local prelude = require("helpers.prelude")

--- The staged hooks' full paths, as prelude names them in its log lines.
local LATE = prelude.HOOK_DIR .. "/pt-late.sh"

--- The first `pt|<name>|…` report line carrying an `env` field — the
--- line a hook prints when it starts, as opposed to its outcome line.
local function report_for(log, name)
    for _, mark in ipairs(prelude.marks(log)) do
        if mark.hook == name and mark.env then
            return mark
        end
    end
    return nil
end

--- A hook's environment, decoded from its `env=` field back into a map
--- of name to value. `pt-hook.sh` renders `env` with commas for
--- newlines, so the trailing empty element is dropped.
local function env_of(mark)
    local vars = {}
    for entry in (mark.env or ""):gmatch("[^,]+") do
        local k, v = entry:match("^([^=]+)=(.*)$")
        if k then vars[k] = v end
    end
    return vars
end

-- C14. `spawn_and_wait` builds a three-element `envp`: TERM=linux,
-- PATH=/usr/bin, and the terminator. Nothing is inherited, because
-- prelude is PID 1 and has nothing to inherit from.
--
-- The count is not the assertion. A hook is a `#!/usr/bin/sh` script, so
-- what actually reports the environment is dash, and dash sets PWD for
-- itself on startup — so the observable set is prelude's two plus one
-- the shell added. What prelude is answerable for is that TERM and PATH
-- are there with those values, and that nothing else came from prelude.
test("a hook's environment is exactly PATH=/usr/bin and TERM=linux",
    { spec = "prelude hook.environment-is-path-and-term" }, function(t)
        local vm = provium:vm("env", "prelude")
        vm:boot()

        local mark = report_for(vm:console():read_log(), "topology")
        t:assert(mark, "the first hook reported the environment it was handed")
        local env = env_of(mark)

        t:assert_eq(env.PATH, "/usr/bin",
            "PATH=/usr/bin, so the initramfs's shell and peiosutils resolve " ..
            "without a root-level view")
        t:assert_eq(env.TERM, "linux", "TERM=linux")

        -- Nothing else is prelude's. PWD is dash's own doing, so it is
        -- the one name allowed beside the two prelude passes.
        for name in pairs(env) do
            t:assert(name == "PATH" or name == "TERM" or name == "PWD",
                "prelude passes no variable but PATH and TERM (PWD is dash's " ..
                "own); found " .. name .. "=" .. tostring(env[name]))
        end
    end)

-- C15. `argv` is built as `[path, ...args, NULL]` and `run_one_hook`
-- passes an empty `args`, so a hook's argv is one element. Nothing
-- documents this, and a hook that read `$1` would find nothing there.
test("a hook's argv is its own path and nothing else",
    { spec = "prelude hook.argv-is-its-own-path-alone" }, function(t)
        local vm = provium:vm("argv", "prelude")
        vm:boot()

        local mark = report_for(vm:console():read_log(), "topology")
        t:assert(mark, "the first hook reported its own argv")

        t:assert_eq(mark.argc, "0", "prelude passes a hook no arguments")
        t:assert_eq(mark.arg0, prelude.HOOK_DIR .. "/pt-topology.sh",
            "argv[0] is the hook's own path, the same string prelude exec'd")

        -- Not a numbered claim, but part of the same handover: prelude
        -- never chdirs before the hooks, so a hook starts at /.
        t:assert_eq(mark.cwd, "/", "a hook runs from the initramfs root")
    end)

-- C16, the first of the three outcomes. Exit 0 is Satisfied: prelude
-- says nothing further about the hook and the sequence carries on.
test("a hook that exits 0 is satisfied",
    { spec = "prelude hook.exit-codes-map-to-outcomes" }, function(t)
        local vm = provium:vm("ok", "prelude")
        vm:boot()

        local log = vm:console():read_log()
        t:assert(log:find("pt|late|outcome=satisfied", 1, true),
            "the hook exited 0")
        t:assert(not log:find(LATE .. ": declined", 1, true),
            "exit 0 is not a decline")
        t:assert(not log:find(LATE .. ": deferred", 1, true),
            "exit 0 is not a deferral")
        t:assert(log:find("ran 3 hook invocation(s)", 1, true),
            "and the run completed with every hook terminal")
    end)

-- C16. Exit 69 is Declined — "not applicable on this machine" — which is
-- a terminal outcome, not a failure. `pt-late.sh` contributes only
-- `rootfs-strata-ready`, which nothing requires, so its decline costs the
-- boot nothing and prelude goes on to hand off.
test("a hook that exits 69 is declined and the boot carries on",
    { spec = "prelude hook.exit-codes-map-to-outcomes" }, function(t)
        local vm = provium:vm("decline", "prelude")
        vm:boot({ kernel_cmdline_append = "pt.late=decline" })

        local log = vm:console():read_log()
        t:assert(log:find("pt|late|outcome=declined", 1, true),
            "the hook exited 69")
        t:assert(log:find("hook " .. LATE .. ": declined (not applicable here)", 1, true),
            "prelude read 69 as Declined")
        t:assert(log:find("ran 3 hook invocation(s)", 1, true),
            "a decline is terminal, so the run completed")
        t:assert(log:find("root mounted at /mnt/rootfs", 1, true),
            "and the boot went on to the handoff rather than failing")
    end)

-- C16. Exit 75 is Deferred — "not yet, and I changed nothing" — so the
-- hook is left pending and tried again. `defer:2` makes it defer once
-- and then act, which is the shortest run that shows prelude read 75 as
-- something other than success and other than failure.
test("a hook that exits 75 is deferred and retried",
    { spec = "prelude hook.exit-codes-map-to-outcomes" }, function(t)
        local vm = provium:vm("defer", "prelude")
        vm:boot({ kernel_cmdline_append = "pt.late=defer:2" })

        local log = vm:console():read_log()
        t:assert(log:find("pt|late|outcome=deferred", 1, true),
            "the hook exited 75 on its first run")
        t:assert(log:find("hook " .. LATE .. ": deferred (will retry)", 1, true),
            "prelude read 75 as Deferred rather than as a failure")
        t:assert(log:find("pt|late|outcome=satisfied", 1, true),
            "and ran it again, where it exited 0")
    end)

-- C17. Everything outside {0, 69, 75} is a failure that ends the boot:
-- `run_one_hook`'s catch-all arm formats `hook <path>: exited with
-- status <code>`. 68 and 70 bracket EX_UNAVAILABLE and 76 sits just
-- above EX_TEMPFAIL, so an off-by-one in the match would show up here
-- and nowhere else.
for _, code in ipairs({ 68, 70, 76 }) do
    test("a hook that exits " .. code .. " ends the boot",
        { spec = "prelude hook.other-exit-code-ends-the-boot" }, function(t)
            local vm = provium:vm("code" .. code, "prelude")
            local out = prelude.boot_halts(t, vm,
                { kernel_cmdline_append = "pt.late=fail:" .. code })

            t:assert(out:find("hook " .. LATE .. ": exited with status " .. code, 1, true),
                "prelude named the hook and the status it exited with: " ..
                out:sub(-400))
            t:assert(out:find("halting system", 1, true),
                "and the machine halted rather than continuing to the handoff")
        end)
end

-- C17, the ordinary case: 1, what any failing command returns.
test("a hook that exits 1 ends the boot",
    { spec = "prelude hook.other-exit-code-ends-the-boot" }, function(t)
        local vm = provium:vm("code1", "prelude")
        local out = prelude.boot_halts(t, vm,
            { kernel_cmdline_append = "pt.late=fail:1" })

        t:assert(out:find("boot failed: hook " .. LATE .. ": exited with status 1", 1, true),
            "the ordinary failure code is reported the same way: " .. out:sub(-400))
        t:assert(not out:find("root mounted at /mnt/rootfs", 1, true),
            "prelude stopped at the hook, never reaching the root check")
    end)

-- C18. `spawn_and_wait` inspects the low seven bits of the wait status
-- BEFORE anything reads an exit code, so a hook killed by a signal is a
-- failure whatever code it might otherwise have produced. This is the
-- one thing the hook page states outright — "A hook killed by a signal
-- is always a failure, whatever code it might have produced" — so the
-- message text is the assertion, not merely that the boot stopped.
test("a hook killed by a signal is a failure naming the signal",
    { spec = "prelude hook.killed-by-a-signal-is-a-failure" }, function(t)
        local vm = provium:vm("signal", "prelude")
        local out = prelude.boot_halts(t, vm,
            { kernel_cmdline_append = "pt.late=signal" })

        t:assert(out:find("pt|late|outcome=signalled", 1, true),
            "the hook reached the point of killing itself")
        t:assert(out:find("hook " .. LATE .. ": killed by signal 15", 1, true),
            "prelude reported the hook killed by signal 15, naming the hook " ..
            "and the signal: " .. out:sub(-400))
        t:assert(not out:find(LATE .. ": exited with status", 1, true),
            "and read no exit code from it: a signalled child never exited")
    end)

-- C19. `wait_failure` has an arm for a stopped child — status low bits
-- 0x7f — that reports `stopped` and is fatal like any other wait
-- failure. No guest can reach it: `spawn_and_wait` calls
-- `waitpid(pid, &mut status, 0)` with no WUNTRACED, so a hook that stops
-- itself is never reported at all and prelude blocks in waitpid until
-- the VM's boot timeout takes the machine away. A live test would assert
-- a hang, and would assert the absence of the very message the claim is
-- about.
test("a hook stopped by a signal is a failure",
    { spec = "prelude hook.stopped-is-a-failure",
      covered_by = "cargo:prelude::tests::signal_termination_is_reported",
      skip = "unreachable from a guest: spawn_and_wait's waitpid passes no " ..
             "WUNTRACED, so a stopped hook hangs the boot instead of being " ..
             "reported; wait_failure's decoding is exercised by " ..
             "prelude::tests::signal_termination_is_reported, which covers " ..
             "the sibling signal arm — the `stopped` arm itself has no test" },
    function(t) end)

-- C20. When `execve` fails, the child is already forked: it logs and
-- `_exit(127)`, so the parent sees an ordinary exit status of 127 and
-- refuses the boot through the same path as any other bad code. A file
-- without its execute bit is the commonest way to get there, and under
-- KACS the execute bit is load-bearing — provium's `files` defaults to
-- 0644, which is exactly the mistake being modelled.
test("a hook that is not executable is reported as status 127",
    { spec = "prelude hook.unexecutable-is-status-127" }, function(t)
        local path = prelude.HOOK_DIR .. "/pt-unexec.sh"
        local vm = provium:vm("unexec", "prelude")
        local out = prelude.boot_halts(t, vm, {
            files = prelude.files({
                seq = "hookseq 2\nhook " .. path .. "\n",
                extra = { { path = path, content = "#!/usr/bin/sh\nexit 0\n" } },
            }),
        })

        t:assert(out:find(path .. ": exec failed", 1, true),
            "the forked child reported that it could not exec the hook: " ..
            out:sub(-400))
        t:assert(out:find("hook " .. path .. ": exited with status 127", 1, true),
            "and prelude saw an ordinary exit status of 127 from it")
    end)

-- C20, the other route to the same status: the file is executable but
-- its interpreter is not there, so the kernel's shebang handling fails
-- the `execve` rather than the permission check.
test("a hook whose interpreter is missing is reported as status 127",
    { spec = "prelude hook.unexecutable-is-status-127" }, function(t)
        local path = prelude.HOOK_DIR .. "/pt-noterp.sh"
        local vm = provium:vm("noterp", "prelude")
        local out = prelude.boot_halts(t, vm, {
            files = prelude.files({
                seq = "hookseq 2\nhook " .. path .. "\n",
                extra = { {
                    path = path,
                    content = "#!/usr/bin/no-such-interpreter\nexit 0\n",
                    mode = 0x1ed,
                } },
            }),
        })

        t:assert(out:find(path .. ": exec failed", 1, true),
            "the exec failed on the shebang's interpreter: " .. out:sub(-400))
        t:assert(out:find("hook " .. path .. ": exited with status 127", 1, true),
            "and reached prelude as an ordinary exit status of 127")
    end)

-- C21. There is no pipe anywhere in `spawn_and_wait`, so a hook inherits
-- prelude's own stdout and stderr, which are the console's. prelude
-- never sees the bytes and so cannot label, align or colour them: they
-- land verbatim, between prelude's own lines.
test("a hook's stdout and stderr reach the console unmodified",
    { spec = "prelude hook.output-goes-straight-to-the-console" }, function(t)
        local path = prelude.HOOK_DIR .. "/pt-say.sh"
        local vm = provium:vm("say", "prelude")
        vm:boot({
            files = prelude.files({
                hooks = { ["pt-say"] = { body = table.concat({
                    "#!/usr/bin/sh",
                    "echo 'pt-out-6f21 on stdout'",
                    "echo 'pt-err-9c40 on stderr' >&2",
                    "exit 0",
                    "",
                }, "\n") } },
                keep = { "pt-mount-root.sh" },
            }),
        })

        local log = vm:console():read_log()
        local out_at = log:find("pt-out-6f21 on stdout", 1, true)
        local err_at = log:find("pt-err-9c40 on stderr", 1, true)
        t:assert(out_at, "what the hook wrote to stdout is on the console, verbatim")
        t:assert(err_at, "and so is what it wrote to stderr")

        -- Interleaved with prelude's own lines rather than collected and
        -- replayed: the run announcement precedes both, the completion
        -- line follows them.
        local ran_at = log:find("prelude: hook: " .. path, 1, true)
        local done_at = log:find("ran 2 hook invocation(s)", 1, true)
        t:assert(ran_at and out_at and ran_at < out_at,
            "prelude's own `hook: <path>` line came first")
        t:assert(done_at and err_at and err_at < done_at,
            "and both streams landed before prelude's completion line")
    end)
