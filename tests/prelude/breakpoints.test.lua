-- Area D: breakpoints and the rescue shell.
--
-- `rd.break` is the one part of prelude that needs a human at the other
-- end of the console, which is why it had no coverage until now: the
-- shell prelude forks inherits prelude's stdin, a test has no way to
-- type into it, and a boot that stops at a breakpoint never reaches an
-- agent — `vm:boot` fails on the agent timeout with the guest already
-- torn down.
--
-- The way in is that `RESCUE_SHELL` is a path — `/usr/bin/sh`, dash's
-- own — and a path is a thing a test can replace. Two stand-ins are
-- injected here, both of which fall through to the real dash for every
-- other caller (the hooks' `#!/usr/bin/sh` shebang among them), and both
-- of which recognise prelude's rescue invocation by its `-i`:
--
--   RESCUE_SH   reports the argv and environment prelude handed it and
--               exits at once. That turns every breakpoint into a
--               resumable one, so the whole of `rd.break` — where it
--               stops, what it matches, what it implies — is assertable
--               on a boot that goes on to complete.
--   FEEDING_SH  execs the *real* dash, `-i`, reading a script this test
--               injected. So one case runs the shipped shell,
--               interactively, and lets it exit on its own.
--
-- One case deliberately keeps the shipped dash untouched and asserts on
-- what it printed to the console before the boot timed out — that is
-- where argv0 and the interactive prompt are visible, and no stand-in
-- could show them.

local prelude = require("helpers.prelude")

local MODE_EXEC = 0x1ed -- 0755
local MODE_DATA = 0x1a4 -- 0644

--- The instrumented stand-in for prelude's rescue shell. On `-i` — the
--- argv prelude and nothing else uses — it reports itself and returns,
--- so the breakpoint resumes; on anything else it is dash.
local RESCUE_SH = [[#!/usr/bin/dash
if [ "$1" = "-i" ]; then
    echo "pt|rescue|path=$0|argc=$#|args=$*|pid=$$|init=$(cat /proc/1/comm)|env=$(env | tr '\n' ',')" >&2
    exit 0
fi
exec /usr/bin/dash "$@"
]]

--- The same trick, but handing the rescue invocation to the real dash
--- with a script on its stdin, so the shipped shell runs interactively
--- and exits of its own accord.
local FEEDING_SH = [[#!/usr/bin/dash
if [ "$1" = "-i" ]; then
    exec /usr/bin/dash -i < /fixtures/rescue-typed
fi
exec /usr/bin/dash "$@"
]]

--- What that dash reads. `exit` is the operator leaving the breakpoint.
local TYPED = [[echo "pt|rescue|typed=1|pid=$$|init=$(cat /proc/1/comm)" >&2
exit
]]

--- A root-mounting hook that does not go through `/usr/bin/sh`, for the
--- one case that has to make that path unusable. Otherwise identical to
--- the profile's staged `pt-mount-root.sh`.
local MOUNT_ROOT_VIA_DASH = [[#!/usr/bin/dash
set -eu
. /fixtures/pt-hook.sh
pt_gate mount-root
mount -t tmpfs tmpfs /mnt/rootfs
seed-sd /mnt/rootfs
cp -a /fixtures/rootfs/. /mnt/rootfs/
pt_mark mount-root outcome=satisfied
]]

--- `files` for a boot, with the instrumented shell over dash's path.
local function with_rescue_sh(files, content, mode)
    files = files or {}
    files[#files + 1] = {
        path = "/usr/bin/sh",
        content = content or RESCUE_SH,
        mode = mode or MODE_EXEC,
    }
    return files
end

--- Every `pt|rescue|…` line the stand-in printed, in order.
local function rescues(log)
    local out = {}
    for _, m in ipairs(prelude.marks(log)) do
        if m.hook == "rescue" then out[#out + 1] = m end
    end
    return out
end

--- Byte offset of a literal in the log, or nil.
local function at(log, needle) return log:find(needle, 1, true) end

--- How many times a literal appears.
local function count(log, needle)
    local n, i = 0, 1
    while true do
        local s = log:find(needle, i, true)
        if not s then return n end
        n, i = n + 1, s + 1
    end
end

local HOOKS = "/usr/libexec/prelude/hooks.d/"

test("bare rd.break opens the shell before the first hook runs",
    { spec = "prelude break.bare-stops-before-any-hook" }, function(t)
        local vm = provium:vm("bare", "prelude")
        vm:boot({ kernel_cmdline_append = "rd.break",
                  files = with_rescue_sh() })
        local log = vm:console():read_log()

        t:assert(at(log, "rd.break: stopping before any hooks (exit to continue)"),
            "prelude announced the breakpoint that stops before any hook runs")
        local shell = at(log, "pt|rescue|")
        local first_hook = at(log, "prelude: hook: ")
        t:assert(shell and first_hook, "both the shell and a hook run are on the console")
        t:assert(shell < first_hook,
            "the shell was opened before any hook was run, not between two of them")
        t:assert_eq(table.concat(prelude.ran(log), ","),
            "pt-topology.sh,pt-mount-root.sh,pt-late.sh",
            "and on exit the boot resumed and ran the whole sequence")
    end)

test("the hook sequence is read before the bare-rd.break breakpoint, so a broken sequence never reaches the shell",
    { spec = "prelude break.sequence-is-read-before-the-breakpoint" }, function(t)
        local vm = provium:vm("seqfirst", "prelude")
        -- The case an operator would most want a shell for: an image
        -- whose sequence prelude cannot parse.
        local err = prelude.boot_halts(t, vm, {
            kernel_cmdline_append = "rd.break",
            files = with_rescue_sh(prelude.files({
                hooks = { one = {} },
                seq = "hookseq 9\nhook " .. HOOKS .. "one.sh\n",
            })),
        })

        t:assert(err:find("hookseq", 1, true),
            "prelude refused the sequence on its marker: " .. err:sub(-400))
        t:assert(not err:find("rd.break: stopping before any hooks", 1, true),
            "the rd.break breakpoint never fired — read_hook_seq() runs before it, "
            .. "so a sequence prelude cannot read halts the boot without ever opening the shell")
        -- The shell that did open is the failure one, after the diagnosis.
        local diag = err:find("boot failed:", 1, true)
        local shell = err:find("pt|rescue|", 1, true)
        t:assert(diag and shell and diag < shell,
            "the only shell on this boot came after the failure, not before the hooks")
    end)

test("rd.break=<hook> is comma-separated and repeatable",
    { spec = "prelude break.named-is-comma-separated-and-repeatable" }, function(t)
        local vm = provium:vm("commas", "prelude")
        vm:boot({
            -- Two elements in one flag, a third in a second flag.
            kernel_cmdline_append = "rd.break=alpha.sh,beta.sh rd.break=gamma.sh",
            files = with_rescue_sh(prelude.files({
                hooks = { alpha = {}, beta = {}, gamma = {} },
                order = { "alpha", "beta", "gamma" },
                keep = { "pt-mount-root.sh" },
            })),
        })
        local log = vm:console():read_log()

        for _, name in ipairs({ "alpha", "beta", "gamma" }) do
            t:assert(at(log, "rd.break: stopping before hook " .. HOOKS .. name .. ".sh"),
                "prelude broke before " .. name .. ", named in a comma-separated, repeated rd.break")
        end
        t:assert_eq(#rescues(log), 3,
            "three breakpoints fired and no more — the fourth hook was not named")
        t:assert(not at(log, "rd.break: stopping before any hooks"),
            "and rd.break=<hook> alone does not imply the before-any-hook breakpoint")
    end)

test("rd.break=<hook> matches the full hook path or the bare file name",
    { spec = "prelude break.matches-path-or-file-name" }, function(t)
        local vm = provium:vm("match", "prelude")
        vm:boot({
            -- alpha by its full path, beta by its file name, and
            -- `gamma` — the file name with its extension cut off, which
            -- is neither of the two things prelude compares against.
            kernel_cmdline_append =
                "rd.break=" .. HOOKS .. "alpha.sh rd.break=beta.sh rd.break=gamma",
            files = with_rescue_sh(prelude.files({
                hooks = { alpha = {}, beta = {}, gamma = {} },
                order = { "alpha", "beta", "gamma" },
                keep = { "pt-mount-root.sh" },
            })),
        })
        local log = vm:console():read_log()

        t:assert(at(log, "rd.break: stopping before hook " .. HOOKS .. "alpha.sh"),
            "the full path matched")
        t:assert(at(log, "rd.break: stopping before hook " .. HOOKS .. "beta.sh"),
            "the bare file name matched")
        t:assert(not at(log, "rd.break: stopping before hook " .. HOOKS .. "gamma.sh"),
            "and nothing else did: the comparison is against the whole path or the whole "
            .. "file name, so a name with the extension stripped matches neither")
        t:assert_eq(#rescues(log), 2, "exactly two breakpoints fired")
    end)

test("an empty element in rd.break= is dropped, leaving no breakpoint at all",
    { spec = "prelude break.empty-element-is-dropped" }, function(t)
        local vm = provium:vm("empty", "prelude")
        -- `rd.break=,` is two empty elements and nothing else. Dropped,
        -- it leaves `hooks` empty, so `Breakpoints::any()` is false and
        -- prelude is NOT in shell-on-failure mode — which is how the
        -- filtering becomes observable from outside.
        local err = prelude.boot_halts(t, vm, {
            kernel_cmdline_append = "rd.break=, pt.mount-root=fail",
            files = with_rescue_sh(prelude.files({ keep = { "pt-mount-root.sh" } })),
        })

        t:assert(err:find("exited with status 1", 1, true),
            "the boot failed on the hook, as set up: " .. err:sub(-400))
        t:assert(not err:find("pt|rescue|", 1, true),
            "no shell was opened: both elements of `rd.break=,` were empty and dropped, "
            .. "so no breakpoint is set and shell-on-failure is not implied")
        t:assert(err:find("halting system", 1, true), "prelude halted immediately instead")
    end)

test("any rd.break implies shell-on-failure, even one that never fires",
    { spec = "prelude break.any-breakpoint-implies-shell-on-failure" }, function(t)
        local vm = provium:vm("implies", "prelude")
        -- No rd.shell anywhere, and the named hook is not in the
        -- sequence, so this breakpoint cannot fire.
        local err = prelude.boot_halts(t, vm, {
            kernel_cmdline_append = "rd.break=no-such-hook.sh pt.mount-root=fail",
            files = with_rescue_sh(prelude.files({ keep = { "pt-mount-root.sh" } })),
        })

        t:assert(not err:find("rd.break: stopping before hook", 1, true),
            "the breakpoint never fired — nothing in the sequence is named no-such-hook.sh")
        t:assert(err:find("rd.shell: boot failed:", 1, true),
            "yet the failure opened a shell: setting any rd.break implies rd.shell: "
            .. err:sub(-400))
        t:assert_eq(#rescues(err), 1, "and it is the failure shell, the only one on this boot")
    end)

test("the rescue shell is /usr/bin/sh -i, with the hooks' environment",
    { spec = "prelude shell.is-interactive-sh-with-the-hook-environment" }, function(t)
        local vm = provium:vm("shellenv", "prelude")
        vm:boot({ kernel_cmdline_append = "rd.break",
                  files = with_rescue_sh() })
        local log = vm:console():read_log()

        local r = rescues(log)[1]
        t:assert(r, "the shell prelude forked reported itself")
        t:assert_eq(r.path, "/usr/bin/sh",
            "prelude exec'd RESCUE_SHELL, the packaged shell's own path")
        t:assert_eq(r.argc, "1", "one argument")
        t:assert_eq(r.args, "-i", "and it is -i: the shell is interactive")
        t:assert(r.env:find("TERM=linux,", 1, true),
            "TERM=linux, as for a hook: " .. r.env)
        t:assert(r.env:find("PATH=/usr/bin,", 1, true),
            "PATH=/usr/bin, as for a hook: " .. r.env)
    end)

test("the shell prelude forks is the shipped dash, running interactively under argv0 sh",
    { spec = "prelude shell.is-interactive-sh-with-the-hook-environment" }, function(t)
        local vm = provium:vm("realdash", "prelude")
        -- No stand-in: /usr/bin/sh is dash, so the breakpoint holds the
        -- boot until the agent timeout. What dash printed on the way in
        -- is the assertion.
        local err = prelude.boot_halts(t, vm, { kernel_cmdline_append = "rd.break" })

        t:assert(err:find("rd.break: stopping before any hooks", 1, true),
            "prelude reached the breakpoint: " .. err:sub(-400))
        t:assert(err:find("sh: 0: can't access tty", 1, true),
            "dash diagnosed itself as `sh`, so prelude passed argv0 sh, not the exec'd path")
        t:assert(err:find("job control turned off", 1, true),
            "and it tried to take job control, which only an interactive shell does")
        t:assert(err:find("\n# ", 1, true),
            "it printed its interactive root prompt and waited")
        t:assert(not err:find("prelude: hook: ", 1, true),
            "no hook ran: the boot is stopped in the shell, not merely slow")
    end)

test("the breakpoint shell is forked, so prelude stays PID 1 and the boot resumes where it paused",
    { spec = "prelude shell.is-forked-so-prelude-stays-pid-1" }, function(t)
        local vm = provium:vm("forked", "prelude")
        -- The real dash, interactive, reading a script that asks who PID
        -- 1 is and then exits.
        vm:boot({
            kernel_cmdline_append = "rd.break",
            files = with_rescue_sh({
                { path = "/fixtures/rescue-typed", content = TYPED, mode = MODE_DATA },
            }, FEEDING_SH),
        })
        local log = vm:console():read_log()

        local r = rescues(log)[1]
        t:assert(r and r.typed == "1", "the shell ran the commands it was given")
        t:assert_neq(r.pid, "1",
            "the shell is a child, not prelude replaced: prelude forked rather than exec'd it")
        -- prelude is /init in the initramfs (a symlink to usr/sbin/prelude),
        -- so PID 1's comm is `init` — what matters is that it is neither
        -- `dash` nor `sh`, which is what it would be had prelude exec'd
        -- the shell over itself.
        t:assert_eq(r.init, "init",
            "PID 1 while the shell was open is still the process the kernel started")
        t:assert(at(log, "prelude: rescue shell exited"), "the shell exited")
        t:assert(at(log, "exec /bin/peinit2"),
            "and the boot resumed where it paused, all the way to the handoff")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "which is the only reason an agent is here to answer")
    end)

test("prelude logs `rescue shell exited` when the shell returns",
    { spec = "prelude shell.exit-is-logged" }, function(t)
        local vm = provium:vm("exitlog", "prelude")
        vm:boot({ kernel_cmdline_append = "rd.break=beta.sh",
                  files = with_rescue_sh(prelude.files({
                      hooks = { alpha = {}, beta = {} },
                      order = { "alpha", "beta" },
                      keep = { "pt-mount-root.sh" },
                  })) })
        local log = vm:console():read_log()

        local shell = at(log, "pt|rescue|")
        local exited = at(log, "prelude: rescue shell exited")
        t:assert(shell and exited and shell < exited,
            "prelude logged `rescue shell exited` after reaping the shell it forked")
        t:assert_eq(count(log, "prelude: rescue shell exited"), 1,
            "once, for the one breakpoint that fired")
        t:assert(exited < at(log, "prelude: hook: " .. HOOKS .. "beta.sh"),
            "and before running the hook it had stopped in front of")
    end)

test("a failure shell still halts the machine when it exits",
    { spec = "prelude shell.failure-shell-still-halts" }, function(t)
        local vm = provium:vm("failhalt", "prelude")
        -- A breakpoint that fires and resumes, then a boot that fails
        -- anyway: two shells, and only the second one ends the machine.
        local err = prelude.boot_halts(t, vm, {
            kernel_cmdline_append = "rd.break pt.mount-root=decline",
            files = with_rescue_sh(prelude.files({ keep = { "pt-mount-root.sh" } })),
        })

        t:assert_eq(count(err, "prelude: rescue shell exited"), 2,
            "two shells were opened and exited: the breakpoint's, then the failure's")
        local failure = err:find("rd.shell: boot failed:", 1, true)
        local halted = err:find("halting system", 1, true)
        t:assert(failure and halted, "the failure shell opened and the machine halted: "
            .. err:sub(-400))
        t:assert(failure < halted,
            "the halt came after the failure shell, not instead of it: exiting a failure "
            .. "shell resumes nothing — prelude halts as it would have anyway")
    end)

test("a rescue shell prelude cannot exec is logged and the boot carries on",
    { spec = "prelude shell.unspawnable-does-not-stop-the-boot" }, function(t)
        local vm = provium:vm("noshell", "prelude")
        -- /usr/bin/sh present but not executable, so the forked child's
        -- execve fails. The sequence is one hook that does not need a
        -- shell to run, so the boot is free to complete without one.
        vm:boot({
            kernel_cmdline_append = "rd.break",
            files = with_rescue_sh(
                prelude.files({ hooks = { ["mount-root"] = { body = MOUNT_ROOT_VIA_DASH } } }),
                "this is not a program\n", MODE_DATA),
        })
        local log = vm:console():read_log()

        t:assert(at(log, "rd.break: stopping before any hooks"),
            "prelude reached the breakpoint")
        t:assert(at(log, "prelude: rescue: exec /usr/bin/sh failed:"),
            "and reported that it could not exec a shell there")
        t:assert(at(log, "prelude: hook: " .. HOOKS .. "mount-root.sh"),
            "the boot carried on into the hooks regardless")
        t:assert_eq(vm:read_file("/proc/1/comm"):gsub("%s+$", ""), "peinit2",
            "and completed the handoff: an unspawnable rescue shell is not a boot failure")
    end)
