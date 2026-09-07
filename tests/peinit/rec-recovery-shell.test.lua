-- Peinit TRM §2.8 — the shell itself: that recovery keeps one running,
-- that it delivers one even when registryd is what went wrong, and what
-- happens when there is no shell to deliver.
--
-- One boot per case, because each case is a different thing broken before
-- peinit starts, and each is a boot that never reaches an agent — so the
-- console tail out of `peinit.boot_to_recovery` is the only record. No
-- file-scope VM: three recovery boots in sequence, one alive at a time.
--
-- Two of the three break something through the StrataFS views. /bin is
-- `/lcl/bin+create:/usr/bin+ro+am` and /sbin the same over /usr/sbin, so a
-- file staged into /lcl/bin or /lcl/sbin shadows the image's own — which is
-- how a test gets an unexecutable /bin/sh, or a registryd that cannot be
-- launched, without touching the image everything else boots from. Staged
-- without `exec`, since under KACS the execute bit is the intrinsic "this
-- is executable" flag and its absence is exactly the failure wanted.

local peinit = require("helpers.peinit")
peinit.claim(1)

local function occurrences(haystack, needle)
    local count, at = 0, 1
    while true do
        local found = haystack:find(needle, at, true)
        if not found then return count end
        count = count + 1
        at = found + 1
    end
end

test("recovery respawns the shell when it exits",
    { spec = "peinit *recovery.the-shell-is-respawned" },
    function(t)
        -- Recovery never exits to an unmanaged PID 1, so a shell that ends
        -- — an operator typing `exit`, a script that returns — has to be
        -- replaced rather than leaving the machine with nothing on the
        -- console. This shell exits deliberately, once a second, and the
        -- count of its greetings is the count of sessions peinit started.
        local console = peinit.boot_to_recovery(t, {
            name = "recovery-respawn",
            agent_timeout = 20,
            append = "peios.recovery=1",
            files = {
                ["lcl/bin/recsh"] = {
                    "#!/bin/sh\necho pt-rec-session\nsleep 1\n",
                    exec = true,
                },
            },
        })
        local sessions = occurrences(console, "pt-rec-session")
        t:assert(sessions >= 3,
            "the shell was started again each time it exited, and ran " ..
            sessions .. " times: " .. console:sub(-400))
    end)

test("a registryd that will not start still gets the administrator a shell",
    {
        spec = {
            "peinit *recovery.a-registryd-failure-does-not-prevent-the-shell",
            "peinit *recovery.recovery-starts-at-most-one-registryd",
        },
    },
    function(t)
        -- registryd failing is the entry §2.8 calls the most important one,
        -- and it is the entry where a shell matters most: the offline
        -- registry tools are the reason the operator is here. Recovery
        -- ignores the failure and delivers the shell anyway.
        --
        -- It also starts no second registryd. Phase 1 has already made the
        -- attempt, and a process may have forked before the failure was
        -- reported — so a second daemon would bind over the first's notify
        -- socket, which succeeds rather than reporting EADDRINUSE because
        -- the bind unlinks the path first, and would open the same hive
        -- files behind its back.
        local reporter = table.concat({
            "#!/bin/sh",
            "regs=0",
            "for d in /proc/[0-9]*; do",
            "  [ \"$(cat $d/comm 2>/dev/null)\" = registryd ] && regs=$((regs+1))",
            "done",
            "echo pt-rec: begin",
            "echo pt-rec: registryd=$regs",
            "echo pt-rec: end",
            "sleep 3600",
            "",
        }, "\n")
        local console = peinit.boot_to_recovery(t, {
            name = "recovery-no-registryd",
            agent_timeout = 25,
            files = peinit.merge(
                { ["lcl/bin/recsh"] = { reporter, exec = true } },
                -- Shadows /usr/sbin/registryd in the /sbin view, and is not
                -- executable, so the launch fails before exec rather than
                -- after a readiness timeout.
                { ["lcl/sbin/registryd"] = "not a program\n" }
            ),
        })
        t:assert(console:find("peinit: entering recovery: Registryd", 1, true),
            "registryd is what sent this boot to recovery: " .. console:sub(-600))
        t:assert(console:find("pt-rec: begin", 1, true),
            "and the shell was delivered anyway")
        t:assert_eq(console:match("pt%-rec: registryd=(%d+)"), "0",
            "recovery made no second attempt of its own")
    end)

test("with neither shell executable peinit halts rather than exiting",
    { spec = "peinit *recovery.no-shell-at-all-syncs-and-halts" },
    function(t)
        -- PID 1 returning would panic the kernel, so the last thing peinit
        -- does is say why, flush, and stop the machine. The sync leaves no
        -- console trace of its own — it is a syscall between the message
        -- and the halt — so what is asserted here is the message and the
        -- stop.
        --
        -- No /bin/recsh is staged and /bin/sh is shadowed by a file with no
        -- execute bit, which is the state a binary-integrity failure leaves
        -- behind. Recovery is forced from the command line so that this
        -- boot never reaches the autorun scripts, which are `#!/bin/sh` and
        -- would otherwise fail for the same reason and confuse the console.
        --
        -- peinit reaches the halt through the exec rather than through the
        -- probe: opening a 0644 file for EXECUTE succeeds on this image, so
        -- `can_execute` reports /bin/sh usable, peinit selects it, and the
        -- missing execute bit surfaces as EACCES from execve. Both routes
        -- end in the same three actions, which are what §2.8 states and
        -- what is asserted here — the reason on the console, and a stopped
        -- machine. The sync between them is a syscall and leaves no trace.
        local console = peinit.boot_to_recovery(t, {
            name = "recovery-no-shell",
            agent_timeout = 20,
            append = "peios.recovery=1",
            files = { ["lcl/bin/sh"] = "not a program\n" },
        })
        t:assert(console:find("failed to start recovery shell", 1, true),
            "peinit said it could not deliver a shell: " .. console:sub(-600))
        t:assert(console:find("/bin/sh failed at exec", 1, true),
            "and said which shell and at which step: " .. console:sub(-600))
        t:assert(console:find("System halted", 1, true),
            "and halted the machine: " .. console:sub(-600))
    end)
