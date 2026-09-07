-- Peinit TRM §11.5 — console output.
--
-- The console is the one thing this suite can always read, so almost
-- everything on this page is directly checkable: the tag column is in
-- the bytes, the banner is in the bytes, the colour escapes are in the
-- bytes. What varies between the boots below is what peinit was asked
-- to do — a boot with a service that cannot launch, a boot whose command
-- line says the terminal can render escapes, a boot with autorun scripts
-- written to misbehave.
--
-- One boundary is deliberately not crossed here. The three `peios.quiet`
-- levels are defined in §2.6 and anchored there; this file cites only
-- what §11.5 defines itself — how a line is put together, and which
-- severity peinit gives its own messages.

local peinit = require("helpers.peinit")
peinit.claim(7) -- six boots at file scope, and the banner test adds one

-- One gigabyte rather than the helper's two. Chapter 11 boots more
-- machines than any other chapter here — a claim about output usually
-- needs a whole boot arranged around it — and provium reserves declared
-- memory for the life of a VM, so at the default these files queue
-- against the pool and each other. A booted guest uses about 300 MB
-- between its working set and the squashfs page cache, and the same
-- assertions hold at either size.
--
-- One vCPU for the same reason: provium admits VMs while the total
-- declared vCPU count fits the host's cores, so two apiece halves how
-- many of these boots can be in flight at once. Nothing here is
-- compute-bound.
local MEM, CPUS = "1G", 1

local TAG = "^%[......%] " -- Six characters between the brackets, always.

--- Every console line, CR/LF stripped.
local function lines(vm)
    return peinit.lines(vm:console():read_log())
end

local function find_line(vm, pattern)
    for _, line in ipairs(lines(vm)) do
        if line:find(pattern) then return line end
    end
end

local function wait_for(vm, service, state)
    for _ = 1, 45 do
        if vm:run("svctl status " .. service).stdout:find(service .. ": " .. state, 1, true) then
            return true
        end
        vm:run("sleep 1")
    end
    return false
end

-- A plain boot, run on until the console login prompt has taken the
-- terminal, so the "who else writes here" claim has its second example.
local vm = peinit.boot({ memory = MEM, cpus = CPUS, name = "console" })
wait_for(vm, "login-console", "active")

-- One boot per *variable*, rather than one per assertion. Each of these
-- differs from the plain boot above in exactly one way, and several
-- tests read each: a virtual machine is the expensive part of this
-- suite and a console log answers many questions at once.

--- `peios.quiet=2`: no banner, no progress, no shutdown narration.
local silent = peinit.boot({ memory = MEM, cpus = CPUS, name = "console-silent", stage = false, append = "peios.quiet=2" })
-- The autorun relay bypasses the quiet policy (§2.3), so this line
-- arrives whatever the level, and waiting for it means the assertions
-- below are about a boot that got past Phase 1 rather than one that had
-- not printed yet.
silent:console():expect("ran 2 autorun script", peinit.STAGE_TIMEOUT)

--- A command line that does not call the terminal dumb, so peinit
--- colours its tags. `TERM=vt220` is appended after the profile's own
--- `TERM=dumb`, and the last occurrence is the one peinit reads.
local colour = peinit.boot({ memory = MEM, cpus = CPUS, name = "console-colour", append = "TERM=vt220" })

--- A boot with one service that cannot be exec'd, one the machine's
--- conditions exclude, and one log knob set below its minimum.
local outcomes = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "console-outcomes",
    files = peinit.seed("zz-pt-outcomes", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        { path = [[Machine\System\Init]] },
        {
            path = [[Machine\System\Init]],
            values = { { name = "MaxLogLineLength", type = "dword", data = 1 } },
        },
        {
            -- Nothing at this path, so the exec fails.
            path = [[Machine\System\Services\pt-cannot-launch]],
            values = {
                { name = "ImagePath", type = "sz", data = "/lcl/pt/absent" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
            },
        },
        {
            -- Nothing wrong with it; the machine simply does not meet the
            -- condition it asked for.
            path = [[Machine\System\Services\pt-condition]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
                { name = "Conditions", type = "multi", data = { "path:/pt-not-here" } },
            },
        },
    }),
})

--- A boot downgraded to Safe mode by a dependency cycle involving a
--- Critical service, and told to write unconditionally. The two go
--- together because the shutdown case needs `peios.quiet=0` — by
--- shutdown time login-console owns the console, and at the default
--- level peinit stays out of a terminal a service holds, which would
--- confound severity with ownership.
local downgraded = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "console-downgraded",
    stage = false,
    append = "peios.quiet=0",
    files = peinit.seed("zz-pt-cycle", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        {
            path = [[Machine\System\Services\pt-cycle-a]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "ErrorControl", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
                { name = "Requires", type = "multi", data = { "pt-cycle-b" } },
            },
        },
        {
            path = [[Machine\System\Services\pt-cycle-b]],
            values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "Readiness", type = "dword", data = 1 },
                { name = "ErrorControl", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
                { name = "Requires", type = "multi", data = { "pt-cycle-a" } },
            },
        },
    }),
})
downgraded:console():expect("downgraded to safe mode", peinit.STAGE_TIMEOUT)

--- Four autorun scripts, one per relay rule.
local relay = peinit.boot({
    memory = MEM, cpus = CPUS,
    name = "console-relay",
    files = {
        ["lcl/policy/autorun.d/40-pt-relay.sh"] = {
            "#!/bin/sh\necho pt-relay-good-news\necho pt-relay-bad-news >&2\nexit 1\n",
            exec = true,
        },
        -- An escape sequence that would clear the screen, and a bell.
        ["lcl/policy/autorun.d/41-pt-escape.sh"] = {
            "#!/bin/sh\nprintf 'pt-escape-\\033[2J-\\007-end\\n'\n",
            exec = true,
        },
        ["lcl/policy/autorun.d/42-pt-long.sh"] = {
            "#!/bin/sh\necho pt-long-" .. string.rep("L", 600) .. "\n",
            exec = true,
        },
        ["lcl/policy/autorun.d/43-pt-many.sh"] = {
            "#!/bin/sh\ni=0\nwhile [ $i -lt 250 ]; do echo \"pt-many-$i\"; " ..
            "i=$((i + 1)); done\n",
            exec = true,
        },
    },
})

test("peinit writes its own progress to the console and never a service's output",
    {
        spec = {
            "peinit *console.peinit-writes-its-own-messages-to-the-console",
            "peinit *console.service-output-is-never-echoed",
        },
    },
    function(t)
        local log = vm:console():read_log()

        -- The list §11.5 opens with: Phase 1 progress, Phase 2 progress.
        for _, expected in ipairs({
            "peinit: phase1 mounting virtual filesystems",
            "peinit: phase1 registryd started",
            "peinit: phase2 boot starting",
            "peinit: phase2 boot complete",
            "peinit: service authd started",
        }) do
            t:assert(log:find(expected, 1, true), "the console carries: " .. expected)
        end

        -- And none of what the services themselves wrote. authd is
        -- talkative — it logs every logon it grants — and lpsd and timed
        -- likewise; not a line of any of it is here.
        for _, service in ipairs({ "authd", "lpsd", "timed" }) do
            local out = vm:run(
                "evctl 'LOGS FROM " .. service .. " SINCE 1h ago TAKE 50' --format jsonl").stdout
            for line in out:gmatch("[^\r\n]+") do
                local message = line:match('"message":"([^"]*)"')
                -- Long messages are the interesting ones and the least
                -- likely to collide with peinit's own wording.
                if message and #message > 30 then
                    t:assert(not log:find(message, 1, true),
                        service .. " wrote this to its pipe and it did not reach the console: " ..
                        message:sub(1, 60))
                end
            end
        end
    end)

test("every line peinit writes is a six-wide bracketed tag, then the component, then the message",
    { spec = "peinit *console.a-line-is-a-tag-then-a-component-then-a-message" },
    function(t)
        -- The tag column is the point of the format: an operator scans
        -- down one column rather than reading sentences, which only
        -- works if the column is in the same place on every line.
        local checked = 0
        for _, line in ipairs(lines(vm)) do
            if line:find("peinit:", 1, true) or line:find("peinit warning:", 1, true) then
                t:assert(line:find(TAG),
                    "line is in the format: " .. line)
                -- The component name follows the tag and the colon
                -- follows the component.
                t:assert(line:match("^%[......%] (%S+):"),
                    "and names its component before the message: " .. line)
                checked = checked + 1
            end
        end
        t:assert(checked > 10, "there were lines to check, found " .. checked)
    end)

test("progress with no outcome carries the blank tag and a success carries OK",
    {
        spec = {
            "peinit *console.the-blank-tag-is-progress-with-no-outcome",
            "peinit *console.the-ok-tag-means-it-worked",
        },
    },
    function(t)
        -- The same step, twice: peinit announces the Phase 2 boot with no
        -- outcome yet, then reports the outcome. The tag is the only
        -- difference, and it holds the column in between so the two lines
        -- align.
        t:assert(find_line(vm, "^%[      %] peinit: phase2 boot starting$"),
            "the announcement is untagged")
        t:assert(find_line(vm, "^%[  OK  %] peinit: phase2 boot complete$"),
            "and the outcome is OK")

        -- OK means it worked, so the thing it claims about has to be
        -- true: authd is reported started and authd is running.
        t:assert(find_line(vm, "^%[  OK  %] peinit: service authd started$"),
            "authd was reported started")
        t:assert(vm:run("svctl status authd").stdout:find("authd: active", 1, true),
            "and authd is in fact active")
    end)

test("only the firmware and the service that owns the terminal write outside the format",
    { spec = "peinit *console.only-firmware-and-a-terminal-owner-write-outside-the-format" },
    function(t)
        local all = lines(vm)

        -- Before any kernel runs: the firmware's own messages, which
        -- nothing in Peios can reach.
        local seabios
        for index, line in ipairs(all) do
            if line:find("SeaBIOS", 1, true) then seabios = index end
        end
        t:assert(seabios, "the firmware announced itself")
        t:assert(not all[seabios]:find(TAG), "and did so outside the format")

        -- After that, everything on the console is in the format except
        -- the banner — which is its own punctuation — and whatever the
        -- terminal's owner writes to it directly. login-console holds
        -- /dev/console and its prompt is not peinit's to format.
        local start
        for index, line in ipairs(all) do
            if line:find("peinit: phase1 starting", 1, true) then start = index end
        end
        t:assert(start, "peinit took over")

        local stray = {}
        for index = start, #all do
            local line = all[index]
            local is_banner = line:find("═", 1, true) or line:find("peinit · real root", 1, true)
            if line ~= "" and not is_banner and not line:find(TAG) then
                stray[#stray + 1] = line
            end
        end
        for _, line in ipairs(stray) do
            t:assert(line:find("^login:") or line:find("^Username:") or line:find("^%$"),
                "the only unformatted line after the handoff is the terminal owner's: " .. line)
        end
        t:assert(#stray > 0,
            "login-console did write to the console it holds, so the case is real")
    end)

test("registryd's Phase 1 output is queryable from eventd and is not on the console",
    { spec = "peinit *console.on-a-normal-boot-registryds-output-goes-to-eventd-alone" },
    function(t)
        -- The failure path relays registryd's pipes to the console. On a
        -- normal boot the descriptors are kept for the runtime instead,
        -- and its startup lines go the ordinary way.
        local messages = {}
        for _ = 1, 45 do
            local out = vm:run(
                "evctl 'LOGS FROM registryd SINCE 1h ago TAKE 100' --format jsonl").stdout
            for line in out:gmatch("[^\r\n]+") do
                local message = line:match('"message":"([^"]*)"')
                if message then messages[#messages + 1] = message end
            end
            if #messages > 0 then break end
            vm:run("sleep 1")
        end
        t:assert(#messages > 0, "registryd's startup output is in the log store")

        local log = vm:console():read_log()
        for _, message in ipairs(messages) do
            t:assert(not log:find(message, 1, true),
                "and none of it was relayed to the console: " .. message)
        end
        t:assert(not log:find("registryd(stderr)", 1, true),
            "the failure-path relay did not run on a boot where registryd was fine")
    end)

test("the banner is the first thing peinit prints, and it names the mode the boot starts in",
    {
        spec = {
            "peinit *console.a-banner-precedes-phase-1",
            "peinit *console.the-banner-names-the-mode-the-boot-starts-in",
            "peinit *console.the-command-line-is-read-before-any-phase-1-work",
        },
    },
    function(t)
        local log = vm:console():read_log()
        local banner = log:find("peinit · real root · PID 1 · Full boot", 1, true)
        t:assert(banner, "the banner names the stage and the mode: Full boot")
        t:assert(banner < log:find("peinit: phase1 mounting virtual filesystems", 1, true),
            "and precedes the first thing Phase 1 does")

        -- Naming the mode is why the command line is read at the very
        -- top: a boot told to be Safe says so in the banner, which is
        -- printed before any Phase 1 step has run.
        local safe = peinit.boot({ memory = MEM, cpus = CPUS, name = "console-safe", append = "peios.safemode=1" })
        local safe_log = safe:console():read_log()
        local safe_banner = safe_log:find("peinit · real root · PID 1 · Safe mode", 1, true)
        t:assert(safe_banner, "a Safe boot's banner says Safe mode")
        t:assert(safe_banner < safe_log:find("peinit: phase1 mounting", 1, true),
            "and it too comes before Phase 1 does any work, so the command line was read first")
    end)

test("a downgrade to Safe mode part-way through is announced without a second banner",
    { spec = "peinit *console.a-later-downgrade-does-not-reprint-the-banner" },
    function(t)
        -- A dependency cycle involving a Critical service downgrades the
        -- boot in place. The banner has already been printed, saying
        -- Full boot, and a second one would read as a second stage.
        local log = downgraded:console():read_log()

        t:assert(log:find("peinit: boot downgraded to safe mode", 1, true),
            "the downgrade was announced by its own message")

        local banners = 0
        for _ in log:gmatch("peinit · real root · PID 1") do banners = banners + 1 end
        t:assert_eq(banners, 1, "and exactly one banner was printed")
        t:assert(log:find("PID 1 · Full boot", 1, true),
            "still naming the mode the boot started in")
    end)

test("a boot told to be silent drops the banner along with the rest of the progress",
    { spec = "peinit *console.the-banner-carries-status-severity" },
    function(t)
        -- The banner is punctuation, not news: it carries ordinary status
        -- severity, so the level that drops progress drops it too.
        t:assert(not silent:console():read_log():find("peinit · real root", 1, true),
            "no banner was printed at peios.quiet=2")
        -- The comparison boot did print one, on the same image.
        t:assert(vm:console():read_log():find("peinit · real root", 1, true),
            "while the default boot did")
    end)

test("shutdown progress is ordinary status, so a silent boot omits it and a loud one keeps it",
    { spec = "peinit *console.shutdown-progress-carries-status-severity" },
    function(t)
        -- Two boots differing only in `peios.quiet`: `0` on one and `2` on
        -- the other. Neither is the default `1`, because by shutdown time
        -- login-console owns the console and at `1` peinit stays out of a
        -- terminal a service holds — which would confound severity with
        -- ownership.
        downgraded:run("svctl shutdown poweroff")
        downgraded:console():expect("peinit: shutdown", 60)
        t:assert(downgraded:console():read_log():find("peinit: shutdown Poweroff started", 1, true),
            "the loud boot narrated its shutdown")

        silent:run("svctl shutdown poweroff")
        -- Wait for the kernel's own last word, which `peios.quiet` does
        -- not govern, so this is not a race against output that was never
        -- going to arrive.
        pcall(function() silent:console():expect("reboot: Power down", 60) end)
        t:assert(not silent:console():read_log():find("peinit: shutdown", 1, true),
            "and the silent one wrote no shutdown progress at all")
    end)

test("a service that cannot launch is FAILED and one its conditions exclude is SKIP",
    {
        spec = {
            "peinit *console.the-failed-tag-means-it-did-not-work",
            "peinit *console.the-skip-tag-means-deliberately-not-done",
        },
    },
    function(t)
        local log = outcomes:console():read_log()

        -- FAILED: it did not work.
        t:assert(log:find("\n%[FAILED%] peinit: service pt%-cannot%-launch failed to launch"),
            "the service that could not be exec'd is FAILED")

        -- SKIP: deliberately not done. Nothing is broken — the condition
        -- was simply not met — and the tag says so rather than crying
        -- failure.
        t:assert(log:find("\n%[ SKIP %] peinit: service pt%-condition skipped: ConditionSkipped"),
            "and the service excluded by its own condition is SKIP")
    end)

test("a producer that outruns the relay cap is warned about, which is what WARN is for",
    { spec = "peinit *console.the-warn-tag-means-the-boot-continues" },
    function(t)
        -- Relaying is capped at 200 lines per producer; past that the
        -- remainder is counted and reported. Something is wrong — output
        -- an operator asked for is not being shown — and the boot carries
        -- on regardless, which is exactly what the WARN tag means.
        t:assert(relay:console():read_log():find(
            "\n%[ WARN %] 43%-pt%-many%.sh: %d+ further line%(s%) not shown"),
            "the cap was reported with the WARN tag")
    end)

test("a configuration warning is tagged WARN rather than FAILED",
    {
        spec = "peinit *console.the-warn-tag-means-the-boot-continues",
        tags = { "known-bug" },
    },
    function(t)
        -- A log knob below its minimum is refused, the default is used
        -- and the boot continues (§11.3) — "wrong, but the boot
        -- continues", which is the WARN row of §11.5's table, and the
        -- shape of §11.5's own worked example (`[ WARN ] peinit warning:
        -- calendar timer not armed: Malformed`).
        --
        -- peinit renders it `[FAILED]`. The Phase 2 progress logger sends
        -- every configuration warning through the error path, so a line
        -- whose own text says "warning" arrives in the column an operator
        -- scans for things that did not work.
        local log = outcomes:console():read_log()
        t:assert(log:find("peinit warning: Machine\\System\\Init\\MaxLogLineLength", 1, true),
            "the warning was written")
        t:assert(log:find("\n%[ WARN %] peinit warning: Machine\\System\\Init\\MaxLogLineLength"),
            "and carries the WARN tag rather than FAILED: " ..
            tostring(find_line(outcomes, "peinit warning: Machine")))
    end)

test("tags are coloured when the command line does not say the terminal is dumb",
    {
        spec = {
            "peinit *console.tags-are-coloured-with-sgr-escapes",
            "peinit *console.colour-is-on-unless-the-command-line-says-term-dumb",
        },
    },
    function(t)
        -- The suite's profile appends `TERM=dumb` for exactly this
        -- reason, so the default boot is the uncoloured half of the pair
        -- and the appended `TERM=vt220` — later on the command line, so
        -- it is the one peinit reads — is the coloured half.
        --
        -- Scoped to peinit's own lines: the firmware writes escapes
        -- before any kernel runs, and prelude's first line is coloured
        -- because prelude has not read the command line yet either —
        -- which is the same rule seen from the other side.
        for _, line in ipairs(lines(vm)) do
            if line:find("peinit:", 1, true) then
                t:assert(not line:find("\27", 1, true),
                    "peinit wrote no escape sequence under TERM=dumb: " .. line)
            end
        end

        local log = colour:console():read_log()

        -- Green for OK, red for FAILED, and the tag alone is wrapped:
        -- the escapes sit inside the brackets, around the word.
        t:assert(log:find("[  \27[1;32mOK\27[0m  ] peinit: phase2 boot complete", 1, true),
            "OK is bold green")
        -- Untagged progress is never coloured, whatever the terminal.
        t:assert(log:find("[      ] peinit: phase2 boot starting", 1, true),
            "and progress with no outcome carries no colour at all")
    end)

test("colour changes the bytes of a line and never its layout",
    { spec = "peinit *console.colour-never-changes-the-layout" },
    function(t)
        -- A serial log and a virtual terminal have to agree about where
        -- the message starts, so that a reader — or a script — can cut
        -- the column off either.
        local coloured = colour:console():read_log()
        t:assert(coloured:find("\27[", 1, true), "this boot did colour its output")

        -- Strip every SGR sequence and the line has to be identical to
        -- the one the uncoloured boot wrote.
        local stripped = coloured:gsub("\27%[[%d;]*m", "")
        for _, line in ipairs({
            "[      ] peinit: phase2 boot starting",
            "[  OK  ] peinit: phase2 boot complete",
            "[  OK  ] peinit: service authd started",
        }) do
            t:assert(stripped:find(line, 1, true),
                "with the escapes removed the coloured boot wrote: " .. line)
            t:assert(vm:console():read_log():find(line, 1, true),
                "and the uncoloured boot wrote the same bytes: " .. line)
        end
    end)

test("autorun output is captured and relayed under the script's own name, always untagged",
    {
        spec = {
            "peinit *console.autorun-output-is-relayed-under-the-scripts-file-name",
            "peinit *console.a-relayed-line-carries-the-blank-tag",
        },
    },
    function(t)
        -- Not left to inherit peinit's streams: peinit captures the
        -- script's output and re-emits it in its own format, under the
        -- file name, so an operator can tell which script said what.
        local log = relay:console():read_log()

        t:assert(log:find("\n%[      %] 40%-pt%-relay%.sh: pt%-relay%-good%-news"),
            "the line is relayed under the script's file name, untagged")
        -- Both streams, and the blank tag on both: peinit has no way to
        -- know which of somebody else's lines is good news, and guessing
        -- from prose is how a rename silently turns an error green.
        t:assert(log:find("\n%[      %] 40%-pt%-relay%.sh: pt%-relay%-bad%-news"),
            "including what the script wrote to stderr, with the same blank tag")

        -- The producer's own outcome is reported separately, from its
        -- exit code, which peinit does know.
        t:assert(log:find("40-pt-relay.sh", 1, true), "and the script is named in the report")
    end)

test("a relayed line is sanitised, cut at 512 characters, and capped at 200 lines per producer",
    {
        spec = {
            "peinit *console.a-control-character-in-a-relayed-line-becomes-a-question-mark",
            "peinit *console.a-relayed-line-is-cut-at-512-characters",
            "peinit *console.a-producer-is-capped-at-200-relayed-lines",
        },
    },
    function(t)
        -- One script per rule, so a failure names which rule broke rather
        -- than which script did.
        local all = lines(relay)

        -- Control characters become `?`, which keeps the line's shape
        -- and length while making it inert. A script sharing the console
        -- could otherwise steer it.
        local escaped
        for _, line in ipairs(all) do
            if line:find("pt-escape-", 1, true) then escaped = line end
        end
        t:assert(escaped, "the escaping script's line was relayed")
        t:assert(not escaped:find("\27", 1, true), "with no escape character left in it")
        t:assert(escaped:find("pt-escape-?[2J-?-end", 1, true),
            "each control character replaced by a question mark: " .. escaped)

        -- Cut at 512 characters. The tag column and the component name
        -- are peinit's own, so the 512 applies to the script's line.
        local cut
        for _, line in ipairs(all) do
            if line:find("pt-long-L", 1, true) then cut = line end
        end
        t:assert(cut, "the long line was relayed")
        local relayed = cut:match("^%[......%] 42%-pt%-long%.sh: (.*)$")
        t:assert(relayed, "and is attributed to its script: " .. cut:sub(1, 60))
        local kept = relayed:match("^(pt%-long%-L*)")
        t:assert_eq(#kept, 512,
            "512 characters of it were kept, got " .. #kept)
        t:assert(#relayed > #kept, "with a mark to say it was cut: " .. relayed:sub(-8))

        -- Capped at 200 lines, with the remainder counted rather than
        -- printed.
        local shown = 0
        for _, line in ipairs(all) do
            if line:find("43-pt-many.sh: pt-many-", 1, true) then shown = shown + 1 end
        end
        t:assert_eq(shown, 200, "exactly 200 of the 250 lines were shown")
        t:assert(relay:console():read_log():find("43-pt-many.sh: 50 further line(s) not shown", 1, true),
            "and the other 50 were counted")
    end)
