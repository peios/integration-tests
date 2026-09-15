-- Peinit TRM §10.2 — the rights table: which right each control command
-- asks for, what the dispatch sequence does with the answer, and what is
-- filtered rather than denied.
--
-- This file replaces a premise, so it is worth stating what the premise
-- was. `control-dispatch.test.lua` used to say the rights table needed
-- "a suite that can log a second principal on", because this profile has
-- one principal — SYSTEM — with every right on everything. That is not
-- what a denial needs. The agent runs on peinit's own token, and a
-- `ServiceSecurity` descriptor naming SYSTEM with a narrow mask is a
-- descriptor about *this* caller: peinit's AccessCheck refuses SYSTEM as
-- readily as it refuses anyone when the descriptor says so. One booted
-- machine can be walked through every row by writing a value and issuing
-- the command the row names.
--
-- §4.6 and §4.7 state these rights from the descriptor's side and are
-- tested in `identity-service-descriptors.test.lua` and
-- `identity-control-descriptor.test.lua`. This file is chapter 10's
-- view: the table as a table, including the four rows §4.6 has no
-- equivalent of — `operation-status`, whose right is checked against the
-- *target service*, and the three job commands, whose descriptor is the
-- job's own and whose mapping is the job mapping (§8.5).
--
-- The two rows this file does not carry are `shutdown` and
-- `reload-config`. Proving those means proving a shutdown is refused
-- without ever proving one is permitted, since permitting it stops the
-- machine underneath the test; `identity-control-descriptor.test.lua`
-- implements that trick and carries both anchors.

local peinit = require("helpers.peinit")
-- Two: the main machine, and one more for the shutdown-gate race, which
-- ends in a poweroff and so cannot be run on the machine every other
-- test in the file is using.
peinit.claim(2)

local TARGET = [[Machine\System\Services\pt-rights]]
local SERVICES = [[Machine\System\Services]]

--- A demand-triggered Oneshot: a command against it can be issued at any
--- moment without waiting for or disturbing a resident process, and
--- `start` is a real operation rather than a no-op.
local function oneshot(name)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
        },
    }
end

local vm = peinit.boot({
    name = "rights",
    files = peinit.seed("pt-rights", {
        { path = [[Machine\System]] },
        { path = SERVICES },
        oneshot("pt-rights"),
        -- A second definition with no descriptor of its own, so the
        -- filtering tests have something that stays visible while
        -- pt-rights is hidden, and something to hide when the Services
        -- key itself is narrowed.
        oneshot("pt-rights-sibling"),
    }),
})

local verdict = peinit.verdict

local function run(command, service)
    return verdict(vm:run("svctl " .. command .. " " .. (service or "pt-rights")))
end

-- A descriptor change takes effect on the next control request, but the
-- registry notification that carries it to peinit is asynchronous. Poll
-- until the answer has moved rather than sleeping a fixed time.
local function set_descriptor(key, mask, expect_status)
    vm:run("reg set '" .. key .. "' ServiceSecurity hex:"
        .. peinit.system_descriptor_hex(mask)):assert_ok()
    for _ = 1, 40 do
        if run("status") == expect_status then return end
        vm:run("sleep 1")
    end
    error(string.format("the reload of %s never landed for mask %#x", key, mask))
end

--- Back to the built-in default: neither the definition nor the Services
--- key carries a value, which is the state a stock boot is in. Every
--- test that writes one ends by calling this, because they share a
--- machine.
local function clear_descriptors()
    vm:run("reg del '" .. TARGET .. "' ServiceSecurity")
    vm:run("reg del '" .. SERVICES .. "' ServiceSecurity")
    for _ = 1, 40 do
        if run("status") == "allowed" and run("stop") == "allowed" then return end
        vm:run("sleep 1")
    end
    error("the descriptors were not cleared")
end

test("every service row of the rights table asks for the right it names",
    {
        spec = {
            "peinit *dispatch.right-start",
            "peinit *dispatch.right-stop",
            "peinit *dispatch.right-restart",
            "peinit *dispatch.right-reload",
            "peinit *dispatch.right-reset",
            "peinit *dispatch.right-status",
        },
    },
    function(t)
        -- Each descriptor grants one right and the six commands are all
        -- issued against it, so every row is asserted twice over: the
        -- command the row names is permitted, and the five that name a
        -- different right are refused. A command that asked for the
        -- wrong right, or for none, fails one half or the other.
        local rows = {
            { mask = 0x0001, right = "SERVICE_QUERY_STATUS",
              allows = { status = true } },
            { mask = 0x0002, right = "SERVICE_START",
              allows = { start = true } },
            { mask = 0x0004, right = "SERVICE_STOP",
              -- `reset` clears a terminal state, which is the tail of
              -- stopping something rather than the head of starting it.
              allows = { stop = true, reset = true } },
            { mask = 0x0008, right = "SERVICE_INTERROGATE",
              allows = { reload = true } },
            -- `restart` has no right of its own: it is checked against
            -- the rights the work it does would need, requested as one
            -- mask, so neither half alone authorises it.
            { mask = 0x0006, right = "SERVICE_START|SERVICE_STOP",
              allows = { start = true, stop = true, reset = true, restart = true } },
        }

        for _, row in ipairs(rows) do
            set_descriptor(TARGET, row.mask, row.allows.status and "allowed" or "denied")
            for _, command in ipairs({ "status", "start", "stop", "reload", "reset", "restart" }) do
                t:assert_eq(run(command), row.allows[command] and "allowed" or "denied",
                    row.right .. (row.allows[command] and " grants " or " does not grant ")
                    .. command)
            end
        end

        clear_descriptors()
    end)

--- Deny SYSTEM query on the Services key, so every registry-defined
--- service without a descriptor of its own drops out of `list`, and wait
--- for peinit to have taken it.
local function narrow_services_key(t)
    vm:run("reg set '" .. SERVICES .. "' ServiceSecurity hex:"
        .. peinit.system_descriptor_hex(0x000E)):assert_ok()
    local landed = false
    for _ = 1, 40 do
        if run("status") == "denied" then landed = true break end
        vm:run("sleep 1")
    end
    t:assert(landed, "a descriptor granting everything but query is in force")
end

--- The services a `svctl --json list` answer names.
local function listed(stdout)
    local named = {}
    for service in stdout:gmatch('"service":"([^"]+)"') do
        named[#named + 1] = service
    end
    return named
end

test("list is filtered per service, and an omission is not a denial",
    { spec = "peinit *dispatch.right-list" },
    function(t)
        narrow_services_key(t)

        local listing = vm:run("svctl --json list")
        -- A successful response, not a refusal: reporting the denials
        -- would answer the question the filtering exists to avoid
        -- answering.
        listing:assert_ok()
        t:assert(not listing.stdout:find("ACCESS_DENIED", 1, true),
            "nothing was answered as a denial: " .. listing.stdout)
        t:assert(not listing.stdout:find('"service":"pt%-rights"'),
            "a service the caller may not query is omitted: " .. listing.stdout)
        t:assert(not listing.stdout:find('"service":"pt%-rights%-sibling"'),
            "and so is its sibling: " .. listing.stdout)

        -- Per service, not all-or-nothing: one definition gets its query
        -- right back and appears, while the sibling beside it, still
        -- under the narrowed key, stays out.
        vm:run("reg set '" .. TARGET .. "' ServiceSecurity hex:"
            .. peinit.system_descriptor_hex(0x0001)):assert_ok()
        local one
        for _ = 1, 40 do
            local again = vm:run("svctl --json list")
            if again:ok() and again.stdout:find('"service":"pt%-rights"') then
                one = again.stdout
                break
            end
            vm:run("sleep 1")
        end
        t:assert(one, "the service the caller may query is listed again")
        t:assert(not one:find('"service":"pt%-rights%-sibling"'),
            "and the one it may not is still omitted: " .. one)

        clear_descriptors()
    end)

test("a caller who may query nothing gets an empty list and a success",
    {
        spec = "peinit *dispatch.list-filters-rather-than-denies",
        -- PEI-1072: the Services-key descriptor never reaches registryd.
        -- `apply_inherited_service_security` (src/registry/service.rs:52)
        -- gives it only to definitions read from the registry, and
        -- registryd is `ServiceDefinition::compiled_in_registryd()` with
        -- `ServiceSecurityDescriptor::Default` — the built-in grant, which
        -- names SYSTEM and Administrators, the only two principals the
        -- control socket admits. So as the code stands, no caller that can
        -- reach peinit can have "no query rights anywhere", and this list
        -- always names registryd. Whether §4.6 or the code gives way is
        -- the ruling PEI-1072 asks for; either answer changes this test.
        -- PEI-1072: fixed in peinit 47d58c4, "fix(boot):
        -- registryd inherits the Services-key ServiceSecurity
        -- like any other service without its own" (ruling:
        -- option 1). Green since 0.0.5-8, once a reload during
        -- the boot window stopped freezing a launched service
        -- (b9b5028).
    },
    function(t)
        -- The narrowed descriptor goes on the Services key rather than on
        -- one definition, so that by §4.6 it covers every service on the
        -- machine without a descriptor of its own — which, on a stock
        -- image, is all of them. That is the claim's own case.
        narrow_services_key(t)

        local listing = vm:run("svctl --json list")
        listing:assert_ok()
        t:assert(not listing.stdout:find("ACCESS_DENIED", 1, true),
            "the caller was answered, not refused: " .. listing.stdout)
        local named = listed(listing.stdout)
        clear_descriptors()
        t:assert_eq(#named, 0,
            "and the list is empty rather than short: " .. table.concat(named, " "))
    end)

test("operation-status is checked against the right on the service the operation is about",
    { spec = "peinit *dispatch.right-operation-status" },
    function(t)
        -- The operation has no descriptor of its own. What the table
        -- says is checked is SERVICE_QUERY_STATUS on the *target
        -- service*, so the same identifier is answered or refused
        -- according to a value written against the service.
        set_descriptor(TARGET, 0x0003, "allowed")
        local started = vm:run("svctl --json start pt-rights")
        local id = started.stdout:match('"operation_id":"([^"]+)"')
        t:assert(id, "the start was accepted and named its operation: " .. started.stdout)

        -- START without QUERY_STATUS: the caller could create this
        -- operation and cannot read it back.
        set_descriptor(TARGET, 0x0002, "denied")
        local refused = vm:run("svctl --json operation-status " .. id)
        t:assert_eq(refused.stdout:match('"code":"([^"]+)"'), "ACCESS_DENIED",
            "operation-status is refused without SERVICE_QUERY_STATUS: " .. refused.stdout)

        -- And the reverse: query alone, which cannot start anything, is
        -- the whole of what reading the operation needs. Well inside the
        -- 60-second retention of a terminal operation.
        set_descriptor(TARGET, 0x0001, "allowed")
        local answered = vm:run("svctl --json operation-status " .. id)
        answered:assert_ok()
        t:assert(not answered.stdout:find("ACCESS_DENIED", 1, true),
            "and answered with it: " .. answered.stdout)
        -- The start's reply calls it `operation_id`; the operation view
        -- nests it as `"operation":{"id":…}`.
        t:assert(answered.stdout:find('"id":"' .. id .. '"', 1, true),
            "for the operation that was asked about: " .. answered.stdout)

        clear_descriptors()
    end)

--- Submit a job whose descriptor grants SYSTEM exactly `mask`, and
--- return its identifier.
---
--- `security_descriptor` is taken as given, with no default entries
--- added (§8.5), so this is the whole of what the console may do to the
--- job it just created. The owner and group are SYSTEM so the descriptor
--- is well-formed; neither conveys access.
local function submit_granting(t, mask)
    local sddl = string.format("O:SYG:SYD:(A;;0x%08x;;;SY)", mask)
    local r = vm:run("svctl --json job submit --security-descriptor '" .. sddl
        .. "' /bin/sleep 120", { timeout = 120 })
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    t:assert(id, "the submission was accepted: " .. r.stdout)
    return id
end

local function job_verdict(result)
    if result.stdout:match('"code":"([^"]+)"') == "ACCESS_DENIED" then
        return "denied"
    end
    -- An answer from peinit, as in `verdict` above: a `--json` reply always
    -- carries a status, and an empty stdout is svctl failing to ask.
    assert(result.stdout:find('"status":', 1, true),
        "svctl got no answer from peinit (exit " .. tostring(result.exit_code) .. "): "
        .. result.stdout .. result.stderr)
    return "allowed"
end

test("the job commands are checked against the job's own descriptor, with the job mapping",
    {
        spec = {
            "peinit *dispatch.right-job-status",
            "peinit *dispatch.right-job-stop",
            "peinit *dispatch.the-access-check-inputs",
        },
    },
    function(t)
        -- The bits are the job's, not a service's: JOB_QUERY is 0x1 and
        -- JOB_STOP is 0x2, where SERVICE_STOP is 0x4. A descriptor
        -- granting 0x1 would grant a *service* nothing but query, and it
        -- grants this job nothing but query too — so the mapping peinit
        -- passed the check was the job one.
        local queryable = submit_granting(t, 0x0001)
        t:assert_eq(job_verdict(vm:run("svctl --json job status " .. queryable)), "allowed",
            "JOB_QUERY grants job-status")
        t:assert_eq(job_verdict(vm:run("svctl --json job stop " .. queryable, { timeout = 60 })),
            "denied", "and does not grant job-stop")

        local stoppable = submit_granting(t, 0x0002)
        t:assert_eq(job_verdict(vm:run("svctl --json job status " .. stoppable)), "denied",
            "JOB_STOP does not grant job-status")
        t:assert_eq(job_verdict(vm:run("svctl --json job stop " .. stoppable, { timeout = 60 })),
            "allowed", "and does grant job-stop")

        -- The check's other input is the caller's token, and it is the
        -- one captured at accept rather than anything the request says.
        -- A job whose descriptor names nobody this caller is refuses
        -- both commands, on a machine where the caller is SYSTEM and the
        -- descriptor's owner is a group SYSTEM is not in.
        local r = vm:run("svctl --json job submit --security-descriptor "
            .. "'O:S-1-5-32-546G:S-1-5-32-546D:(A;;GA;;;S-1-5-32-546)' /bin/sleep 120",
            { timeout = 120 })
        local stranger = r.stdout:match('"id":"([^"]+)"')
        t:assert(stranger, "the submission was accepted: " .. r.stdout)
        t:assert_eq(job_verdict(vm:run("svctl --json job status " .. stranger)), "denied",
            "a descriptor naming nobody the caller is refuses a query")

        -- Tidy up the two the console can still reach. The third is
        -- unstoppable by design and ends with its own 120-second sleep.
        vm:run("svctl --json job stop " .. queryable, { timeout = 60 })
    end)

test("job-list is filtered per job by JOB_QUERY, independently of what else the job grants",
    { spec = "peinit *dispatch.right-job-list" },
    function(t)
        -- A job granting JOB_STOP and not JOB_QUERY is the case that
        -- separates the two rows: the caller can stop it, so it is not
        -- that the descriptor refuses everything, and it is still absent
        -- from the listing, because listing is the query right.
        local visible = submit_granting(t, 0x0001)
        local hidden = submit_granting(t, 0x0002)

        local listing = vm:run("svctl --json job list")
        listing:assert_ok()
        t:assert(listing.stdout:find(visible, 1, true),
            "the job the caller may query is listed: " .. listing.stdout)
        t:assert(not listing.stdout:find(hidden, 1, true),
            "the job it may not is omitted: " .. listing.stdout)
        t:assert(not listing.stdout:find("ACCESS_DENIED", 1, true),
            "and the omission is not reported as a denial: " .. listing.stdout)

        t:assert_eq(job_verdict(vm:run("svctl --json job stop " .. hidden, { timeout = 60 })),
            "allowed", "while the omitted job is one this caller may stop")
        vm:run("svctl --json job stop " .. visible, { timeout = 60 })
    end)

--- Every event of the named kinds currently in the ring, newest last.
local function events(kind)
    local r = vm:run("revstrm --snapshot --pretty --type '" .. kind .. "'", { timeout = 60 })
    r:assert_ok()
    local out, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        local name = line:match("^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
        if name then
            current = { type = name, payload = "" }
            out[#out + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    return out
end

local function field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

test("a denial is answered and audited, by the kind of thing that was refused",
    { spec = "peinit *dispatch.a-denial-is-answered-and-audited" },
    function(t)
        -- Silent denial is not acceptable, so each refusal leaves a
        -- record carrying who asked, what they asked about, the right by
        -- name, and both masks. The event kind follows the target: a
        -- service denial is `access.denied`, a job denial is
        -- `job.access_denied`.
        set_descriptor(TARGET, 0x0001, "allowed")
        t:assert_eq(run("start"), "denied", "the service command was refused")

        local service_denial
        for _ = 1, 20 do
            for _, event in ipairs(events("access.denied")) do
                if field(event, "target") == "pt-rights"
                    and field(event, "requested_right") == "SERVICE_START" then
                    service_denial = event
                end
            end
            if service_denial then break end
            vm:run("sleep 1")
        end
        t:assert(service_denial, "and recorded as access.denied, named by the right it asked for")
        t:assert_eq(field(service_denial, "caller_sid"), "S-1-5-18",
            "naming the caller: " .. service_denial.payload)
        t:assert_eq(field(service_denial, "target_type"), "service",
            "and the kind of target: " .. service_denial.payload)
        t:assert_eq(field(service_denial, "requested_access_bits"), "2",
            "with the bits requested: " .. service_denial.payload)
        t:assert(field(service_denial, "granted_access_bits"),
            "and the bits granted: " .. service_denial.payload)
        clear_descriptors()

        -- The same refusal against a job, which is the other half of the
        -- rule: same fields, different event.
        local id = submit_granting(t, 0x0001)
        t:assert_eq(job_verdict(vm:run("svctl --json job stop " .. id, { timeout = 60 })),
            "denied", "the job command was refused")

        local job_denial
        for _ = 1, 20 do
            for _, event in ipairs(events("job.access_denied")) do
                if field(event, "target") == id
                    and field(event, "requested_right") == "JOB_STOP" then
                    job_denial = event
                end
            end
            if job_denial then break end
            vm:run("sleep 1")
        end
        t:assert(job_denial, "and recorded as job.access_denied rather than access.denied")
        t:assert_eq(field(job_denial, "target_type"), "job",
            "naming the kind of target: " .. job_denial.payload)
        t:assert_eq(field(job_denial, "requested_access_bits"), "2",
            "with the bits requested: " .. job_denial.payload)

        vm:run("svctl --json job stop " .. id, { timeout = 60 })
    end)

test("during shutdown a caller who would have been denied is told the state, not the denial",
    { spec = "peinit *dispatch.the-gate-runs-before-the-access-check" },
    function(t)
        -- The gate is step 1 and the access check is step 3, so the
        -- ordering is observable as a change of answer: the same command
        -- from the same caller against the same descriptor is
        -- ACCESS_DENIED before the shutdown begins and INVALID_STATE
        -- after. Only a caller who *would* be denied can show that;
        -- against a caller with every right, INVALID_STATE is what both
        -- orderings produce.
        local seed = peinit.seed("pt-gate", {
            { path = [[Machine\System]] },
            { path = SERVICES },
            {
                path = [[Machine\System\Services\pt-stubborn]],
                values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sh" },
                    -- A loop rather than one long sleep: SIGTERM goes to
                    -- the whole cgroup, so a single `sleep 600` child
                    -- dies on the first signal and takes the shell's exit
                    -- with it. Re-running a short sleep keeps the shell —
                    -- which ignores TERM — alive for the full
                    -- StopTimeout, and that wait is the window.
                    { name = "Arguments", type = "multi",
                      data = { "-c", "trap '' TERM; while :; do sleep 1; done" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "StopTimeout", type = "dword", data = 30 },
                    { name = "RestartPolicy", type = "dword", data = 0 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                },
            },
        })

        local probe, missed
        for attempt = 1, 3 do
            local other = peinit.boot({ name = "rights-gate-" .. attempt, files = seed })

            t:assert(other:run("svctl --json status pt-stubborn").stdout
                    :find('"state":"active"', 1, true),
                "the service that will hold the shutdown open is running")

            -- Query only. `start` on this service now needs a right the
            -- descriptor does not grant, and the answer is the denial —
            -- which is asserted before the shutdown so that the change
            -- afterwards means something.
            other:run("reg set '" .. [[Machine\System\Services\pt-stubborn]]
                .. "' ServiceSecurity hex:" .. peinit.system_descriptor_hex(0x0001))
                :assert_ok()
            local denied = false
            for _ = 1, 40 do
                if other:run("svctl --json start pt-stubborn").stdout
                        :find("ACCESS_DENIED", 1, true) then
                    denied = true
                    break
                end
                other:run("sleep 1")
            end
            t:assert(denied, "and the caller is refused the start it is about to reissue")

            -- The window opens and closes in the time a couple of svctl
            -- invocations take, so the shutdown is requested from inside
            -- the loop, a few iterations in, with the loop already hot.
            -- A lost race is retried on a fresh machine, because one that
            -- has begun shutting down cannot be asked twice.
            local run = other:run(
                "i=0; while [ $i -lt 5000 ]; do " ..
                "  [ $i -eq 3 ] && { svctl shutdown poweroff >/dev/null 2>&1 & }; " ..
                "  out=$(svctl --json start pt-stubborn 2>&1); " ..
                "  case \"$out\" in " ..
                "    *INVALID_STATE*) echo \"GATED:$out\"; break;; " ..
                "    *ACCESS_DENIED*) denied=$((denied+1));; " ..
                "    *'No such file'*) echo MISSED; break;; " ..
                "    *) echo \"UNEXPECTED:$out\"; break;; " ..
                "  esac; i=$((i+1)); done; echo \"DENIALS:$denied\"; echo END",
                { timeout = 120 })

            if run.stdout:find("GATED:", 1, true) then
                probe = run.stdout
                break
            end
            missed = run.stdout
            other:shutdown()
        end

        t:assert(probe,
            "the gated command was reached in three attempts. Last: " .. tostring(missed))
        t:assert(probe:find('GATED:.*"code":"INVALID_STATE"'),
            "and refused as invalid for the state: " .. probe)
        t:assert(not probe:find("GATED:.*ACCESS_DENIED"),
            "rather than as the denial it had been getting: " .. probe)

        -- The denials before it are what makes the last answer evidence
        -- of an ordering rather than of a caller who was always allowed.
        local denials = tonumber(probe:match("DENIALS:(%d+)"))
        t:assert(denials and denials > 0,
            "the same command was answered ACCESS_DENIED until the gate closed: " .. probe)
    end)
