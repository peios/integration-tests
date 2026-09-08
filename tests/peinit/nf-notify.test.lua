-- peinit TRM §10.5 — the notification socket, and the two sd_notify
-- fields §1.4 says peinit does not implement.
--
-- Everything here is a datagram peinit believed or refused. The image
-- ships nothing that can write a Unix datagram with ancillary data, and
-- peinit will not believe one from anything but a service's own main
-- process, so the instrument is `pt-notify` (tests/tools/pt-notify.c):
-- a program whose Arguments are a script of steps and whose datagrams
-- authenticate because the process running them *is* the service's main
-- job.
--
-- Each test therefore defines its own service. A pt-notify script is
-- fixed at exec, so "send this datagram now" is spelled "define a
-- service whose script sends it, and start it" -- which is why the
-- definitions below are written at runtime through `reg apply` and
-- picked up by peinit's registry watch, rather than seeded at boot.
--
-- Two claims in this article have no route from here:
--
--   notify.a-datagram-without-credentials-is-rejected
--     peinit sets SO_PASSCRED on the socket (notify/socket.rs), so the
--     kernel attaches a correct SCM_CREDENTIALS to every datagram
--     whether the sender supplied one or not. pt-notify has a
--     `send-nocred` step and it makes no observable difference: there is
--     no way to present the receiver with a credential-less datagram.
--
--   notify.a-stale-activation-generation-is-rejected
--     A stale generation needs a live process whose job record is a
--     previous incarnation's. job/store/create.rs forbids a second live
--     main job, so the previous process is always reaped before the
--     generation advances -- and a reaped pid cannot be forged either,
--     since the kernel answers ESRCH.
--
-- The pidfd step (notify.the-pidfd-is-verified-against-the-senders-pid)
-- is in the same family: it differs from the plain pid match only once a
-- pid has been recycled under a job record peinit still holds, and
-- peinit reaps a job the moment its pidfd signals exit. What is
-- reachable is the authentication chain's outcome, which the
-- unauthenticated-sender test below asserts.

local peinit = require("helpers.peinit")
-- One VM: every test here is a service definition written into a running
-- peinit, and one peinit can hold all of them.
peinit.claim(1)

local vm = peinit.boot({ name = "nfnotify", files = peinit.tool("pt-notify") })

local SOCKET = "/run/services/peinit/notify.sock"

--- Write a batch of registry keys through `reg apply`, the way an
--- administrator would. peinit's registry watch delivers it with no
--- `reload-config` asked for.
local function apply(keys)
    local batch = peinit.encode_json({ keys = keys })
    vm:run("cat > /tmp/nf.json <<'PT_JSON_EOF'\n" .. batch ..
        "\nPT_JSON_EOF\nreg apply /tmp/nf.json"):assert_ok()
end

local function status(name)
    local out = vm:run("svctl --json status " .. name)
    if not out:ok() then return nil end
    if out.stdout:find("UNKNOWN_SERVICE", 1, true) then return nil end
    local ok, view = pcall(json.decode, out.stdout)
    if not ok then return nil end
    return view
end

--- Define a pt-notify service whose script is `steps`.
---
--- The script always opens with `sleep 1` and always closes with a
--- marker file and a long sleep. The opening sleep is the documented
--- trap in `peinit.tool`: immediately after exec peinit has not yet
--- processed the launch, so the first datagram is refused as an
--- unauthenticated sender and lost. The closing pair is what lets a test
--- know the steps ran (the marker) without the process exiting and
--- taking the service's main job -- and so its right to notify -- with
--- it.
---
--- `values` overrides or adds registry values by name.
local function define(name, steps, values)
    local arguments = { "--log", "/run/" .. name .. ".log", "sleep", "1" }
    for _, step in ipairs(steps) do arguments[#arguments + 1] = step end
    for _, step in ipairs({ "write", "/run/" .. name .. ".done", "ok",
                            "sleep", "100000" }) do
        arguments[#arguments + 1] = step
    end

    local base = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
        { name = "Arguments", type = "multi", data = arguments },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        -- Alive, not Notify: readiness is not the subject here, and a
        -- service that is Active the moment it is running is one whose
        -- datagrams are all sent from a settled state.
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
    }
    for _, value in ipairs(values or {}) do
        local replaced = false
        for index, existing in ipairs(base) do
            if existing.name == value.name then
                base[index] = value
                replaced = true
            end
        end
        if not replaced then base[#base + 1] = value end
    end

    apply({ { path = [[Machine\System\Services\]] .. name, values = base } })
    wait_until(function() return status(name) ~= nil or nil end,
        { timeout = 60, interval = 0.3,
          desc = "the registry watch to deliver " .. name })
end

--- Start a service defined by `define` and wait until its script has run
--- to the marker.
local function run_steps(name)
    vm:run("svctl --json start " .. name):assert_ok()
    wait_until(function()
        return vm:run("test -f /run/" .. name .. ".done"):ok() or nil
    end, { timeout = 90, interval = 0.2,
           desc = name .. " to run its notification script" })
    -- The marker is written by the step after the last datagram, but a
    -- datagram is only *sent* by then; peinit still has to read it. Half
    -- a second is far more than one turn of its loop and keeps every
    -- assertion below about content rather than about scheduling.
    vm:run("sleep 0.5")
end

local function launch(name, steps, values)
    define(name, steps, values)
    run_steps(name)
    return status(name)
end

--- The pid of a service's current main job.
local function main_pid(name)
    local view = wait_until(function()
        local current = status(name)
        return current and current.current_job and current.current_job.pid and current or nil
    end, { timeout = 60, interval = 0.3, desc = name .. " to have a running main job" })
    return view.current_job.pid
end

--- pt-notify's own log: one line per step, `step=… rc=… errno=… detail=…`.
local function tool_log(name)
    return vm:read_file("/run/" .. name .. ".log")
end

--- How many descriptors PID 1 holds open on `path`.
---
--- peinit holds a stored descriptor open, so `/proc/1/fd` is the fd
--- store made directly visible: one symlink per descriptor, pointing at
--- whatever it was opened on. The guest ships no `grep`, so the counting
--- is done here rather than in a pipeline.
local function held_fds(path)
    local listing = vm:run("ls -l /proc/1/fd 2>/dev/null").stdout
    local count = 0
    for line in listing:gmatch("[^\r\n]+") do
        local target = line:match("%->%s+(.*)$")
        if target then
            target = target:gsub("%s+$", "")
            -- A descriptor on an unlinked file still names it, with
            -- ` (deleted)` appended.
            if target == path or target == path .. " (deleted)" then
                count = count + 1
            end
        end
    end
    return count
end

--- Every event of the given types still in the KMES ring, oldest first,
--- as `{type, payload}` with the payload in revstrm's pretty form.
---
--- The ring has a consumer and `--snapshot` prints only what is still
--- buffered, so every read below is of events this file has just made.
local function events(globs)
    local flags = ""
    for _, glob in ipairs(globs) do flags = flags .. " --type '" .. glob .. "'" end
    local r = vm:run("revstrm --snapshot --pretty" .. flags, { timeout = 60 })
    r:assert_ok()
    local out, current = {}, nil
    for line in r.stdout:gmatch("[^\r\n]+") do
        local kind = line:match("^%d%d:%d%d:%d%d[%.%d]*%s+cpu.-#%d+%s+%u+%s+([%w_]+%.[%w_]+)%s*$")
        if kind then
            current = { type = kind, payload = "" }
            out[#out + 1] = current
        elseif current and line:match("^%s") then
            current.payload = current.payload .. line .. "\n"
        end
    end
    return out, r.stdout
end

local function field(event, name)
    local value = event.payload:match("\n?%s+" .. name .. "%s%s+([^\r\n]*)")
    if not value then return nil end
    return (value:gsub('^"', ""):gsub('"$', ""))
end

--- Every event of `kind` attributed to `service`.
local function events_for(list, kind, service)
    local out = {}
    for _, event in ipairs(list) do
        if event.type == kind and field(event, "service") == service then
            out[#out + 1] = event
        end
    end
    return out
end

test("a service reaches the socket through NOTIFY_SOCKET and nothing else",
    { spec = "peinit *notify.the-path-reaches-a-service-through-notify-socket" },
    function(t)
        -- pt-notify is given no `--socket`, so the only path it has is
        -- `$NOTIFY_SOCKET`. A datagram that lands is therefore evidence
        -- about the variable rather than about a path the tool knew.
        local view = launch("pt-nf-path", {
            "report", "/run/pt-nf-path.report",
            "send", "STATUS=reached through the environment",
        })

        local report = vm:read_file("/run/pt-nf-path.report")
        t:assert_eq(report:match("NOTIFY_SOCKET=([^\r\n]*)"), SOCKET,
            "peinit put the socket's path in the service's environment")
        t:assert_eq(view.status_text, "reached through the environment",
            "and a datagram addressed to that path and nothing else arrived")
    end)

test("every line of a datagram is applied, and three of the fields emit events",
    {
        spec = {
            "peinit *notify.every-line-of-a-datagram-is-applied",
            "peinit *notify.status-is-exposed-as-status-text",
            "peinit *notify.status-errno-and-exit-status-emit-events",
        },
    },
    function(t)
        -- One datagram, three fields, all well-formed. Each has a
        -- separate observable, so "every line was applied" is three
        -- independent findings rather than one.
        local view = launch("pt-nf-lines", {
            "send", "STATUS=serving\\nERRNO=13\\nEXIT_STATUS=7",
        })

        t:assert_eq(view.status_text, "serving",
            "STATUS= is stored on the runtime state and answered as status_text")

        local ring = events({ "notify.*" })
        local statuses = events_for(ring, "notify.status", "pt-nf-lines")
        local errnos = events_for(ring, "notify.errno", "pt-nf-lines")
        local exits = events_for(ring, "notify.exit_status", "pt-nf-lines")

        t:assert_eq(#statuses, 1, "one notify.status for the one STATUS= line")
        t:assert_eq(#errnos, 1, "one notify.errno for the one ERRNO= line")
        t:assert_eq(#exits, 1, "one notify.exit_status for the one EXIT_STATUS= line")

        t:assert_eq(field(statuses[1], "status"), "serving",
            "the status event carries the value")
        t:assert_eq(field(errnos[1], "errno"), "13",
            "the errno event carries the value")
        t:assert_eq(field(exits[1], "exit_status"), "7",
            "the exit_status event carries the value")

        -- The attribution the article names: service, job, operation and
        -- activation generation, on each of the three.
        for _, event in ipairs({ statuses[1], errnos[1], exits[1] }) do
            t:assert(field(event, "job_id"), event.type .. " names the job")
            t:assert(field(event, "operation_id"),
                event.type .. " names the operation")
            t:assert(field(event, "generation"),
                event.type .. " names the activation generation")
        end
    end)

test("ERRNO= and EXIT_STATUS= are emitted and not retained",
    { spec = "peinit *notify.errno-and-exit-status-are-not-stored" },
    function(t)
        -- The distinguishing observation is that STATUS= survives a
        -- later datagram carrying only the two unstored fields: if
        -- either were stored anywhere status_text can be read from, the
        -- second datagram would have moved it.
        local view = launch("pt-nf-unstored", {
            "send", "STATUS=kept",
            "send", "ERRNO=99\\nEXIT_STATUS=42",
        })
        t:assert_eq(view.status_text, "kept",
            "a datagram of ERRNO= and EXIT_STATUS= left status_text alone")

        local ring = events({ "notify.*" })
        t:assert_eq(#events_for(ring, "notify.errno", "pt-nf-unstored"), 1,
            "the ERRNO= was received rather than dropped")
        t:assert_eq(#events_for(ring, "notify.exit_status", "pt-nf-unstored"), 1,
            "and so was the EXIT_STATUS=")
    end)

test("one malformed line voids the whole datagram, and the rejection is recorded",
    {
        spec = {
            "peinit *notify.a-malformed-line-voids-the-whole-datagram",
            "peinit *notify.a-rejected-datagram-is-dropped-and-recorded",
        },
    },
    function(t)
        -- The second datagram's first line is a perfectly good STATUS=,
        -- and its third is a perfectly good ERRNO=. The middle line has
        -- no `=`. Nothing from the datagram may be applied -- which the
        -- surviving status_text from the *first* datagram is what shows.
        local view = launch("pt-nf-malformed", {
            "send", "STATUS=before",
            "send", "STATUS=after\\nnot-a-pair\\nERRNO=5",
        })

        t:assert_eq(view.status_text, "before",
            "the well-formed STATUS= in the voided datagram was not applied")

        local ring = events({ "notify.*" })
        t:assert_eq(#events_for(ring, "notify.errno", "pt-nf-malformed"), 0,
            "nor the well-formed ERRNO= after the malformed line")

        local rejected = events_for(ring, "notify.rejected", "pt-nf-malformed")
        t:assert_eq(#rejected, 1, "the datagram was recorded as rejected")
        t:assert_eq(field(rejected[1], "reason"),
            "parse: MalformedLine { line_index: 1 }",
            "naming the line that voided it: " .. rejected[1].payload)
        -- Attribution is what makes the record useful: parsing fails
        -- before application, but the sender is authenticated anyway so
        -- the event can say whose datagram it was.
        t:assert(field(rejected[1], "job_id"), "the rejection names the job")
        t:assert(field(rejected[1], "operation_id"),
            "and the operation")
        t:assert(field(rejected[1], "generation"),
            "and the activation generation")
        t:assert(field(rejected[1], "sender_pid"),
            "and the pid the datagram came from")
    end)

test("a datagram from a pid that is no service's main job is dropped and recorded",
    { spec = "peinit *notify.a-rejected-datagram-is-dropped-and-recorded" },
    function(t)
        -- The five authentication steps have one outcome between them,
        -- and this is it. The credentials here are forged -- the kernel
        -- lets a SYSTEM caller name any live pid -- so the datagram is
        -- well-formed, correctly credentialed and still refused, because
        -- the pid it claims is not any service's current main job.
        --
        -- pid 1 is peinit itself: alive for certain, and the one pid that
        -- can never be a service's main job.
        local view = launch("pt-nf-unauth", {
            "send", "STATUS=this service's own",
            "send-cred", "1", "0", "0", "STATUS=on behalf of PID 1",
        })

        t:assert_eq(view.status_text, "this service's own",
            "the forged datagram moved nothing")

        local log = tool_log("pt-nf-unauth")
        t:assert(log:match("step=send%-cred rc=(%d+)"),
            "the send itself succeeded, so the refusal is peinit's: " .. log)

        local ring = events({ "notify.rejected" })
        local found = nil
        for _, event in ipairs(ring) do
            if field(event, "sender_pid") == "1" then found = event end
        end
        t:assert(found, "peinit recorded a rejection for the forged sender")
        t:assert_eq(field(found, "reason"),
            "apply: UnauthenticatedSender { pid: 1 }",
            "as an unauthenticated sender: " .. found.payload)
        -- A rejection is recorded after authentication so that it can
        -- name the service where one could be established. Here none
        -- could, so every attribution field is nil -- and in particular
        -- the record is not attributed to pt-nf-unauth, which is the
        -- service that actually wrote the bytes.
        t:assert_eq(field(found, "service"), "nil",
            "with no service named, because none could be established: " ..
            found.payload)
        t:assert_eq(field(found, "generation"), "nil",
            "and no generation either")
    end)

test("the credential UID and GID are not policy inputs",
    { spec = "peinit *notify.the-credential-uid-and-gid-are-not-policy-inputs" },
    function(t)
        -- Identity on Peios is a token, and the token here is which job
        -- the sender is. So a datagram whose SCM_CREDENTIALS claim a uid
        -- and gid peinit has never heard of is applied on exactly the
        -- same terms as one carrying the sender's own -- because the
        -- credentials' pid is the only field consulted.
        define("pt-nf-subject", { "send", "STATUS=its own" })
        run_steps("pt-nf-subject")
        local pid = main_pid("pt-nf-subject")

        launch("pt-nf-forger", {
            "send-cred", tostring(pid), "4242", "4343",
            "STATUS=from a uid peinit has never heard of",
        })

        local view = status("pt-nf-subject")
        t:assert_eq(view.status_text, "from a uid peinit has never heard of",
            "a datagram claiming uid 4242 / gid 4343 was applied unchanged")

        -- And attributed to the service the pid identifies, not to the
        -- one that actually wrote the bytes.
        local ring = events({ "notify.status" })
        local mine = events_for(ring, "notify.status", "pt-nf-subject")
        local last = mine[#mine]
        t:assert(last, "the status event was attributed to the pid's service")
        t:assert_eq(field(last, "status"),
            "from a uid peinit has never heard of",
            "carrying the forged datagram's value")
    end)

test("READY=1 and RELOADING=1 emit no event of their own",
    { spec = "peinit *notify.ready-and-reloading-emit-no-event" },
    function(t)
        -- One datagram carrying all three fields. STATUS= is the control:
        -- it proves the datagram was received and applied whole, so the
        -- absence of an event for the other two is about those two rather
        -- than about a datagram that never arrived.
        local view = launch("pt-nf-quiet", {
            "send", "READY=1\\nRELOADING=1\\nSTATUS=the only event here",
        })
        t:assert_eq(view.status_text, "the only event here",
            "the datagram was applied")

        local ring = events({ "notify.*" })
        local mine = {}
        for _, event in ipairs(ring) do
            if field(event, "service") == "pt-nf-quiet" then
                mine[#mine + 1] = event.type
            end
        end
        t:assert_eq(#mine, 1,
            "exactly one notify.* event for the whole datagram: " ..
            table.concat(mine, ", "))
        t:assert_eq(mine[1], "notify.status",
            "and it is the STATUS=, not the READY= or the RELOADING=")
    end)

test("STOPPING=1 emits an event, because its only effect is an absence",
    { spec = "peinit *notify.stopping-emits-an-event" },
    function(t)
        local view = launch("pt-nf-stopping", { "send", "STOPPING=1" })
        t:assert_eq(view.state, "active",
            "the service is still running: STOPPING= is a claim, not a stop")

        local stopping = events_for(events({ "notify.stopping" }),
            "notify.stopping", "pt-nf-stopping")
        t:assert_eq(#stopping, 1, "STOPPING=1 emitted notify.stopping")
        t:assert(field(stopping[1], "job_id"), "with the same attribution")
        t:assert(field(stopping[1], "generation"),
            "including the activation generation")
        -- No value: the field has none, and the event is the record that
        -- the suppression of SIGTERM later on was asked for.
        t:assert(not field(stopping[1], "status"),
            "and no value, because STOPPING= carries none")
    end)

test("status_text is cleared at the start of every activation generation",
    { spec = "peinit *notify.status-text-is-cleared-on-each-activation-generation" },
    function(t)
        -- The status must come from somewhere other than the subject's
        -- own script: a restarted pt-notify runs the same steps again,
        -- so a subject that sets its own status would set it again a
        -- second after the restart and the clearing would be a race to
        -- observe. Here the subject sends nothing at all and a second
        -- service sets its status by forging its pid, which leaves
        -- "cleared and stayed cleared" as a settled state rather than a
        -- window.
        define("pt-nf-gen", {})
        run_steps("pt-nf-gen")
        local pid = main_pid("pt-nf-gen")
        local job_before = status("pt-nf-gen").current_job.id

        launch("pt-nf-gen-set", {
            "send-cred", tostring(pid), "0", "0", "STATUS=generation one",
        })
        t:assert_eq(status("pt-nf-gen").status_text, "generation one",
            "the first activation generation carries a status")

        vm:run("svctl --json restart pt-nf-gen"):assert_ok()
        local view = wait_until(function()
            local current = status("pt-nf-gen")
            return current and current.state == "active"
                and current.current_job
                and current.current_job.id ~= job_before and current or nil
        end, { timeout = 90, interval = 0.3,
               desc = "pt-nf-gen to reach a second activation generation" })

        t:assert(not view.status_text,
            "the new generation did not inherit the old one's status: " ..
            tostring(view.status_text))

        -- And it is not merely late: nothing restores it, because the
        -- text described a process that no longer exists.
        vm:run("sleep 3")
        t:assert(not status("pt-nf-gen").status_text,
            "and it stays cleared")
    end)

test("a datagram larger than the receive buffer is refused as truncated",
    { spec = "peinit *notify.the-datagram-and-descriptor-bounds" },
    function(t)
        -- 70 000 bytes against a 64 KiB buffer. The surviving prefix
        -- begins `STATUS=`, so a receiver that acted on what fitted
        -- would have set a status; the assertion is that none was.
        local view = launch("pt-nf-big", {
            "send", "STATUS=small enough",
            "send-pad", "70000", "STATUS=",
        })
        t:assert_eq(view.status_text, "small enough",
            "the oversized datagram was not applied from its prefix")

        local log = tool_log("pt-nf-big")
        t:assert(log:match("step=send%-pad rc=70000"),
            "the guest did send 70 000 bytes: " .. log)

        local truncations = {}
        for _, event in ipairs(events({ "notify.rejected" })) do
            local reason = field(event, "reason") or ""
            if reason:find("truncated: payload=true", 1, true) then
                truncations[#truncations + 1] = reason
            end
        end
        t:assert(#truncations >= 1,
            "and peinit recorded it as a truncated payload rather than acting on it")
        t:assert(truncations[#truncations]:find("control=false", 1, true),
            "the control message was intact; it was the payload that overran: " ..
            truncations[#truncations])
    end)

test("sixty-four descriptors fit and sixty-five is refused as truncated",
    { spec = "peinit *notify.the-datagram-and-descriptor-bounds" },
    function(t)
        -- The control buffer is sized for exactly 64, so 64 is the
        -- boundary rather than an approximation of one. Both sends are
        -- FDSTORE=1 against a store big enough for either, so the only
        -- thing that can decide them is the descriptor bound.
        vm:run("echo bound > /run/pt-nf-bound.marker"):assert_ok()
        launch("pt-nf-bound", {
            "send-fds", "65", "/run/pt-nf-bound.marker",
                "FDSTORE=1\\nFDNAME=over",
            "send-fds", "64", "/run/pt-nf-bound.marker",
                "FDSTORE=1\\nFDNAME=under",
        }, { { name = "FdStoreMax", type = "dword", data = 200 } })

        t:assert_eq(held_fds("/run/pt-nf-bound.marker"), 64,
            "peinit holds the 64 from the accepted send and none from the 65")

        local truncations = {}
        for _, event in ipairs(events({ "notify.rejected" })) do
            local reason = field(event, "reason") or ""
            if reason:find("control=true", 1, true) then
                truncations[#truncations + 1] = reason
            end
        end
        t:assert(#truncations >= 1,
            "the 65-descriptor send was recorded as a truncated control message")
        t:assert(truncations[#truncations]:find("payload=false", 1, true),
            "with the payload intact -- it was the descriptors that overran: " ..
            truncations[#truncations])
    end)

test("MAINPID= and BUSERROR= are accepted as lines and do nothing",
    {
        spec = {
            "peinit *compat.mainpid-is-not-supported",
            "peinit *compat.buserror-is-not-supported",
        },
    },
    function(t)
        -- Not supported does not mean rejected. Both are well-formed
        -- `KEY=VALUE` lines, so neither voids the datagram they arrive
        -- in -- an sd_notify client that sends them keeps working, and
        -- what it loses is only the effect.
        --
        -- MAINPID names pid 1, which is the most redirectable-looking
        -- value there is: if peinit honoured it, supervision would move
        -- to itself.
        local view = launch("pt-nf-compat", {
            "send", "MAINPID=1\\nBUSERROR=org.freedesktop.DBus.Error.Failed" ..
                "\\nSTATUS=the rest was applied",
        })

        t:assert_eq(view.status_text, "the rest was applied",
            "the datagram was not voided by the two unsupported lines")

        local pid = view.current_job and view.current_job.pid
        t:assert(pid and pid ~= 1,
            "supervision still names the process peinit forked, not the " ..
            "pid MAINPID asked for: " .. tostring(pid))

        -- And neither produced an event of its own, the way an
        -- unsupported-but-noticed field would.
        local mine = {}
        for _, event in ipairs(events({ "notify.*" })) do
            if field(event, "service") == "pt-nf-compat" then
                mine[#mine + 1] = event.type
            end
        end
        t:assert_eq(#mine, 1,
            "only the STATUS= was acted on: " .. table.concat(mine, ", "))
    end)
