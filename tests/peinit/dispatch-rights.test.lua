-- peinit TRM §10.2 — what a caller may do, and §4.6's built-in default.
--
-- A `status`, and every job view on the control socket, carries
-- `granted`: the rights the caller holds on the target, found by asking
-- AccessCheck for MAXIMUM_ALLOWED instead of for one right. Two things
-- make that observable. First, `granted` describes the caller, so two
-- callers asking about the same thing must be told different things —
-- and the console has only one identity. The second caller is a provium
-- worker's (helpers/peinit_client.lua), minted for a local account the
-- image has never heard of, which since PEI-1231 the control socket
-- admits like any authenticated principal. Second, the check behind
-- `granted` is a question rather than a command, so it must leave no
-- record of a refusal; that is read from KACS's
-- `kacs.audit.access.checked` records, in eventd, beside a deliberate
-- denial that must leave one.
--
-- The same second caller is what §4.6's built-in default needs: the
-- default lets every authenticated principal query a service, and the
-- console's SYSTEM holds everything anyway.
--
-- Last, the retained operation: a terminal operation outlives its
-- service when the definition is removed, and is then checked against
-- the descriptor the service had. A fall-back to the built-in default
-- would let the minted user, an authenticated principal, read every such
-- operation — so the case that discriminates is the one it is refused.

local peinit = require("helpers.peinit")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local sys = require("helpers.sys")
local f = require("helpers.peinit_client")
local eventd = require("helpers.eventd")
local revstrm = require("helpers.revstrm")
peinit.claim(1)

local SERVICES = [[Machine\System\Services]]
local USER = token.SID.TEST_USER
local USER_SID = token.sid_string(USER)
local SYSTEM = token.SID.LOCAL_SYSTEM

local ALL = '["query_status","start","stop","interrogate"]'

--- A demand-triggered Oneshot: a command against it can be issued at any
--- moment, and `start` is a real operation rather than a no-op.
local function oneshot(name)
    return { path = SERVICES .. [[\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/true" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
    } }
end

local vm = peinit.boot({
    name = "dispatch-rights",
    files = peinit.seed("pt-dr", {
        { path = [[Machine\System]] },
        { path = SERVICES },
        -- Active for the whole file, so a `start` has nothing to do.
        { path = SERVICES .. [[\pt-dr-plain]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- No descriptor of its own, ever: the built-in default.
        oneshot("pt-dr-open"),
        oneshot("pt-dr-narrow"),
        oneshot("pt-dr-user"),
        oneshot("pt-dr-keep-a"),
        oneshot("pt-dr-keep-b"),
    }),
})

local verdict = peinit.verdict

--- Write `ServiceSecurity` on a service as allow ACEs, then wait until
--- `landed()` says peinit has it: the registry watch carries it there
--- asynchronously.
local function set_descriptor(name, aces, landed)
    vm:run("reg set '" .. SERVICES .. "\\" .. name .. "' ServiceSecurity hex:"
        .. f.descriptor_hex(SYSTEM, aces)):assert_ok()
    wait_until(function() return landed() or nil end,
        { timeout = 60, interval = 0.5, desc = "the descriptor on " .. name .. " to land" })
end

--- An impersonation token for USER: Everyone and Authenticated Users,
--- nothing else. SeChangeNotifyPrivilege so the walk to the socket's
--- directory is not refused on traverse.
local function mint_user(w)
    local enabled = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
        | token.GROUP.ENABLED
    local notify = token.bit(token.PRIV.CHANGE_NOTIFY)
    return assert(token.mint(w, {
        user_sid = USER,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IMPERSONATION,
        groups = {
            { sid = token.SID.EVERYONE, attributes = enabled },
            { sid = token.SID.AUTHENTICATED_USERS, attributes = enabled },
        },
        privs_present = notify,
        privs_enabled = notify,
    }))
end

--- Send one control frame as USER, on a fresh connection, and return the
--- raw answer.
local function as_user(frame)
    local answer
    f.with_worker(vm, function(w)
        local fd = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, mint_user(w)))
        answer = assert(f.control_request(w, fd, frame))
        sys.close(w, fd)
    end)
    return answer
end

local function status_frame(name)
    return '{"command":"status","service":"' .. name .. '"}'
end

local function granted(answer)
    return answer:match('"granted":(%[[^%]]*%])')
end

--- `f.descriptor_hex`'s descriptor with a SACL of one failure-audit ACE
--- for Everyone over every right, as peinit's built-in defaults carry. A
--- descriptor written to the registry is used as given, so a test that
--- wants KACS to record a refusal under its own has to ask for it.
local function audited_descriptor_hex(owner, aces)
    local body = ""
    for _, ace in ipairs(aces) do
        body = body .. string.pack("<BBI2I4", 0, 0, 8 + #ace.sid, ace.mask) .. ace.sid
    end
    local dacl = string.pack("<BBI2I2I2", 2, 0, 8 + #body, #aces, 0) .. body
    local everyone = string.pack("BB", 1, 1) .. string.pack(">I2>I4", 0, 1)
        .. string.pack("<I4", 0)
    -- SYSTEM_AUDIT_ACE_TYPE (2), FAILED_ACCESS_ACE_FLAG (0x80).
    local audit = string.pack("<BBI2I4", 2, 0x80, 8 + #everyone, 0xf) .. everyone
    local sacl = string.pack("<BBI2I2I2", 2, 0, 8 + #audit, 1, 0) .. audit
    -- SACL_PRESENT | DACL_PRESENT | SELF_RELATIVE.
    local sacl_at = 20 + 2 * #owner
    local header = string.pack("<BBI2I4I4I4I4", 1, 0, 0x8014,
        20, 20 + #owner, sacl_at, sacl_at + #sacl)
    return ((header .. owner .. owner .. sacl .. dacl):gsub(".",
        function(byte) return string.format("%02x", byte:byte()) end))
end

--- The rights requested by every refused check KACS recorded on an object
--- of `kind` that `match(row)` picks out (`kacs.audit.access.checked`,
--- read from eventd).
local function denials(kind, match)
    local rows = eventd.rows(vm, 'EVENTS kacs.audit.access.checked WHERE object.kind == "'
        .. kind .. '" SINCE 1h ago TAKE 1000')
    local rights = {}
    for _, row in ipairs(rows) do
        if match(row) and row["outcome.success"] == false then
            rights[#rights + 1] = tostring(row["access.requested"])
        end
    end
    return rights
end

local function service_named(name)
    return function(row) return row["object.service.name"] == name end
end

local function job_named(id)
    return function(row) return revstrm.guid(row["object.job.guid"]) == id:lower() end
end

--- Submit a job as the console (SYSTEM) under `sddl`; return its id and
--- the jobs socket's answer.
local function submit(sddl)
    local r = vm:run("svctl --json job submit --security-descriptor '" .. sddl
        .. "' /bin/sleep 120", { timeout = 120 })
    r:assert_ok()
    local id = r.stdout:match('"id":"([^"]+)"')
    assert(id, "no job identifier in: " .. r.stdout)
    return id, r.stdout
end

--- The entry for `id` in a `job-list` answer, decoded.
local function listed(answer, id)
    local ok, decoded = pcall(json.decode, answer)
    if not ok or type(decoded) ~= "table" then return nil end
    for _, job in ipairs(decoded.jobs or {}) do
        if job.id == id then return job end
    end
    return nil
end

test("a status reports the service rights its caller holds, and only those",
    { spec = "peinit *dispatch.status-reports-the-callers-rights" },
    function(t)
        -- The same service, two callers: SYSTEM holds everything under the
        -- built-in default, and an authenticated user holds query alone.
        local system = vm:run("svctl --json status pt-dr-open")
        system:assert_ok()
        t:assert_eq(granted(system.stdout), ALL,
            "SYSTEM is told it holds all four service rights, in the wire order: "
            .. system.stdout)
        local user = as_user(status_frame("pt-dr-open"))
        t:assert_eq(granted(user), '["query_status"]',
            "and " .. USER_SID .. " is told it holds query alone: " .. user)

        -- A descriptor that narrows SYSTEM to query and stop. SYSTEM is
        -- the descriptor's owner too, which conveys READ_CONTROL and
        -- WRITE_DAC: standard rights the check grants and `granted` does
        -- not report, because they are not service rights.
        set_descriptor("pt-dr-narrow", { { sid = SYSTEM, mask = 0x0005 } }, function()
            return verdict(vm:run("svctl start pt-dr-narrow")) == "denied"
        end)
        local narrowed = vm:run("svctl --json status pt-dr-narrow")
        narrowed:assert_ok()
        t:assert_eq(granted(narrowed.stdout), '["query_status","stop"]',
            "a narrower descriptor is reported as exactly what it grants: " .. narrowed.stdout)
    end)

test("a status answering a command that had nothing to do reports its caller's rights",
    { spec = "peinit *dispatch.a-status-answering-a-command-reports-the-callers-rights" },
    function(t)
        -- `start` on an Active service has nothing to do and answers with
        -- the status, which carries `granted` for whoever sent the start.
        local started = vm:run("svctl --json start pt-dr-plain")
        started:assert_ok()
        t:assert(not started.stdout:find('"operation_id"', 1, true),
            "the start had nothing to do and named no operation: " .. started.stdout)
        t:assert_eq(granted(started.stdout), ALL,
            "and the status it returned carries SYSTEM's rights: " .. started.stdout)

        -- And for another caller, the other caller's: a user granted
        -- query and stop, sending a stop to an Inactive service.
        set_descriptor("pt-dr-user", {
            { sid = SYSTEM, mask = 0x000F },
            { sid = USER, mask = 0x0005 },
        }, function()
            return granted(as_user(status_frame("pt-dr-user"))) == '["query_status","stop"]'
        end)
        local stopped = as_user('{"command":"stop","service":"pt-dr-user"}')
        t:assert(not stopped:find('"operation_id"', 1, true),
            "the user's stop of an Inactive service had nothing to do: " .. stopped)
        t:assert_eq(granted(stopped), '["query_status","stop"]',
            "and its status carries the user's rights, not SYSTEM's: " .. stopped)
    end)

test("every job view on the control socket carries the caller's job rights, and the jobs socket's does not",
    { spec = "peinit *dispatch.job-views-on-the-control-socket-report-the-callers-rights" },
    function(t)
        -- SYSTEM holds every job right and the user holds query alone.
        local id, submitted = submit(string.format(
            "O:SYG:SYD:(A;;0x7;;;SY)(A;;0x1;;;%s)", USER_SID))
        t:assert(not submitted:find('"granted"', 1, true),
            "the submit answer is the jobs socket's view, which has no granted: " .. submitted)

        local status = vm:run("svctl --json job status " .. id)
        status:assert_ok()
        t:assert_eq(granted(status.stdout), '["query","stop","signal"]',
            "job-status tells SYSTEM it holds all three: " .. status.stdout)
        local user_status = as_user('{"command":"job-status","job_id":"' .. id .. '"}')
        t:assert_eq(granted(user_status), '["query"]',
            "and tells the user it holds query: " .. user_status)

        local list = vm:run("svctl --json job list")
        list:assert_ok()
        local entry = listed(list.stdout, id)
        t:assert(entry, "SYSTEM's job-list has the job: " .. list.stdout)
        t:assert_eq(table.concat(entry.granted or {}, ","), "query,stop,signal",
            "and each entry carries SYSTEM's rights on it: " .. list.stdout)
        local user_list = as_user('{"command":"job-list"}')
        local user_entry = listed(user_list, id)
        t:assert(user_entry, "the user's job-list has the job: " .. user_list)
        t:assert_eq(table.concat(user_entry.granted or {}, ","), "query",
            "carrying the user's rights on it: " .. user_list)

        -- job-stop, waiting: the terminal view is written by the run loop
        -- with no caller's token to hand, so the rights are the ones found
        -- when the stop was taken. The user may query and stop this one.
        local stoppable = submit(string.format(
            "O:SYG:SYD:(A;;0x7;;;SY)(A;;0x3;;;%s)", USER_SID))
        local stopped = as_user('{"command":"job-stop","job_id":"' .. stoppable
            .. '","wait":true}')
        t:assert(stopped:find('"ended_at":"', 1, true),
            "the waited stop answered with the terminal view: " .. stopped)
        t:assert_eq(granted(stopped), '["query","stop"]',
            "and that view carries the rights of the user who stopped it: " .. stopped)

        local system_stop = vm:run("svctl --json job stop " .. id, { timeout = 90 })
        system_stop:assert_ok()
        t:assert_eq(granted(system_stop.stdout), '["query","stop","signal"]',
            "SYSTEM's own stop carries SYSTEM's: " .. system_stop.stdout)
    end)

test("asking what a caller may do is not a denial of what it may not",
    { spec = "peinit *dispatch.a-maximum-allowed-check-is-not-a-denial" },
    function(t)
        -- A service on which SYSTEM may only query, under a descriptor
        -- whose SACL audits every refusal: the status answer leaves out
        -- start, stop and interrogate, and KACS records no refusal for
        -- leaving them out. A start afterwards is a command, refused and
        -- recorded — which is the evidence the record is being read at
        -- all.
        eventd.ready(vm)
        vm:run("reg set '" .. SERVICES .. "\\pt-dr-narrow' ServiceSecurity hex:"
            .. audited_descriptor_hex(SYSTEM, { { sid = SYSTEM, mask = 0x0001 } })):assert_ok()
        wait_until(function()
            return granted(vm:run("svctl --json status pt-dr-narrow").stdout)
                == '["query_status"]' or nil
        end, { timeout = 60, interval = 0.5, desc = "the descriptor on pt-dr-narrow to land" })
        local before = #denials("service", service_named("pt-dr-narrow"))
        t:assert_eq(granted(vm:run("svctl --json status pt-dr-narrow").stdout),
            '["query_status"]', "the status is answered with query alone")
        t:assert_eq(verdict(vm:run("svctl start pt-dr-narrow")), "denied",
            "and a start is refused")

        local after = wait_until(function()
            local rights = denials("service", service_named("pt-dr-narrow"))
            return #rights > before and rights or nil
        end, { timeout = 30, interval = 0.5, desc = "the start's refusal to be recorded" })
        local fresh = {}
        for i = before + 1, #after do fresh[#fresh + 1] = after[i] end
        t:assert_eq(table.concat(fresh, ","), "2",
            "the one refusal recorded since is the start's (SERVICE_START, 0x2): "
            .. "the status's check left none")

        -- The same for a job: SYSTEM may only query it. The submitter's
        -- descriptor is used as given, so it carries the SACL itself.
        local id = submit("O:SYG:SYD:(A;;0x1;;;SY)S:(AU;FA;0x7;;;WD)")
        local status = vm:run("svctl --json job status " .. id)
        status:assert_ok()
        t:assert_eq(granted(status.stdout), '["query"]',
            "the job view leaves out stop and signal: " .. status.stdout)
        local stop = vm:run("svctl --json --no-wait job stop " .. id, { timeout = 60 })
        t:assert(stop.stdout:find("ACCESS_DENIED", 1, true),
            "and a job-stop is refused: " .. stop.stdout)
        local job_denials = wait_until(function()
            local rights = denials("job", job_named(id))
            return #rights > 0 and rights or nil
        end, { timeout = 30, interval = 0.5, desc = "the job-stop's refusal to be recorded" })
        t:assert_eq(table.concat(job_denials, ","), "2",
            "the only refusal recorded for the job is the stop's (JOB_STOP, 0x2)")
    end)

test("an operation outlives its service and is still checked against the service's descriptor",
    { spec = "peinit *dispatch.a-retained-operation-keeps-its-services-descriptor" },
    function(t)
        -- Two services, each telling the user something different. On A
        -- the user may query; on B only SYSTEM is named. SYSTEM's own
        -- mask on A leaves out stop, so a refused stop is how the console
        -- sees A's descriptor land; B's lands when the user is refused a
        -- status, which the built-in default would have answered.
        set_descriptor("pt-dr-keep-a", {
            { sid = SYSTEM, mask = 0x000B },
            { sid = USER, mask = 0x0001 },
        }, function()
            return verdict(vm:run("svctl stop pt-dr-keep-a")) == "denied"
        end)
        set_descriptor("pt-dr-keep-b", { { sid = SYSTEM, mask = 0x000F } }, function()
            return as_user(status_frame("pt-dr-keep-b")):find("ACCESS_DENIED", 1, true)
        end)

        local ids = {}
        for _, name in ipairs({ "pt-dr-keep-a", "pt-dr-keep-b" }) do
            local r = vm:run("svctl --json start " .. name, { timeout = 60 })
            ids[name] = r.stdout:match('"operation_id":"([^"]+)"')
            t:assert(ids[name], name .. "'s start named its operation: " .. r.stdout)
        end
        local function ask(name)
            return as_user('{"command":"operation-status","operation_id":"' .. ids[name] .. '"}')
        end

        -- While the services exist, the live descriptors decide.
        t:assert(ask("pt-dr-keep-a"):find('"status":"ok"', 1, true),
            "the user may read A's operation while A exists")
        t:assert(ask("pt-dr-keep-b"):find("ACCESS_DENIED", 1, true),
            "and may not read B's")

        -- Both definitions go, and with nothing running both entries are
        -- discarded. The operations are terminal and kept for 60 s.
        for _, name in ipairs({ "pt-dr-keep-a", "pt-dr-keep-b" }) do
            vm:run("reg del '" .. SERVICES .. "\\" .. name .. "' --recursive"):assert_ok()
        end
        for _, name in ipairs({ "pt-dr-keep-a", "pt-dr-keep-b" }) do
            wait_until(function()
                return vm:run("svctl --json status " .. name).stdout
                    :find("UNKNOWN_SERVICE", 1, true) and true or nil
            end, { timeout = 30, interval = 0.3, desc = name .. " to be discarded" })
        end

        local a = ask("pt-dr-keep-a")
        t:assert(a:find('"status":"ok"', 1, true) and a:find(ids["pt-dr-keep-a"], 1, true),
            "with A gone, the user still reads A's operation, as A's descriptor allowed: " .. a)
        local b = ask("pt-dr-keep-b")
        t:assert(b:find("ACCESS_DENIED", 1, true),
            "and is still refused B's, as B's descriptor said — not answered under the " ..
            "built-in default, which lets every authenticated user query: " .. b)
        for _, name in ipairs({ "pt-dr-keep-a", "pt-dr-keep-b" }) do
            local system = vm:run("svctl --json operation-status " .. ids[name])
            t:assert(system.stdout:find('"status":"ok"', 1, true),
                "SYSTEM, named by both, reads " .. name .. "'s: " .. system.stdout)
        end
    end)

test("under the built-in default every authenticated principal may query a service, and only query",
    { spec = "peinit *svcsd.the-built-in-default-lets-everyone-query" },
    function(t)
        -- Neither the definition nor the Services key carries a value, so
        -- what decides is the default compiled into peinit.
        t:assert(vm:run("reg get '" .. SERVICES .. "\\pt-dr-open' ServiceSecurity").exit_code ~= 0,
            "pt-dr-open carries no ServiceSecurity of its own")
        t:assert(vm:run("reg get '" .. SERVICES .. "' ServiceSecurity").exit_code ~= 0,
            "and neither does the Services key")

        local status = as_user(status_frame("pt-dr-open"))
        t:assert(status:find('"status":"ok"', 1, true) and status:find('"state":"', 1, true),
            "a user who is neither SYSTEM nor an administrator may read its state: " .. status)
        local list = as_user('{"command":"list"}')
        t:assert(list:find('"pt-dr-open"', 1, true),
            "and sees it in the list: " .. list)
        for _, command in ipairs({ "start", "stop", "reload" }) do
            local answer = as_user('{"command":"' .. command .. '","service":"pt-dr-open"}')
            t:assert(answer:find("ACCESS_DENIED", 1, true),
                "but may not " .. command .. " it: " .. answer)
        end
    end)
