-- Peinit TRM §13.3 — what the socket descriptors mean in practice.
--
-- The three sockets have different populations. The control socket
-- admits every authenticated principal (§10.1) and decides what each may
-- do per command, so its ACCESS_DENIED path is reachable by anyone who
-- can log on. The notification socket admits SYSTEM and the Service
-- group `S-1-5-6` and nothing else, and a principal outside those is
-- refused at `connect()` by the filesystem, before peinit has a peer to
-- record anything about — which is the chapter's anchored claim.
--
-- Two kinds of caller are needed, and neither is the agent, which runs
-- on peinit's own token. The first is a principal that is not a service
-- at all: a provium worker mints one (helpers/peinit_client.lua) and
-- impersonates it around `connect()`, so the same process can knock on
-- each door as a non-service user, as that user with the Service group
-- added, and as itself. The second is a real service: two definitions
-- are seeded into the registry, one running a shell that probes the
-- control socket and reports through its exit status, since a service's
-- own output goes to eventd rather than anywhere a test can read it,
-- and one that just sleeps, so that there is a live process of that
-- identity whose token the filesystem's own access check can be run
-- against.
--
-- The probe checks its own identity first. Without that the test would
-- pass just as well against a peinit that ran everything as SYSTEM.

local peinit = require("helpers.peinit")
local token = require("helpers.token")
local us = require("helpers.unixsock")
local f = require("helpers.peinit_client")
peinit.claim(1)

local NOTIFY_SOCKET = "/run/services/peinit/notify.sock"
local SERVICE_GROUP = token.sid(5, 6)
local USER = token.SID.TEST_USER
-- EACCES.
local EACCES = 13

--- A boot-triggered Oneshot running `image` as `identity`.
---
--- `WorkingDirectory` is `/run` rather than the default `/`, and that is
--- not decoration. The descriptor on this profile's root filesystem is
--- not the same on every boot — on some it carries the Everyone
--- read-and-traverse ACE of §2.3 and on others only the SYSTEM one — and
--- the pre-exec `chdir` is the one traversal that does not get the
--- `SeChangeNotifyPrivilege` bypass, so a non-SYSTEM service left on the
--- default working directory fails to launch on those boots with
--- `PreExecFailure: set-working-directory failed with errno 13`. The
--- image's own `resolvd` and `trustd` fail the same way when it happens.
--- `/run` is stamped by peinit itself, in Phase 1, and grants Everyone
--- traverse on every boot.
local function service(name, identity, image, args)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = image },
            { name = "Arguments", type = "multi", data = args },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = identity },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "Triggers", type = "multi", data = { "boot" } },
            { name = "WorkingDirectory", type = "sz", data = "/run" },
        },
    }
end

-- svctl exits 69 when it could not reach the socket at all, and with
-- `--json` everything peinit answers — an `ok` or an error, ACCESS_DENIED
-- included — is a JSON object carrying `status`. So a 69 is a refusal at
-- connect(), and a `"status":` in the output is peinit having been asked.
local LS_CONTROL = [[
case "$(token user)" in *S-1-5-19*) : ;; *) exit 11 ;; esac
out=$(svctl --json status registryd 2>&1); rc=$?
[ "$rc" = 69 ] && exit 12
case "$out" in *'"status":'*) exit 0 ;; esac
exit 13
]]

local vm = peinit.boot({
    name = "surface",
    files = peinit.seed("pt-surface", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        service("pt-ls-control", "LocalService", "/bin/sh", { "-c", LS_CONTROL }),
        service("pt-ls-live", "LocalService", "/bin/sleep", { "300" }),
    }),
})

--- Assert a probe service ran and reached `exit 0`.
---
--- The wait is for the boot start operation to finish rather than for
--- the service: these order after authd, so Phase 2 can report the boot
--- complete while their start is still in flight, and a status read at
--- that moment says nothing either way.
local function ran_clean(t, name, what)
    local status = wait_until(function()
        local r = vm:run("svctl --json status " .. name)
        if r:ok() and r.stdout:find('"current_operation":null', 1, true) then
            return r.stdout
        end
    end, { timeout = 30, desc = name .. "'s boot start to settle" })
    t:assert(status:find('"state":"inactive"', 1, true) and
             status:find('"cause":"clean_exit"', 1, true),
        what .. " (" .. name .. " exited 0): " .. status)
end

--- A primary-shaped impersonation token for USER: Everyone and
--- Authenticated Users, plus whatever `extra` groups are named. No
--- Administrators and, unless asked for, no Service group — a principal
--- that is neither a service nor an administrator.
---
--- SeChangeNotifyPrivilege because a minted token holds no privileges at
--- all, and without it the walk to /run/services/peinit fails on
--- traverse before the socket is reached: that directory grants the
--- Service group traverse and nobody else outside SYSTEM and
--- Administrators, and a refusal there would be the directory's, not
--- the socket's.
local function mint_user(w, extra)
    local enabled = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT
        | token.GROUP.ENABLED
    local groups = {
        { sid = token.SID.EVERYONE, attributes = enabled },
        { sid = token.SID.AUTHENTICATED_USERS, attributes = enabled },
    }
    for _, sid in ipairs(extra or {}) do
        groups[#groups + 1] = { sid = sid, attributes = enabled }
    end
    local notify = token.bit(token.PRIV.CHANGE_NOTIFY)
    return assert(token.mint(w, {
        user_sid = USER,
        token_type = token.TYPE.IMPERSONATION,
        impersonation_level = token.LEVEL.IMPERSONATION,
        groups = groups,
        privs_present = notify,
        privs_enabled = notify,
    }))
end

--- Every `notify.rejected` still in the KMES ring, as sender pids.
local function rejected_senders()
    local r = vm:run("revstrm --snapshot --pretty --type 'notify.rejected'", { timeout = 60 })
    r:assert_ok()
    local pids = {}
    for pid in r.stdout:gmatch("sender_pid%s+(%d+)") do pids[#pids + 1] = pid end
    return pids
end

local function contains(list, value)
    for _, item in ipairs(list) do
        if item == value then return true end
    end
    return false
end

test("a principal the notification socket's descriptor excludes is refused at connect",
    { spec = "peinit *surface.a-refused-connect-never-reaches-peinit" },
    function(t)
        f.with_worker(vm, function(w)
            local pid = tostring(w:syscall(39).ret)
            local outsider = mint_user(w)

            -- A user that is not a service: no SYSTEM, no S-1-5-6. Both
            -- the connect and an unconnected send are refused with EACCES
            -- by the kernel, so nothing reaches peinit to be authenticated
            -- or recorded.
            local fd = assert(us.socket(w, us.AF_UNIX, us.SOCK.DGRAM))
            t:assert_eq(token.impersonate(w, outsider).ret, 0, "impersonating the outsider")
            local connected = us.connect(w, fd, NOTIFY_SOCKET)
            local sent = us.sendto(w, fd, "STATUS=from outside", NOTIFY_SOCKET)
            token.revert(w)
            t:assert(connected.ret ~= 0, "the connect was refused")
            t:assert_eq(connected.errno, EACCES,
                "by the filesystem's access check: " .. us.errname(connected.errno))
            t:assert_eq(sent.errno, EACCES,
                "and so was a datagram addressed to the path: " .. us.errname(sent.errno))
            t:assert(not contains(rejected_senders(), pid),
                "peinit recorded nothing, because it was never handed a datagram to refuse")

            -- The control: the same user with the Service group added is
            -- admitted, and what it sends reaches peinit. The worker is
            -- nobody's main job, so peinit refuses the datagram itself —
            -- and records that it did, which is the record the refusal at
            -- connect() above could not produce.
            local member = mint_user(w, { SERVICE_GROUP })
            local admitted = assert(f.connect_as(w, NOTIFY_SOCKET, us.SOCK.DGRAM, member))
            t:assert(us.sendmsg(w, admitted, "STATUS=from a member").ret > 0,
                "a member of the Service group may send")
            local recorded = wait_until(function()
                return contains(rejected_senders(), pid) or nil
            end, { timeout = 30, interval = 0.5,
                   desc = "peinit to record the datagram it was handed" })
            t:assert(recorded,
                "and its datagram reached peinit, which recorded the rejection")

            -- And the refusal is that socket's: the outsider who could not
            -- reach the notification socket is admitted on the control
            -- socket and answered there by peinit.
            local control = assert(f.connect_as(w, f.CONTROL_SOCKET, us.SOCK.STREAM, outsider))
            local answer = f.control_request(w, control,
                '{"command":"status","service":"registryd"}')
            t:assert(answer and answer:find('"status":', 1, true),
                "the same principal reached peinit on the control socket: " .. tostring(answer))
        end)
    end)

test("a LocalService caller reaches peinit on the control socket rather than being refused",
    {
        spec = {
            "peinit *control.the-socket-descriptor",
            "peinit *notify.the-socket-descriptor",
        },
    },
    function(t)
        -- The control socket admits every authenticated principal, so a
        -- service running as LocalService — neither SYSTEM nor an
        -- administrator — is not refused at connect(): its command is
        -- answered by peinit, which decides it against the service's
        -- descriptor.
        ran_clean(t, "pt-ls-control",
            "a LocalService caller was answered by peinit rather than refused at connect()")

        -- The same identity, asked of the filesystem directly. `sd check`
        -- runs the kernel's own access check against a named process's
        -- token, which is the check `connect()` makes: write access on
        -- the socket inode.
        local pid = wait_until(function()
            local r = vm:run("svctl --json status pt-ls-live")
            local running = r:ok() and r.stdout:match('"pid":(%d+)')
            if running then return running end
        end, { timeout = 30, desc = "the LocalService probe process to be running" })

        local user = vm:run("token user --pid " .. pid)
        user:assert_ok()
        t:assert(user.stdout:find("S-1-5-19", 1, true),
            "the probe process really runs as LocalService: " .. user.stdout)

        local function may_write(path)
            local check = vm:run("sd check " .. path .. " w --pid " .. pid)
            check:assert_ok()
            return check.stdout:find("granted:%s+true") ~= nil, check.stdout
        end

        -- All three doors admit it: the control and jobs sockets by their
        -- Authenticated Users ACE, and the notification socket because
        -- every token peinit mints for a service carries S-1-5-6.
        local control, control_text = may_write("/run/services/peinit/control.sock")
        t:assert(control, "the control socket admits this principal: " .. control_text)
        local jobs, jobs_text = may_write("/run/services/peinit/jobs.sock")
        t:assert(jobs, "so does the jobs socket: " .. jobs_text)
        local notify, notify_text = may_write(NOTIFY_SOCKET)
        t:assert(notify, "and the notification socket, as a service: " .. notify_text)
    end)
