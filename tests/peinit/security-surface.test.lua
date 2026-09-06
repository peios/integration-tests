-- Peinit TRM §13.3 — what the socket descriptors mean in practice.
--
-- The chapter's claim is about a caller peinit never sees: a principal
-- the control socket's descriptor does not admit is refused at
-- `connect()` by the filesystem, so peinit's own ACCESS_DENIED path and
-- the audit event that goes with it are unreachable for that caller.
--
-- Testing it needs a principal that is neither SYSTEM nor an
-- administrator, and the agent is neither — it runs on peinit's own
-- token. So the caller here is a service. Three definitions are seeded
-- into the registry: two run a shell that probes a door and reports
-- through its exit status, since a service's own output goes to eventd
-- rather than anywhere a test can read it, and the third just sleeps, so
-- that there is a live process of that identity whose token the
-- filesystem's own access check can be run against.
--
-- Each script checks its own identity first. Without that the test would
-- pass just as well against a peinit that ran everything as SYSTEM,
-- which is the failure it exists to detect.

local peinit = require("helpers.peinit")

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

-- svctl exits 69 when it could not reach the socket at all and 1 when
-- peinit answered an error, so the exit code is exactly the distinction
-- the chapter draws. The message is checked too, because 69 alone would
-- also cover a socket that was simply missing.
local LS_CONTROL = [[
case "$(token user)" in *S-1-5-19*) : ;; *) exit 11 ;; esac
out=$(svctl status registryd 2>&1); rc=$?
[ "$rc" = 69 ] || exit 12
case "$out" in *"Permission denied"*) exit 0 ;; esac
exit 13
]]

local SYS_CONTROL = [[
case "$(token user)" in *S-1-5-18*) : ;; *) exit 11 ;; esac
svctl status registryd >/dev/null 2>&1 || exit 12
exit 0
]]

local vm = peinit.boot({
    name = "surface",
    files = peinit.seed("pt-surface", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        service("pt-ls-control", "LocalService", "/bin/sh", { "-c", LS_CONTROL }),
        service("pt-sys-control", "SYSTEM", "/bin/sh", { "-c", SYS_CONTROL }),
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

test("a principal the control socket's descriptor excludes is refused at connect",
    { spec = "peinit *surface.a-refused-connect-never-reaches-peinit" },
    function(t)
        -- The control socket is stamped for SYSTEM and Administrators
        -- only. LocalService is neither, so the kernel refuses the
        -- connect with EACCES before any peer token exists: svctl reports
        -- a transport failure rather than an ACCESS_DENIED, and there is
        -- no denial for peinit to have audited because peinit was never
        -- asked anything.
        ran_clean(t, "pt-ls-control",
            "a LocalService caller was refused at connect() with EACCES, not answered ACCESS_DENIED")

        -- The control: the same command on the same socket in the same
        -- boot, from a principal the descriptor does admit. Without it,
        -- a socket nobody could reach would pass the assertion above.
        ran_clean(t, "pt-sys-control",
            "and a SYSTEM caller was served")
    end)

test("the refusal is the socket's descriptor, not the principal",
    { spec = "peinit *surface.a-refused-connect-never-reaches-peinit" },
    function(t)
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

        local control, control_text = may_write("/run/services/peinit/control.sock")
        t:assert(not control,
            "the control socket denies this principal the write access connect() needs: "
            .. control_text)

        -- And the refusal is that descriptor's alone: the same token is
        -- admitted on the jobs socket, whose descriptor carries an ACE
        -- for every authenticated principal, and on the notification
        -- socket, whose ACE is for the Service group the token also
        -- carries. A service that could reach neither would look the
        -- same from the control socket's side.
        local jobs, jobs_text = may_write("/run/services/peinit/jobs.sock")
        t:assert(jobs, "the jobs socket admits it: " .. jobs_text)
        local notify, notify_text = may_write("/run/services/peinit/notify.sock")
        t:assert(notify, "and so does the notification socket: " .. notify_text)
    end)
