-- peinit TRM §1 — the introduction's own claims.
--
-- An introduction is usually scene-setting, but this one makes several
-- statements of fact about the running system that nothing else in the
-- manual restates: that peinit is PID 1 and single-threaded, that every
-- supervised process is its child, that it sets no UID, GID or Linux
-- capability on anything it launches, that it keeps no history, and
-- that a daemon which forks and exits is not supervised afterwards.
-- Each of those is checkable against a booted machine, so this file
-- checks them.
--
-- Everything here runs against one VM. Services are created at runtime
-- with `reg` rather than seeded at boot: peinit holds a watch on the
-- registry and any drained event triggers a full reload (§10.4), so a
-- definition written after boot is one peinit knows about a moment
-- later — which is what lets a whole chapter's worth of claims share a
-- single boot.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot()

--- One field out of a /proc/N/status file, as a string.
local function proc_status(pid, field)
    local text = vm:run("cat /proc/" .. pid .. "/status").stdout
    return text:match("\n" .. field .. ":%s*([^\n\r]+)") or text:match("^" .. field .. ":%s*([^\n\r]+)")
end

--- The main process's PID for a service, or nil if it has none.
local function main_pid(service)
    return vm:run("svctl --json status " .. service).stdout:match('"pid":(%d+)')
end

--- Define a service at runtime and wait for peinit to notice it. Returns
--- nothing; the caller starts it.
local function define(name, values)
    vm:run("reg new 'Machine\\System\\Services\\" .. name .. "'"):assert_ok()
    for _, value in ipairs(values) do
        vm:run("reg set 'Machine\\System\\Services\\" .. name .. "' "
            .. value[1] .. " '" .. value[2] .. "'"):assert_ok()
    end
    -- The watch has usually already fired; asking explicitly costs one
    -- round trip and removes the race from the test.
    vm:run("svctl reload-config"):assert_ok()
end

test("peinit is PID 1, and it is one thread",
    {
        spec = {
            "peinit *intro.peinit-is-pid-1",
            "peinit *intro.peinit-is-single-threaded",
        },
    },
    function(t)
        local exe = vm:run("readlink /proc/1/exe")
        exe:assert_ok()
        t:assert(exe.stdout:find("peinit", 1, true),
            "PID 1 is peinit: " .. exe.stdout)

        -- Single-threaded is not a stylistic claim: it is the constraint
        -- the whole design answers to, and the kernel counts threads for
        -- us. A second thread would mean the model of "a blocking
        -- syscall in PID 1 stops everything" no longer holds.
        t:assert_eq(proc_status(1, "Threads"), "1",
            "PID 1 runs exactly one thread")
    end)

test("every supervised process is a child of peinit",
    { spec = "peinit *intro.every-supervised-process-is-forked-by-peinit" },
    function(t)
        -- The claim is about the whole machine, so the subjects are the
        -- image's own services rather than any this test made up.
        local list = vm:run("svctl --json list")
        list:assert_ok()

        local checked = 0
        for service in list.stdout:gmatch('"service":"([^"]+)"') do
            local pid = main_pid(service)
            if pid then
                local ppid = proc_status(pid, "PPid")
                t:assert_eq(ppid, "1",
                    service .. " (pid " .. pid .. ") was forked by peinit")
                checked = checked + 1
            end
        end
        t:assert(checked > 0,
            "the image booted services with running processes to check")
    end)

test("a service process is handed peinit's own UID, GID and capabilities",
    { spec = "peinit *intro.no-uid-gid-or-capability-is-set" },
    function(t)
        -- "peinit never sets a UID, a GID, or a Linux capability" is an
        -- absence, and an absence shows up as inheritance: whatever PID
        -- 1 has is what the child has, because nothing in between
        -- changed it. Identity is carried by the token instead, which is
        -- §4's subject and not restated here.
        define("pt-intro-ids", {
            { "ImagePath", "sz:/bin/sleep" },
            { "Arguments", "multi:100000" },
            { "Identity", "sz:SYSTEM" },
            { "Readiness", "dword:1" },
        })
        vm:run("svctl start pt-intro-ids"):assert_ok()
        local pid = main_pid("pt-intro-ids")
        t:assert(pid, "the service has a main process")

        for _, field in ipairs({ "Uid", "Gid", "CapEff", "CapPrm", "CapBnd" }) do
            t:assert_eq(proc_status(pid, field), proc_status(1, field),
                field .. " is peinit's own, unchanged")
        end
    end)

test("a job that has reached a terminal state is dropped, not kept",
    { spec = "peinit *intro.a-terminal-job-or-operation-is-dropped" },
    function(t)
        -- peinit is not the historian: a finished job is emitted to KMES
        -- and forgotten. So the id of a job that has completed stops
        -- resolving, rather than resolving to a completed job.
        --
        -- A *service's* job, not a submitted one. A submitted job's
        -- outcome is deliberately retained for a grace period so its
        -- submitter can collect it (§8.5), which is an exception to this
        -- rule rather than an instance of it.
        define("pt-intro-oneshot", {
            { "ImagePath", "sz:/bin/sleep" },
            { "Arguments", "multi:3" },
            { "Identity", "sz:SYSTEM" },
            { "Readiness", "dword:1" },
            { "Type", "dword:1" },
        })
        vm:run("svctl start pt-intro-oneshot --no-wait"):assert_ok()

        local id = wait_until(function()
            return vm:run("svctl --json status pt-intro-oneshot").stdout
                :match('"current_job":{"id":"([^"]+)"')
        end, { timeout = 20, desc = "the started service reports a current job" })

        wait_until(function()
            local view = vm:run("svctl --json job status " .. id).stdout
            return not view:find('"id":"' .. id .. '"', 1, true)
        end, { timeout = 30, desc = "the finished job's id stops resolving" })
    end)

test("a daemon that forks and exits is not supervised afterwards",
    { spec = "peinit *intro.forking-daemons-are-not-supported" },
    function(t)
        -- There is no MAINPID and no way to point supervision at a
        -- different process, so peinit's subject is the process it
        -- forked and nothing else. A script that backgrounds its real
        -- work and exits therefore ends the service, while the
        -- background process carries on unwatched.
        vm:run([[echo '/bin/sleep 3600 & echo $! > /run/pt-forked.pid' > /run/pt-fork.sh]])
            :assert_ok()
        define("pt-intro-fork", {
            { "ImagePath", "sz:/bin/sh" },
            { "Arguments", "multi:/run/pt-fork.sh" },
            { "Identity", "sz:SYSTEM" },
            { "Readiness", "dword:1" },
            { "Type", "dword:1" },
        })
        vm:run("svctl start pt-intro-fork")

        wait_until(function()
            local state = vm:run("svctl --json status pt-intro-fork").stdout
                :match('"state":"([^"]+)"')
            return state and state ~= "starting" and state ~= "active"
        end, {
            timeout = 30,
            desc = "the service leaves the running states once its script exits",
        })

        -- Meanwhile the process it backgrounded is still running, and
        -- nothing is watching it. That is the whole of why the pattern
        -- is unsupported: supervision follows the process peinit forked,
        -- there is no `MAINPID=` to point it at another, and the daemon
        -- the service actually left behind is now an orphan that peinit
        -- will neither restart nor stop.
        local forked = vm:run("cat /run/pt-forked.pid").stdout:match("%d+")
        t:assert(forked, "the script recorded the pid it backgrounded")
        t:assert_eq(vm:run("cat /proc/" .. forked .. "/comm").exit_code, 0,
            "the backgrounded process outlived the service peinit was supervising")
    end)

test("registryd is loregd",
    { spec = "peinit *term.registryd-is-loregd" },
    function(t)
        -- The manual calls it registryd throughout and says the
        -- distinction is visible only in recovery mode. Outside recovery
        -- the service is named registryd and the binary behind it is
        -- loregd, which is exactly that claim from the other side.
        local pid = main_pid("registryd")
        t:assert(pid, "registryd has a main process")
        local exe = vm:run("readlink /proc/" .. pid .. "/exe")
        exe:assert_ok()
        t:assert(exe.stdout:find("loregd", 1, true),
            "the process behind registryd is loregd: " .. exe.stdout)
    end)

test("a submitted job's processes live under the jobs cgroup",
    { spec = "peinit *term.a-submitted-job-is-under-the-jobs-cgroup" },
    function(t)
        local submitted = vm:run("svctl --json job submit /bin/sleep 30")
        submitted:assert_ok()
        local pid = submitted.stdout:match('"pid":(%d+)')
        t:assert(pid, "the submission answered with a pid: " .. submitted.stdout)

        local cgroup = vm:run("cat /proc/" .. pid .. "/cgroup").stdout
        t:assert(cgroup:find("/peinit/jobs/", 1, true),
            "a submitted job sits under /sys/fs/cgroup/peinit/jobs/: " .. cgroup)
    end)

test("LimitNOFILE reaches the process, and nothing else is limited",
    { spec = "peinit *compat.rlimit-nofile-and-core-are-the-only-limits" },
    function(t)
        define("pt-intro-limits", {
            { "ImagePath", "sz:/bin/sleep" },
            { "Arguments", "multi:100000" },
            { "Identity", "sz:SYSTEM" },
            { "Readiness", "dword:1" },
            { "LimitNOFILE", "dword:1234" },
        })
        vm:run("svctl start pt-intro-limits"):assert_ok()
        local pid = main_pid("pt-intro-limits")
        t:assert(pid, "the service has a main process")

        local limits = vm:run("cat /proc/" .. pid .. "/limits").stdout
        t:assert(limits:find("1234", 1, true),
            "the definition's LimitNOFILE reached the process: " .. limits)

        -- And the cgroup is for tracking and clean kill only: peinit
        -- sets no accounting or limit knob in it, so the memory
        -- controller's ceiling is still the default.
        local cgroup = vm:run("cat /proc/" .. pid .. "/cgroup").stdout:match("0::([^\n\r]+)")
        t:assert(cgroup, "the process has a cgroup path: " .. cgroup)
        local max = vm:run("cat /sys/fs/cgroup" .. cgroup .. "/memory.max")
        if max.exit_code == 0 then
            t:assert_eq(max.stdout:match("%S+"), "max",
                "peinit set no memory ceiling on the service's cgroup")
        end
    end)
