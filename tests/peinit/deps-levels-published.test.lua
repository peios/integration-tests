-- peinit TRM §7.5 — readiness levels that actually arrive.
--
-- deps-levels.test.lua can only watch the gate stay shut: its publisher
-- is netd, which on a loopback-only VM never reaches a level anyone asks
-- for. Everything that needs a level to *arrive* — exactness,
-- retraction, a level outliving its publisher's state, a level falling
-- away under a running dependent, a role with two providers — needs a
-- publisher a test can script, and that is `pt-notify`: a service's own
-- main process, so its datagrams authenticate, sending `LEVEL=` when its
-- script says to.
--
-- A pt-notify script is fixed at exec, so a publisher's timeline is
-- written into its definition. Each one opens with two READY=1s a second
-- apart (the first datagram after exec is routinely refused, see
-- `peinit.tool`), and drops a marker file after each datagram a test
-- needs to wait for — a datagram is only *sent* by then, so every wait
-- on a marker is followed by half a second for peinit's loop to read it.
--
-- Dependents are Oneshots that append a line to /run/<name>.runs, so
-- "ran" is a count, and "held" is the count not moving while the start
-- operation stays open. Everything is started by hand; no boot trigger
-- anywhere, which keeps PEI-829 and PEI-830 (both boot-path) out of it.

local peinit = require("helpers.peinit")
peinit.claim(1, { memory_mib = 800 })

local function publisher_steps(name, steps)
    local out = { "--log", "/run/" .. name .. ".log",
        "sleep", "1", "send", "READY=1", "sleep", "1", "send", "READY=1" }
    for _, step in ipairs(steps) do out[#out + 1] = step end
    out[#out + 1] = "sleep"
    out[#out + 1] = "100000"
    return out
end

local function publisher(name, steps, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/usr/bin/pt-notify" },
        { name = "Arguments", type = "multi", data = publisher_steps(name, steps) },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

--- `send LEVEL=<level>` and a marker once it is sent.
local function level(name, value, marker)
    return { "send", "LEVEL=" .. value, "write", "/run/" .. name .. "." .. marker, "ok" }
end

local function join(...)
    local out = {}
    for _, list in ipairs({ ... }) do
        for _, item in ipairs(list) do out[#out + 1] = item end
    end
    return out
end

local function counted(name, kind, targets, extra)
    local values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi",
          data = { "-c", "echo ran >> /run/" .. name .. ".runs" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Type", type = "dword", data = 1 },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = kind, type = "multi", data = targets },
    }
    for _, value in ipairs(extra or {}) do values[#values + 1] = value end
    return { path = [[Machine\System\Services\]] .. name, values = values }
end

local function resident(name, kind, targets)
    return { path = [[Machine\System\Services\]] .. name, values = {
        { name = "ImagePath", type = "sz", data = "/bin/sleep" },
        { name = "Arguments", type = "multi", data = { "100000" } },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 1 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = kind, type = "multi", data = targets },
    } }
end

--- The second incarnation of pt-lp-clear publishes nothing: the script
--- is chosen by a marker the test drops between the two.
local function clear_arguments()
    local function quoted(list)
        local out = {}
        for _, item in ipairs(list) do out[#out + 1] = "'" .. item .. "'" end
        return table.concat(out, " ")
    end
    local first = publisher_steps("pt-lp-clear", level("pt-lp-clear", "up", "published"))
    local second = publisher_steps("pt-lp-clear", { "write", "/run/pt-lp-clear.second-up", "ok" })
    return { "-c", "if [ -e /run/pt-lp-clear.again ]; then exec /usr/bin/pt-notify " ..
        quoted(second) .. "; else exec /usr/bin/pt-notify " .. quoted(first) .. "; fi" }
end

local SEED = {
    { path = [[Machine\System]] },
    { path = [[Machine\System\Services]] },

    -- Exactness: publishes `routed`, and nothing else.
    publisher("pt-lp-exact", level("pt-lp-exact", "routed", "published")),
    counted("pt-lp-routed", "Requires", { "pt-lp-exact:routed" }),
    counted("pt-lp-addressed", "Requires", { "pt-lp-exact:addressed" }),

    -- Retraction: `up`, then six seconds later the empty value.
    publisher("pt-lp-retract", join(level("pt-lp-retract", "up", "published"),
        { "sleep", "6" }, level("pt-lp-retract", "", "retracted"))),
    counted("pt-lp-onretract", "Requires", { "pt-lp-retract:up" }),

    -- A drop under running dependents: `up`, then eight seconds later
    -- the empty value.
    publisher("pt-lp-drop", join(level("pt-lp-drop", "up", "published"),
        { "sleep", "8" }, level("pt-lp-drop", "", "retracted"))),
    resident("pt-lp-dropreq", "Requires", { "pt-lp-drop:up" }),
    resident("pt-lp-dropbind", "BindsTo", { "pt-lp-drop:up" }),

    -- A level outliving its publisher's state: the first incarnation
    -- publishes `up`, the second nothing.
    { path = [[Machine\System\Services\pt-lp-clear]], values = {
        { name = "ImagePath", type = "sz", data = "/bin/sh" },
        { name = "Arguments", type = "multi", data = clear_arguments() },
        { name = "Identity", type = "sz", data = "SYSTEM" },
        { name = "Readiness", type = "dword", data = 0 },
        { name = "RestartPolicy", type = "dword", data = 0 },
        { name = "StartTimeout", type = "dword", data = 60 },
    } },
    counted("pt-lp-onclear", "Requires", { "pt-lp-clear:up" }),

    -- A role with two providers, one quick to publish and one slow.
    publisher("pt-lp-rolea", level("pt-lp-rolea", "up", "published"),
        { { name = "Provides", type = "multi", data = { "pt-lp-role" } } }),
    publisher("pt-lp-roleb", join({ "sleep", "8" }, level("pt-lp-roleb", "up", "published")),
        { { name = "Provides", type = "multi", data = { "pt-lp-role" } } }),
    counted("pt-lp-onrole", "Requires", { "pt-lp-role:up" }),
}

local vm = peinit.boot({
    memory = "800M",
    name = "levelspub",
    files = peinit.merge(peinit.tool("pt-notify"), peinit.tool("pt-unixpeer"),
        peinit.seed("zz-pt-levelspub", SEED)),
})

local function run(command, seconds)
    return vm:run(command, { timeout = seconds or 30 })
end

local function status(name)
    local out = run("svctl --json status " .. name)
    out:assert_ok()
    local view = json.decode(out.stdout)
    view.raw = out.stdout
    return view
end

local function runs(name)
    local ok, text = pcall(function() return vm:read_file("/run/" .. name .. ".runs") end)
    if not ok then return 0 end
    return #peinit.lines(text)
end

local function marker(name, which)
    wait_until(function()
        return run("test -e /run/" .. name .. "." .. which).exit_code == 0 or nil
    end, { timeout = 60, interval = 0.3, desc = name .. " to reach its `" .. which .. "` marker" })
    -- Sent is not yet read.
    run("sleep 0.5")
end

local function start(name)
    run("svctl --json --no-wait start " .. name):assert_ok()
end

local function ran(name, times)
    wait_until(function() return runs(name) >= times or nil end,
        { timeout = 30, interval = 0.3, desc = name .. " to have run " .. times .. " time(s)" })
end

--- Assert `name` is held: after `seconds`, it has still run only
--- `times` times and its start operation is still open.
local function held(t, name, times, seconds, why)
    run("sleep " .. seconds, seconds + 10)
    local view = status(name)
    t:assert_eq(runs(name), times, why .. ": it has not run again")
    t:assert(view.current_operation and view.current_operation.type == "start",
        why .. ": its start is still pending: " .. view.raw)
end

test("a level is matched exactly: `routed` does not satisfy a dependency on `addressed`",
    { spec = "peinit *ready.a-level-is-matched-exactly-and-never-implied" },
    function(t)
        start("pt-lp-exact")
        marker("pt-lp-exact", "published")

        -- The control: the level the publisher did publish opens the
        -- gate, so the level arrived and peinit read it.
        start("pt-lp-routed")
        ran("pt-lp-routed", 1)

        -- netd knows routed implies addressed; peinit does not, and
        -- does not guess.
        start("pt-lp-addressed")
        held(t, "pt-lp-addressed", 0, 5, "a dependency on `addressed` is not met by `routed`")
    end)

test("an empty LEVEL= retracts the level",
    { spec = "peinit *ready.an-empty-level-retracts-it" },
    function(t)
        start("pt-lp-retract")
        marker("pt-lp-retract", "published")
        start("pt-lp-onretract")
        ran("pt-lp-onretract", 1)

        -- The publisher then sends `LEVEL=` with nothing after it. The
        -- same start that went straight through a moment ago is now held.
        marker("pt-lp-retract", "retracted")
        t:assert_eq(status("pt-lp-retract").state, "active",
            "the publisher is still running: only its level went")
        start("pt-lp-onretract")
        held(t, "pt-lp-onretract", 1, 5, "after the retraction the same dependency waits")
    end)

test("a level dropping after a dependent has started does nothing to the dependent",
    { spec = "peinit *ready.a-level-dropping-after-the-start-does-nothing" },
    function(t)
        start("pt-lp-drop")
        marker("pt-lp-drop", "published")
        start("pt-lp-dropreq")
        start("pt-lp-dropbind")
        local before = {}
        for _, name in ipairs({ "pt-lp-dropreq", "pt-lp-dropbind" }) do
            before[name] = wait_until(function()
                local view = status(name)
                return view.state == "active" and view.current_job and view or nil
            end, { timeout = 30, interval = 0.3, desc = name .. " to be up on the level" })
        end

        -- The level falls away. Neither the Requires nor the BindsTo
        -- dependent is told, stopped or restarted: the gate is a start
        -- gate, and the start has happened.
        marker("pt-lp-drop", "retracted")
        run("sleep 4", 15)
        t:assert_eq(status("pt-lp-drop").state, "active", "the publisher is still up")
        for _, name in ipairs({ "pt-lp-dropreq", "pt-lp-dropbind" }) do
            local after = status(name)
            t:assert_eq(after.state, "active", name .. " is still running: " .. after.raw)
            t:assert_eq(after.current_job.id, before[name].current_job.id,
                name .. " is the same incarnation, not restarted")
            t:assert(not after.current_operation,
                name .. " has nothing in flight against it: " .. after.raw)
        end
    end)

test("a level is cleared when its publisher leaves a state that satisfies dependents",
    { spec = "peinit *ready.a-level-is-cleared-when-its-publisher-stops-satisfying-dependents" },
    function(t)
        start("pt-lp-clear")
        marker("pt-lp-clear", "published")
        start("pt-lp-onclear")
        ran("pt-lp-onclear", 1)

        -- Stop the publisher and start it again. The new incarnation is
        -- Active and publishes nothing. A level that survived the stop
        -- would still read `up`.
        run("touch /run/pt-lp-clear.again"):assert_ok()
        run("svctl stop pt-lp-clear", 60):assert_ok()
        t:assert_eq(status("pt-lp-clear").state, "inactive", "the publisher stopped")
        start("pt-lp-clear")
        marker("pt-lp-clear", "second-up")
        wait_until(function() return status("pt-lp-clear").state == "active" or nil end,
            { timeout = 30, interval = 0.3, desc = "the publisher's second incarnation" })

        start("pt-lp-onclear")
        held(t, "pt-lp-onclear", 1, 5,
            "the level died with the incarnation that published it")
    end)

test("a role with several providers becomes one level entry per provider",
    { spec = "peinit *ready.a-role-with-several-providers-becomes-one-entry-per-provider" },
    function(t)
        -- pt-lp-onrole requires `pt-lp-role:up`, and two services provide
        -- pt-lp-role. Neither is running. Starting the dependent must pull
        -- both in — one entry each — and wait for both levels.
        start("pt-lp-onrole")
        for _, name in ipairs({ "pt-lp-rolea", "pt-lp-roleb" }) do
            local view = wait_until(function()
                local current = status(name)
                return current.state == "active" and current or nil
            end, { timeout = 30, interval = 0.3, desc = name .. " to be started for the dependent" })
            t:assert_eq(view.cause, "dependency_start",
                name .. " was started as one of the dependent's own requirements")
        end

        -- pt-lp-rolea publishes at once; pt-lp-roleb eight seconds later.
        -- One provider's level is not the role's.
        marker("pt-lp-rolea", "published")
        t:assert(run("test -e /run/pt-lp-roleb.published").exit_code ~= 0,
            "pt-lp-roleb has not published yet")
        t:assert_eq(runs("pt-lp-onrole"), 0,
            "the dependent waits while only one provider has the level")
        t:assert(status("pt-lp-onrole").current_operation,
            "with its start still pending")

        marker("pt-lp-roleb", "published")
        ran("pt-lp-onrole", 1)
    end)

--- Every Unix socket `pid` holds, from pt-unixpeer, as records.
local function unix_sockets(pid)
    local out = run("/usr/bin/pt-unixpeer " .. pid)
    out:assert_ok()
    assert(out.stdout:find("\ndone", 1, true) or out.stdout:find("^done"),
        "pt-unixpeer did not finish: " .. out.stdout)
    local records = {}
    for _, line in ipairs(peinit.lines(out.stdout)) do
        local fd, inode, state, peer, pids, path = line:match(
            "^socket pid=%d+ fd=(%d+) inode=(%d+) state=(%d+) peer=(%d+) peer_pids=(%S*) path=(.*)$")
        if fd then
            local owners = {}
            for owner in pids:gmatch("%d+") do owners[#owners + 1] = owner end
            records[#records + 1] = { fd = fd, inode = inode, state = tonumber(state),
                peer = peer, owners = owners, path = path, line = line }
        end
    end
    return records, out.stdout
end

local function main_pid(name)
    local view = status(name)
    return view.current_job and tostring(view.current_job.pid), view.raw
end

test("peinit never connects to a publisher's own socket, and needs none to receive a level",
    { spec = "peinit *ready.peinit-never-connects-to-a-publishers-own-socket" },
    function(t)
        -- A publisher with no socket of its own at all. pt-notify listens
        -- on nothing: it sends datagrams to the notification socket and
        -- that is its whole footprint. Its level still opens a gate, so
        -- there is nothing for peinit to have found or connected to.
        if status("pt-lp-exact").state ~= "active" then
            start("pt-lp-exact")
            marker("pt-lp-exact", "published")
        end
        if runs("pt-lp-routed") == 0 then
            start("pt-lp-routed")
            ran("pt-lp-routed", 1)
        end
        t:assert(runs("pt-lp-routed") >= 1, "pt-lp-exact's level opened a gate")
        local publisher_pid = main_pid("pt-lp-exact")
        local own = unix_sockets(publisher_pid)
        for _, record in ipairs(own) do
            t:assert(record.state ~= 10,
                "pt-lp-exact listens on nothing: " .. record.line)
        end

        -- The shipped publishers. netd and timed are up and hold sockets
        -- of their own; PID 1 holds no connection it made to any of them.
        -- A connection PID 1 accepted on one of its own listeners carries
        -- that listener's path; one PID 1 made does not, so only unnamed
        -- sockets are PID 1's own outbound ends.
        local shipped = {}
        for _, name in ipairs({ "netd", "timed" }) do
            local pid, raw = main_pid(name)
            t:assert(pid, name .. " is running: " .. raw)
            local held = unix_sockets(pid)
            t:assert(#held > 0, name .. " holds Unix sockets of its own")
            shipped[pid] = name
        end

        local pid1, raw = unix_sockets(1)
        t:assert(#pid1 > 0, "pt-unixpeer can see PID 1's sockets: " .. raw)
        for _, record in ipairs(pid1) do
            if record.path == "" then
                for _, owner in ipairs(record.owners) do
                    t:assert(not shipped[owner],
                        "PID 1 holds a connection to " .. tostring(shipped[owner]) ..
                        ": " .. record.line)
                end
            end
        end
    end)
