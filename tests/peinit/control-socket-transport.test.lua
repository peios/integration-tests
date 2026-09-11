-- Peinit TRM §10.1 — the control socket as a transport: its three
-- limits, what peinit sets on what it creates, and what a connection may
-- do while a wait is pending on it.
--
-- svctl is the only control client the image ships, and it never tests
-- a limit: one request per connection, answered before it sends another,
-- never oversized. The client here is `pt-ctl` (tests/tools/pt-ctl.c),
-- which speaks the same newline-framed JSON but does what it is told —
-- holds a connection idle, sends a frame past the bound, pipelines a
-- request behind a wait — and reports when each answer arrived and
-- whether the connection survived.
--
-- The limits are seeded down so the claims are about the bounds and not
-- their values: a 4 KiB frame, four seconds idle, three connections.
-- registry/config.rs takes each value as it is, so what is seeded is
-- what peinit runs with. The file's own svctl calls are made outside the
-- window where the connection limit is full.

local peinit = require("helpers.peinit")
peinit.claim(1)

local MAX_REQUEST = 4096
local IDLE_TIMEOUT = 4
local MAX_CONNECTIONS = 3
local CONTROL_SOCKET = "/run/services/peinit/control.sock"

--- A demand-started Oneshot that runs `/bin/sleep seconds`. A `start`
--- with wait on it is answered when the sleep ends, which makes it a wait
--- of a known length that the test can hold a connection on.
local function sleeper(name, seconds)
    return {
        path = [[Machine\System\Services\]] .. name,
        values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { tostring(seconds) } },
            { name = "Type", type = "dword", data = 1 },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
        },
    }
end

local vm = peinit.boot({
    name = "control-transport",
    files = peinit.merge(
        peinit.tool("pt-ctl"),
        peinit.seed("pt-control-transport", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Init]], values = {
                { name = "MaxRequestSize", type = "dword", data = MAX_REQUEST },
                { name = "ConnectionTimeout", type = "dword", data = IDLE_TIMEOUT },
                { name = "MaxControlConnections", type = "dword", data = MAX_CONNECTIONS },
            } },
            { path = [[Machine\System\Services]] },
            sleeper("pt-hold", 12),
            sleeper("pt-pipe", 3),
        })
    ),
})

--- Run pt-ctl with `steps` on one connection and parse its report, as
--- `{replies = {{at, json}, …}, closed = bool, raw = …}`. `closed` is the
--- manager ending the connection: end of file where an answer was
--- expected, or a send refused because the far end had gone.
local function pt_ctl(steps, name)
    local log = "/run/pt-ctl-" .. name .. ".log"
    local quoted = {}
    for _, step in ipairs(steps) do
        quoted[#quoted + 1] = "'" .. step .. "'"
    end
    local r = vm:run("pt-ctl --log " .. log .. " " .. table.concat(quoted, " "),
        { timeout = 60 })
    local text = tostring(vm:read_file(log))
    local out = { replies = {}, raw = text, exit_code = r.exit_code }
    local current
    for line in text:gmatch("[^\r\n]+") do
        local at = line:match("^reply rc=%d+ at=([%d%.]+)")
        if at then
            current = { at = tonumber(at) }
            out.replies[#out.replies + 1] = current
        end
        local json = line:match("^reply%-json (.*)$")
        if json and current then current.json = json end
        if line:match("^reply closed") or line:match("^send rc=%-1") then out.closed = true end
    end
    return out
end

--- A file's contents, or "" while it does not exist yet. `wait_until`
--- re-raises a predicate's error rather than retrying, so a poll on a log
--- its writer has not created yet must not raise.
local function read_if_present(path)
    local ok, text = pcall(function() return vm:read_file(path) end)
    return ok and tostring(text) or ""
end

local function field(reply, name)
    return reply and reply.json and reply.json:match('"' .. name .. '":"([^"]+)"')
end

local function status_request(service)
    return '{"command":"status","service":"' .. service .. '"}'
end

-- ---- request size ------------------------------------------------------

test("a frame past MaxRequestSize is REQUEST_TOO_LARGE, and the connection goes with it",
    { spec = "peinit *control.max-request-size" },
    function(t)
        -- A status request padded with a field peinit does not recognise,
        -- which PSPU §4.8 says is ignored, so the one thing wrong with the
        -- larger of the two is its size.
        local function padded(n)
            return '{"command":"status","service":"pt-hold","pad":"' .. string.rep("A", n) .. '"}'
        end
        local fits, big = padded(MAX_REQUEST - 200), padded(MAX_REQUEST)
        assert(#fits < MAX_REQUEST and #big > MAX_REQUEST)

        local under = pt_ctl({ fits }, "fits")
        t:assert_eq(field(under.replies[1], "status"), "ok",
            "a frame just under the bound is answered: " .. under.raw)

        -- Frame-level, per PSPU §4.5: peinit no longer knows where the
        -- next frame begins, so it answers and closes.
        local over = pt_ctl({ big, status_request("pt-hold") }, "big")
        t:assert_eq(field(over.replies[1], "code"), "REQUEST_TOO_LARGE",
            "the same request past the bound is too large: " .. over.raw)
        t:assert(over.closed, "and the connection is closed behind it: " .. over.raw)
        t:assert_eq(#over.replies, 1,
            "so the request after it is never answered: " .. over.raw)
    end)

-- ---- idle timeout ------------------------------------------------------

test("a connection idle past ConnectionTimeout is closed",
    { spec = "peinit *control.connection-timeout" },
    function(t)
        local brief = pt_ctl({ "sleep", "1", status_request("pt-hold") }, "brief")
        t:assert_eq(field(brief.replies[1], "status"), "ok",
            "a connection idle for one second is still served: " .. brief.raw)

        local long = pt_ctl({ "sleep", tostring(IDLE_TIMEOUT + 3), status_request("pt-hold") },
            "idle")
        t:assert(long.closed,
            "one idle for " .. (IDLE_TIMEOUT + 3) .. "s against a " .. IDLE_TIMEOUT
            .. "s timeout was closed: " .. long.raw)
        t:assert_eq(#long.replies, 0, "and its request went unanswered: " .. long.raw)
    end)

-- ---- connection limit --------------------------------------------------

--- Established connections to the control socket, from /proc/net/unix:
--- accepted server-side sockets carry the listener's path and state 03,
--- the listener itself is state 01.
local function established()
    local text = tostring(vm:read_file("/proc/net/unix"))
    local n = 0
    for line in text:gmatch("[^\r\n]+") do
        if line:find(CONTROL_SOCKET, 1, true) and line:match("%s03%s+%d+%s") then
            n = n + 1
        end
    end
    return n
end

test("a connection past MaxControlConnections is closed without a response",
    {
        spec = {
            "peinit *control.max-control-connections",
            "peinit *control.an-inadmissible-connection-is-closed-without-a-response",
        },
    },
    function(t)
        -- The first connections have to stay held, and a pending wait is
        -- what holds one: a connection with work in flight is never idle,
        -- so the four-second timeout does not free a slot under the test.
        -- The holders all wait on one start of pt-hold, which merges them
        -- onto a single operation that ends when its twelve-second sleep
        -- does.
        --
        -- Anything in the image that already holds a control connection
        -- takes a slot too, so the holders make up the difference from
        -- what is established now rather than assuming nobody else is
        -- connected.
        --
        -- The anchor's other half, a peer whose token cannot be obtained,
        -- is not reachable from a guest process: every process has one.
        local baseline = established()
        t:assert(baseline < MAX_CONNECTIONS,
            "the image leaves room under the bound to test it (" .. baseline .. " held)")
        local wait = '{"command":"start","service":"pt-hold","wait":true}'
        local holders = MAX_CONNECTIONS - baseline
        for k = 1, holders do
            vm:run("( pt-ctl --log /run/pt-ctl-hold" .. k .. ".log '" .. wait
                .. "' ) >/dev/null 2>&1 &")
        end
        wait_until(function() return established() == MAX_CONNECTIONS end,
            { timeout = 30, desc = "the bound to fill" })

        local over = pt_ctl({ status_request("pt-hold") }, "over")
        t:assert(over.closed, "one connection past the bound was closed: " .. over.raw)
        t:assert_eq(#over.replies, 0,
            "without any response, since no protocol state exists to deliver one in: " .. over.raw)

        -- And it is the bound rather than a broken socket: once the start
        -- the holders wait on completes, they are answered and let go, and
        -- a new connection is served again.
        for k = 1, holders do
            wait_until(function()
                return read_if_present("/run/pt-ctl-hold" .. k .. ".log"):find("reply%-json")
            end, { timeout = 40, desc = "holder " .. k .. " to be answered" })
        end
        local after = wait_until(function()
            local r = pt_ctl({ status_request("pt-hold") }, "after")
            if field(r.replies[1], "status") == "ok" then return r end
        end, { timeout = 30, desc = "a slot to free" })
        t:assert(after, "a connection is served once the holders are released")
    end)

-- ---- pipelining --------------------------------------------------------

-- PEI-1073, for both tests below. Each readable turn drains the kernel
-- buffer into the connection's own read buffer and then processes one
-- frame (supervisor/control_connection/turn/standard.rs); nothing goes
-- back for a second complete frame already buffered, and the kernel,
-- emptied, has no readiness left to signal. Behind a wait that is
-- certain: `flush_terminal_control_waits` (…/wait.rs) answers the wait and
-- never looks at what was buffered meanwhile, so the pipelined request is
-- stranded until ConnectionTimeout closes the connection with it
-- unanswered. Without a wait it happens whenever frames coalesce.

test("a request pipelined behind a wait is not read until the wait is answered",
    {
        spec = "peinit *control.pipelined-requests-serialise-behind-a-wait",
        -- PEI-1073, above.
        tags = { "known-bug" },
    },
    function(t)
        local SECONDS = 3

        -- The control: a status request on its own is answered at once.
        local alone = pt_ctl({ status_request("pt-pipe") }, "alone")
        t:assert(alone.replies[1] and alone.replies[1].at < 1,
            "a status request on its own is answered at once: " .. alone.raw)

        -- Both go out before either is read. peinit handles one frame per
        -- turn and reads nothing more from a connection with a wait
        -- pending, so the status sits unread until the start resolves.
        local r = pt_ctl({
            "send-only", '{"command":"start","service":"pt-pipe","wait":true}',
            "send-only", status_request("pt-pipe"),
            "read",
            "read",
        }, "pipelined")
        t:assert_eq(#r.replies, 2, "both were answered in the end: " .. r.raw)
        -- Served while the wait was pending, the status would have come
        -- back first, at once, with the service still activating.
        t:assert(r.replies[1].at >= SECONDS - 1,
            "nothing came back until the start resolved (" .. tostring(r.replies[1].at)
            .. "s): " .. r.raw)
        t:assert(r.replies[1].json:find('"operation', 1, true),
            "the first answer was the start's: " .. tostring(r.replies[1].json))
        t:assert(r.replies[2].at >= r.replies[1].at,
            "and the status came after it: " .. r.raw)
        t:assert(not r.replies[2].json:find('"state":"activating"', 1, true)
                and not r.replies[2].json:find('"state":"active"', 1, true),
            "reporting the service after its run, not during it: " .. tostring(r.replies[2].json))
    end)

test("frames that arrive together are each answered, in order",
    {
        spec = "peinit *control.pipelined-requests-serialise-behind-a-wait",
        -- PEI-1073, above. The same claim without the wait: "serialised"
        -- means every pipelined request is answered in its turn, and the
        -- purest pipelining is frames that reach peinit in one read. Kept
        -- beside the wait case so that a fix which re-drives only after a
        -- wait flush still shows red here.
        tags = { "known-bug" },
    },
    function(t)
        -- Three frames in a single send(2), so they are in the socket
        -- together before peinit reads any of them. Separate sends would
        -- usually each get a readable event of their own and pass by luck.
        local s = status_request("pt-pipe")
        local r = pt_ctl({ "send-raw", s .. "\\n" .. s .. "\\n" .. s .. "\\n",
                           "read", "read", "read" }, "coalesced")
        t:assert_eq(#r.replies, 3, "all three frames were answered: " .. r.raw)
        for k = 1, 3 do
            t:assert_eq(field(r.replies[k], "status"), "ok",
                "frame " .. k .. " was served: " .. tostring(r.replies[k] and r.replies[k].json))
        end
        t:assert(not r.closed, "and the connection was not closed on them: " .. r.raw)
    end)

-- ---- what peinit creates -------------------------------------------------

test("peinit sets no mode bits on the sockets it creates",
    { spec = "peinit *control.no-posix-mode-bits-are-set" },
    function(t)
        -- bind(2) gives a socket inode 0777 less the creator's umask, and
        -- that is all a socket's mode is unless something chmods it. So a
        -- socket peinit never touched has exactly that mode, and one it
        -- had set bits on — 0600, 0660, anything — would not. peinit's
        -- umask is its own to read, in /proc/1/status.
        local status = tostring(vm:read_file("/proc/1/status"))
        local umask = tonumber(status:match("Umask:%s*(%d+)"), 8)
        t:assert(umask, "PID 1 reports its umask: " .. status:sub(1, 200))
        local expected = string.format("%o", 0x1ff & ~umask)

        for _, path in ipairs({
            CONTROL_SOCKET,
            "/run/services/peinit/jobs.sock",
            "/run/services/peinit/notify.sock",
        }) do
            local r = vm:run("stat -c '%F %a' " .. path)
            r:assert_ok()
            local kind, mode = r.stdout:match("^(.-) (%d+)")
            t:assert_eq(kind, "socket", path .. " is a socket: " .. r.stdout)
            t:assert_eq(mode, expected,
                path .. " carries bind's mode under PID 1's umask "
                .. string.format("%03o", umask) .. ", and nothing peinit chose")
        end
    end)
