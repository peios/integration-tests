-- trustd comes back after a restart (PEI-1373).
--
-- trustd, like resolvd and timed, leaves its socket in /run/trustd when it
-- ends, and peinit keeps the directory across a restart. The descriptor it
-- wrote on both once named SYSTEM and Everyone alone, so the next run
-- could not delete the stale socket: every restart failed with EACCES at
-- the bind and crash-looped until a reboot. It now keeps its own SID's
-- full access (trustd 3306052). No trustd TRM states this yet, so the test
-- cites no anchor; resolvd's equivalent is
-- `resolvd *sockets.stale-socket-removed-on-restart` (resolvd-sockets).
--
-- Harness: a whole Peios (helpers.network) with trustd under peinit; no
-- network is needed. trustd is read on its socket (`status`) and in
-- eventd's copy of its standard error.
--
-- Own VM: trustd is stopped, restarted and killed.

local peinit = require("helpers.peinit")
local network = require("helpers.network")

peinit.claim(1)

local sut = network.boot()

local SOCK = "/run/trustd/trust.sock"
local FATAL = "trustd: error: control socket: Permission denied (os error 13)"
local REMOVED = "trustd: warn: removed a stale /run/trustd/trust.sock"

local function tpid() return peinit.pid_of_comm(sut, "trustd") end

--- Wait until a trustd other than `old` answers `status` on its socket.
local function answering(old)
    wait_until(function()
        local p = tpid()
        if not p or p == old then return false end
        local s = network.call(sut, { query = "status" }, { path = SOCK, timeout_ms = 500 })
        return s ~= nil and s.ok ~= false
    end, { timeout = 30, interval = 0.25, desc = "a trustd answering on " .. SOCK })
    return tpid()
end

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- trustd's log lines after `since` (ns), oldest first.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM trustd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then newest_first[#newest_first + 1] = (msg:gsub("\\(.)", "%1")) end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function check(t, how, old, mark)
    local ok, pid = pcall(answering, old)
    local lines = log_since(mark)
    t:log(how .. ": pid " .. tostring(old) .. " -> " .. tostring(pid) .. "\n" .. table.concat(lines, "\n")
        .. "\n" .. sut:run("svctl status trustd").stdout)
    t:assert(ok, how .. ": a new trustd answers on " .. SOCK)
    local fatal, removed = false, false
    for _, l in ipairs(lines) do
        if l == FATAL then fatal = true end
        if l == REMOVED then removed = true end
    end
    t:assert(not fatal, how .. ": no run failed at the control socket")
    t:assert(removed, how .. ": the new run removed the stale socket and logged it at warn")
    return pid
end

test("a start after a stop, svctl restart, and a restart after SIGKILL each bring back a trustd answering on its socket",
    {}, function(t)
        local before = answering(nil)
        sut:run("svctl stop trustd"):assert_ok()
        wait_until(function() return tpid() == nil end, { timeout = 30, interval = 0.25, desc = "trustd stopped" })
        t:assert_eq(sut:stat(SOCK).entry_type, "socket", "the stopped trustd left its socket behind")
        local mark = guest_ns()
        sut:run("svctl start trustd"):assert_ok()
        local p1 = check(t, "svctl stop; svctl start", before, mark)

        mark = guest_ns()
        sut:run("svctl restart trustd"):assert_ok()
        local p2 = check(t, "svctl restart", p1, mark)

        mark = guest_ns()
        peinit.signal(sut, p2, "KILL")
        check(t, "SIGKILL and the restart policy", p2, mark)
    end)
