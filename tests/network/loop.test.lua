-- netd §2.2 — The loop: one thread around one poll(2), a kernel event
-- answered by a fresh dump and a full pass, the full pass's step order,
-- its repetition while the kernel keeps changing, and a lease marking
-- its interface to be judged again.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). Kernel events are made from the agent
-- (`ntfe.if_down`, `rtnl.add_address`), and the cable is pulled with
-- provium's NIC (`lan:nic(sut)`).
--
-- netd's log is the evidence for ORDER inside one pass, which nothing
-- else shows: a pass logs a line at each step that does something
-- (`network <id>` when it identifies, `JOIN(...) by <rule>` when a
-- verdict changes, `dhcp starting`, `applying [...]`), and the machine
-- readiness line is logged by the publish that follows the repeats.
--
-- Own VMs: the tests pull the cable, take the link down and add rules
-- that switch eth0's profile; each puts the baseline back.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local ntfe = require("helpers.ntfe")
local unixsock = require("helpers.unixsock")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- netd's log lines newer than `since` (guest ns), oldest first. evctl
--- lists newest first in the order eventd recorded them; lines written
--- together can carry one timestamp, so that order (not the timestamp)
--- is the sequence.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM netd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function find(lines, text, from, to)
    for i = from or 1, to or #lines do
        if lines[i] and lines[i].msg:find(text, 1, true) then return i end
    end
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = l.msg end
    t:log("netd log:\n" .. table.concat(out, "\n"))
end

local function rebind(t, why)
    local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
    t:assert(s, why or "eth0 holds a bound lease")
    return s
end

local function apply(doc)
    sut:write_file("/tmp/pt-batch.json", json.encode(doc))
    network.reg(sut, { "apply", "/tmp/pt-batch.json" }):assert_ok()
end

-- ---------------------------------------------------------------------------
-- One thread, one poll
-- ---------------------------------------------------------------------------

test("netd is one thread blocked in one poll(2)",
    { spec = "netd *loop.one-thread-one-poll" }, function(t)
        rebind(t, "bound")
        local pid = network.netd_pid(sut)
        t:assert(pid, "netd's pid")
        local status = sut:read_file("/proc/" .. pid .. "/status")
        t:assert_eq(status:match("\nThreads:%s*(%d+)"), "1", "one thread")
        local tasks = sut:listdir("/proc/" .. pid .. "/task")
        t:log("tasks: " .. json.encode(tasks))
        t:assert_eq(#tasks, 1, "one task under /proc/<pid>/task")
        -- Idle, the one thread is in poll(2) (x86_64 syscall 7).
        local idle = 0
        for _ = 1, 5 do
            local sc = sut:read_file("/proc/" .. pid .. "/syscall")
            local wchan = sut:read_file("/proc/" .. pid .. "/wchan")
            t:log("syscall: " .. sc:gsub("\n", "") .. "  wchan: " .. wchan)
            if sc:match("^7 ") and wchan == "do_sys_poll" then idle = idle + 1 end
            sut:run("sleep 0.2")
        end
        t:assert(idle >= 4, "netd waits in poll(2): " .. idle .. " of 5 samples")
        -- One thread means a handler that blocks holds everything: a
        -- connection that sends nothing keeps netd in its read for up to
        -- 2 s (PEI-1329, the documented current behaviour), and a second
        -- client waits for it.
        local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
        local r = unixsock.connect(sut, fd, network.CONTROL)
        t:assert_eq(r.ret, 0, "connected without sending")
        local m = sut:run("s=$(date +%s%N); net status >/dev/null; e=$(date +%s%N); echo $(( (e - s) / 1000000 ))")
        sys.close(sut, fd)
        local ms = tonumber(m.stdout:match("%d+"))
        t:log("net status took " .. tostring(ms) .. " ms behind a silent connection")
        t:assert(ms and ms >= 1000, "the second client waited for the first's handler")
        -- Unblocked, the same request is quick.
        local q = sut:run("s=$(date +%s%N); net status >/dev/null; e=$(date +%s%N); echo $(( (e - s) / 1000000 ))")
        local quick = tonumber(q.stdout:match("%d+"))
        t:log("and " .. tostring(quick) .. " ms on its own")
        t:assert(quick and quick < ms - 500, "alone it does not wait")
    end)

-- ---------------------------------------------------------------------------
-- Kernel events
-- ---------------------------------------------------------------------------

test("a kernel event leads to a fresh dump and a full pass",
    { spec = "netd *loop.kernel-event-redumps-and-converges" }, function(t)
        local s = rebind(t, "bound")
        local index = network.iface(s, "eth0").index
        -- A foreign address: the kernel's event is netd's only input.
        local mark = guest_ns()
        t:assert(rtnl.add_address(sut, index, "10.77.0.99", { prefix = 24 }), "a foreign address added")
        wait_until(function() return rtnl.address(sut, index, "10.77.0.99") == nil end,
            { timeout = 10, interval = 0.2, desc = "netd to remove the foreign address" })
        local lines = log_since(mark)
        dump(t, lines)
        t:assert(find(lines, "DelAddress(Address { index: " .. index .. ", address: 10.77.0.99") ~= nil,
            "the pass the event caused removed it")

        -- The link taken down: only a full pass judges carrier and starts
        -- a client (a reconcile never does), so `carrier lost` and a new
        -- `dhcp starting` with no other input show the event led to one.
        mark = guest_ns()
        t:assert(ntfe.if_down(sut, "eth0"), "eth0 taken down from the agent")
        local b = rebind(t, "netd brought eth0 back up and bound again")
        lines = log_since(mark)
        dump(t, lines)
        local lost = find(lines, "interface eth0: carrier lost")
        local up = find(lines, "applying [LinkUp(" .. index .. ")")
        local start = find(lines, "interface eth0: dhcp starting")
        t:log(string.format("carrier lost=%s LinkUp=%s dhcp starting=%s", tostring(lost), tostring(up), tostring(start)))
        t:assert(lost and up and start, "judged without carrier, brought up, and the client restarted")
        t:assert(lost < up and up < start, "in that order")
        t:assert_eq(network.iface(b, "eth0").up, true, "eth0 is up")
    end)

test("a full pass repeats while the kernel's state keeps changing, before it publishes",
    { spec = "netd *loop.converge-repeats-until-stable" }, function(t)
        -- Taking eth0 down makes one pass bring it up, after which the
        -- kernel shows carrier: that is a different dump, so the steps run
        -- again and the second round starts the DHCP client. Publishing
        -- (the machine readiness line) comes once, after the repeats, so
        -- the client is started BEFORE the new level is published. With
        -- one pass per event, `machine readiness is link` would come first
        -- and the client would wait for the next event.
        -- The bound (the steps run at most four times in one pass) is
        -- unanchored prose in §2.2: no state this guest can make keeps the
        -- kernel changing on every pass, so nothing outside can observe it.
        local s = rebind(t, "bound")
        t:assert_eq(s.level, "routed", "the machine starts routed")
        local index = network.iface(s, "eth0").index
        local mark = guest_ns()
        t:assert(ntfe.if_down(sut, "eth0"), "eth0 taken down from the agent")
        rebind(t, "bound again")
        local lines = log_since(mark)
        dump(t, lines)
        local up = find(lines, "applying [LinkUp(" .. index .. ")")
        local start = find(lines, "interface eth0: dhcp starting", up)
        local level = find(lines, "machine readiness is ")
        t:log(string.format("LinkUp=%s dhcp starting=%s first readiness=%s (%s)", tostring(up),
            tostring(start), tostring(level), level and lines[level].msg or "-"))
        t:assert(up and start and level, "each logged")
        t:assert(up < start, "the client starts in a later round than the link-up")
        t:assert(start < level, "and before the pass publishes: the round repeated within one pass")
        t:assert_eq(lines[level].msg, "netd: info: machine readiness is link",
            "the first level published is the one after both rounds")
    end)

-- ---------------------------------------------------------------------------
-- A lease and re-judgement
-- ---------------------------------------------------------------------------

local episode -- the log of the lease that switched eth0's profile

test("a lease marks its interface for re-judgement, so its iteration runs a full pass",
    { spec = "netd *loop.lease-marks-for-rejudgement" }, function(t)
        local s = rebind(t, "bound")
        local netid = network.iface(s, "eth0").network
        t:assert(netid, "the network is identified")
        local nic = lan:nic(sut)
        nic:disconnect()
        local off = network.serve_until(gw, sut, function(i) return i.carrier == false and i.network == nil end,
            { iface = "eth0", timeout = 30 })
        t:assert(off, "carrier gone, and the network with it")
        -- A rule that speaks only once the network is identified, for a
        -- profile with a static address of its own, so the pass that
        -- switches to it has something to reconcile.
        apply({ keys = {
            { path = [[Machine\System\Network\Profiles\pt-home]],
              values = { { name = "Address.Offered", type = "dword", data = 1 },
                         { name = "Address.Static", type = "multi", data = { "10.77.0.60/24" } } } },
            { path = [[Machine\System\Network\Rules\Interface\pt-home]],
              values = { { name = "Network.Id.Equal", type = "sz", data = netid },
                         { name = "Priority", type = "dword", data = 20 },
                         { name = "Actions", type = "multi", data = { "JOIN(pt-home)" } } } },
        } })
        local before = network.status(sut)
        t:assert_eq(before.refusal, nil, "the rule is taken")
        t:assert_eq(network.iface(before, "eth0").rule, "wired", "and does not speak while no network is known")

        local mark = guest_ns()
        nic:reconnect()
        local home = network.serve_until(gw, sut,
            function(i) return i.profile == "pt-home" and network.bound(i) end,
            { iface = "eth0", timeout = 60 })
        t:assert(home, "the lease identified the network and eth0 joined pt-home")
        episode = log_since(mark)
        dump(t, episode)
        local lease = find(episode, "interface eth0: lease 10.77.0.50/24 from 10.77.0.1")
        local ident = find(episode, "interface eth0: network " .. netid, lease)
        local judged = find(episode, "interface eth0: JOIN(pt-home) by pt-home", lease)
        t:log(string.format("lease=%s network=%s judged=%s", tostring(lease), tostring(ident), tostring(judged)))
        t:assert(lease and ident and judged, "lease, identification and re-judgement logged")
        t:assert(lease < ident and ident < judged, "in that order")
        -- A reconcile alone would have applied the leased address before
        -- any pass identified the network; the mark sent the lease's own
        -- iteration through a full pass instead.
        t:assert_eq(find(episode, "applying", lease, judged), nil,
            "nothing was applied between the lease and the re-judgement")

        -- Put it back.
        network.delete(sut, [[Rules\Interface\pt-home]]):assert_ok()
        network.delete(sut, [[Profiles\pt-home]]):assert_ok()
        local back = network.serve_until(gw, sut,
            function(i) return i.profile == "default" and network.bound(i) end,
            { iface = "eth0", timeout = 60 })
        t:assert(back, "eth0 is back on default and bound")
    end)

test("a full pass identifies, judges, starts clients, then reconciles, in that order",
    { spec = "netd *loop.full-pass-sequence" }, function(t)
        t:assert(episode, "the previous test's pass was recorded")
        local lease = find(episode, "interface eth0: lease 10.77.0.50/24 from 10.77.0.1")
        t:assert(lease, "the lease")
        -- The pass the lease caused: everything after it up to the next
        -- lease line (the pt-home client's own).
        local stop = find(episode, "interface eth0: lease ", lease + 1) or #episode + 1
        local ident = find(episode, "interface eth0: network ", lease, stop - 1)
        local judged = find(episode, "interface eth0: JOIN(pt-home) by pt-home", lease, stop - 1)
        local dhcp = find(episode, "interface eth0: dhcp starting", lease, stop - 1)
        local ipv6 = find(episode, "interface eth0: soliciting routers", lease, stop - 1)
        local applied = find(episode, "interface eth0: applying ", lease, stop - 1)
        t:log(string.format("1 identify=%s 2 judge=%s 3 dhcp=%s 4 ipv6=%s 5 reconcile=%s",
            tostring(ident), tostring(judged), tostring(dhcp), tostring(ipv6), tostring(applied)))
        t:assert(ident and judged and dhcp and applied, "steps 1, 2, 3 and 5 each logged in the pass")
        t:assert(ident < judged, "identify (1) before judge (2)")
        t:assert(judged < dhcp, "judge (2) before the DHCPv4 clients (3)")
        t:assert(dhcp < applied, "the DHCPv4 clients (3) before the reconcile (5)")
        if ipv6 then
            t:assert(dhcp < ipv6 and ipv6 < applied, "router discovery (4) between 3 and 5")
        end
        t:assert(episode[applied].msg:find("AddAddress(Address { index: " .. network.iface(network.status(sut), "eth0").index
            .. ", address: 10.77.0.60", 1, true) ~= nil,
            "the reconcile applied the new profile's static address")
    end)
