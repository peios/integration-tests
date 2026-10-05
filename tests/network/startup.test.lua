-- netd §2.1 — Startup: readiness after the first pass and not after a
-- lease, the startup sequence (its order, which failures only degrade
-- netd and which are fatal), a rule tie present at startup, and what a
-- restart changes.
--
-- Harness: the scripted gateway (helpers.gateway) on a per-run bridge
-- and a whole Peios under peinit (helpers.network). netd is restarted
-- through peinit (`svctl`), which is how every startup here after the
-- first is reached.
--
-- Own VMs: the first test needs the boot's own first DHCP exchange to go
-- unanswered, so the gateway starts silent; and the later tests stop,
-- restart and finally break netd's start. The last test leaves netd
-- started again, but it is still the file's last.
--
-- netd's log is used for the order of the startup steps, which nothing
-- else shows: each step that degrades netd logs one line, and the line
-- after the kernel dump (`N rule tree(s), N profile(s), N link(s)`)
-- separates the steps before the dump from the first pass.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- Silent from the start: the boot's first DISCOVERs are recorded and
-- never answered, so no lease can exist when netd reports READY=1.
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, silent = true })
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

--- The guest's realtime clock, ns (eventd stamps log lines with it).
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

--- Index of the first line at or after `from` containing `text`.
local function find(lines, text, from)
    for i = from or 1, #lines do
        if lines[i].msg:find(text, 1, true) then return i end
    end
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = l.msg end
    t:log("netd log:\n" .. table.concat(out, "\n"))
end

--- peinit's view of netd.
local function svc()
    local r = sut:run("svctl --json status netd")
    return json.decode(r.stdout) or {}
end

--- Wait until peinit has no operation in flight on netd.
local function settle()
    wait_until(function() return svc().current_operation == nil end,
        { timeout = 60, interval = 0.25, desc = "peinit's operation on netd to finish" })
end

--- Stop netd through peinit and wait until its process is gone.
local function stop_netd()
    sut:run("svctl stop netd")
    wait_until(function() return network.netd_pid(sut) == nil end,
        { timeout = 60, interval = 0.25, desc = "netd to stop" })
    settle()
end

--- Start netd through peinit and wait until it answers.
local function start_netd()
    settle()
    sut:run("svctl start netd")
    wait_until(function()
        local s = network.call(sut, { query = "status" })
        return s ~= nil and s.ok == true
    end, { timeout = 60, interval = 0.25, desc = "netd answering" })
end

local function exists(path)
    return (pcall(function() return sut:stat(path) end))
end

local function ifstatus()
    return network.iface(network.status(sut), "eth0")
end

--- Pump the gateway until eth0 holds a bound lease.
local function rebind(t, why)
    gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
    local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
    t:assert(s, why or "eth0 holds a bound lease again")
    return s
end

--- Write a registry batch (libreg's JSON document) and apply it as one
--- transaction, so netd builds one generation from all of it.
local function apply(doc)
    sut:write_file("/tmp/pt-batch.json", json.encode(doc))
    network.reg(sut, { "apply", "/tmp/pt-batch.json" }):assert_ok()
end

--- The rtnetlink address and route events for interface `index` that
--- arrive on `fd` (a multicast listener) until it has been quiet for
--- 300 ms.
local function rtnl_listen()
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW | ntfe.SOCK_NONBLOCK, 0)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    -- RTMGRP_IPV4_IFADDR | IPV4_ROUTE | IPV6_IFADDR | IPV6_ROUTE
    local sa = string.pack("<I2I2I4I4", 16, 0, 0, 0x10 | 0x40 | 0x100 | 0x400)
    local b = sut:syscall(ntfe.NR.bind, { args = { s.ret, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
    assert(b.ret == 0, "netlink bind: " .. sys.errname(b.errno))
    return s.ret
end

local NAMES = { [20] = "NEWADDR", [21] = "DELADDR", [24] = "NEWROUTE", [25] = "DELROUTE" }

local function attrs(b, at)
    local out = {}
    while at + 3 <= #b do
        local len, kind = string.unpack("<I2I2", b, at)
        if len < 4 then break end
        out[kind & 0x7FFF] = b:sub(at + 4, at + len - 1)
        at = at + ((len + 3) & ~3)
    end
    return out
end

local function iptext(bytes)
    if not bytes then return "-" end
    if #bytes == 4 then return ntfe.ip4_text(bytes) end
    return gateway.ip6_text(bytes)
end

local function rtnl_events(fd, index)
    local mine, all = {}, {}
    while true do
        local buf = ntfe.recv(sut, fd, 300, 65536)
        if not buf then break end
        local at = 1
        while at + 15 <= #buf do
            local len, kind = string.unpack("<I4I2", buf, at)
            if len < 16 then break end
            local body = buf:sub(at + 16, at + len - 1)
            local e
            if kind == 20 or kind == 21 then
                local _, plen, _, _, idx = string.unpack("<I1I1I1I1i4", body)
                local a = attrs(body, 9)
                e = { index = idx, text = string.format("%s %s/%d on %d", NAMES[kind],
                    iptext(a[2] or a[1]), plen, idx) }
            elseif kind == 24 or kind == 25 then
                local _, dlen = string.unpack("<I1I1", body)
                local a = attrs(body, 13)
                local oif = a[4] and string.unpack("<i4", a[4])
                e = { index = oif, text = string.format("%s %s/%d via %s dev %s", NAMES[kind],
                    iptext(a[1]), dlen, iptext(a[5]), tostring(oif)) }
            end
            if e then
                all[#all + 1] = e.text
                if e.index == index then mine[#mine + 1] = e.text end
            end
            at = at + ((len + 3) & ~3)
        end
    end
    return mine, all
end

-- ---------------------------------------------------------------------------
-- Readiness
-- ---------------------------------------------------------------------------

test("netd reports READY=1 after its first pass, with no lease anywhere",
    { spec = "netd *startup.ready-after-first-pass-not-a-lease" }, function(t)
        -- peinit holds a Readiness=Notify service in its starting state
        -- until READY=1, so `active` is netd's readiness as peinit took it.
        wait_until(function() return svc().state == "active" end,
            { timeout = 60, interval = 0.25, desc = "peinit to see netd ready" })
        local s = network.status(sut)
        local i = network.iface(s, "eth0")
        t:log(string.format("at READY: verdict=%s up=%s carrier=%s level=%s lease=%s",
            tostring(i.verdict), tostring(i.up), tostring(i.carrier), tostring(i.level),
            tostring(i.lease and i.lease.state)))
        -- The first pass is done: eth0 is judged, joined and up.
        t:assert_eq(i.verdict, "JOIN", "eth0 was judged by the first pass")
        t:assert_eq(i.up, true, "and brought up by it")
        -- No lease: the gateway has answered nothing.
        t:assert_eq(i.lease, nil, "netd is ready with no lease")
        t:assert_eq(network.ipv4(i)[1], nil, "and no IPv4 address")
        gw:pump(200)
        t:assert(#gw:dhcp_messages(gateway.DHCP.DISCOVER) >= 1,
            "netd's DHCP client was already asking (started by the first pass)")
        t:assert_eq(#gw:dhcp_messages(gateway.DHCP.REQUEST), 0, "and nothing was offered")
        -- A lease is a network event that comes afterwards, to a ready netd.
        local b = rebind(t, "the lease arrives once the gateway answers")
        t:assert_eq(network.ipv4(network.iface(b, "eth0"))[1], "10.77.0.50/24", "the leased address")
    end)

-- ---------------------------------------------------------------------------
-- A tie at startup
-- ---------------------------------------------------------------------------

local TIE = {
    keys = {
        { path = [[Machine\System\Network\Profiles\pt-tie-a]],
          values = { { name = "Address.Offered", type = "dword", data = 1 } } },
        { path = [[Machine\System\Network\Profiles\pt-tie-b]],
          values = { { name = "Address.Offered", type = "dword", data = 1 } } },
        { path = [[Machine\System\Network\Rules\Interface\pt-tie-a]],
          values = { { name = "Interface.Kind.Equal", type = "sz", data = "wired" },
                     { name = "Priority", type = "dword", data = 20 },
                     { name = "Actions", type = "multi", data = { "JOIN(pt-tie-a)" } } } },
        { path = [[Machine\System\Network\Rules\Interface\pt-tie-b]],
          values = { { name = "Interface.Kind.Equal", type = "sz", data = "wired" },
                     { name = "Priority", type = "dword", data = 20 },
                     { name = "Actions", type = "multi", data = { "JOIN(pt-tie-b)" } } } },
    },
}

test("a tie present at startup is judged per interface as a conflict, not a refused generation",
    { spec = "netd *startup.tie-at-startup-is-a-conflict-not-a-refusal" }, function(t)
        -- PEI-1333: the same tie written at runtime refuses the generation
        -- (the last good one stands), but at startup it is taken. This
        -- asserts the documented current behaviour of both halves.
        apply(TIE)
        local runtime
        wait_until(function()
            runtime = network.status(sut)
            return runtime.refusal ~= nil
        end, { timeout = 20, interval = 0.25, desc = "the runtime tie to be refused" })
        t:log("runtime refusal: " .. tostring(runtime.refusal))
        t:assert_eq(runtime.refusal, "rules pt-tie-a vs pt-tie-b tie on interface eth0",
            "written at runtime, the tie refuses the generation")
        t:assert_eq(network.iface(runtime, "eth0").rule, "wired", "and the last good generation stands")

        local mark = guest_ns()
        network.restart_netd(sut)
        local s = network.status(sut)
        local i = network.iface(s, "eth0")
        local lines = log_since(mark)
        dump(t, lines)
        t:log(string.format("after restart: refusal=%s verdict=%s rule=%s warning=%s",
            tostring(s.refusal), tostring(i.verdict), tostring(i.rule), tostring(i.warning)))
        t:assert_eq(s.refusal, nil, "at startup the generation is not refused")
        t:assert(find(lines, "3 rule tree(s), 3 profile(s), ") ~= nil,
            "the startup generation holds both tie rules and their profiles")
        t:assert_eq(find(lines, "interface layer refused"), nil, "nothing is logged as refused")
        t:assert_eq(i.verdict, nil, "eth0 has no verdict")
        t:assert_eq(i.rule, "pt-tie-a vs pt-tie-b", "attributed to the two tied rules")
        t:assert_eq(i.warning, "rules pt-tie-a vs pt-tie-b tie; the interface is ignored",
            "with the conflict warning")
        t:assert(find(lines, "interface eth0: rules pt-tie-a vs pt-tie-b tie; ignoring it") ~= nil,
            "and the warning is logged")
        t:assert_eq(i.lease, nil, "an ignored interface gets no DHCP client")

        -- Put it back: both rules off in one generation, then gone.
        apply({ keys = {
            { path = [[Machine\System\Network\Rules\Interface\pt-tie-a]],
              values = { { name = "Enabled", type = "dword", data = 0 } } },
            { path = [[Machine\System\Network\Rules\Interface\pt-tie-b]],
              values = { { name = "Enabled", type = "dword", data = 0 } } },
        } })
        rebind(t, "with the tie disabled, eth0 joins default and binds again")
        for _, k in ipairs({ [[Rules\Interface\pt-tie-a]], [[Rules\Interface\pt-tie-b]],
                             [[Profiles\pt-tie-a]], [[Profiles\pt-tie-b]] }) do
            network.delete(sut, k):assert_ok()
        end
        wait_until(function()
            local x = network.status(sut)
            return x.refusal == nil and network.iface(x, "eth0").rule == "wired"
        end, { timeout = 20, interval = 0.25, desc = "the baseline generation" })
    end)

-- ---------------------------------------------------------------------------
-- Restart
-- ---------------------------------------------------------------------------

test("a restarted netd changes nothing visible on an interface whose policy and offer are unchanged",
    { spec = "netd *startup.restart-changes-nothing-visible", tags = { "known-bug" } }, function(t)
        -- PEI-1365 (the shipped service seed's own comment
        -- says a restart "costs nothing visible", so the code, not the TRM,
        -- is taken to be wrong): a restarted netd holds no lease until the
        -- INIT-REBOOT is answered, so its first pass desires no leased
        -- address and deletes it and the default route, then adds both
        -- back when the ACK comes (see the events logged below).
        local before = rebind(t, "bound before the restart")
        local index = network.iface(before, "eth0").index
        local fd = rtnl_listen()
        rtnl_events(fd, index) -- drain anything already queued
        gw:forget()
        local mark = guest_ns()
        network.restart_netd(sut)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "the restarted netd binds again")
        gw:serve({ timeout = 2 })
        local mine, all = rtnl_events(fd, index)
        sys.close(sut, fd)
        t:log("rtnetlink events on eth0 (index " .. index .. ") across the restart:\n"
            .. table.concat(mine, "\n") .. "\nall events:\n" .. table.concat(all, "\n"))
        dump(t, log_since(mark))
        local reqs = gw:dhcp_messages(gateway.DHCP.REQUEST)
        for _, m in ipairs(reqs) do
            t:log(string.format("REQUEST ciaddr=%s opt50=%s opt54=%s", m.ciaddr,
                m.opt[50] and gateway.ip4_text(m.opt[50]) or "-",
                m.opt[54] and gateway.ip4_text(m.opt[54]) or "-"))
        end
        t:assert(reqs[1] and reqs[1].ciaddr == "0.0.0.0" and reqs[1].opt[54] == nil
            and reqs[1].opt[50] and gateway.ip4_text(reqs[1].opt[50]) == "10.77.0.50",
            "the client began with an INIT-REBOOT for the old address")
        t:assert_eq(network.ipv4(network.iface(s, "eth0"))[1], "10.77.0.50/24", "the same address")
        t:assert_eq(#mine, 0, "no address or route on eth0 changed across the restart")
    end)

-- ---------------------------------------------------------------------------
-- The startup sequence
-- ---------------------------------------------------------------------------

test("startup opens, degrades and reads in the documented order, and a control socket it cannot bind is fatal",
    { spec = "netd *startup.sequence" }, function(t)
        rebind(t, "bound before the stop")
        stop_netd()
        local stale = exists("/run/netd/control.sock")
        t:log("after the stop, /run/netd/control.sock " .. (stale and "remains" or "is gone"))
        if not stale then
            -- Place one, as a crashed run would have left it.
            sut:write_file("/run/netd/control.sock", "")
        end
        -- Step 3's resource, held by somebody else (no SO_REUSEADDR, so
        -- netd's bind cannot share it).
        local s = sut:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_DGRAM, 0)
        t:assert(s.ret >= 0, "a UDP socket")
        local sa = ntfe.sockaddr("0.0.0.0", 68)
        local b = sut:syscall(ntfe.NR.bind, { args = { s.ret, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
        t:assert_eq(b.ret, 0, "udp/68 held by the agent: " .. sys.errname(b.errno or 0))
        -- Step 4 must undo this on every interface that exists.
        for _, c in ipairs({ "all", "default", "eth0" }) do
            sut:write_file("/proc/sys/net/ipv6/conf/" .. c .. "/accept_ra", "1\n")
        end
        -- Step 5: a generation that cannot build.
        network.write(sut, [[Profiles\pt-bad]], { ["Address.Bogus"] = "dword:1" })

        local mark = guest_ns()
        start_netd()
        local lines = log_since(mark)
        dump(t, lines)
        local i_stale = find(lines, "removed a stale /run/netd/control.sock")
        local i_absorb = find(lines, "could not bind udp/68 (")
        local i_refused = find(lines,
            "interface layer refused: profile pt-bad: unknown value Address.Bogus; every interface is ignored")
        local i_dump = find(lines, "0 rule tree(s), 0 profile(s), ")
        local i_pass = find(lines, "interface eth0 (pci-0000:00:02.0) is ")
        t:log(string.format("stale=%s absorber=%s refused=%s dump=%s first-pass=%s", tostring(i_stale),
            tostring(i_absorb), tostring(i_refused), tostring(i_dump), tostring(i_pass)))
        t:assert(i_stale and i_absorb and i_refused and i_dump and i_pass, "every step logged")
        t:assert(i_stale < i_absorb, "the control socket (2) before the absorber (3)")
        t:assert(i_absorb < i_refused, "the absorber (3) before the configuration (5)")
        t:assert(i_refused < i_dump, "the configuration (5) before the kernel dump (7)")
        t:assert(i_dump < i_pass, "the dump (7) before the first pass (8)")
        t:assert_eq(find(lines, "registry watch unavailable"), nil, "the watch was armed (6)")
        t:assert(lines[i_absorb].msg:find("^netd: warn: ") ~= nil, "a lost absorber is a warning")

        -- Step 2: the stale socket was replaced by a live one.
        local st = sut:stat("/run/netd/control.sock")
        t:log("control.sock stat: " .. json.encode(st))
        t:assert(network.call(sut, { query = "status" }).ok, "the control socket answers")
        -- Step 3 degraded, not fatal: netd runs.
        t:assert_eq(svc().state, "active", "netd is running and ready (9) without the absorber")
        -- Step 4: kernel RA processing off everywhere.
        for _, c in ipairs({ "all", "default", "eth0" }) do
            t:assert_eq(sut:read_file("/proc/sys/net/ipv6/conf/" .. c .. "/accept_ra"), "0\n",
                "accept_ra switched off in " .. c)
        end
        -- Step 5: refused at startup, so an empty policy and the backstop.
        local status = network.status(sut)
        local i = network.iface(status, "eth0")
        t:assert_eq(status.refusal, "profile pt-bad: unknown value Address.Bogus", "the refusal is reported")
        t:assert_eq(i.rule, "backstop", "the backstop judges eth0 under the empty policy")
        t:assert_eq(i.verdict, nil, "and eth0 has no verdict: ignored")

        -- Back to a working netd: the agent lets udp/68 go, the bad
        -- profile goes (the watch, armed in step 6, sees it).
        sys.close(sut, s.ret)
        network.delete(sut, [[Profiles\pt-bad]]):assert_ok()
        rebind(t, "a good generation joins eth0 again")
        t:assert_eq(network.status(sut).refusal, nil, "the refusal clears")

        -- Step 2 is fatal: a directory where the socket goes cannot be
        -- removed, so netd cannot bind.
        sut:run("rm -f /run/netd/control.sock && mkdir /run/netd/control.sock"):assert_ok()
        local mark2 = guest_ns()
        sut:run("svctl --no-wait restart netd")
        local failed
        wait_until(function()
            failed = log_since(mark2)
            return find(failed, "netd: error: control socket:") ~= nil
        end, { timeout = 30, interval = 0.5, desc = "netd to fail on its control socket" })
        dump(t, failed)
        t:assert_eq(find(failed, "rule tree(s)"), nil, "a fatal failure stops startup before the dump")
        local state = svc().state
        t:log("peinit state after the fatal start: " .. tostring(state))
        t:assert(network.call(sut, { query = "status" }) == nil, "nothing answers on the control socket")

        sut:run("rmdir /run/netd/control.sock"):assert_ok()
        sut:run("svctl reset netd")
        settle()
        if svc().state ~= "active" then sut:run("svctl start netd") end
        wait_until(function()
            local x = network.call(sut, { query = "status" })
            return x ~= nil and x.ok == true
        end, { timeout = 60, interval = 0.5, desc = "netd back" })
    end)
