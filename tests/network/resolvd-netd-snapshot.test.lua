-- resolvd §3.3 — applying a snapshot: the hostname, each scope's fields
-- as parsed, the summary line, which cached answers each snapshot
-- discards, and what happens to questions already in flight. PSPU §6.9:
-- the resolver replaces its scopes with each snapshot, and uses the
-- kernel's name when the manager reports none.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns) on two addresses (10.77.0.1 and 10.77.0.2), and a whole
-- Peios (helpers.network). The agent stands in for netd, as in
-- resolvd-netd-subscribe.test.lua: netd's socket is renamed aside (netd
-- keeps the lease, so the gateway stays reachable over eth0), a listener
-- of the agent's takes its path, and resolvd is restarted onto it. Each
-- snapshot is then whatever the test writes, so scope keys, server lists
-- and hostnames can be changed one at a time. The cache is read through
-- `status` (`cache_entries`) and `resolv query` (source `cache` or `dns`,
-- `via <server> on <interface>`), and the gateway's query log says
-- which server was asked.
--
-- Own VMs: resolvd runs against a stand-in netd for the whole file, and
-- the kernel's hostname is rewritten.
--
-- Non-obvious: whatever the snapshot's scope addresses say, every
-- question leaves by eth0's connected route to the gateway; the scope a
-- question went to is the server it was sent to. Positive answers carry
-- TTL 300, so nothing expires during the file.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local dns = require("helpers.dns")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

assert(rtnl.add_address(gw.vm, gw.ifindex, "10.77.0.2", { prefix = 24 }), "the gateway's second server address")

local RSOCK = "/run/resolvd/resolv.sock"
local ASIDE = "/run/netd/control.pt-aside.sock"
local SOCK_SDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GRGWGX;;;WD)"
local S1, S2 = "10.77.0.1", "10.77.0.2"
local E = msgpack.array

local ZONE = {}
for _, n in ipairs({ "a", "b", "c", "keep", "late", "slow1", "slow2", "www" }) do
    ZONE[n .. ".example.test"] = { { type = "A", ttl = 300, data = "10.77.9." .. (#n + 10) } }
end
ZONE["b.three.test"] = { { type = "A", ttl = 300, data = "10.77.9.33" } }

-- Per-test DNS behaviour: `hooks[name] = fn(q, default, ctx)`.
local hooks = {}
dns.serve(gw, { zone = ZONE, on = function(q, default, ctx)
    local qn = q.questions and q.questions[1]
    if not qn then return nil end
    for name, fn in pairs(hooks) do
        if dns.same_name(qn.name, name) then return fn(q, default, ctx) end
    end
end })

-- ---- resolvd, read back ----------------------------------------------------

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = RSOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err or (s and s.error)))
    return s
end

local function now_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

local function rlog(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > (since or 0) then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function names(st)
    local out = {}
    for _, s in ipairs(st.scopes or {}) do out[#out + 1] = s.interface end
    return table.concat(out, ",")
end

local function list(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function status_until(pred, timeout)
    local last
    local ok = pcall(wait_until, function()
        last = rstatus()
        return pred(last)
    end, { timeout = timeout or 10, interval = 0.1, desc = "resolvd status" })
    return last, ok
end

--- Run `cmd` in the guest while the gateway pumps.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- `resolv query <name> A`: {exit, line (the summary), out}.
local function ask(name)
    local r = served("resolv query " .. name .. " A")
    return { exit = r.exit_code, line = r.stdout:match("^[^\n]*") or "", out = r.stdout .. r.stderr }
end

local function asked(name)
    return dns.queries(gw, function(e)
        local qn = e.msg and e.msg.questions[1]
        return qn ~= nil and dns.same_name(qn.name, name)
    end)
end

local function servers_asked(name)
    local out = {}
    for _, e in ipairs(asked(name)) do out[#out + 1] = e.server end
    return list(out)
end

local function entries() return rstatus().cache_entries end

-- ---- the stand-in netd -----------------------------------------------------

local fake = {}

local function listen()
    sys.unlink(sut, network.CONTROL)
    local l = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local r = unixsock.bind(sut, l, network.CONTROL)
    assert(r.ret == 0, "bind: " .. unixsock.errname(r.errno))
    -- netd's own descriptor on its socket (netd §9.1): without it the file
    -- inherits /run's SYSTEM-only one and resolvd's connect is refused.
    local sd = sut:run("sd set " .. network.CONTROL .. " '" .. SOCK_SDDL .. "'", { timeout = 15 })
    assert(sd.exit_code == 0, "sd set: " .. sd.stdout .. sd.stderr)
    r = unixsock.listen(sut, l, 16)
    assert(r.ret == 0, "listen: " .. unixsock.errname(r.errno))
    fake.l = l
end

local function accept(timeout_ms)
    local ev = ntfe.poll(sut, fake.l, ntfe.POLLIN, timeout_ms or 15000)
    if ev == 0 then return nil, "no connection" end
    local fd, e = unixsock.accept(sut, fake.l)
    if not fd then return nil, "accept: " .. unixsock.errname(e) end
    return { fd = fd }
end

local conn

local function frame(v)
    local p = msgpack.encode(v)
    return string.pack("<I4", #p) .. p
end

local function scope(o)
    return {
        ifid = o.ifid or ("pt-ifid-" .. o.name), name = o.name,
        servers = E(o.servers or {}), domains = E(o.domains or {}), ntp = E({}),
        addresses = E(o.addresses or {}),
        default_route = o.default_route == true, exclusive = o.exclusive == true,
        metric = o.metric or 100, level = o.level or "routed",
    }
end

--- Send a snapshot and wait until resolvd has applied it (its summary
--- line is logged). Returns resolvd's status.
local function apply(scopes, hostname)
    local since = now_ns()
    local f = frame({ ok = true, kind = "snapshot", hostname = hostname or "", scopes = E(scopes) })
    local r = ntfe.send(sut, conn.fd, f)
    assert(r.ret == #f, "send: " .. tostring(r.ret))
    wait_until(function()
        for _, l in ipairs(rlog(since)) do
            if l.msg:find("resolvd: info: netd: ", 1, true) then return true end
        end
        return false
    end, { timeout = 10, interval = 0.1, desc = "the snapshot applied" })
    return rstatus()
end

local function kernel_hostname(name)
    sut:write_file("/tmp/pt-hn", name .. "\n")
    sut:run("cat /tmp/pt-hn > /proc/sys/kernel/hostname"):assert_ok()
end

local function attach(t)
    if not fake.moved then
        local r = sys.rename(sut, network.CONTROL, ASIDE)
        t:assert(r.ret == 0, "netd's socket moved aside: " .. sys.errname(r.errno or 0))
        fake.moved = true
        listen()
    end
    if conn then sys.close(sut, conn.fd) end
    -- Not `svctl restart`: that leaves resolvd unable to bind its socket
    -- (PEI-1373).
    sut:run("svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd", { timeout = 30 }):assert_ok()
    local why
    conn, why = accept(15000)
    t:assert(conn, "resolvd connected to the stand-in: " .. tostring(why))
end

--- One routed scope that claims the default route: what most cases need.
local function one(o)
    o.default_route = o.default_route ~= false
    return scope(o)
end

-- ---------------------------------------------------------------------------

test("every scope is kept whatever its level or server count, in snapshot order, with its name reported; each snapshot replaces them all, an empty one leaving none; one summary line each",
    { spec = "resolvd *netd-snapshot.every-scope-kept resolvd *netd-snapshot.summary-log-line resolvd *netd-snapshot.name-is-reported-interface PSPU *nri-manager.resolver-replaces-scopes" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        kernel_hostname("pt-kernel0")
        attach(t)
        local since = now_ns()
        local st = apply({
            scope({ name = "pt-eth", servers = { S1, S2 }, domains = { "corp.test" }, default_route = true }),
            scope({ name = "pt-link", servers = {}, level = "link", metric = 50 }),
            scope({ name = "pt-absent", servers = { "10.77.0.3" }, level = "absent", metric = 10 }),
            scope({ name = "pt-oddlevel", level = "no-such-level", metric = 5 }),
        })
        t:log("status scopes: " .. names(st))
        t:assert_eq(names(st), "pt-eth,pt-link,pt-absent,pt-oddlevel", "all four, in snapshot order")
        t:assert_eq(list(st.scopes[1].servers), "[10.77.0.1, 10.77.0.2]", "pt-eth's servers")
        t:assert_eq(list(st.scopes[2].servers), "[]", "pt-link: no servers, kept")
        t:assert_eq(st.scopes[3].metric, 10, "pt-absent kept with its metric")
        local lines = rlog(since)
        local summary
        for _, l in ipairs(lines) do if l.msg:find("netd: ", 1, true) then summary = l.msg end end
        t:log("summary: " .. tostring(summary))
        t:assert_eq(summary, "resolvd: info: netd: pt-eth: 2 server(s), 1 domain(s), default; "
            .. "pt-link: 0 server(s), 0 domain(s); pt-absent: 1 server(s), 0 domain(s); "
            .. "pt-oddlevel: 0 server(s), 0 domain(s)", "the summary line")

        -- The name is what answers are reported on.
        st = apply({ one({ name = "pt-named", ifid = "pt-k-named", servers = { S1 } }) })
        t:assert_eq(names(st), "pt-named", "the new snapshot replaced all four")
        local a = ask("www.example.test")
        t:log("www: " .. a.out)
        t:assert(a.line:find("^found  dns via 10%.77%.0%.1 on pt%-named  "), "answered on pt-named: " .. a.line)

        since = now_ns()
        st = apply({})
        t:assert_eq(names(st), "", "an empty snapshot leaves no scopes")
        lines = rlog(since)
        t:assert(lines[#lines] and lines[#lines].msg == "resolvd: info: netd: no scopes",
            "logged `netd: no scopes`: " .. tostring(lines[#lines] and lines[#lines].msg))
    end)

test("servers, domains and addresses are parsed: non-addresses (a zoned one, one with a port, included), unparseable names and the root, and malformed address/prefix strings are dropped silently; servers are asked on port 53",
    { spec = "resolvd *netd-snapshot.servers-parsed-malformed-dropped resolvd *netd-snapshot.domains-parsed-malformed-dropped resolvd *netd-snapshot.addresses-parsed-malformed-dropped" },
    function(t)
        t:assert(conn, "attached")
        local since = now_ns()
        local st = apply({ one({ name = "pt-parse", ifid = "pt-k-parse",
            servers = { "not-an-ip", "fe80::1%eth0", "10.77.0.1:53", "10.77.0.300", S1, "fd77::1" },
            domains = { "corp.test", "bad..dom", ".", string.rep("x", 64) .. ".test", "other.test" },
            addresses = { "10.77.0.50/24", "junk", "10.77.0.51", "fd77::50/64", "10.77.0.52/abc", "/24" },
        }) })
        local sc = st.scopes[1]
        t:log(string.format("parsed: servers %s domains %s subnets %s", list(sc.servers), list(sc.domains), list(sc.subnets)))
        t:assert_eq(list(sc.servers), "[10.77.0.1, fd77::1]", "the two addresses kept, in order")
        t:assert_eq(list(sc.domains), "[corp.test, other.test]", "the two names kept, in order")
        t:assert_eq(list(sc.subnets), "[10.77.0.50/24, fd77::50/64]", "the two address/prefix pairs kept")
        local lines = rlog(since)
        local warned = false
        for _, l in ipairs(lines) do
            t:log(l.msg)
            if l.msg:find("warn:", 1, true) then warned = true end
        end
        t:assert(not warned, "nothing about the dropped entries is logged")
        t:assert(lines[#lines].msg:find("pt-parse: 2 server(s), 2 domain(s), default", 1, true),
            "the summary counts what was left")

        dns.forget(gw)
        local port
        hooks["a.example.test"] = function(_, _, ctx)
            port = ctx.frame and ctx.frame.udp and ctx.frame.udp.dport
        end
        local a = ask("a.example.test")
        hooks["a.example.test"] = nil
        t:log("a: " .. a.out .. " (destination port " .. tostring(port) .. ")")
        t:assert(a.line:find("^found  dns via 10%.77%.0%.1 on pt%-parse"), "answered by the first server")
        local q = asked("a.example.test")
        t:assert(#q >= 1 and q[1].server == S1, "the gateway got it at 10.77.0.1")
        t:assert_eq(port, 53, "on port 53")
    end)

test("the snapshot's hostname is used; an unparseable one or the root leaves no hostname; an empty one reads the kernel's at that moment, `(none)` and empty counting as none, and the kernel's is not read again until the next such snapshot",
    { spec = "resolvd *netd-snapshot.empty-hostname-reads-kernel-hostname resolvd *netd-snapshot.unparseable-hostname-is-no-hostname resolvd *netd-snapshot.kernel-hostname-read-only-at-snapshot-or-startup PSPU *nri-manager.empty-hostname-uses-kernel" },
    function(t)
        t:assert(conn, "attached")
        local sc = { one({ name = "pt-host", ifid = "pt-k-host", servers = { S1 } }) }
        local st = apply(sc, "pt-snaphost")
        t:assert_eq(st.hostname, "pt-snaphost", "the snapshot's name")
        local a = ask("pt-snaphost")
        t:log("pt-snaphost: " .. a.out)
        t:assert(a.line:find("^found  synthetic"), "answered synthetically")

        st = apply(sc, "bad..host")
        t:assert_eq(st.hostname, "", "an unparseable name: no hostname")
        a = ask("pt-snaphost")
        t:assert(not a.line:find("synthetic", 1, true), "the old name is no longer synthetic: " .. a.line)
        st = apply(sc, "pt-again")
        t:assert_eq(st.hostname, "pt-again", "a good name again")
        st = apply(sc, ".")
        t:assert_eq(st.hostname, "", "the root: no hostname")

        kernel_hostname("pt-kernel1")
        st = apply(sc, "")
        t:assert_eq(st.hostname, "pt-kernel1", "an empty hostname: the kernel's")
        a = ask("pt-kernel1")
        t:assert(a.line:find("^found  synthetic"), "and it is answered synthetically: " .. a.line)
        kernel_hostname("pt-kernel2")
        sut:run("sleep 1")
        t:assert_eq(rstatus().hostname, "pt-kernel1", "a kernel change alone is not seen")
        st = apply(sc, "pt-named-again")
        t:assert_eq(st.hostname, "pt-named-again", "nor by a snapshot that names a host")
        st = apply(sc, "")
        t:assert_eq(st.hostname, "pt-kernel2", "the next empty-hostname snapshot reads it")

        kernel_hostname("(none)")
        st = apply(sc, "")
        t:assert_eq(st.hostname, "", "a kernel hostname of (none) counts as none")
        kernel_hostname("pt-kernel3")
        st = apply(sc, "")
        t:assert_eq(st.hostname, "pt-kernel3", "back to a name")
        kernel_hostname("")
        t:assert_eq((sut:read_file("/proc/sys/kernel/hostname"):gsub("%s+$", "")), "", "the kernel's name is empty")
        st = apply(sc, "")
        t:assert_eq(st.hostname, "", "an empty kernel hostname counts as none")

        -- Startup is the other time it is read.
        kernel_hostname("pt-boot")
        attach(t)
        st = rstatus()
        t:assert_eq(names(st), "", "a restarted resolvd has no snapshot yet")
        t:assert_eq(st.hostname, "pt-boot", "but has read the kernel's name at startup")
        kernel_hostname("pt-boot2")
        sut:run("sleep 1")
        t:assert_eq(rstatus().hostname, "pt-boot", "and does not read it again by itself")
        kernel_hostname("pt-kernel0")
    end)

test("the cache: a change of domains, addresses, flags, metric, level or name keeps a scope's answers; a change of its server list's order or content discards them; so does a change of its ifid, the scope key",
    { spec = "resolvd *netd-snapshot.other-changes-keep-cache resolvd *netd-snapshot.changed-server-list-flushes-scope resolvd *netd-snapshot.ifid-is-scope-key" },
    function(t)
        t:assert(conn, "attached")
        local base = { name = "pt-one", ifid = "pt-k1", servers = { S1, S2 } }
        apply({ one(base) })
        sut:run("resolv flush"):assert_ok()
        t:assert_eq(entries(), 0, "an empty cache")
        local a = ask("a.example.test")
        t:assert(a.line:find("^found  dns"), "a asked upstream: " .. a.line)
        t:assert_eq(entries(), 1, "one cached answer")

        -- Everything but the servers and the key.
        apply({ scope({ name = "pt-renamed", ifid = "pt-k1", servers = { S1, S2 }, domains = { "corp.test" },
            addresses = { "10.77.0.50/24" }, default_route = false, exclusive = true, metric = 77, level = "addressed" }) })
        t:assert_eq(entries(), 1, "domains, addresses, flags, metric, level and name changed: the answer is kept")
        a = ask("a.example.test")
        t:log("after the other changes: " .. a.line)
        t:assert(a.line:find("^found  cache via 10%.77%.0%.1 on pt%-renamed"), "a cache hit, reported on the new name")

        -- The same servers in another order.
        apply({ one({ name = "pt-one", ifid = "pt-k1", servers = { S2, S1 } }) })
        t:assert_eq(entries(), 0, "the server list reordered: the answer is gone")
        a = ask("a.example.test")
        t:assert(a.line:find("^found  dns via 10%.77%.0%.2"), "asked again, of the now-first server: " .. a.line)
        t:assert_eq(entries(), 1, "cached again")

        -- Different content.
        apply({ one({ name = "pt-one", ifid = "pt-k1", servers = { S2 } }) })
        t:assert_eq(entries(), 0, "a server dropped: the answer is gone")
        a = ask("a.example.test")
        t:assert(a.line:find("^found  dns"), "asked again: " .. a.line)
        t:assert_eq(entries(), 1, "cached again")

        -- The key: the same scope in every field but its ifid.
        apply({ one({ name = "pt-one", ifid = "pt-k2", servers = { S2 } }) })
        t:assert_eq(entries(), 0, "a new ifid is a new scope: the old key's answer is gone")
        a = ask("a.example.test")
        t:assert(a.line:find("^found  dns"), "asked again under the new key: " .. a.line)
    end)

test("a scope missing from the new snapshot loses its answers, and only it",
    { spec = "resolvd *netd-snapshot.missing-scope-flushed" }, function(t)
        t:assert(conn, "attached")
        local k2 = one({ name = "pt-one", ifid = "pt-k2", servers = { S2 } })
        local k3 = scope({ name = "pt-three", ifid = "pt-k3", servers = { S1 }, domains = { "three.test" } })
        apply({ k2, k3 })
        sut:run("resolv flush"):assert_ok()
        local a = ask("a.example.test")
        local b = ask("b.three.test")
        t:log("a: " .. a.line .. " | b: " .. b.line)
        t:assert(a.line:find("on pt%-one"), "a went to pt-one")
        t:assert(b.line:find("via 10%.77%.0%.1 on pt%-three"), "b.three.test went to pt-three by its domain")
        t:assert_eq(entries(), 2, "one answer under each")
        apply({ k2 })
        t:assert_eq(entries(), 1, "pt-three gone: its answer gone, pt-one's kept")
        a = ask("a.example.test")
        t:assert(a.line:find("^found  cache"), "pt-one's answer still served from the cache: " .. a.line)
        b = ask("b.three.test")
        t:assert(b.line:find("^found  dns via 10%.77%.0%.2 on pt%-one"), "b asked again, through pt-one: " .. b.line)
    end)

test("a scope whose key is new loses whatever is cached under that key: a scope keyed `fallback` discards the fallback scope's answers, another new key leaves them",
    { spec = "resolvd *netd-snapshot.new-scope-key-flushed" }, function(t)
        t:assert(conn, "attached")
        network.write(sut, "Dns", { FallbackServers = "multi:" .. S1 })
        status_until(function(s) return s.fallback_servers and s.fallback_servers[1] == S1 end)
        apply({})
        sut:run("resolv flush"):assert_ok()
        local c = ask("c.example.test")
        t:log("c with no scopes: " .. c.line)
        t:assert(c.line:find("^found  dns via 10%.77%.0%.1"), "answered through the fallback server")
        t:assert(not c.line:find(" on ", 1, true), "on no interface")
        t:assert_eq(entries(), 1, "cached under the fallback scope")

        apply({ scope({ name = "pt-new", ifid = "pt-new", servers = { S2 } }) })
        t:assert_eq(entries(), 1, "a new scope under another key: the fallback answer stays")
        apply({ scope({ name = "pt-new", ifid = "pt-new", servers = { S2 } }),
                scope({ name = "pt-fb", ifid = "fallback", servers = { S1 } }) })
        t:assert_eq(entries(), 0, "a new scope keyed `fallback`: the fallback answer is gone")

        network.reg(sut, { "del", network.KEY .. "\\Dns", "FallbackServers" })
        status_until(function(s) return #(s.fallback_servers or {}) == 0 end)
    end)

test("a question in flight keeps its scope key: its retry uses the scope's new servers, and finds none when the scope has gone",
    { spec = "resolvd *netd-snapshot.in-flight-retries-follow-scope-key" }, function(t)
        t:assert(conn, "attached")
        hooks["slow1.example.test"] = function(_, _, ctx) if ctx.server == S1 then return false end end
        hooks["slow2.example.test"] = function(_, _, ctx) if ctx.server == S1 then return false end end
        apply({ one({ name = "pt-fly", ifid = "pt-fly", servers = { S1 } }) })
        dns.forget(gw)

        -- The scope's servers change under the question.
        local p = sut:run_async("sh", { args = { "-c", "resolv query slow1.example.test A" } })
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("slow1.example.test") > 0 end }),
            "the first attempt reached 10.77.0.1")
        apply({ one({ name = "pt-fly", ifid = "pt-fly", servers = { S2 } }) })
        gw:serve({ timeout = 20, until_ = function() return p:status() == "exited" end })
        local r = p:wait(5)
        t:log("slow1: " .. r.stdout .. " asked at " .. servers_asked("slow1.example.test"))
        t:assert_eq(r.exit_code, 0, "found")
        t:assert(r.stdout:find("^found  dns via 10%.77%.0%.2 on pt%-fly"), "answered by the new server")
        t:assert_eq(servers_asked("slow1.example.test"), "[10.77.0.1, 10.77.0.2]", "the retry went to the new list")

        -- The scope goes; another, with a live server, takes its place.
        apply({ one({ name = "pt-fly", ifid = "pt-fly", servers = { S1 } }) })
        p = sut:run_async("sh", { args = { "-c", "resolv query slow2.example.test A" } })
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("slow2.example.test") > 0 end }),
            "the first attempt reached 10.77.0.1")
        apply({ one({ name = "pt-other", ifid = "pt-other", servers = { S2 } }) })
        gw:serve({ timeout = 20, until_ = function() return p:status() == "exited" end })
        r = p:wait(5)
        t:log("slow2: " .. r.stdout .. r.stderr .. " asked at " .. servers_asked("slow2.example.test"))
        t:assert_eq(r.exit_code, 3, "unavailable")
        t:assert(r.stdout:find("^unavailable"), "the outcome is unavailable")
        t:assert_eq(servers_asked("slow2.example.test"), "[10.77.0.1]", "the other scope's server was never asked")
        hooks["slow1.example.test"], hooks["slow2.example.test"] = nil, nil
    end)

test("a transaction already sent survives a snapshot that flushes its scope, and its late reply is cached under the scope key",
    { spec = "resolvd *netd-snapshot.in-flight-reply-cached-after-flush" }, function(t)
        t:assert(conn, "attached")
        apply({ one({ name = "pt-late", ifid = "pt-late", servers = { S1 } }) })
        sut:run("resolv flush"):assert_ok()
        local k = ask("keep.example.test")
        t:assert(k.line:find("^found  dns"), "keep cached: " .. k.line)
        t:assert_eq(entries(), 1, "one answer under pt-late")
        -- Held, and sent at the first pump after the snapshot (the test
        -- stops pumping once the question is seen); the attempt's 2 s
        -- timeout bounds how long the snapshot may take.
        hooks["late.example.test"] = function(_, default) default.delay = 0.1; return default end
        dns.forget(gw)
        local p = sut:run_async("sh", { args = { "-c", "resolv query late.example.test A" } })
        t:assert(gw:serve({ timeout = 10, until_ = function() return #asked("late.example.test") > 0 end }),
            "the question reached 10.77.0.1")
        apply({ one({ name = "pt-late", ifid = "pt-late", servers = { S2 } }) })
        t:assert_eq(entries(), 0, "the server change flushed pt-late (keep is gone)")
        gw:serve({ timeout = 20, until_ = function() return p:status() == "exited" end })
        local r = p:wait(5)
        t:log("late: " .. r.stdout)
        t:assert(r.stdout:find("^found  dns via 10%.77%.0%.1 on pt%-late"), "the old server's late reply answered it")
        t:assert_eq(entries(), 1, "and was cached")
        dns.forget(gw)
        local again = ask("late.example.test")
        t:log("late again: " .. again.line)
        t:assert(again.line:find("^found  cache via 10%.77%.0%.1 on pt%-late"),
            "served from the cache, from the old server, though the scope now lists only 10.77.0.2")
        t:assert_eq(#asked("late.example.test"), 0, "nothing was asked")
        hooks["late.example.test"] = nil
    end)

test("the live facts reach resolvd over the channel alone: it uses the servers a snapshot names, not what the registry records, and applying a snapshot writes none of it to the registry",
    { spec = "PSPU *nri-manager.live-facts-never-in-registry" }, function(t)
        t:assert(conn, "attached")
        local function tree()
            local r = network.reg(sut, { "tree", network.KEY, "--values" })
            t:assert_eq(r.exit_code, 0, "reg tree: " .. r.stderr)
            return r.stdout
        end
        -- netd's own record of eth0's network lists the lease's server
        -- (netd §7.2); the stand-in names another.
        local before = tree()
        t:assert(before:find("DnsServers = [^\n]*10%.77%.0%.1"),
            "the registry records 10.77.0.1 as the network's DnsServers (netd's network record)")
        t:assert(not before:find("10.77.0.2", 1, true), "and nowhere 10.77.0.2")
        local st = apply({ one({ name = "pt-live", ifid = "pt-live", servers = { S2 }, domains = { "pt-live.test" } }) })
        t:assert_eq(list(st.scopes[1].servers), "[10.77.0.2]", "resolvd's scope has the snapshot's server alone")
        sut:run("resolv flush"):assert_ok()
        dns.forget(gw)
        local a = ask("www.example.test")
        t:log("www: " .. a.line)
        t:assert(a.line:find("^found  dns via 10%.77%.0%.2 on pt%-live"), "and asks it")
        t:assert_eq(servers_asked("www.example.test"), "[10.77.0.2]", "only it")
        local after = tree()
        t:assert(not after:find("10.77.0.2", 1, true), "the snapshot's server was not written to the registry")
        t:assert(not after:find("pt-live", 1, true), "nor its interface or domain")
    end)
