-- resolvd §4.2 — synthetic names: localhost, the static names, the
-- machine's own name, `.local`, the reverse-mapping names, the order they
-- are checked in, and what every synthetic answer looks like; with the
-- PSPU §6.7 "Synthetic answers" requirements they implement.
--
-- Harness: the scripted gateway (helpers.gateway) leasing 10.77.0.50 with
-- itself as the DNS server and `lan` as the domain (option 15), and its
-- DNS server (helpers.dns), whose zone holds names that the static names
-- shadow, so an answer from the network is told apart from a synthetic
-- one by its data and its `source`. Questions go to resolvd's native
-- socket from the agent, while the gateway pumps (`ask`), so a question
-- that wrongly went upstream is answered by the zone and fails visibly
-- rather than hanging.
--
-- "No query was sent" is proven against a marker: after the questions, a
-- name only the marker uses is resolved through the network. The gateway
-- reads frames in order, so once the marker's query is in its log, any
-- query resolvd sent before it would be too.
--
-- The hostname is the registry's `Hostname` (netd sets it and puts it in
-- the snapshot, netd TRM §8.4). Static names are `Dns\Hosts` values,
-- written live; each test waits for resolvd to apply them by asking until
-- the answer changes.
--
-- Own VMs: the tests set the hostname and rewrite `Dns\Hosts`; the last
-- one pulls the cable. The machine's own addresses across several scopes
-- are resolvd-synthetic-own.test.lua.
--
-- helpers.msgpack drops a map entry whose value is nil, so a nil `server`
-- or `interface` reads as absent; that is what is asserted.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, options = { { 15, "lan" } } })
dns.serve(gw, {
    zone = {
        ["shadow.example.test"] = { { type = "A", ttl = 60, data = "10.77.0.81" } },
        ["printer.lan"] = { { type = "A", ttl = 60, data = "10.77.0.82" } },
        ["99.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 60, data = "far.example.test" } },
        ["1.0.0.127.in-addr.arpa"] = { { type = "TXT", ttl = 60, data = "from-dns" } },
    },
    soa = { name = "example.test", data = { minimum = 30 } },
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local HOSTS = [[Dns\Hosts]]
local T = dns.TYPE

-- ---- resolvd -----------------------------------------------------------

--- Send `req` on the native socket and read the reply, pumping the
--- gateway while resolvd works. Raises when there is no reply.
local function ask(req, o)
    o = o or {}
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local c = unixsock.connect(sut, fd, SOCK)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    local p = msgpack.encode(req)
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local buf, reply = "", nil
    local function poll()
        local chunk = ntfe.recv(sut, fd, 30, 65536)
        if chunk and #chunk > 0 then buf = buf .. chunk end
        if #buf >= 4 then
            local len = string.unpack("<I4", buf)
            if #buf >= 4 + len then
                reply = msgpack.decode(buf:sub(5, 4 + len))
                return true
            end
        end
        return false
    end
    if not poll() then gw:serve({ timeout = o.timeout or 20, until_ = poll }) end
    sys.close(sut, fd)
    assert(reply, "resolvd gave no reply to " .. tostring(req.query) .. " "
        .. tostring(req.name or req.address))
    return reply
end

local function resolve(name, rtype, no_cache)
    return ask({ query = "resolve", name = name, type = rtype or T.A, no_cache = no_cache })
end

local function rstatus()
    local s = ask({ query = "status" })
    assert(s.ok and s.kind == "status", "resolvd status")
    return s
end

--- "A 10.0.0.1, AAAA ::1": an answer's records, type and text, in order.
local function texts(r)
    local out = {}
    for _, rec in ipairs(r.records or {}) do
        out[#out + 1] = (dns.TYPE_NAME[rec.type] or tostring(rec.type)) .. " " .. tostring(rec.text)
    end
    return table.concat(out, ", ")
end

--- Assert a synthetic answer: found (or `outcome`), `source`, no server,
--- no interface, rcode 0, unvalidated, every record TTL 0, and the
--- records `want` (texts form).
local function synthetic(t, r, source, want, what, outcome)
    t:assert(r.ok and r.kind == "answer", what .. ": an answer (" .. tostring(r.error) .. ")")
    t:log(string.format("%s: %s %s [%s]", what, tostring(r.outcome), tostring(r.source), texts(r)))
    t:assert_eq(r.outcome, outcome or "found", what .. ": outcome")
    t:assert_eq(r.source, source, what .. ": source")
    t:assert_eq(r.server, nil, what .. ": no server")
    t:assert_eq(r.interface, nil, what .. ": no interface")
    t:assert_eq(r.rcode, 0, what .. ": rcode 0")
    t:assert_eq(r.validation, "unvalidated", what .. ": validation")
    for _, rec in ipairs(r.records or {}) do
        t:assert_eq(rec.ttl, 0, what .. ": TTL 0 on " .. tostring(rec.text))
    end
    if want then t:assert_eq(texts(r), want, what .. ": records") end
end

--- Assert an answer that came from the network.
local function from_dns(t, r, what, outcome)
    t:log(string.format("%s: %s %s via %s [%s]", what, tostring(r.outcome), tostring(r.source),
        tostring(r.server), texts(r)))
    t:assert_eq(r.source, "dns", what .. ": from the network")
    t:assert_eq(r.server, "10.77.0.1", what .. ": asked of the gateway")
    if outcome then t:assert_eq(r.outcome, outcome, what .. ": outcome") end
end

-- ---- the gateway's view ---------------------------------------------------

--- The queries the gateway's server got for `name` (any case).
local function asked(name, rtype)
    return dns.queries(gw, function(q)
        local qn = q.msg and q.msg.questions[1]
        return qn ~= nil and dns.same_name(qn.name, name) and (not rtype or qn.type == rtype)
    end)
end

local markers = 0
--- Push a marker through the network, so every query sent before it has
--- been read by the gateway.
local function marker(t)
    markers = markers + 1
    local name = "marker" .. markers .. ".example.test"
    local r = resolve(name, T.A, true)
    t:assert(r.source == "dns" and #asked(name) >= 1, "the marker " .. name .. " went upstream")
end

--- Assert that no query matching `pred(question)` reached the gateway.
local function none_asked(t, pred, what)
    marker(t)
    local hits = dns.queries(gw, function(q)
        local qn = q.msg and q.msg.questions[1]
        return qn ~= nil and pred(qn)
    end)
    for _, q in ipairs(hits) do
        t:log("asked upstream: " .. q.msg.questions[1].name .. " type " .. q.msg.questions[1].type)
    end
    t:assert_eq(#hits, 0, what)
end

local function under(suffix)
    return function(qn)
        local n = qn.name:lower():gsub("%.$", "")
        return n == suffix or n:sub(-(#suffix + 1)) == "." .. suffix
    end
end

-- ---- configuration -----------------------------------------------------------

--- Replace every static name with `values` ({name = "sz:..."}) and wait
--- until `probe` (a name, its expected texts) shows it applied.
local function set_hosts(t, values, probe_name, probe_rtype, probe_want)
    network.delete(sut, HOSTS)
    -- `reg new` makes one level, so the Dns key first.
    network.write(sut, "Dns", {})
    if values and next(values) then network.write(sut, HOSTS, values) end
    local last
    local ok = pcall(wait_until, function()
        last = resolve(probe_name, probe_rtype)
        return texts(last) == probe_want
    end, { timeout = 15, interval = 0.25, desc = "static names applied" })
    t:assert(ok, "static names applied: " .. probe_name .. " gives [" .. texts(last or {}) .. "]")
end

--- The machine's own addresses as resolvd holds them: every non-loopback
--- address of every scope, in status order (one scope here).
local function own(s)
    local v4, v6 = {}, {}
    for _, sc in ipairs(s.scopes or {}) do
        for _, a in ipairs(sc.subnets or {}) do
            local addr = a:match("^([^/]+)")
            if addr:find(":", 1, true) then v6[#v6 + 1] = addr else v4[#v4 + 1] = addr end
        end
    end
    return v4, v6
end

local function rev4(a)
    local o = {}
    for x in a:gmatch("%d+") do table.insert(o, 1, x) end
    return table.concat(o, ".") .. ".in-addr.arpa"
end

local function rev6(a, upper)
    local b, out = ntfe.ip6(a), {}
    for i = 16, 1, -1 do
        local byte = b:byte(i)
        out[#out + 1] = string.format(upper and "%X" or "%x", byte & 0xF)
        out[#out + 1] = string.format(upper and "%X" or "%x", byte >> 4)
    end
    return table.concat(out, ".") .. (upper and ".IP6.ARPA" or ".ip6.arpa")
end

--- One question to the stub door; returns the decoded reply.
local function stub(name, rtype)
    local fd = assert(ntfe.udp_connect(sut, "127.0.0.53", 53))
    ntfe.send(sut, fd, dns.encode(dns.query(name, rtype or "A", { id = math.random(1, 0xFFFF) })))
    local got = ntfe.recv(sut, fd, 50, 4096)
    if not got then
        gw:serve({ timeout = 15, until_ = function()
            got = ntfe.recv(sut, fd, 30, 4096)
            return got ~= nil
        end })
    end
    sys.close(sut, fd)
    assert(got, "no stub reply for " .. name)
    return assert(dns.decode(got))
end

-- ---------------------------------------------------------------------------

test("localhost and every name under it are 127.0.0.1 for A, ::1 for AAAA, both for ANY, source synthetic",
    { spec = "resolvd *engine-synthetic.localhost PSPU *nri-resolution.synthetic-localhost" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        t:assert(pcall(wait_until, function()
            local s = rstatus()
            return s.scopes[1] ~= nil and #s.scopes[1].servers == 1
        end, { timeout = 20, interval = 0.25 }), "resolvd has eth0's scope with its server")
        dns.forget(gw)
        synthetic(t, resolve("localhost", T.A), "synthetic", "A 127.0.0.1", "localhost A")
        synthetic(t, resolve("localhost", T.AAAA), "synthetic", "AAAA ::1", "localhost AAAA")
        synthetic(t, resolve("localhost.", T.ANY), "synthetic", "A 127.0.0.1, AAAA ::1", "localhost. ANY")
        synthetic(t, resolve("LocalHost", T.A), "synthetic", "A 127.0.0.1", "LocalHost A")
        synthetic(t, resolve("app.LOCALHOST", T.A), "synthetic", "A 127.0.0.1", "app.LOCALHOST A")
        synthetic(t, resolve("a.b.localhost", T.AAAA), "synthetic", "AAAA ::1", "a.b.localhost AAAA")
        none_asked(t, under("localhost"), "no localhost question reached the network")
    end)

test("a static name is answered with its addresses of the asked family, exactly and case-insensitively, source hosts, and wins over DNS",
    { spec = "resolvd *engine-synthetic.static-name PSPU *nri-resolution.synthetic-static-names PSPU *nri-resolution.static-name-wins-over-dns" },
    function(t)
        from_dns(t, resolve("shadow.example.test", T.A, true), "shadow.example.test before any static name", "found")
        set_hosts(t, {
            ["printer.home"] = "multi:10.99.0.2,fd99::2",
            ["shadow.example.test"] = "sz:10.99.0.1",
        }, "printer.home", T.A, "A 10.99.0.2")
        synthetic(t, resolve("printer.home", T.AAAA), "hosts", "AAAA fd99::2", "printer.home AAAA")
        synthetic(t, resolve("printer.home", T.ANY), "hosts", "A 10.99.0.2, AAAA fd99::2", "printer.home ANY")
        synthetic(t, resolve("PRINTER.Home.", T.A), "hosts", "A 10.99.0.2", "PRINTER.Home. A")
        dns.forget(gw)
        synthetic(t, resolve("shadow.example.test", T.A, true), "hosts", "A 10.99.0.1",
            "shadow.example.test, also in the zone (10.77.0.81), with no_cache")
        -- Exact: a name under a static name is not that name.
        local sub = resolve("x.printer.home", T.A)
        t:log("x.printer.home: " .. tostring(sub.source) .. " " .. tostring(sub.outcome))
        t:assert_eq(sub.source, "dns", "a name under a static name is not answered by it")
        none_asked(t, function(qn) return dns.same_name(qn.name, "shadow.example.test")
            or dns.same_name(qn.name, "printer.home") end,
            "no question for a static name reached the network")
    end)

test("the hostname, exactly and case-insensitively, is answered with the machine's own addresses, source synthetic",
    { spec = "resolvd *engine-synthetic.hostname PSPU *nri-resolution.synthetic-hostname" }, function(t)
        dns.forget(gw)
        network.write(sut, network.KEY, { Hostname = "sz:peibox" })
        t:assert(pcall(wait_until, function() return rstatus().hostname == "peibox" end,
            { timeout = 20, interval = 0.25 }), "resolvd has the hostname peibox")
        local v4, v6 = own(rstatus())
        t:log("own addresses: " .. table.concat(v4, " ") .. " | " .. table.concat(v6, " "))
        t:assert_eq(table.concat(v4, " "), "10.77.0.50", "the lease's address is the IPv4 one")
        t:assert(#v6 >= 1 and v6[1]:match("^fe80:"), "the kernel's link-local address is among them")
        local want4 = "A " .. table.concat(v4, ", A ")
        local want6 = "AAAA " .. table.concat(v6, ", AAAA ")
        synthetic(t, resolve("peibox", T.A), "synthetic", want4, "peibox A")
        synthetic(t, resolve("PeiBox.", T.AAAA), "synthetic", want6, "PeiBox. AAAA")
        synthetic(t, resolve("PEIBOX", T.ANY), "synthetic", want4 .. ", " .. want6, "PEIBOX ANY")
        none_asked(t, function(qn) return dns.same_name(qn.name, "peibox") end,
            "the hostname was not asked upstream")
    end)

test("local and every name under it is notfound, source synthetic, whatever the type, and no query reaches a DNS server",
    { spec = "resolvd *engine-synthetic.local-is-notfound PSPU *nri-resolution.local-is-notfound PSPU *nri-resolution.local-never-reaches-dns" },
    function(t)
        dns.forget(gw)
        synthetic(t, resolve("local", T.A), "synthetic", "", "local A", "notfound")
        synthetic(t, resolve("printer.local", T.A), "synthetic", "", "printer.local A", "notfound")
        synthetic(t, resolve("a.b.LOCAL.", T.AAAA), "synthetic", "", "a.b.LOCAL. AAAA", "notfound")
        synthetic(t, resolve("svc.local", T.MX), "synthetic", "", "svc.local MX", "notfound")
        synthetic(t, resolve("svc.local", T.ANY), "synthetic", "", "svc.local ANY", "notfound")
        local l = ask({ query = "lookup", name = "nas.local" })
        t:log("lookup nas.local: " .. tostring(l.outcome) .. " " .. tostring(l.source))
        -- (A lookup reports the source of its last found task, else local:
        -- §4.9.)
        t:assert_eq(l.outcome, "notfound", "lookup of nas.local is notfound")
        local s = stub("cam.local", "A")
        t:log("stub cam.local: rcode " .. s.rcode .. ", " .. #s.answers .. " answers")
        t:assert_eq(s.rcode, dns.RCODE.NXDOMAIN, "the stub door answers cam.local NXDOMAIN")
        none_asked(t, under("local"), "no .local question reached the DNS server")
    end)

test("static names are checked before the hostname and .local: a static printer.local and a static name equal to the hostname answer",
    { spec = "resolvd *engine-synthetic.check-order" }, function(t)
        set_hosts(t, {
            ["printer.local"] = "sz:10.99.0.3",
            ["peibox"] = "sz:10.99.0.4",
        }, "printer.local", T.A, "A 10.99.0.3")
        synthetic(t, resolve("printer.local", T.A), "hosts", "A 10.99.0.3", "static printer.local")
        synthetic(t, resolve("other.local", T.A), "synthetic", "", "other.local, not static", "notfound")
        synthetic(t, resolve("PEIBOX", T.ANY), "hosts", "A 10.99.0.4", "the static peibox overrides the own addresses")
        set_hosts(t, {}, "printer.local", T.A, "")
        local r = resolve("peibox", T.A)
        synthetic(t, r, "synthetic", "A 10.77.0.50", "without it, peibox is the machine's own again")
    end)

test("localhost is checked before the static names: static localhost names never answer forward, but answer reverse unless loopback",
    { spec = "resolvd *engine-synthetic.static-name-under-localhost-unused" }, function(t)
        set_hosts(t, {
            ["localhost"] = "sz:10.99.0.6",
            ["printer.localhost"] = "sz:10.99.0.5",
            ["loopy"] = "sz:127.0.0.5",
            ["probe.home"] = "sz:10.99.0.11",
        }, "probe.home", T.A, "A 10.99.0.11")
        synthetic(t, resolve("localhost", T.A), "synthetic", "A 127.0.0.1", "localhost, though static")
        synthetic(t, resolve("printer.localhost", T.A), "synthetic", "A 127.0.0.1", "printer.localhost, though static")
        synthetic(t, resolve("printer.localhost", T.ANY), "synthetic", "A 127.0.0.1, AAAA ::1", "printer.localhost ANY")
        synthetic(t, ask({ query = "reverse", address = "10.99.0.5" }), "hosts", "PTR printer.localhost",
            "reverse of printer.localhost's address")
        synthetic(t, ask({ query = "reverse", address = "10.99.0.6" }), "hosts", "PTR localhost",
            "reverse of the static localhost's address")
        synthetic(t, ask({ query = "reverse", address = "127.0.0.5" }), "synthetic", "PTR localhost",
            "reverse of a static loopback address: the loopback row first")
        synthetic(t, resolve("loopy", T.A), "hosts", "A 127.0.0.5", "the loopback static name itself still answers forward")
    end)

test("for the address-bearing kinds any other type, or a missing family, is an empty found, not notfound, and is not forwarded",
    { spec = "resolvd *engine-synthetic.other-types-are-empty-found" }, function(t)
        dns.forget(gw)
        set_hosts(t, { ["v4only.home"] = "sz:10.99.0.8" }, "v4only.home", T.A, "A 10.99.0.8")
        synthetic(t, resolve("localhost", T.MX), "synthetic", "", "localhost MX")
        synthetic(t, resolve("localhost", T.TXT), "synthetic", "", "localhost TXT")
        synthetic(t, resolve("v4only.home", T.AAAA), "hosts", "", "v4only.home AAAA")
        synthetic(t, resolve("v4only.home", T.SRV), "hosts", "", "v4only.home SRV")
        synthetic(t, resolve("peibox", T.MX), "synthetic", "", "peibox MX")
        synthetic(t, resolve("peibox", 99), "synthetic", "", "peibox type 99")
        none_asked(t, function(qn)
            return under("localhost")(qn) or dns.same_name(qn.name, "v4only.home") or dns.same_name(qn.name, "peibox")
        end, "none of them was forwarded")
    end)

test("a reverse-mapping name has 4 decimal labels under in-addr.arpa or 32 hex nibbles under ip6.arpa; anything else is not one",
    { spec = "resolvd *engine-synthetic.reverse-name-forms" }, function(t)
        set_hosts(t, { ["printer.home"] = "multi:10.99.0.2,fd99::2" }, "printer.home", T.A, "A 10.99.0.2")
        synthetic(t, resolve("1.0.0.127.in-addr.arpa", T.PTR), "synthetic", "PTR localhost", "1.0.0.127.in-addr.arpa")
        synthetic(t, resolve("1.0.0.0127.in-addr.arpa", T.PTR), "synthetic", "PTR localhost", "a leading zero")
        synthetic(t, resolve("+1.0.0.127.in-addr.arpa", T.PTR), "synthetic", "PTR localhost", "a leading +")
        synthetic(t, resolve("1.0.0.127.IN-ADDR.Arpa", T.PTR), "synthetic", "PTR localhost", "the suffix in another case")
        synthetic(t, resolve(rev6("::1"), T.PTR), "synthetic", "PTR localhost", "::1 in nibbles")
        synthetic(t, resolve(rev6("fd99::2", true), T.PTR), "hosts", "PTR printer.home",
            "fd99::2 in upper-case nibbles and suffix")
        synthetic(t, resolve("2.0.99.10.in-addr.arpa", T.PTR), "hosts", "PTR printer.home", "10.99.0.2")
        -- Not reverse-mapping names: each goes to the network.
        local nibbles = rev6("::1")
        local bad = {
            "0.0.127.in-addr.arpa",                 -- three labels
            "1.1.0.0.127.in-addr.arpa",             -- five labels
            "256.0.0.127.in-addr.arpa",             -- a label over 255
            "x1.0.0.127.in-addr.arpa",              -- not decimal
            nibbles:gsub("^1%.0%.", "10."),         -- a two-digit label (31 labels)
            nibbles:gsub("^1%.", "g."),             -- not hexadecimal
            "0." .. nibbles,                        -- 33 labels
        }
        for _, name in ipairs(bad) do
            dns.forget(gw)
            local r = resolve(name, T.PTR)
            from_dns(t, r, name)
            t:assert(#asked(name, T.PTR) >= 1, name .. " was asked upstream")
        end
    end)

test("asked for PTR or ANY, a loopback address is localhost, a static name's address is the name, and an own address is the hostname, in that order",
    { spec = "resolvd *engine-synthetic.reverse-loopback resolvd *engine-synthetic.reverse-static-name resolvd *engine-synthetic.reverse-own-address PSPU *nri-resolution.synthetic-reverses" },
    function(t)
        set_hosts(t, { ["printer.home"] = "multi:10.99.0.2,fd99::2" }, "printer.home", T.A, "A 10.99.0.2")
        dns.forget(gw)
        synthetic(t, ask({ query = "reverse", address = "127.0.0.1" }), "synthetic", "PTR localhost", "reverse 127.0.0.1")
        synthetic(t, ask({ query = "reverse", address = "127.1.2.3" }), "synthetic", "PTR localhost", "reverse 127.1.2.3")
        synthetic(t, ask({ query = "reverse", address = "::1" }), "synthetic", "PTR localhost", "reverse ::1")
        synthetic(t, resolve(rev4("127.0.0.1"), T.ANY), "synthetic", "PTR localhost", "127.0.0.1's name asked for ANY")
        synthetic(t, ask({ query = "reverse", address = "10.99.0.2" }), "hosts", "PTR printer.home", "reverse 10.99.0.2")
        synthetic(t, ask({ query = "reverse", address = "fd99::2" }), "hosts", "PTR printer.home", "reverse fd99::2")
        local _, v6 = own(rstatus())
        synthetic(t, ask({ query = "reverse", address = "10.77.0.50" }), "synthetic", "PTR peibox", "reverse of the lease's address")
        synthetic(t, ask({ query = "reverse", address = v6[1] }), "synthetic", "PTR peibox", "reverse of " .. v6[1])
        synthetic(t, resolve(rev4("10.77.0.50"), T.ANY), "synthetic", "PTR peibox", "the lease's reverse name asked for ANY")
        -- The static row comes before the own-address row.
        set_hosts(t, { ["mine.home"] = "sz:10.77.0.50" }, "mine.home", T.A, "A 10.77.0.50")
        synthetic(t, ask({ query = "reverse", address = "10.77.0.50" }), "hosts", "PTR mine.home",
            "an own address that is also static: the static name")
        none_asked(t, function(qn) return qn.type == T.PTR and (under("in-addr.arpa")(qn) or under("ip6.arpa")(qn))
            and not dns.same_name(qn.name, "99.0.77.10.in-addr.arpa") end,
            "no synthetic reverse question reached the network")
    end)

test("an address listed by several static names reverses to one of them, the same one for every question under one configuration",
    { spec = "resolvd *engine-synthetic.shared-static-address-reverse-per-configuration" }, function(t)
        local names = { ["alpha.home"] = true, ["beta.home"] = true, ["gamma.home"] = true }
        set_hosts(t, {
            ["alpha.home"] = "sz:10.99.0.7", ["beta.home"] = "sz:10.99.0.7", ["gamma.home"] = "sz:10.99.0.7",
        }, "gamma.home", T.A, "A 10.99.0.7")
        local function five(what)
            local first
            for i = 1, 5 do
                local r = ask({ query = "reverse", address = "10.99.0.7" })
                synthetic(t, r, "hosts", nil, what .. " #" .. i)
                t:assert_eq(#r.records, 1, what .. ": one PTR")
                local name = r.records[1].text
                t:assert(names[name], what .. ": " .. name .. " is one of the static names")
                first = first or name
                t:assert_eq(name, first, what .. ": the same name every time")
            end
            return first
        end
        local a = five("first configuration")
        -- A change to any value builds the table afresh (PEI-1354: which
        -- name comes back may then differ; the TRM states only that it is
        -- one of them, fixed until the next change).
        network.write(sut, HOSTS, { ["zeta.home"] = "sz:10.99.0.9" })
        t:assert(pcall(wait_until, function() return texts(resolve("zeta.home", T.A)) == "A 10.99.0.9" end,
            { timeout = 15, interval = 0.25 }), "the change is applied")
        local b = five("after a configuration change")
        t:log("first configuration: " .. a .. "; after the change: " .. b)
    end)

test("a reverse name asked for another type, and one whose address matches no row, goes to the network",
    { spec = "resolvd *engine-synthetic.other-reverse-questions-go-to-network" }, function(t)
        dns.forget(gw)
        local r = resolve("1.0.0.127.in-addr.arpa", T.TXT)
        from_dns(t, r, "127.0.0.1's reverse name asked for TXT", "found")
        t:assert_eq(texts(r), 'TXT "from-dns"', "the zone's TXT record")
        r = resolve(rev4("10.77.0.50"), T.A)
        from_dns(t, r, "the lease's reverse name asked for A")
        t:assert(#asked(rev4("10.77.0.50"), T.A) == 1, "asked upstream")
        r = ask({ query = "reverse", address = "10.77.0.99" })
        from_dns(t, r, "reverse of 10.77.0.99, which no row matches", "found")
        t:assert_eq(texts(r), "PTR far.example.test", "the zone's PTR")
    end)

test("every synthetic record has TTL 0 and every synthetic answer has source synthetic or hosts, at the native socket and the stub door",
    { spec = "resolvd *engine-synthetic.ttl-zero PSPU *nri-resolution.synthetic-source-and-ttl-zero" }, function(t)
        set_hosts(t, { ["printer.home"] = "multi:10.99.0.2,fd99::2" }, "printer.home", T.A, "A 10.99.0.2")
        local cases = {
            { "localhost", T.ANY, "synthetic" }, { "printer.home", T.ANY, "hosts" },
            { "peibox", T.ANY, "synthetic" }, { rev4("127.0.0.1"), T.PTR, "synthetic" },
            { rev4("10.99.0.2"), T.PTR, "hosts" }, { rev4("10.77.0.50"), T.PTR, "synthetic" },
        }
        for _, c in ipairs(cases) do
            local r = resolve(c[1], c[2])
            synthetic(t, r, c[3], nil, c[1])
            t:assert(#r.records >= 1, c[1] .. ": has records to carry the TTL")
        end
        local l = ask({ query = "lookup", name = "printer.home" })
        t:log("lookup printer.home: " .. tostring(l.source))
        t:assert_eq(l.source, "hosts", "lookup of a static name: source hosts")
        for _, a in ipairs(l.addresses or {}) do t:assert_eq(a.ttl, 0, "lookup address " .. a.address .. ": TTL 0") end
        for _, name in ipairs({ "localhost", "printer.home", "peibox" }) do
            local s = stub(name, "A")
            t:assert_eq(s.rcode, 0, "stub " .. name .. ": NOERROR")
            t:assert(#s.answers >= 1, "stub " .. name .. ": an answer")
            for _, rec in ipairs(s.answers) do t:assert_eq(rec.ttl, 0, "stub " .. name .. ": TTL 0") end
        end
    end)

test("synthetic answers are never cached, and no_cache makes no difference to them",
    { spec = "resolvd *engine-synthetic.never-cached" }, function(t)
        local before = rstatus()
        local function both(name, rtype, source, what, outcome)
            local a, b = resolve(name, rtype), resolve(name, rtype, true)
            synthetic(t, a, source, nil, what, outcome)
            synthetic(t, b, source, texts(a), what .. " with no_cache", outcome)
        end
        both("localhost", T.ANY, "synthetic", "localhost")
        both("printer.home", T.ANY, "hosts", "printer.home")
        both("peibox", T.A, "synthetic", "peibox")
        both("x.local", T.A, "synthetic", "x.local", "notfound")
        both(rev4("127.0.0.1"), T.PTR, "synthetic", "127.0.0.1's reverse")
        both("localhost", T.ANY, "synthetic", "localhost again")
        local after = rstatus()
        t:log(string.format("cache entries %d -> %d; cache hits %d -> %d", before.cache_entries, after.cache_entries,
            before.counters.cache_hits, after.counters.cache_hits))
        t:assert_eq(after.cache_entries, before.cache_entries, "no cache entry was added")
        t:assert_eq(after.counters.cache_hits, before.counters.cache_hits, "and none was hit")
    end)

test("only the name as asked is checked: a single label expanded to a static name's name is sent to the network",
    { spec = "resolvd *engine-synthetic.expanded-candidates-not-checked" }, function(t)
        t:assert_eq(table.concat(rstatus().scopes[1].domains, " "), "lan", "eth0's search domain is lan")
        set_hosts(t, { ["printer.lan"] = "sz:10.99.0.10" }, "printer.lan", T.A, "A 10.99.0.10")
        dns.forget(gw)
        local r = resolve("printer", T.A, true)
        from_dns(t, r, "printer, expanded to printer.lan", "found")
        t:assert_eq(texts(r), "A 10.77.0.82", "the zone's address, not the static one")
        t:assert_eq(#asked("printer.lan", T.A), 1, "printer.lan was asked upstream")
        synthetic(t, resolve("printer.lan", T.A), "hosts", "A 10.99.0.10", "printer.lan asked as itself")
    end)

test("every kind of synthetic name is answered before any network, at the native socket and the stub door",
    { spec = "PSPU *nri-resolution.synthetic-before-network" }, function(t)
        set_hosts(t, { ["printer.home"] = "multi:10.99.0.2,fd99::2" }, "printer.home", T.A, "A 10.99.0.2")
        dns.forget(gw)
        local names = { "localhost", "a.localhost", "printer.home", "peibox", "nas.local",
            rev4("127.0.0.1"), rev4("10.99.0.2"), rev4("10.77.0.50") }
        for _, n in ipairs(names) do
            local r = resolve(n, n:find("arpa$") and T.PTR or T.A)
            t:assert(r.source == "synthetic" or r.source == "hosts", n .. ": answered locally (" .. tostring(r.source) .. ")")
            -- A lookup asks A and AAAA, which a reverse name answers only
            -- for PTR and ANY; so only the forward names are looked up.
            if not n:find("arpa$") then
                local l = ask({ query = "lookup", name = n })
                if n == "nas.local" then
                    t:assert_eq(l.outcome, "notfound", "lookup nas.local: notfound")
                else
                    t:assert(l.source == "synthetic" or l.source == "hosts",
                        "lookup " .. n .. ": answered locally (" .. tostring(l.source) .. ")")
                end
            end
            local s = stub(n, n:find("arpa$") and "PTR" or "A")
            t:assert(s.qr, "stub " .. n .. ": a reply")
        end
        for _, a in ipairs({ "127.0.0.1", "10.99.0.2", "10.77.0.50", "::1" }) do
            local r = ask({ query = "reverse", address = a })
            t:assert(r.source == "synthetic" or r.source == "hosts", "reverse " .. a .. ": answered locally")
        end
        none_asked(t, function(qn)
            for _, n in ipairs(names) do if dns.same_name(qn.name, n) then return true end end
            return under("localhost")(qn) or under("local")(qn) or dns.same_name(qn.name, rev6("::1"))
        end, "none of them reached the network")
    end)

test("LLMNR is not spoken: no frame to port 5355 left the machine, and no socket on it is open",
    { spec = "PSPU *nri-resolution.no-llmnr" }, function(t)
        -- Single labels that no search domain can answer, the questions an
        -- LLMNR responder would multicast.
        for _, n in ipairs({ "lonely", "printer", "nas" }) do resolve(n, T.A, true) end
        gw:serve({ timeout = 2 })
        local llmnr = gw:frames(function(f)
            return (f.udp and (f.udp.dport == 5355 or f.udp.sport == 5355))
                or f.dst_ip == "224.0.0.252" or f.dst_ip == "ff02::1:3"
        end)
        local udp = 0
        for _ in pairs(gw.seen) do udp = udp + 1 end
        t:log(string.format("%d frames seen from the machine this boot; %d LLMNR", udp, #llmnr))
        t:assert(udp > 0, "the gateway has been watching the machine")
        t:assert_eq(#llmnr, 0, "no LLMNR frame")
        local socks = sut:run("cat /proc/net/udp /proc/net/udp6 /proc/net/tcp /proc/net/tcp6")
        socks:assert_ok()
        local open = socks.stdout:match(":14EB ") ~= nil
        t:assert(not open, "no socket on port 5355")
    end)

test("with no scope at addressed or better, the hostname is answered with 127.0.0.1 and ::1",
    { spec = "resolvd *engine-synthetic.hostname-without-addresses-is-loopback" }, function(t)
        local nic = lan:nic(sut)
        nic:disconnect()
        t:assert(pcall(wait_until, function() return #rstatus().scopes == 0 end, { timeout = 20, interval = 0.25 }),
            "with the cable out, resolvd has no scope")
        t:assert_eq(rstatus().hostname, "peibox", "and still has the hostname")
        synthetic(t, resolve("peibox", T.ANY), "synthetic", "A 127.0.0.1, AAAA ::1", "peibox ANY")
        synthetic(t, resolve("peibox", T.A), "synthetic", "A 127.0.0.1", "peibox A")
        nic:reconnect()
    end)
