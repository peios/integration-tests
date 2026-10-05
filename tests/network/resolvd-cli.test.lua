-- resolvd §8.1 — the resolv command: its verbs and the request each
-- sends, the arguments it checks before contacting resolvd, its output
-- formats and its exit statuses.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). eth0's lease names
-- the gateway (10.77.0.1) as its DNS server and `pt-cli.test` as its
-- domain, so real answers carry `via 10.77.0.1 on eth0`. One name,
-- `silent.example.test`, is never answered, for `unavailable`.
--
-- The first tests run `resolv` against the real resolvd and compare what
-- it prints with the reply to the same request sent from the agent on
-- the native socket (a cached or synthetic answer, so the agent's
-- blocking call is safe).
--
-- The later tests stop resolvd and put a fake one in its place: the
-- agent listens on /run/resolvd/resolv.sock itself, reads what `resolv`
-- sends, and answers with whatever the test chooses. That shows exactly
-- one connection and one request per verb, the request's fields, which
-- invocations never connect at all, and how `resolv` renders replies the
-- real daemon cannot produce on demand: a `found` with a non-zero
-- response code, a status with no scopes or with every flag, a reply of
-- the wrong kind, a broken frame, a reply held back for twelve seconds.
-- `svctl stop resolvd` leaves resolvd's socket behind (R1's finding); the
-- test removes it before binding its own.
--
-- Own VMs: the file stops resolvd for good half-way through.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local msgpack = require("helpers.msgpack")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" }, options = { { 15, "pt-cli.test" } } })
dns.serve(gw, {
    zone = {
        ["www.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" },
                                 { type = "AAAA", ttl = 300, data = "fd77::80" } },
        ["alias.example.test"] = { { type = "CNAME", ttl = 300, data = "www.example.test" } },
        ["80.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 300, data = "www.example.test" } },
        ["81.0.77.10.in-addr.arpa"] = { { type = "CNAME", ttl = 300, data = "81.sub.0.77.10.in-addr.arpa" } },
        ["81.sub.0.77.10.in-addr.arpa"] = { { type = "PTR", ttl = 300, data = "alias.example.test" } },
    },
    on = function(q)
        if q.questions[1] and q.questions[1].name:lower() == "silent.example.test" then return false end
    end,
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

local SOCK = "/run/resolvd/resolv.sock"
local DNS = network.KEY .. [[\Dns]]

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function native(req, timeout_ms)
    local r, err = network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms })
    assert(r, "native " .. tostring(req.query) .. ": " .. tostring(err))
    return r
end

local function scope(s, name)
    for _, sc in ipairs(s.scopes or {}) do if sc.interface == name then return sc end end
end

--- Run a guest command while the gateway pumps; returns its result.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

local function lines(s)
    local out = {}
    for l in s:gmatch("([^\n]*)\n") do out[#out + 1] = l end
    return out
end

local function show(t, what, r)
    t:log(string.format("%s: exit %s\n--stdout--\n%s--stderr--\n%s", what, tostring(r.exit_code), r.stdout, r.stderr))
end

local function questions_for(name)
    return dns.queries(gw, function(e)
        local q = e.msg and e.msg.questions[1]
        return q and q.name:lower() == name
    end)
end

-- What resolv prints for each reply, per the TRM; applied to the real
-- daemon's replies and to the fake's.
local TYPE_NAME = { [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA", [12] = "PTR", [15] = "MX",
                    [16] = "TXT", [28] = "AAAA", [33] = "SRV", [255] = "ANY" }

local function render_answer_records(a, out)
    for _, r in ipairs(a.records or {}) do
        out[#out + 1] = string.format("%s\t%d\t%s\t%s", r.name, r.ttl,
            TYPE_NAME[r.type] or ("TYPE" .. r.type), r.text)
    end
end

local function render_status(s)
    local o = {}
    o[#o + 1] = "hostname   " .. ((s.hostname or "") ~= "" and s.hostname or "(unset)")
    o[#o + 1] = "netd       " .. (s.netd and "connected" or "not connected")
    o[#o + 1] = "cache      " .. tostring(s.cache_entries) .. " entries"
    if #(s.scopes or {}) == 0 then o[#o + 1] = "scopes     (none)" end
    for _, sc in ipairs(s.scopes or {}) do
        o[#o + 1] = ""
        local flags = {}
        if sc.default_route then flags[#flags + 1] = "default-route" end
        if sc.exclusive then flags[#flags + 1] = "exclusive" end
        o[#o + 1] = sc.interface .. "  metric " .. tostring(sc.metric)
            .. (#flags > 0 and ("  [" .. table.concat(flags, ", ") .. "]") or "")
        local demoted = {}
        for _, d in ipairs(sc.demoted or {}) do demoted[d] = true end
        for _, a in ipairs(sc.servers or {}) do
            o[#o + 1] = "  server   " .. a .. (demoted[a] and "  (demoted)" or "")
        end
        for _, d in ipairs(sc.domains or {}) do o[#o + 1] = "  domain   " .. d end
        for _, n in ipairs(sc.subnets or {}) do o[#o + 1] = "  subnet   " .. n end
    end
    if #(s.fallback_servers or {}) > 0 then
        o[#o + 1] = ""
        o[#o + 1] = "fallback   " .. table.concat(s.fallback_servers, " ")
    end
    local c = s.counters
    o[#o + 1] = ""
    o[#o + 1] = string.format("queries %d  synthetic %d  cache-hits %d  upstream sent %d answered %d failed %d  refused %d",
        c.queries, c.synthetic, c.cache_hits, c.upstream_sent, c.upstream_answered, c.upstream_failed, c.refused)
    return table.concat(o, "\n") .. "\n"
end

local function render_lookup(a)
    local o = { string.format("%s  %s  canonical %s", a.outcome, a.source, a.canonical) }
    for _, x in ipairs(a.addresses or {}) do o[#o + 1] = x.address .. "\t" .. x.ttl end
    return table.concat(o, "\n") .. "\n"
end

local function render_reverse(a)
    local o = { a.outcome .. "  " .. a.source }
    for _, r in ipairs(a.records or {}) do o[#o + 1] = r.text end
    return table.concat(o, "\n") .. "\n"
end

-- ---- the fake resolvd ------------------------------------------------------

local fake = {}

--- Stop resolvd (once) and see that it stays stopped.
local function stop_resolvd(t)
    if fake.stopped then return end
    sut:run("svctl stop resolvd"):assert_ok()
    wait_until(function() return peinit.pid_of_comm(sut, "resolvd") == nil end,
        { timeout = 20, interval = 0.25, desc = "resolvd to stop" })
    sut:run("sleep 2")
    t:assert_eq(peinit.pid_of_comm(sut, "resolvd"), nil, "resolvd stays stopped")
    t:log("after stop: " .. sut:run("ls -la /run/resolvd 2>&1").stdout)
    sut:run("rm -f " .. SOCK .. "; mkdir -p /run/resolvd"):assert_ok()
    fake.stopped = true
end

--- The fake's listening socket, made on first use.
local function fake_listener(t)
    stop_resolvd(t)
    if fake.lfd then return fake.lfd end
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local b = unixsock.bind(sut, fd, SOCK)
    assert(b.ret == 0, "bind " .. SOCK .. ": " .. unixsock.errname(b.errno))
    local l = unixsock.listen(sut, fd, 8)
    assert(l.ret == 0, "listen: " .. unixsock.errname(l.errno))
    sut:run("chmod 0666 " .. SOCK)
    fake.lfd = fd
    return fd
end

local function fake_close()
    if fake.lfd then sys.close(sut, fake.lfd); fake.lfd = nil end
    sut:run("rm -f " .. SOCK)
end

local function read_exact(fd, n, timeout_ms)
    local got = ""
    while #got < n do
        local chunk, err = ntfe.recv(sut, fd, timeout_ms or 5000, n - #got)
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        got = got .. chunk
    end
    return got
end

local function frame(payload) return string.pack("<I4", #payload) .. payload end

--- Run `cmd` against the fake. When it connects, read one request and
--- answer `reply` (a table, encoded and framed; `o.raw` sends bytes as
--- they are; `o.hold` waits that many seconds first). Returns:
---   connections  how many connections the command opened (0 or 1, then
---                `second` says whether another one followed)
---   req          the decoded request; `body` its bytes
---   extra        what arrived on the connection after the request ("" = EOF)
---   running      when `o.hold`: whether the command was still running
---   result       the command's result
local function exchange(t, cmd, reply, o)
    o = o or {}
    local lfd = fake_listener(t)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    local out = { connections = 0 }
    if ntfe.poll(sut, lfd, ntfe.POLLIN, o.connect_ms or 5000) == 0 then
        out.result = p:wait(10)
        out.second = ntfe.poll(sut, lfd, ntfe.POLLIN, 300) ~= 0
        return out
    end
    local c = assert(unixsock.accept(sut, lfd))
    out.connections = 1
    local head = read_exact(c, 4)
    if head then
        out.body = read_exact(c, string.unpack("<I4", head))
        out.req = out.body and msgpack.decode(out.body)
    end
    if o.hold then
        local deadline = os.time() + o.hold
        while os.time() < deadline do sut:run("sleep 0.5") end
        out.running = p:status() == "running"
    end
    if o.raw then
        ntfe.send(sut, c, o.raw)
    elseif reply then
        ntfe.send(sut, c, frame(msgpack.encode(reply)))
    end
    if o.close then sys.close(sut, c); c = nil end
    out.result = p:wait(10)
    if c then
        local more = ntfe.recv(sut, c, 500, 4096)
        out.extra = more
        sys.close(sut, c)
    end
    out.second = ntfe.poll(sut, lfd, ntfe.POLLIN, 300) ~= 0
    if out.second then
        local c2 = unixsock.accept(sut, lfd)
        if c2 then sys.close(sut, c2) end
    end
    return out
end

local function keys_of(m)
    local ks = {}
    for k in pairs(m or {}) do ks[#ks + 1] = k end
    table.sort(ks)
    return table.concat(ks, ",")
end

local A = msgpack.array

local function answer(o)
    return { ok = true, kind = "answer", outcome = o.outcome or "found", records = A(o.records or {}),
             source = o.source or "dns", server = o.server or msgpack.NIL, interface = o.interface or msgpack.NIL,
             validation = "unvalidated", rcode = o.rcode or 0 }
end

local function status_reply(o)
    return { ok = true, kind = "status", hostname = o.hostname or "", netd = o.netd,
             scopes = A(o.scopes or {}), fallback_servers = A(o.fallback_servers or {}),
             cache_entries = o.cache_entries or 0,
             counters = o.counters or { queries = 0, synthetic = 0, cache_hits = 0, upstream_sent = 0,
                                        upstream_answered = 0, upstream_failed = 0, refused = 0 } }
end

local function fake_scope(o)
    return { interface = o.interface, servers = A(o.servers or {}), domains = A(o.domains or {}),
             default_route = o.default_route or false, exclusive = o.exclusive or false,
             metric = o.metric or 0, subnets = A(o.subnets or {}), demoted = A(o.demoted or {}) }
end

-- ---------------------------------------------------------------------------
-- The real resolvd
-- ---------------------------------------------------------------------------

test("exit status 0 for found and for status, flush and version; 2 for notfound; 3 for unavailable; flush prints nothing",
    { spec = "resolvd *resolv.exit-0 resolvd *resolv.exit-2 resolvd *resolv.exit-3 resolvd *resolv.flush-silent" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        wait_until(function()
            local sc = scope(native({ query = "status" }), "eth0")
            return sc ~= nil and #(sc.servers or {}) > 0
        end, { timeout = 30, interval = 0.25, desc = "resolvd to see eth0's server" })

        local function exit_of(cmd, want, what)
            local r = served(cmd)
            show(t, cmd, r)
            t:assert_eq(r.exit_code, want, what)
            return r
        end
        local r = exit_of("resolv query www.example.test", 0, "found exits 0")
        t:assert(r.stdout:match("^found  "), "and was found")
        exit_of("resolv lookup www.example.test", 0, "a found lookup exits 0")
        exit_of("resolv reverse 127.0.0.1", 0, "a found reverse exits 0")
        exit_of("resolv status", 0, "status exits 0")
        exit_of("resolv version", 0, "version exits 0")
        r = exit_of("resolv flush", 0, "flush exits 0")
        t:assert_eq(r.stdout, "", "flush prints nothing on stdout")
        t:assert_eq(r.stderr, "", "or stderr")

        r = exit_of("resolv query nx.example.test", 2, "notfound exits 2")
        t:assert(r.stdout:match("^notfound  "), "and was notfound")
        exit_of("resolv lookup nx.example.test", 2, "a notfound lookup exits 2")
        exit_of("resolv reverse 10.77.0.99", 2, "a notfound reverse exits 2")

        r = exit_of("resolv query silent.example.test", 3, "unavailable exits 3")
        t:assert(r.stdout:match("^unavailable  "), "and was unavailable")
    end)

test("an argument list resolv does not recognise prints a usage line on stderr and exits 64",
    { spec = "resolvd *resolv.usage-exit-64" }, function(t)
        for _, args in ipairs({ "", "bogus", "query", "query a.test A extra", "status extra", "flush now",
                                "lookup", "lookup a b", "reverse", "reverse 10.0.0.1 10.0.0.2", "version x",
                                "--no-cache", "help", "-h", "QUERY a.test", "Status" }) do
            local r = sut:run("resolv " .. args)
            local ls = lines(r.stderr)
            t:log(string.format("resolv %s -> %d %q", args, r.exit_code, r.stderr))
            t:assert_eq(r.exit_code, 64, "`resolv " .. args .. "` exits 64")
            t:assert_eq(r.stdout, "", "nothing on stdout")
            t:assert_eq(#ls, 1, "one line on stderr")
            t:assert(ls[1] and ls[1]:match("^usage: resolv "), "a usage line: " .. tostring(ls[1]))
        end
    end)

test("--no-cache is taken from anywhere on the command line and affects only query",
    { spec = "resolvd *resolv.no-cache-anywhere" }, function(t)
        sut:run("resolv flush"):assert_ok()
        local r = served("resolv query www.example.test")
        t:assert(r.stdout:match("^found  dns "), "asked upstream first")
        served("resolv query www.example.test AAAA"):assert_ok()
        dns.forget(gw)
        r = served("resolv query www.example.test")
        t:assert(r.stdout:match("^found  cache "), "then answered from the cache: " .. r.stdout)
        t:assert_eq(#questions_for("www.example.test"), 0, "without a question upstream")

        for _, args in ipairs({ "--no-cache query www.example.test", "query --no-cache www.example.test",
                                "query www.example.test --no-cache", "query www.example.test A --no-cache",
                                "query --no-cache www.example.test A", "query www.example.test --no-cache A" }) do
            dns.forget(gw)
            r = served("resolv " .. args)
            show(t, args, r)
            t:assert_eq(r.exit_code, 0, args .. ": found")
            t:assert(r.stdout:match("^found  dns via 10%.77%.0%.1 on eth0  "), args .. ": the cache was skipped")
            local asked = questions_for("www.example.test")
            t:assert(#asked >= 1 and asked[1].msg.questions[1].type == dns.TYPE.A,
                args .. ": an A question went upstream")
        end

        -- Other verbs: the flag is removed and has no effect.
        dns.forget(gw)
        r = sut:run("resolv status --no-cache")
        t:assert_eq(r.exit_code, 0, "status --no-cache is status")
        t:assert(r.stdout:match("^hostname   "), "and prints the status")
        r = served("resolv lookup --no-cache www.example.test")
        show(t, "lookup --no-cache", r)
        t:assert_eq(r.exit_code, 0, "lookup --no-cache is found")
        t:assert_eq(#questions_for("www.example.test"), 0, "from the cache: --no-cache did not reach lookup")
        r = sut:run("resolv --no-cache flush")
        t:assert_eq(r.exit_code, 0, "flush --no-cache is flush")
        t:assert_eq(r.stdout .. r.stderr, "", "silently")
    end)

test("output: query, lookup, reverse and status print the reply in the documented layout",
    { spec = "resolvd *resolv.query-output resolvd *resolv.lookup-output resolvd *resolv.reverse-output resolvd *resolv.status-output" },
    function(t)
        local r
        -- query, from a server, fresh: the TTLs are the server's.
        r = served("resolv query www.example.test A --no-cache")
        show(t, "query www", r)
        local ls = lines(r.stdout)
        t:assert_eq(#ls, 2, "a summary line and one record line")
        t:assert_eq(ls[1], "found  dns via 10.77.0.1 on eth0  validation unvalidated", "the summary line")
        local name, rest = ls[2]:match("^([^\t]+)\t(.*)$")
        t:assert(name and dns.same_name(name, "www.example.test"), "the record's name")
        t:assert_eq(rest, "300\tA\t10.77.0.80", "ttl, type and text, tab-separated")

        r = served("resolv query alias.example.test --no-cache")
        show(t, "query alias", r)
        ls = lines(r.stdout)
        local cached = native({ query = "resolve", name = "alias.example.test", type = 1, no_cache = false })
        t:assert_eq(cached.source, "cache", "the native check is answered from the cache")
        t:assert_eq(#ls, 1 + #cached.records, "one line per record")
        t:assert_eq(ls[1], "found  dns via 10.77.0.1 on eth0  validation unvalidated", "the summary line")
        for i, rec in ipairs(cached.records) do
            local n, ttl, ty, text = ls[i + 1]:match("^([^\t]+)\t(%d+)\t([^\t]+)\t(.*)$")
            t:assert(n and dns.same_name(n, rec.name), "record " .. i .. "'s name")
            t:assert_eq(ty, TYPE_NAME[rec.type], "record " .. i .. "'s type")
            t:assert_eq(text, rec.text, "record " .. i .. "'s text")
            t:assert_eq(tonumber(ttl), 300, "record " .. i .. "'s ttl, fresh")
        end
        t:assert_eq(ls[2]:match("\t(%u+)\t"), "CNAME", "the CNAME first")

        -- Synthetic: no via, no on.
        r = sut:run("resolv query localhost")
        t:assert_eq(r.stdout, "found  synthetic  validation unvalidated\nlocalhost\t0\tA\t127.0.0.1\n",
            "a synthetic answer")
        r = sut:run("resolv query localhost AAAA")
        t:assert_eq(r.stdout, "found  synthetic  validation unvalidated\nlocalhost\t0\tAAAA\t::1\n",
            "a synthetic AAAA")
        -- notfound with response code 3: no rcode line (that is for found).
        r = served("resolv query nx.example.test")
        t:assert_eq(r.stdout, "notfound  dns via 10.77.0.1 on eth0  validation unvalidated\n",
            "NXDOMAIN: the summary alone")

        -- lookup.
        r = served("resolv lookup www.example.test")
        show(t, "lookup", r)
        ls = lines(r.stdout)
        local o, src, canon = (ls[1] or ""):match("^(%S+)  (%S+)  canonical (%S+)$")
        t:assert_eq(o, "found", "lookup's summary: outcome")
        t:assert(src and canon and dns.same_name(canon, "www.example.test"), "source and canonical name")
        local got = {}
        for i = 2, #ls do
            local a, ttl = ls[i]:match("^([^\t]+)\t(%d+)$")
            t:assert(a, "an address line: " .. ls[i])
            got[#got + 1] = a
        end
        table.sort(got)
        t:assert_eq(table.concat(got, " "), "10.77.0.80 fd77::80", "one line per address")
        local nl = native({ query = "lookup", name = "localhost", family = "any" })
        r = sut:run("resolv lookup localhost")
        t:assert_eq(r.stdout, render_lookup(nl), "lookup localhost renders the reply exactly")

        -- reverse: every record's text, whatever its type.
        r = served("resolv reverse 10.77.0.81")
        show(t, "reverse .81", r)
        local nr = native({ query = "reverse", address = "10.77.0.81" })
        t:assert_eq(nr.source, "cache", "the native check is answered from the cache")
        t:assert_eq(#nr.records, 2, "a CNAME and a PTR")
        ls = lines(r.stdout)
        t:assert_eq(ls[1], "found  dns", "reverse's summary line")
        t:assert_eq(#ls, 3, "and a line per record")
        t:assert_eq(ls[2], nr.records[1].text, "the CNAME's text")
        t:assert_eq(ls[3], nr.records[2].text, "the PTR's text")
        r = sut:run("resolv reverse 127.0.0.1")
        t:assert_eq(r.stdout, render_reverse(native({ query = "reverse", address = "127.0.0.1" })),
            "reverse 127.0.0.1 renders the reply exactly")

        -- status, with a fallback list, against the reply. Background
        -- questions move the counters, so the reply is read on both sides
        -- of the command and must not have changed.
        network.reg(sut, { "new", DNS })
        network.reg(sut, { "set", DNS, "FallbackServers", "multi:10.77.0.9" }):assert_ok()
        local done = false
        for attempt = 1, 8 do
            local before = native({ query = "status" })
            r = sut:run("resolv status")
            local after = native({ query = "status" })
            if #(after.fallback_servers or {}) > 0 and render_status(before) == render_status(after) then
                show(t, "status", r)
                t:log("reply: " .. json.encode(after))
                t:assert_eq(r.stdout, render_status(after), "status renders the reply exactly")
                t:assert(r.stdout:find("\neth0  metric ", 1, true), "with eth0's scope")
                t:assert(r.stdout:find("\nfallback   10.77.0.9\n", 1, true), "and the fallback line")
                done = true
                break
            end
            sut:run("sleep 0.3")
        end
        t:assert(done, "a status taken while nothing moved")
        network.reg(sut, { "del", DNS, "FallbackServers" })

        -- The fake resolvd, for what the real one does not produce on demand.
        local function q(reply, args)
            local x = exchange(t, "resolv query " .. (args or "x.test"), reply)
            t:assert_eq(x.connections, 1, "connected")
            return x.result
        end
        local rec = { name = "x.test", type = 1, ttl = 5, text = "10.0.0.1" }
        r = q(answer({ records = { rec }, server = "10.0.0.53", interface = "eth9", rcode = 2 }))
        t:assert_eq(r.stdout, "found  dns via 10.0.0.53 on eth9  validation unvalidated\nrcode SERVFAIL\nx.test\t5\tA\t10.0.0.1\n",
            "found with response code 2: the rcode line follows the summary")
        r = q(answer({ records = { rec, { name = "x.test", type = 99, ttl = 6, text = "\\# 1 00" } }, rcode = 0 }))
        t:assert_eq(r.stdout, "found  dns  validation unvalidated\nx.test\t5\tA\t10.0.0.1\nx.test\t6\tTYPE99\t\\# 1 00\n",
            "no server, no interface, rcode 0: neither via, on nor rcode; one line per record")
        r = q(answer({ outcome = "notfound", server = "10.0.0.53", rcode = 3 }))
        t:assert_eq(r.stdout, "notfound  dns via 10.0.0.53  validation unvalidated\n", "via without on")
        r = q(answer({ outcome = "unavailable", source = "local", interface = "eth9" }))
        t:assert_eq(r.stdout, "unavailable  local on eth9  validation unvalidated\n", "on without via")

        local lk = { ok = true, kind = "addresses", outcome = "found", canonical = "c.test",
                     addresses = A({ { address = "10.0.0.1", ttl = 7 }, { address = "fd00::1", ttl = 8 } }),
                     source = "dns", validation = "unvalidated" }
        r = exchange(t, "resolv lookup x.test", lk).result
        t:assert_eq(r.stdout, "found  dns  canonical c.test\n10.0.0.1\t7\nfd00::1\t8\n", "lookup's layout")

        r = exchange(t, "resolv reverse 10.0.0.1", answer({ records = {
            { name = "1.0.0.10.in-addr.arpa", type = 5, ttl = 1, text = "1.sub.example" },
            { name = "1.sub.example", type = 12, ttl = 1, text = "host.example" },
            { name = "1.sub.example", type = 16, ttl = 1, text = "\"a txt\"" } } })).result
        t:assert_eq(r.stdout, "found  dns\n1.sub.example\nhost.example\n\"a txt\"\n",
            "reverse prints every record's text, whatever its type")

        local full = status_reply({
            hostname = "pt-host", netd = true, cache_entries = 12,
            scopes = {
                fake_scope({ interface = "eth0", metric = 100, default_route = true, exclusive = true,
                    servers = { "10.0.0.1", "10.0.0.2" }, demoted = { "10.0.0.1" },
                    domains = { "a.test", "b.test" }, subnets = { "10.0.0.5/24", "fd00::5/64" } }),
                fake_scope({ interface = "wg0", metric = 50, exclusive = true, servers = { "10.9.0.1" } }),
                fake_scope({ interface = "eth1", metric = 200, default_route = true }),
                fake_scope({ interface = "eth2", metric = 300 }),
            },
            fallback_servers = { "9.9.9.9", "2620:fe::fe" },
            counters = { queries = 1, synthetic = 2, cache_hits = 3, upstream_sent = 4,
                         upstream_answered = 5, upstream_failed = 6, refused = 7 },
        })
        r = exchange(t, "resolv status", full).result
        local want = table.concat({
            "hostname   pt-host",
            "netd       connected",
            "cache      12 entries",
            "",
            "eth0  metric 100  [default-route, exclusive]",
            "  server   10.0.0.1  (demoted)",
            "  server   10.0.0.2",
            "  domain   a.test",
            "  domain   b.test",
            "  subnet   10.0.0.5/24",
            "  subnet   fd00::5/64",
            "",
            "wg0  metric 50  [exclusive]",
            "  server   10.9.0.1",
            "",
            "eth1  metric 200  [default-route]",
            "",
            "eth2  metric 300",
            "",
            "fallback   9.9.9.9 2620:fe::fe",
            "",
            "queries 1  synthetic 2  cache-hits 3  upstream sent 4 answered 5 failed 6  refused 7",
        }, "\n") .. "\n"
        t:log(r.stdout)
        t:assert_eq(r.stdout, want, "status with every element")
        r = exchange(t, "resolv status", status_reply({ netd = false })).result
        t:assert_eq(r.stdout, table.concat({
            "hostname   (unset)",
            "netd       not connected",
            "cache      0 entries",
            "scopes     (none)",
            "",
            "queries 0  synthetic 0  cache-hits 0  upstream sent 0 answered 0 failed 0  refused 0",
        }, "\n") .. "\n", "status with nothing: (unset), not connected, (none), no fallback line")
    end)

-- ---------------------------------------------------------------------------
-- The fake resolvd
-- ---------------------------------------------------------------------------

test("every verb but version is one request on one connection",
    { spec = "resolvd *resolv.one-request-per-verb" }, function(t)
        local cases = {
            { "resolv status", { query = "status" }, status_reply({ netd = true }) },
            { "resolv query www.x.test MX --no-cache", { query = "resolve", name = "www.x.test", type = 15, no_cache = true },
              answer({}) },
            { "resolv query www.x.test", { query = "resolve", name = "www.x.test", type = 1, no_cache = false }, answer({}) },
            { "resolv lookup h.x.test", { query = "lookup", name = "h.x.test", family = "any" },
              { ok = true, kind = "addresses", outcome = "found", canonical = "h.x.test", addresses = A({}),
                source = "dns", validation = "unvalidated" } },
            { "resolv reverse fd00:0::0001", { query = "reverse", address = "fd00::1" }, answer({}) },
            { "resolv flush", { query = "flush" }, { ok = true } },
        }
        for _, c in ipairs(cases) do
            local x = exchange(t, c[1], c[3])
            show(t, c[1], x.result)
            t:log("request: " .. json.encode(x.req))
            t:assert_eq(x.connections, 1, c[1] .. ": one connection")
            t:assert_eq(keys_of(x.req), keys_of(c[2]), c[1] .. ": the request's fields")
            for k, v in pairs(c[2]) do
                t:assert_eq(x.req and x.req[k], v, c[1] .. ": " .. k)
            end
            t:assert_eq(x.extra, "", c[1] .. ": nothing after the one request; the connection is closed")
            t:assert_eq(x.second, false, c[1] .. ": no second connection")
            t:assert_eq(x.result.exit_code, 0, c[1] .. ": the reply was taken")
        end
        local x = exchange(t, "resolv version", nil, { connect_ms = 1500 })
        t:assert_eq(x.connections, 0, "version opens no connection")
        t:assert_eq(x.second, false, "at all")
        t:assert(x.result.stdout:match("^resolv %S+\n$"), "and prints its version: " .. x.result.stdout)
    end)

test("query's type is A when omitted, one of ten names in any case, or TYPE<n> for 0 to 65535",
    { spec = "resolvd *resolv.query-type-names" }, function(t)
        local cases = {
            { "", 1 }, { "A", 1 }, { "a", 1 }, { "Ns", 2 }, { "CNAME", 5 }, { "soa", 6 }, { "Ptr", 12 },
            { "mx", 15 }, { "TXT", 16 }, { "aaaa", 28 }, { "SRV", 33 }, { "any", 255 },
            { "TYPE0", 0 }, { "type99", 99 }, { "Type65535", 65535 },
        }
        for _, c in ipairs(cases) do
            local cmd = "resolv query t.x.test " .. c[1]
            local x = exchange(t, cmd, answer({ outcome = "notfound" }))
            t:assert_eq(x.connections, 1, cmd .. ": sent")
            t:assert_eq(x.req and x.req.type, c[2], cmd .. ": type " .. c[2])
            t:assert_eq(x.result.exit_code, 2, cmd .. ": the reply rendered")
        end
    end)

test("a type or an address resolv cannot parse is refused before resolvd is contacted, with exit 1",
    { spec = "resolvd *resolv.unknown-type-exits-1 resolvd *resolv.bad-address-exits-1" }, function(t)
        for _, ty in ipairs({ "BOGUS", "AXFR", "TYPE65536", "TYPE", "TYPEx", "TYPE-1", "1" }) do
            local x = exchange(t, "resolv query t.x.test " .. ty, nil, { connect_ms = 1500 })
            show(t, "query type " .. ty, x.result)
            t:assert_eq(x.connections, 0, ty .. ": resolvd is not contacted")
            t:assert_eq(x.result.exit_code, 1, ty .. ": exit 1")
            t:assert_eq(x.result.stderr, 'resolv: unknown record type "' .. ty .. '"\n', ty .. ": the message")
            t:assert_eq(x.result.stdout, "", ty .. ": nothing on stdout")
        end
        for _, a in ipairs({ "nope", "10.0.0.256", "fe80::1%eth0", "10.0.0", "x.test" }) do
            local x = exchange(t, "resolv reverse '" .. a .. "'", nil, { connect_ms = 1500 })
            show(t, "reverse " .. a, x.result)
            t:assert_eq(x.connections, 0, a .. ": resolvd is not contacted")
            t:assert_eq(x.result.exit_code, 1, a .. ": exit 1")
            t:assert_eq(x.result.stderr, 'resolv: "' .. a .. '" is not an address\n', a .. ": the message")
        end
    end)

test("exit 1: an error reply, access denied included, a protocol failure, and a reply of the wrong kind (silently)",
    { spec = "resolvd *resolv.exit-1" }, function(t)
        local function case(cmd, reply, o, want_err, what)
            local x = exchange(t, cmd, reply, o)
            show(t, what, x.result)
            t:assert_eq(x.connections, 1, what .. ": connected")
            t:assert_eq(x.result.exit_code, 1, what .. ": exit 1")
            t:assert_eq(x.result.stdout, "", what .. ": nothing on stdout")
            if want_err == true then
                t:assert(x.result.stderr:match("^resolv: .+\n$"), what .. ": an error line")
            else
                t:assert_eq(x.result.stderr, want_err, what .. ": stderr")
            end
        end
        for _, cmd in ipairs({ "resolv status", "resolv query x.test", "resolv lookup x.test",
                               "resolv reverse 10.0.0.1", "resolv flush" }) do
            case(cmd, { ok = false, error = "access denied" }, nil, "resolv: access denied\n", cmd .. " denied")
        end
        case("resolv query x.test", { ok = false, error = "pt: some failure" }, nil, "resolv: pt: some failure\n",
            "another error reply")
        -- The wrong kind of reply: exit 1 with no message.
        case("resolv status", { ok = true }, nil, "", "status answered ok")
        case("resolv query x.test", status_reply({ netd = true }), nil, "", "query answered with a status")
        case("resolv lookup x.test", answer({}), nil, "", "lookup answered with an answer")
        case("resolv reverse 10.0.0.1", { ok = true }, nil, "", "reverse answered ok")
        case("resolv flush", status_reply({ netd = true }), nil, "", "flush answered with a status")
        -- Protocol failures.
        case("resolv status", nil, { raw = string.pack("<I4", 0x00100000) }, true, "a frame too large")
        case("resolv status", nil, { raw = frame("\xc1\xc1") }, true, "bytes that are not MessagePack")
        case("resolv status", nil, { close = true }, true, "the connection closed without a reply")
    end)

test("resolv sets no timeout: it waits as long as resolvd takes",
    { spec = "resolvd *resolv.no-timeout" }, function(t)
        local x = exchange(t, "resolv status", status_reply({ netd = true }), { hold = 12 })
        show(t, "held status", x.result)
        t:assert_eq(x.running, true, "after twelve seconds without a reply resolv is still waiting")
        t:assert_eq(x.result.exit_code, 0, "and takes the reply when it comes")
        t:assert(x.result.stdout:match("^hostname   %(unset%)\n"), "and prints it")
    end)

test("version needs no daemon; an unreachable resolvd is reported with the socket's path and exit 1",
    { spec = "resolvd *resolv.version-needs-no-daemon resolvd *resolv.unreachable-message" }, function(t)
        stop_resolvd(t)
        fake_close()
        t:assert_eq(sut:run("test -e " .. SOCK).exit_code, 1, "no socket at all")
        for _, v in ipairs({ "version", "--version" }) do
            local r = sut:run("resolv " .. v)
            show(t, v, r)
            t:assert_eq(r.exit_code, 0, v .. " exits 0 with no resolvd")
            t:assert(r.stdout:match("^resolv %d+%.%d+%.%d+%S*\n$"), v .. " prints resolv <version>")
        end
        local r = sut:run("resolv status")
        show(t, "status, no socket", r)
        t:assert_eq(r.exit_code, 1, "unreachable exits 1")
        t:assert(r.stderr:find("resolv: resolvd is not reachable at /run/resolvd/resolv.sock: ", 1, true) == 1,
            "the message names the socket")
        t:assert(r.stderr:match("No such file or directory"), "and the error")
        -- A socket nobody listens on.
        local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
        t:assert_eq(unixsock.bind(sut, fd, SOCK).ret, 0, "a dead socket file")
        sys.close(sut, fd)
        sut:run("chmod 0666 " .. SOCK)
        r = sut:run("resolv query x.test")
        show(t, "query, dead socket", r)
        t:assert_eq(r.exit_code, 1, "exit 1")
        t:assert(r.stderr:find("resolv: resolvd is not reachable at /run/resolvd/resolv.sock: ", 1, true) == 1,
            "the same message")
        t:assert(r.stderr:match("Connection refused"), "with the refusal")
        sut:run("rm -f " .. SOCK)
    end)
