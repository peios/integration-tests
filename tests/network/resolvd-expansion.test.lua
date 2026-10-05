-- resolvd §4.3 "Single-label expansion", with PSPU §6.7 "Search
-- expansion" — which search domains a single label is expanded with, in
-- what order, how the candidates are built (duplicates, overlong ones,
-- their case), how they are asked (one at a time, until one is not
-- `notfound`), and what is never expanded.
--
-- Harness: as resolvd-routing.test.lua — the scripted gateway and its
-- DNS server (helpers.gateway, helpers.dns) and a whole Peios
-- (helpers.network), with two dummy links joined by rules of the file's
-- own to profiles `r5a` (dummy0) and `r5b` (dummy1) beside eth0's DHCP
-- scope. Each scope's server is a different address on the gateway's
-- one wire (10.77.0.1 eth0, .2 dummy0, .3 dummy1), so the gateway's log
-- gives each candidate asked, in order, with the scope it went to.
-- `ExtraSearchDomains` is written in one transaction with a fresh
-- placeholder `FallbackServers` (192.0.2.N, never used: eth0 always has a
-- server here, so the fallback scope takes nothing), and the test waits
-- for resolvd's status to show that placeholder, which proves the whole
-- `Dns` key has been re-read. Absent names are NXDOMAIN with no SOA, so
-- no negative answer is cached.
--
-- Own VMs: the dummy module, two joined links, their profiles rewritten
-- throughout, and the `Dns` key's values.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local RSOCK = "/run/resolvd/resolv.sock"
local SERVER = { E = "10.77.0.1", A = "10.77.0.2", B = "10.77.0.3" }
local PROFILE = { dummy0 = [[Profiles\r5a]], dummy1 = [[Profiles\r5b]] }

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
for _, a in ipairs({ SERVER.A, SERVER.B }) do
    assert(rtnl.add_address(gw.vm, gw.ifindex, a, { prefix = 24 }), "gateway address " .. a)
end
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })

local ZONE = {}
local hook
dns.serve(gw, { zone = ZONE, on = function(q, default, ctx)
    local qn = q.questions[1]
    if not (hook and qn) then return nil end
    return hook(q, default, ctx, qn.name:lower())
end })

local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- Local helpers (as resolvd-routing.test.lua)
-- ---------------------------------------------------------------------------

local KEY = network.KEY

local function full(path)
    if path:match("^Machine\\") then return path end
    return KEY .. "\\" .. path
end

--- One registry transaction: `{ {path, {name, type, data}, …}, … }`.
local function apply(keys)
    local doc, seen = { keys = {} }, {}
    local function add(path, values)
        if seen[path] and #values == 0 then return end
        seen[path] = true
        doc.keys[#doc.keys + 1] = { path = path, values = values }
    end
    for _, k in ipairs(keys) do
        local acc = KEY
        for part in k[1]:gmatch("[^\\]+") do
            acc = acc .. "\\" .. part
            if acc ~= full(k[1]) then add(acc, {}) end
        end
        local values = {}
        for i = 2, #k do values[#values + 1] = { name = k[i][1], type = k[i][2], data = k[i][3] } end
        add(full(k[1]), values)
    end
    sut:write_file("/tmp/r5-apply.json", peinit.encode_json(doc))
    local r = sut:run("reg apply /tmp/r5-apply.json")
    assert(r.exit_code == 0, "reg apply failed: " .. r.stdout .. r.stderr)
end

local function list_value(name, items)
    if #items == 0 then return { name, "sz", "" } end
    return { name, "multi", items }
end

local function same(a, b)
    if #a ~= #b then return false end
    for k = 1, #a do if a[k] ~= b[k] then return false end end
    return true
end

local function lower_all(l)
    local out = {}
    for i, v in ipairs(l or {}) do out[i] = v:lower() end
    return out
end

local function scope_of(s, ifname)
    for _, sc in ipairs((s and s.scopes) or {}) do
        if sc.interface == ifname then return sc end
    end
end

local function describe(s)
    if not s then return "no status" end
    local out = {}
    for _, sc in ipairs(s.scopes or {}) do
        out[#out + 1] = string.format("%s(metric %s%s%s servers=[%s] domains=[%s])",
            tostring(sc.interface), tostring(sc.metric), sc.default_route and " default" or "",
            sc.exclusive and " exclusive" or "", table.concat(sc.servers or {}, " "),
            table.concat(sc.domains or {}, " "))
    end
    return table.concat(out, "; ")
end

local function scope_matches(sc, p)
    if not same(sc.servers or {}, p.servers or {}) then return false, "servers" end
    if not same(lower_all(sc.domains), lower_all(p.domains)) then return false, "domains" end
    if (sc.exclusive == true) ~= (p.exclusive == true) then return false, "exclusive" end
    if (sc.default_route == true) ~= (p.default == true) then return false, "default_route" end
    if sc.metric ~= (p.metric or 100) then return false, "metric" end
    local subnets = {}
    for _, a in ipairs(sc.subnets or {}) do subnets[a] = true end
    for _, a in ipairs(p.addr or {}) do
        if not subnets[a] then return false, "subnet " .. a end
    end
    return true
end

local function profile_values(p)
    return {
        list_value("Address.Static", p.addr or {}),
        list_value("Dns.Servers", p.servers or {}),
        list_value("Dns.Domains", p.domains or {}),
        { "Dns.Exclusive", "dword", p.exclusive and 1 or 0 },
        { "Dns.Default", "dword", p.default and 1 or 0 },
        { "Route.Metric", "dword", p.metric or 100 },
    }
end

local set_up = false

--- Bring the dummies' scopes to `cfg` = { dummy0 = spec, dummy1 = spec }
--- (spec: addr, servers, domains, exclusive, default, metric) and wait
--- until resolvd and netd show it.
local function configure(t, cfg, what)
    local a, b = cfg.dummy0 or {}, cfg.dummy1 or {}
    apply({ { PROFILE.dummy0, table.unpack(profile_values(a)) },
            { PROFILE.dummy1, table.unpack(profile_values(b)) } })
    if not set_up then
        apply({
            { [[Rules\Interface\r5-d0]], { "Interface.Equal", "multi", { "dummy0" } },
                { "Priority", "dword", 20 }, { "Actions", "multi", { "JOIN(r5a)" } } },
            { [[Rules\Interface\r5-d1]], { "Interface.Equal", "multi", { "dummy1" } },
                { "Priority", "dword", 20 }, { "Actions", "multi", { "JOIN(r5b)" } } },
        })
        local mp = sut:run("modprobe dummy numdummies=2")
        t:assert_eq(mp.exit_code, 0, "the dummy module loads: " .. mp.stderr)
        set_up = true
    end
    local want = { dummy0 = a, dummy1 = b }
    local last, why
    local ok = gw:serve({ timeout = 45, until_ = function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        if not (s and s.scopes) then why = "resolvd status"; return false end
        last = s
        local ns = network.call(sut, { query = "status" })
        for ifn, p in pairs(want) do
            local sc = scope_of(s, ifn)
            if not sc then why = ifn .. " has no scope"; return false end
            local m, reason = scope_matches(sc, p)
            if not m then why = ifn .. " " .. reason; return false end
            local i = ns and network.iface(ns, ifn)
            local level = #(p.addr or {}) > 0 and "addressed" or "link"
            if not (i and i.level == level) then
                why = ifn .. " level " .. tostring(i and i.level) .. ", want " .. level
                return false
            end
        end
        local e = scope_of(s, "eth0")
        if not (e and same(e.servers or {}, { SERVER.E }) and e.default_route == true and e.metric == 100
            and #(e.domains or {}) == 0) then
            why = "eth0"
            return false
        end
        return true
    end })
    t:log((what or "configured") .. ": " .. describe(last))
    t:assert(ok, (what or "configured") .. ": resolvd shows the configuration (waiting on " .. tostring(why) .. ")")
end

--- Set `ExtraSearchDomains` to `domains` (none: removed), with a fresh
--- placeholder FallbackServers in the same transaction, and wait until
--- resolvd's status shows the placeholder.
local marker = 0
local function extra(t, domains)
    network.reg(sut, { "del", full("Dns"), "ExtraSearchDomains" })
    marker = marker + 1
    local placeholder = "192.0.2." .. marker
    local key = { "Dns", { "FallbackServers", "multi", { placeholder } } }
    if domains and #domains > 0 then key[#key + 1] = { "ExtraSearchDomains", "multi", domains } end
    apply({ key })
    t:assert(wait_until(function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        return s ~= nil and same(s.fallback_servers or {}, { placeholder })
    end, { timeout = 15, interval = 0.25, desc = "resolvd re-reading the Dns key" }),
        "ExtraSearchDomains [" .. table.concat(domains or {}, " ") .. "] taken")
end

local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 30, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- Every question the gateway logged for `label` itself or a name under
--- it (any case), oldest first: {name (lower case), server, transport,
--- type, at}. `qtype` (a number) narrows it to one type.
local function asked_under(label, qtype)
    label = label:lower()
    local out = {}
    for _, e in ipairs(dns.queries(gw)) do
        local q = e.msg and e.msg.questions[1]
        if q and (not qtype or q.type == qtype) then
            local n = q.name:lower()
            if n == label or n:sub(1, #label + 1) == label .. "." then
                out[#out + 1] = { name = n, server = e.server, transport = e.transport, type = q.type, at = e.at }
            end
        end
    end
    return out
end

local function show(list)
    local out = {}
    for _, q in ipairs(list) do out[#out + 1] = q.name .. "@" .. q.server end
    return out
end

--- `resolv query <name> <type>`, pumping while it runs and for a second
--- after. Returns the exit status, the output, the summary's fields, and
--- every question asked under the name's first label.
local function ask(t, name, qtype, label)
    local r = served("resolv query " .. name .. " " .. (qtype or "A"))
    gw:serve({ timeout = 1 })
    local head = r.stdout:match("^[^\n]*") or ""
    label = label or name:gsub("%.$", "")
    local out = {
        name = name, exit = r.exit_code, head = head, stdout = r.stdout,
        outcome = head:match("^(%S+)"), source = head:match("^%S+%s+(%S+)"),
        via = head:match(" via (%S+)"), on = head:match(" on (%S+)"),
        asked = asked_under(label, qtype and dns.TYPE[qtype] or dns.TYPE.A),
    }
    t:log(string.format("resolv query %s %s -> exit %s:\n%s\ngateway asked [%s]", name, qtype or "A",
        tostring(r.exit_code), r.stdout .. r.stderr, table.concat(show(out.asked), " ")))
    return out
end

local function expect_asked(t, r, want, why)
    t:assert(same(show(r.asked), want), why .. ": asked [" .. table.concat(show(r.asked), " ")
        .. "], want [" .. table.concat(want, " ") .. "]")
end

local function setup(t)
    hook = nil
    if not set_up then
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound a lease")
    end
end

-- The usual layout: dummy0 at metric 200 with a1.test and a2.test, dummy1
-- at metric 50 with b1.test, both with a server; ExtraSearchDomains x.test.
local function usual(t)
    configure(t, {
        dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "a1.test", "a2.test" }, metric = 200 },
        dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "b1.test" }, metric = 50 },
    }, "a1.test a2.test on dummy0 (200), b1.test on dummy1 (50)")
    extra(t, { "x.test" })
end

local function at(server, ...)
    local out = {}
    for _, n in ipairs({ ... }) do out[#out + 1] = n .. "@" .. server end
    return table.unpack(out)
end

-- ---------------------------------------------------------------------------
-- The domains and the order
-- ---------------------------------------------------------------------------

test("a single label is expanded with every routable scope's domains, scopes by metric, then ExtraSearchDomains; the candidates are asked one at a time, in that order, each routed on its own",
    { spec = "resolvd *engine-expansion.routable-scope-domains-then-extra resolvd *engine-expansion.candidates-asked-one-at-a-time PSPU *nri-resolution.candidates-asked-in-turn" },
    function(t)
        setup(t)
        usual(t)
        -- Each NXDOMAIN is held for a second: a candidate asked before the
        -- previous one's answer would arrive less than a second after it.
        hook = function(_, default, _, name)
            if name:find("^x1host%.") then default.delay = 1; return default end
        end
        local r = ask(t, "x1host")
        t:assert_eq(r.exit, 2, "every candidate NXDOMAIN: notfound")
        expect_asked(t, r, {
            "x1host.b1.test@" .. SERVER.B,
            "x1host.a1.test@" .. SERVER.A, "x1host.a2.test@" .. SERVER.A,
            "x1host.x.test@" .. SERVER.E,
        }, "dummy1's domain (metric 50), dummy0's in their order (200), then ExtraSearchDomains, each to its own scope")
        for i = 2, #r.asked do
            local gap = r.asked[i].at - r.asked[i - 1].at
            t:log(string.format("%s asked %.2f s after %s", r.asked[i].name, gap, r.asked[i - 1].name))
            t:assert(gap >= 0.95, r.asked[i].name .. " was asked only after " .. r.asked[i - 1].name
                .. "'s held answer (" .. string.format("%.2f", gap) .. " s)")
        end
    end)

test("the trailing dot does not suppress expansion, a top-level domain is asked only as its expansions, and a single label is never sent bare",
    { spec = "resolvd *engine-expansion.trailing-dot-does-not-suppress-expansion resolvd *engine-expansion.top-level-domain-cannot-be-asked PSPU *nri-resolution.single-label-never-sent-bare" },
    function(t)
        setup(t)
        usual(t)
        local dot = ask(t, "x2host.", "A", "x2host")
        t:assert_eq(dot.exit, 2, "x2host. is notfound")
        expect_asked(t, dot, {
            "x2host.b1.test@" .. SERVER.B, "x2host.a1.test@" .. SERVER.A,
            "x2host.a2.test@" .. SERVER.A, "x2host.x.test@" .. SERVER.E,
        }, "`x2host.` is expanded exactly as `x2host` is")
        local tld = ask(t, "com", "SOA")
        t:assert_eq(tld.exit, 2, "com is notfound")
        expect_asked(t, tld, {
            "com.b1.test@" .. SERVER.B, "com.a1.test@" .. SERVER.A,
            "com.a2.test@" .. SERVER.A, "com.x.test@" .. SERVER.E,
        }, "`com` is asked only as its expansions, never as itself")
    end)

test("a multi-label name, and the root, have one candidate, themselves: never expanded",
    { spec = "resolvd *engine-expansion.multi-label-single-candidate PSPU *nri-resolution.multi-label-never-expanded" },
    function(t)
        setup(t)
        usual(t)
        local m = ask(t, "x2m.sub", "A", "x2m")
        t:assert_eq(m.exit, 2, "x2m.sub is notfound")
        expect_asked(t, m, { "x2m.sub@" .. SERVER.E }, "two labels: asked as they are, once, and no expansion")
        local before = #asked_under(".", dns.TYPE.NS)
        local root = ask(t, ".", "NS", ".")
        local roots = {}
        for i = before + 1, #root.asked do roots[#roots + 1] = root.asked[i] end
        root.asked = roots
        expect_asked(t, root, { ".@" .. SERVER.E }, "the root: asked as itself, once")
    end)

test("an up scope with no servers contributes none of its search domains",
    { spec = "resolvd *engine-expansion.scope-without-servers-contributes-no-domains" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "a1.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "b1.test" }, metric = 200 },
        }, "dummy0 serverless with a1.test (50), dummy1 with b1.test (200)")
        extra(t, { "x.test" })
        local r = ask(t, "x9host")
        t:assert_eq(r.exit, 2, "notfound")
        expect_asked(t, r, { "x9host.b1.test@" .. SERVER.B, "x9host.x.test@" .. SERVER.E },
            "a1.test, of the serverless scope, is not applied")
    end)

test("while an exclusive scope is chosen its search domains are the only ones: no other scope's and no ExtraSearchDomains",
    { spec = "resolvd *engine-expansion.exclusive-scope-domains-only resolvd *engine-expansion.extra-domains-ignored-under-exclusive" },
    function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "vpn.test" },
                exclusive = true, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "b1.test" }, metric = 50 },
        }, "dummy0 exclusive with vpn.test, dummy1 with b1.test")
        extra(t, { "x.test" })
        local r = ask(t, "x8host")
        t:assert_eq(r.exit, 2, "notfound")
        expect_asked(t, r, { "x8host.vpn.test@" .. SERVER.A }, "only the exclusive scope's domain")
    end)

test("with no applicable search domain a single label is notfound without a query",
    { spec = "PSPU *nri-resolution.no-domain-is-notfound-without-query" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 50 },
        }, "no scope has a search domain")
        extra(t, nil)
        local r = ask(t, "x11host")
        t:assert_eq(r.exit, 2, "notfound")
        t:assert_eq(r.outcome, "notfound", "the summary says notfound")
        t:assert_eq(r.source, "local", "decided without the network")
        t:assert(#r.asked == 0, "nothing asked: [" .. table.concat(show(r.asked), " ") .. "]")
    end)

-- ---------------------------------------------------------------------------
-- Building the candidates
-- ---------------------------------------------------------------------------

test("a candidate already in the list, compared case-insensitively, is not added again",
    { spec = "resolvd *engine-expansion.duplicate-candidates-removed" }, function(t)
        setup(t)
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "dup.test" }, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "DUP.Test" }, metric = 50 },
        }, "dup.test on both dummies, in two cases")
        extra(t, { "Dup.TEST", "x.test" })
        local r = ask(t, "x5host")
        t:assert_eq(r.exit, 2, "notfound")
        expect_asked(t, r, { "x5host.dup.test@" .. SERVER.B, "x5host.x.test@" .. SERVER.E },
            "x5host.dup.test once (dummy1's, the first in the list), then x5host.x.test")
    end)

test("a candidate longer than 255 bytes on the wire is left out; one of exactly 255 is asked",
    { spec = "resolvd *engine-expansion.overlong-candidates-left-out" }, function(t)
        setup(t)
        -- 4 labels of 60: 245 bytes on the wire with the root. A 9-byte
        -- label makes 255, a 10-byte one 256.
        local long = table.concat({ string.rep("a", 60), string.rep("b", 60), string.rep("c", 60),
            string.rep("d", 60) }, ".")
        t:assert_eq(#dns.name(long), 245, "the long domain is 245 bytes on the wire")
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { long, "ok6.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 200 },
        }, "dummy0 with a 245-byte domain and ok6.test")
        extra(t, nil)
        local fits = ask(t, "x6abcdefg")
        t:assert_eq(#dns.name("x6abcdefg." .. long), 255, "x6abcdefg under it is 255 bytes")
        expect_asked(t, fits, { "x6abcdefg." .. long .. "@" .. SERVER.A, "x6abcdefg.ok6.test@" .. SERVER.A },
            "255 bytes: the candidate is asked")
        local over = ask(t, "x6abcdefgh")
        expect_asked(t, over, { "x6abcdefgh.ok6.test@" .. SERVER.A }, "256 bytes: left out; the next domain is asked")
        t:assert_eq(over.exit, 2, "notfound")
    end)

test("a candidate keeps the case of the label as asked and of the domain as configured, and its records are reported at that case",
    { spec = "resolvd *engine-expansion.candidate-case-preserved" }, function(t)
        setup(t)
        ZONE["x7host.case.test"] = { { type = "A", ttl = 60, data = "10.77.0.87" } }
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, servers = { SERVER.A }, domains = { "Case.Test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, metric = 200 },
        }, "dummy0 with Case.Test")
        extra(t, nil)
        local r = ask(t, "X7Host")
        t:assert_eq(r.exit, 0, "found")
        local record = r.stdout:match("\n([^\n]+)")
        t:assert(record ~= nil, "a record line")
        local owner, _, rtype, text = record:match("^([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)$")
        t:assert_eq(owner, "X7Host.Case.Test", "the record's name is the candidate, in the case asked and configured")
        t:assert_eq(rtype, "A", "an A record")
        t:assert_eq(text, "10.77.0.87", "its address")
    end)

-- ---------------------------------------------------------------------------
-- When asking stops
-- ---------------------------------------------------------------------------

test("found, with records or without (NODATA), is the answer: later candidates are not asked",
    { spec = "resolvd *engine-expansion.found-or-nodata-ends-expansion" }, function(t)
        setup(t)
        ZONE["x3host.a1.test"] = { { type = "A", ttl = 60, data = "10.77.0.83" } }
        ZONE["x3host.a2.test"] = { { type = "A", ttl = 60, data = "10.77.0.84" },
                                   { type = "AAAA", ttl = 60, data = "fd77::84" } }
        usual(t)
        local a = ask(t, "x3host", "A")
        t:assert_eq(a.exit, 0, "found")
        t:assert(a.stdout:find("x3host.a1.test\t", 1, true) ~= nil, "the answer is x3host.a1.test's")
        expect_asked(t, a, { "x3host.b1.test@" .. SERVER.B, "x3host.a1.test@" .. SERVER.A },
            "the first found ends it: a2 and x never asked")
        local aaaa = ask(t, "x3host", "AAAA")
        t:assert_eq(aaaa.exit, 0, "found, with no records")
        t:assert_eq(aaaa.outcome, "found", "the summary says found")
        t:assert(not aaaa.stdout:find("\n%S"), "and no record lines")
        expect_asked(t, aaaa, { "x3host.b1.test@" .. SERVER.B, "x3host.a1.test@" .. SERVER.A },
            "NODATA at x3host.a1.test ends it: x3host.a2.test's AAAA is never asked for")
    end)

test("unavailable is the answer: later candidates are not asked",
    { spec = "resolvd *engine-expansion.unavailable-ends-expansion" }, function(t)
        setup(t)
        usual(t)
        hook = function(_, _, _, name)
            if name == "x4host.b1.test" then return false end
        end
        local r = ask(t, "x4host")
        t:assert_eq(r.exit, 3, "the first candidate's attempts all time out: unavailable")
        expect_asked(t, r, { at(SERVER.B, "x4host.b1.test", "x4host.b1.test", "x4host.b1.test") },
            "three attempts at the first candidate, and nothing after")
    end)

-- ---------------------------------------------------------------------------
-- What the contract requires (known bugs)
-- ---------------------------------------------------------------------------

test("the applicable domains are the exclusive scope's when one is up, and otherwise every up scope's, servers or not",
    { spec = "PSPU *nri-resolution.applicable-search-domains", tags = { "known-bug" } }, function(t)
        setup(t)
        -- An exclusive VPN-like dummy0, addressed, its servers not yet
        -- arrived: its vpn.test is the only domain, and the candidate it
        -- makes is routed to it, so the question is unavailable unasked.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "vpn.test" }, exclusive = true, metric = 200 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "b1.test" }, metric = 50 },
        }, "dummy0 exclusive and serverless with vpn.test")
        extra(t, { "x.test" })
        local excl = ask(t, "k10host")
        -- A non-exclusive serverless dummy0 at metric 50: its a1.test comes
        -- first, the candidate goes to it (step 2) and is unavailable.
        configure(t, {
            dummy0 = { addr = { "10.91.0.1/24" }, domains = { "a1.test" }, metric = 50 },
            dummy1 = { addr = { "10.92.0.1/24" }, servers = { SERVER.B }, domains = { "b1.test" }, metric = 200 },
        }, "dummy0 serverless with a1.test, not exclusive")
        local plain = ask(t, "k10b")
        -- PEI-1337: resolvd ignores the serverless exclusive scope and
        -- expands k10host with b1.test and x.test, asking 10.77.0.3 and
        -- 10.77.0.1 (the VPN leak).
        t:assert_eq(excl.exit, 3, "k10host: only vpn.test applies and its candidate is unavailable (got `" .. excl.head .. "`)")
        t:assert(#excl.asked == 0, "k10host: nothing asked (asked [" .. table.concat(show(excl.asked), " ") .. "])")
        -- PEI-1360 (widened to steps 2, 3 and expansion): resolvd drops a1.test (the scope
        -- has no servers) and asks k10b.b1.test and k10b.x.test.
        t:assert_eq(plain.exit, 3, "k10b: k10b.a1.test comes first and is unavailable (got `" .. plain.head .. "`)")
        t:assert(#plain.asked == 0, "k10b: nothing asked (asked [" .. table.concat(show(plain.asked), " ") .. "])")
    end)
