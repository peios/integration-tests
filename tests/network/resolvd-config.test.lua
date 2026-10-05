-- resolvd §2.3 — Registry configuration: the values resolvd reads from
-- Machine\System\Network\Dns, how each is parsed and what a malformed one
-- does, and how a change reaches the running daemon. The two ways the
-- registry watch can fail are resolvd-config-watch.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) with its DNS server
-- (helpers.dns), and a whole Peios (helpers.network). The gateway's DHCP
-- offers no DNS server, so eth0's scope has none and is not routable:
-- every question that leaves the machine goes to the fallback scope,
-- which is exactly what FallbackServers configures. The gateway answers
-- on 10.77.0.1 and on a second address, 10.77.0.2, so a change of server
-- shows in which address was asked. The last test gives eth0 a server
-- through a DHCP renewal, for the one claim about interface scopes.
--
-- What resolvd made of the key is read where it shows:
--   FallbackServers     the native `status` reply's fallback_servers;
--   ExtraSearchDomains  the names a single label is expanded to upstream;
--   ControlSecurity     whether SYSTEM may `flush` (RESOLVER_CONTROL);
--   Hosts\              a native `resolve` answered from source `hosts`,
--                       and `resolv reverse` of a listed address;
-- and resolvd's log (evctl) for the warnings and `configuration changed`.
--
-- Values the `reg` command cannot spell (an SZ with a second string after
-- its NUL or bytes that are not UTF-8, a MULTI_SZ with empty or broken
-- items, a value name that is not UTF-8, a key's default value) are
-- written with the registry's own calls from the agent (`set_raw`, as in
-- config.test.lua).
--
-- A barrier: before asserting that something was NOT logged or did NOT
-- change, a Hosts value whose name does not parse (`pt..barrier-N`) is
-- written. resolvd logs it as malformed and never takes it into its
-- configuration, so once that line is in the log every earlier registry
-- event has been read, and the barrier itself changed nothing.
--
-- netd writes under the watched key on its own (a network's LastSeen),
-- so every malformed-string warning can be logged again at any moment;
-- the tests assert that a warning is present after their trigger, never
-- how many times it was logged.
--
-- Own VMs: the tests replace the Dns key wholesale, swap resolvd's
-- control object, restart resolvd, and renew eth0's lease with a server.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local rtnl = require("helpers.rtnl")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
-- A second address beside 10.77.0.1 (rtnl adds; ntfe.if_addr's
-- SIOCSIFADDR would replace the first).
assert(rtnl.add_address(gw.vm, gw.ifindex, "10.77.0.2", { prefix = 24 }), "gateway address 10.77.0.2")
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = false })
-- No SOA: a negative answer has lifetime 0 and is never cached, so a
-- question for a name the zone lacks goes upstream every time it is asked.
dns.serve(gw, { zone = {
    ["www.example.test"] = { { type = "A", ttl = 300, data = "10.77.0.80" },
                             { type = "AAAA", ttl = 300, data = "fd77::80" } },
} })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local KEY = network.KEY
local DNS = KEY .. [[\Dns]]
local HOSTS = DNS .. [[\Hosts]]
local SOCK = "/run/resolvd/resolv.sock"

-- Registry value types (PKM's, Windows' numbering).
local T = { SZ = 1, EXPAND_SZ = 2, BINARY = 3, DWORD = 4, MULTI_SZ = 7, QWORD = 11 }

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- resolvd's log lines newer than `since` (guest ns), oldest first.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM resolvd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")), raw = line }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function find(lines, text, from)
    for i = from or 1, #lines do
        if lines[i].msg:find(text, 1, true) then return i end
    end
end

local function count(lines, text)
    local n = 0
    for _, l in ipairs(lines) do
        if l.msg:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local function dump(t, lines, raw)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = raw and l.raw or l.msg end
    t:log("resolvd log:\n" .. table.concat(out, "\n"))
end

local function reg(args)
    return network.reg(sut, args)
end

local function set(name, typed)
    reg({ "set", DNS, name, typed }):assert_ok()
end

local function unset(key, name)
    reg({ "del", key, name })
end

local function apply(doc)
    sut:write_file("/tmp/pt-batch.json", json.encode(doc))
    local r = reg({ "apply", "/tmp/pt-batch.json" })
    assert(r.exit_code == 0, "reg apply: " .. r.stdout .. r.stderr)
end

--- Set a value's raw bytes under any type and name, through the
--- registry's own calls (reg_open_key, REG_IOC_SET_VALUE). Returns true,
--- or false and the errno when the registry refuses the value.
local function try_raw(path, name, vtype, data)
    local o = sut:syscall(1100, { -- reg_open_key
        args = { -1, 0, 0x000F003F, 0 }, bufs = { path .. "\0" }, ptrs = { 1 } })
    assert(o.ret >= 0, "reg_open_key " .. path .. ": errno " .. tostring(o.errno))
    local r = sut:syscall(sys.NR.ioctl, {
        args = { o.ret, 0x40405201, 0 }, -- REG_IOC_SET_VALUE
        bufs = {
            string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8", #name, 0, 0, vtype, #data, 0, 0, 0, 0, -1, 0, 0),
            name, data,
        },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 8 }, { parent = 1, child = 3, offset = 24 } },
    })
    sys.close(sut, o.ret)
    if r.ret ~= 0 then return false, r.errno end
    return true
end

local function set_raw(path, name, vtype, data)
    local ok, errno = try_raw(path, name, vtype, data)
    assert(ok, "set " .. path .. " " .. name .. ": errno " .. tostring(errno))
end

local function native(req, timeout_ms)
    return network.call(sut, req, { path = SOCK, timeout_ms = timeout_ms })
end

local function rstatus()
    local s, err = native({ query = "status" })
    assert(s, "resolvd status: " .. tostring(err))
    assert(s.ok, "resolvd status: " .. tostring(s.error))
    return s
end

local function list_text(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function fallback() return list_text(rstatus().fallback_servers) end

local function fallback_becomes(want)
    wait_until(function() return fallback() == want end,
        { timeout = 15, interval = 0.25, desc = "fallback servers " .. want })
end

local function scope(s, name)
    for _, sc in ipairs(s.scopes or {}) do if sc.interface == name then return sc end end
end

--- A synthetic answer, from the native socket (it is answered at once,
--- so the agent's blocking call is safe). Questions that go upstream
--- use `served` instead.
local function resolve(name, rtype)
    local r, err = native({ query = "resolve", name = name, type = rtype or 1, no_cache = false })
    assert(r, "resolve " .. name .. ": " .. tostring(err))
    return r
end

local function addrs(r)
    local out = {}
    for _, rec in ipairs(r.records or {}) do out[#out + 1] = rec.text end
    table.sort(out)
    return table.concat(out, " ")
end

local function is_static(name, rtype)
    local r = resolve(name, rtype)
    return r.ok and r.source == "hosts", r
end

--- Run a guest command while the gateway pumps; returns its result.
local function served(cmd, timeout)
    local p = sut:run_async("sh", { args = { "-c", cmd } })
    gw:serve({ timeout = timeout or 20, until_ = function() return p:status() == "exited" end })
    return p:wait(5)
end

--- `resolv query`'s output, parsed: outcome, source, server, iface,
--- records ({name, ttl, type, text}), exit.
local function ask(args)
    local r = served("resolv query " .. args)
    local out = { exit = r.exit_code, stdout = r.stdout, stderr = r.stderr, records = {} }
    local first = true
    for l in r.stdout:gmatch("[^\n]+") do
        if first then
            local o, rest = l:match("^(%S+)  (.-)  validation %S+$")
            out.outcome = o
            if rest then
                out.source = rest:match("^(%S+)")
                out.server = rest:match(" via (%S+)")
                out.iface = rest:match(" on (%S+)")
            end
            first = false
        else
            local name, ttl, typ, text = l:match("^([^\t]+)\t(%d+)\t([^\t]+)\t(.*)$")
            if name then
                out.records[#out.records + 1] = { name = name, ttl = tonumber(ttl), type = typ, text = text }
            end
        end
    end
    return out
end

--- `resolv reverse <addr>`: outcome, source, and the record texts.
local function reverse(addr)
    local r = served("resolv reverse " .. addr)
    local lines = {}
    for l in r.stdout:gmatch("[^\n]+") do lines[#lines + 1] = l end
    local o, src = (lines[1] or ""):match("^(%S+)  (%S+)$")
    return { outcome = o, source = src, texts = { table.unpack(lines, 2) }, exit = r.exit_code, stdout = r.stdout }
end

local function questions_for(suffix)
    return dns.queries(gw, function(e)
        local q = e.msg and e.msg.questions[1]
        return q and q.name:lower():find(suffix, 1, true) ~= nil
    end)
end

local nbar = 0
--- Wait until resolvd has read every registry event before this call.
local function barrier()
    nbar = nbar + 1
    local name = "pt..barrier-" .. nbar
    local mark = guest_ns()
    reg({ "new", HOSTS })
    set_raw(HOSTS, name, T.SZ, "10.0.0.1\0")
    local want = 'Dns Hosts: ignoring malformed name "' .. name .. '"'
    wait_until(function() return find(log_since(mark), want) ~= nil end,
        { timeout = 15, interval = 0.25, desc = "resolvd to read barrier " .. name })
    unset(HOSTS, name)
end

--- Wait until resolvd has logged nothing for two seconds: with a
--- malformed string present every re-read logs, so a quiet log means no
--- re-read is pending (netd's echo of an earlier write included).
local function quiesce()
    wait_until(function()
        local m = guest_ns()
        sut:run("sleep 2")
        return #log_since(m) == 0
    end, { timeout = 30, interval = 0.1, desc = "resolvd's log to go quiet" })
end

local function flush_reply()
    local r, err = native({ query = "flush" })
    assert(r, "flush: " .. tostring(err))
    return r
end

local function flush_allowed(want)
    wait_until(function() return flush_reply().ok == want end,
        { timeout = 15, interval = 0.25, desc = "flush " .. (want and "allowed" or "denied") })
end

-- SYSTEM granted RESOLVER_QUERY (1) only: `status` works, `flush`
-- (RESOLVER_CONTROL) is denied. A descriptor resolvd takes is visible.
local QUERY_ONLY = peinit.system_descriptor_hex(0x1)

--- A fresh resolvd. Not `svctl restart`: on this image a restarted
--- resolvd cannot set up /run/resolvd again (`native socket: Permission
--- denied`, a crash loop; see the report), so the directory is removed
--- while the service is stopped and peinit provisions it anew, as at boot.
local function restart_resolvd(t)
    local before = peinit.pid_of_comm(sut, "resolvd")
    local mark = guest_ns()
    sut:run("svctl stop resolvd"):assert_ok()
    wait_until(function() return peinit.pid_of_comm(sut, "resolvd") == nil end,
        { timeout = 20, interval = 0.25, desc = "resolvd to stop" })
    sut:run("rm -rf /run/resolvd"):assert_ok()
    local rr = sut:run("svctl start resolvd")
    t:log("svctl start: exit " .. tostring(rr.exit_code) .. " " .. rr.stdout .. rr.stderr)
    local ok, err = pcall(wait_until, function()
        local now = peinit.pid_of_comm(sut, "resolvd")
        if not now or now == before then return false end
        local s = native({ query = "status" })
        return s ~= nil and s.ok == true
    end, { timeout = 30, interval = 0.25, desc = "a new resolvd answering" })
    if not ok then
        t:log("svctl status: " .. sut:run("svctl status resolvd").stdout)
        t:log("ls: " .. sut:run("ls -la /run/resolvd").stdout)
        dump(t, log_since(mark), true)
        error(err)
    end
end

-- ---------------------------------------------------------------------------
-- The key and its defaults
-- ---------------------------------------------------------------------------

test("without the Dns key every value takes its default, and the key is seen when it appears and goes",
    { spec = "resolvd *config.absent-key-gives-defaults resolvd *config.watches-network-key-recursively" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "eth0 bound")
        -- The premise of the file: eth0 is up in resolvd's view, with no server.
        local s
        wait_until(function()
            s = rstatus()
            local sc = scope(s, "eth0")
            return s.netd and sc ~= nil and #(sc.subnets or {}) > 0
        end, { timeout = 30, interval = 0.25, desc = "resolvd to see eth0 addressed" })
        t:assert_eq(list_text(scope(s, "eth0").servers), "[]", "eth0's scope has no server")

        local exported = reg({ "export", DNS })
        t:log("Dns key at boot: exit " .. exported.exit_code .. "\n" .. exported.stdout .. exported.stderr)
        if exported.exit_code == 0 then reg({ "del", "-r", DNS }):assert_ok() end
        fallback_becomes("[]")

        -- Defaults: no fallback servers, the compiled control object
        -- (SYSTEM may flush), no static names, so nothing can be asked.
        t:assert_eq(flush_reply().ok, true, "the default control object lets SYSTEM flush")
        local q = ask("pt-boot.test")
        t:log("pt-boot.test with no key:\n" .. q.stdout)
        t:assert_eq(q.outcome, "unavailable", "no static name and no server: unavailable")
        t:assert_eq(q.source, "local", "decided locally")
        t:assert_eq(q.exit, 3, "resolv exits 3")

        -- The key appears, in one transaction, under the watched
        -- Machine\System\Network: resolvd sees it.
        apply({ keys = {
            { path = DNS, values = {
                { name = "FallbackServers", type = "multi", data = { "10.77.0.1" } },
                { name = "ControlSecurity", type = "binary", data = QUERY_ONLY } } },
            { path = HOSTS, values = { { name = "pt-boot.test", type = "sz", data = "10.77.0.40" } } },
        } })
        fallback_becomes("[10.77.0.1]")
        t:assert_eq(flush_reply().error, "access denied", "the key's ControlSecurity is in force")
        local static, r = is_static("pt-boot.test")
        t:assert(static, "pt-boot.test is a static name: " .. json.encode(r))
        -- A change two levels below the watched key is seen too.
        reg({ "set", HOSTS, "pt-deep.test", "sz:10.77.0.39" }):assert_ok()
        barrier()
        t:assert((is_static("pt-deep.test")), "a value under Dns\\Hosts is seen")

        -- The key goes: every value is back at its default.
        reg({ "del", "-r", DNS }):assert_ok()
        fallback_becomes("[]")
        flush_allowed(true)
        t:assert_eq((is_static("pt-boot.test")), false, "no static names without the key")
        q = ask("pt-boot.test")
        t:assert_eq(q.outcome, "unavailable", "and no fallback server to ask")
    end)

-- ---------------------------------------------------------------------------
-- Reading strings
-- ---------------------------------------------------------------------------

test("an SZ is read to its first NUL and one that is not UTF-8 is absent; an EXPAND_SZ is not expanded; a MULTI_SZ skips empty and non-UTF-8 strings; other types are absent",
    { spec = "resolvd *config.single-string-read-to-first-nul resolvd *config.expand-sz-not-expanded resolvd *config.multi-sz-empty-and-non-utf8-strings-skipped resolvd *config.other-value-types-treated-as-absent" },
    function(t)
        reg({ "new", DNS })
        -- SZ: the second string, after the NUL, is not read.
        set_raw(DNS, "FallbackServers", T.SZ, "10.77.0.1\0" .. "10.77.0.2\0")
        fallback_becomes("[10.77.0.1]")
        -- SZ not UTF-8: absent, silently.
        local mark = guest_ns()
        set_raw(DNS, "FallbackServers", T.SZ, "\xff\xfe10.77.0.2\0")
        fallback_becomes("[]")
        barrier()
        local lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(count(lines, "Dns FallbackServers"), 0, "an SZ that is not UTF-8 is absent, with no log line")

        -- EXPAND_SZ: a string, read as stored.
        set_raw(DNS, "FallbackServers", T.EXPAND_SZ, "10.77.0.2\0")
        fallback_becomes("[10.77.0.2]")
        mark = guest_ns()
        set_raw(DNS, "FallbackServers", T.EXPAND_SZ, "%PATH%\0")
        fallback_becomes("[]")
        barrier()
        lines = log_since(mark)
        dump(t, lines, true)
        t:assert(find(lines, 'resolvd: warn: Dns FallbackServers: ignoring malformed address "%PATH%"') ~= nil,
            "the EXPAND_SZ reached the parser as stored: %PATH% unexpanded")

        -- MULTI_SZ: an empty string and one that is not UTF-8 are
        -- skipped, silently; the others are used, in order. (First a
        -- good value, so no later re-read can find %PATH% to log.)
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.1]")
        mark = guest_ns()
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.2\0\0\xff\xfe\0" .. "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.2, 10.77.0.1]")
        barrier()
        lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(count(lines, "Dns FallbackServers"), 0, "the skipped strings were not logged")

        -- Any other type: absent, silently.
        for _, case in ipairs({
            { T.DWORD, string.pack("<I4", 0x0A4D0001), "DWORD" },
            { T.BINARY, "10.77.0.1\0", "BINARY" },
            { T.QWORD, string.pack("<I8", 1), "QWORD" },
        }) do
            set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
            fallback_becomes("[10.77.0.1]")
            mark = guest_ns()
            set_raw(DNS, "FallbackServers", case[1], case[2])
            fallback_becomes("[]")
            barrier()
            lines = log_since(mark)
            t:assert_eq(count(lines, "Dns FallbackServers"), 0, case[3] .. " is absent, with no log line")
        end
        unset(DNS, "FallbackServers")
    end)

-- ---------------------------------------------------------------------------
-- FallbackServers
-- ---------------------------------------------------------------------------

test("a FallbackServers string that does not parse is skipped and logged as stored; there is no port, every server is asked on 53",
    { spec = "resolvd *config.fallback-malformed-address-skipped-and-logged resolvd *config.fallback-servers-port-53" },
    function(t)
        reg({ "new", DNS })
        local mark = guest_ns()
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, table.concat({
            " 10.77.0.1 ", "bogus", "   ", "fe80::1%eth0", "10.77.0.2:53", "[fd77::1]:53", 'a"b\\c\t', "",
        }, "\0") .. "\0")
        fallback_becomes("[10.77.0.1]")
        barrier()
        local lines = log_since(mark)
        dump(t, lines, true)
        local W = 'resolvd: warn: Dns FallbackServers: ignoring malformed address '
        for _, s in ipairs({ '"bogus"', '"   "', '"fe80::1%eth0"', '"10.77.0.2:53"', '"[fd77::1]:53"',
                             '"a\\"b\\\\c\\t"' }) do
            t:assert(find(lines, W .. s) ~= nil, "logged: " .. W .. s)
        end
        t:assert_eq(count(lines, "10.77.0.1 "), 0, "the padded address was trimmed and taken, not logged")

        -- A lone SZ that is empty, or only whitespace.
        for _, case in ipairs({ { "\0", '""' }, { "  \0", '"  "' } }) do
            set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
            fallback_becomes("[10.77.0.1]")
            mark = guest_ns()
            set_raw(DNS, "FallbackServers", T.SZ, case[1])
            fallback_becomes("[]")
            barrier()
            lines = log_since(mark)
            t:assert(find(lines, W .. case[2]) ~= nil, "a lone SZ " .. case[2] .. " is logged")
        end

        -- Port 53: the gateway answers only datagrams to port 53.
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.1]")
        sut:run("resolv flush"):assert_ok()
        dns.forget(gw)
        local q = ask("www.example.test")
        t:log(q.stdout)
        t:assert_eq(q.outcome, "found", "the fallback server answered")
        t:assert_eq(q.source, "dns", "from the network")
        t:assert_eq(q.server, "10.77.0.1", "the fallback server")
        local asked = questions_for("www.example.test")
        t:assert(#asked >= 1, "the gateway was asked")
        for _, e in ipairs(asked) do
            t:assert_eq(e.server, "10.77.0.1", "asked at the configured address")
        end
        local frames = 0
        for _, f in ipairs(gw.seen) do
            if f.udp and f.dst_ip == "10.77.0.1" and f.payload and f.udp.sport ~= 53 then
                local m = dns.decode(f.payload)
                if m and not m.qr and m.questions[1] and m.questions[1].name:lower() == "www.example.test" then
                    frames = frames + 1
                    t:assert_eq(f.udp.dport, 53, "the question went to port 53")
                end
            end
        end
        t:assert(frames >= 1, "the question's frame was seen")
    end)

-- ---------------------------------------------------------------------------
-- ExtraSearchDomains
-- ---------------------------------------------------------------------------

test("an ExtraSearchDomains string that does not parse, or is the root, is skipped and logged; the rest are used untrimmed",
    { spec = "resolvd *config.extra-search-domain-malformed-skipped-and-logged" },
    function(t)
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.1]")
        local mark = guest_ns()
        set_raw(DNS, "ExtraSearchDomains", T.MULTI_SZ,
            table.concat({ "pt-good.test", "bad..test", ".", " pt-sp.test", "pt-dot.test." }, "\0") .. "\0\0")
        barrier()
        local lines = log_since(mark)
        dump(t, lines, true)
        local W = 'resolvd: warn: Dns ExtraSearchDomains: ignoring malformed domain '
        t:assert(find(lines, W .. '"bad..test"') ~= nil, "an empty label is malformed, and logged")
        t:assert(find(lines, W .. '"."') ~= nil, "the root is skipped, and logged")
        t:assert_eq(count(lines, "pt-good.test"), 0, "a good domain is not logged")
        t:assert_eq(count(lines, "pt-sp.test"), 0, "a leading space is not malformed")
        t:assert_eq(count(lines, "pt-dot.test"), 0, "a trailing dot is allowed")

        -- The domains taken, seen as the expansions of a single label.
        dns.forget(gw)
        local q = ask("pt-xs")
        t:log(q.stdout .. q.stderr)
        local names = {}
        for _, e in ipairs(questions_for("pt-xs.")) do names[#names + 1] = e.msg.questions[1].name end
        t:log("asked: " .. table.concat(names, " | "))
        local want = { "pt-xs.pt-good.test", "pt-xs.\\032pt-sp.test", "pt-xs.pt-dot.test" }
        t:assert_eq(#names, #want, "one candidate per domain taken")
        for i, w in ipairs(want) do
            t:assert(names[i] and dns.same_name(names[i], w), "candidate " .. i .. " is " .. w)
        end
        t:assert_eq(q.outcome, "notfound", "every candidate NXDOMAIN")

        -- A lone SZ that is empty, or a lone dot: the root.
        for _, case in ipairs({ { "\0", '""' }, { ".\0", '"."' } }) do
            mark = guest_ns()
            set_raw(DNS, "ExtraSearchDomains", T.SZ, case[1])
            barrier()
            lines = log_since(mark)
            t:assert(find(lines, W .. case[2]) ~= nil, "a lone SZ " .. case[2] .. " is logged")
        end
        unset(DNS, "ExtraSearchDomains")
    end)

-- ---------------------------------------------------------------------------
-- ControlSecurity, and what a change does
-- ---------------------------------------------------------------------------

test("ControlSecurity: empty or of another type selects the default silently; invalid bytes select it with a warning at startup and at every change",
    { spec = "resolvd *config.control-security-empty-or-wrong-type-selects-default resolvd *config.control-security-invalid-selects-default-and-logs resolvd *config.change-rebuilds-control-object resolvd *config.change-logged" },
    function(t)
        local INVALID = "ControlSecurity is not a valid descriptor ("
        local function deny()
            set("ControlSecurity", "hex:" .. QUERY_ONLY)
            flush_allowed(false)
            t:assert_eq(flush_reply().error, "access denied", "a valid descriptor is in force")
        end
        -- Empty BINARY.
        deny()
        local mark = guest_ns()
        set_raw(DNS, "ControlSecurity", T.BINARY, "")
        flush_allowed(true)
        barrier()
        t:assert_eq(count(log_since(mark), INVALID), 0, "an empty value selects the default with no log line")
        -- The right bytes, as another type.
        deny()
        mark = guest_ns()
        set_raw(DNS, "ControlSecurity", T.SZ, QUERY_ONLY .. "\0")
        flush_allowed(true)
        barrier()
        t:assert_eq(count(log_since(mark), INVALID), 0, "an SZ selects the default with no log line")

        -- Bytes that are not a descriptor: the default, and a warning,
        -- built (and logged) before `configuration changed`.
        deny()
        mark = guest_ns()
        set_raw(DNS, "ControlSecurity", T.BINARY, "\1\2\3")
        flush_allowed(true)
        barrier()
        local lines = log_since(mark)
        dump(t, lines)
        local i = find(lines, INVALID)
        t:assert(i ~= nil, "the invalid descriptor is logged")
        t:assert(lines[i].msg:match("^resolvd: warn: ControlSecurity is not a valid descriptor %(.+%); using the default$"),
            "in the documented form: " .. lines[i].msg)
        local j = find(lines, "configuration changed", i)
        t:assert(j ~= nil, "configuration changed follows it")
        t:assert_eq(lines[j].msg, "resolvd: info: configuration changed", "at info level")

        -- Another change rebuilds the control object from the same bytes,
        -- so the warning comes again, again before `configuration changed`.
        mark = guest_ns()
        reg({ "set", HOSTS, "pt-cs.test", "sz:10.77.0.60" }):assert_ok()
        barrier()
        t:assert((is_static("pt-cs.test")), "the Hosts change applied")
        lines = log_since(mark)
        dump(t, lines)
        i = find(lines, INVALID)
        t:assert(i ~= nil, "a change elsewhere rebuilds the control object: the warning again")
        t:assert(find(lines, "resolvd: info: configuration changed", i) ~= nil,
            "control object first, then configuration changed")
        t:assert_eq(flush_reply().ok, true, "still the default")

        -- And at startup.
        mark = guest_ns()
        restart_resolvd(t)
        lines = log_since(mark)
        dump(t, lines)
        t:assert(find(lines, INVALID) ~= nil, "a resolvd starting with the bytes logs the warning")
        t:assert_eq(flush_reply().ok, true, "and uses the default")
        unset(DNS, "ControlSecurity")
        unset(HOSTS, "pt-cs.test")
    end)

-- ---------------------------------------------------------------------------
-- Hosts\
-- ---------------------------------------------------------------------------

test("Hosts: each value is a static name; bad names and addresses are skipped as documented; names match in any case; a change is visible to the next question",
    { spec = "resolvd *config.hosts-value-is-one-static-name resolvd *config.hosts-non-utf8-name-skipped resolvd *config.hosts-malformed-name-skipped-and-logged resolvd *config.hosts-root-name-skipped-silently resolvd *config.hosts-malformed-address-skipped-and-logged resolvd *config.hosts-name-without-address-dropped resolvd *config.hosts-names-case-insensitive resolvd *config.static-name-change-visible-at-once resolvd *config.change-replaces-static-names" },
    function(t)
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.1]")
        reg({ "new", HOSTS })
        local mark = guest_ns()
        set_raw(HOSTS, "pt-sz.test", T.SZ, "10.77.0.41\0")
        set_raw(HOSTS, "pt-exp.test", T.EXPAND_SZ, "10.77.0.42\0")
        set_raw(HOSTS, "pt-multi.test", T.MULTI_SZ, "10.77.0.43\0fd77::43\0\0")
        local raw_ok, raw_errno = try_raw(HOSTS, "\xffpt-raw", T.SZ, "10.77.0.44\0")
        t:log("a value name that is not UTF-8: " .. (raw_ok and "accepted" or ("refused, errno " .. tostring(raw_errno))))
        set_raw(HOSTS, "pt..bad", T.SZ, "10.77.0.45\0")
        set_raw(HOSTS, ".", T.SZ, "10.77.0.46\0")
        set_raw(HOSTS, "", T.SZ, "10.77.0.47\0")
        set_raw(HOSTS, "pt-mix.test", T.MULTI_SZ, "10.77.0.48\0nope-mix\0\0")
        set_raw(HOSTS, "pt-none.test", T.SZ, "nope-none\0")
        set_raw(HOSTS, "pt-dword.test", T.DWORD, string.pack("<I4", 0x31004D0A))
        set_raw(HOSTS, "Pt-Case.Test", T.SZ, "10.77.0.49\0")
        barrier()
        local lines = log_since(mark)
        dump(t, lines, true)

        -- One value, one static name: SZ, EXPAND_SZ, MULTI_SZ.
        local static, r = is_static("pt-sz.test")
        t:assert(static, "an SZ value is a static name")
        t:assert_eq(addrs(r), "10.77.0.41", "with its address")
        static, r = is_static("pt-exp.test")
        t:assert(static, "an EXPAND_SZ value is a static name")
        t:assert_eq(addrs(r), "10.77.0.42", "with its address")
        static, r = is_static("pt-multi.test", 255)
        t:assert(static, "a MULTI_SZ value is a static name")
        t:assert_eq(addrs(r), "10.77.0.43 fd77::43", "with each of its addresses")
        local rv = reverse("10.77.0.41")
        t:assert_eq(rv.source, "hosts", "and its address reverses to it: " .. rv.stdout)

        -- A name that is not UTF-8.
        if raw_ok then
            rv = reverse("10.77.0.44")
            t:log(rv.stdout)
            t:assert(rv.source ~= "hosts", "a value name that is not UTF-8 is no static name")
            t:assert_eq(count(lines, "pt-raw"), 0, "and is skipped silently")
        else
            -- The registry itself refuses such a name (as it does on this
            -- image), so no such value can reach resolvd: the skip is
            -- unreachable, and the refusal is what a VM can show.
            t:assert_eq(raw_errno, 22, "the registry refuses a value name that is not UTF-8 (EINVAL)")
        end
        -- A name that does not parse.
        t:assert(find(lines, 'resolvd: warn: Dns Hosts: ignoring malformed name "pt..bad"') ~= nil,
            "a malformed name is logged")
        rv = reverse("10.77.0.45")
        t:assert(rv.source ~= "hosts", "and is no static name: " .. rv.stdout)
        -- The root: "." and the key's default value.
        for _, a in ipairs({ "10.77.0.46", "10.77.0.47" }) do
            rv = reverse(a)
            t:assert(rv.source ~= "hosts", a .. ": a root name is no static name: " .. rv.stdout)
        end
        t:assert_eq(count(lines, 'malformed name "."'), 0, "\".\" is skipped silently")
        t:assert_eq(count(lines, 'malformed name ""'), 0, "the empty name is skipped silently")
        -- A malformed address beside a good one.
        t:assert(find(lines, 'resolvd: warn: Dns Hosts: ignoring malformed address "nope-mix"') ~= nil,
            "a malformed address is logged")
        static, r = is_static("pt-mix.test")
        t:assert(static, "the name keeps its good address")
        t:assert_eq(addrs(r), "10.77.0.48", "and only that")
        -- No address left: not a static name; it goes to the network.
        dns.forget(gw)
        for _, n in ipairs({ "pt-none.test", "pt-dword.test" }) do
            local q = ask(n)
            t:log(n .. ":\n" .. q.stdout)
            t:assert_eq(q.source, "dns", n .. " is asked upstream")
            t:assert(#questions_for(n) >= 1, "the gateway was asked for " .. n)
        end
        -- Case.
        for _, n in ipairs({ "pt-case.test", "PT-CASE.TEST", "Pt-Case.Test", "pT-cAsE.tEsT" }) do
            static, r = is_static(n)
            t:assert(static, n .. " matches Pt-Case.Test")
            t:assert_eq(addrs(r), "10.77.0.49", n .. "'s address")
        end

        -- A new value: the very next question sees it; a removed one: the
        -- very next question goes past it.
        reg({ "set", HOSTS, "pt-now.test", "sz:10.77.0.51" }):assert_ok()
        static, r = is_static("pt-now.test")
        t:assert(static, "a new static name answers the next question: " .. json.encode(r))
        unset(HOSTS, "pt-now.test")
        dns.forget(gw)
        local q = ask("pt-now.test")
        t:log(q.stdout)
        t:assert_eq(q.source, "dns", "a removed static name is gone for the next question")

        -- A change replaces the static names: a rewritten value has only
        -- its new address.
        mark = guest_ns()
        reg({ "set", HOSTS, "pt-sz.test", "sz:10.77.0.52" }):assert_ok()
        static, r = is_static("pt-sz.test")
        t:assert(static, "still static")
        t:assert_eq(addrs(r), "10.77.0.52", "with the new address only")
        rv = reverse("10.77.0.41")
        t:assert(rv.source ~= "hosts", "the old address no longer reverses to it: " .. rv.stdout)
        t:assert(find(log_since(mark), "resolvd: info: configuration changed") ~= nil, "a logged change")
        reg({ "del", "-r", HOSTS })
    end)

-- ---------------------------------------------------------------------------
-- Re-reading
-- ---------------------------------------------------------------------------

test("any change under Machine\\System\\Network, netd's own included, re-reads the Dns key; an unchanged reading applies nothing",
    { spec = "resolvd *config.any-event-rereads-dns-key resolvd *config.unchanged-configuration-is-a-no-op" },
    function(t)
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0pt-rr-bogus\0\0")
        set_raw(DNS, "ControlSecurity", T.BINARY, "\1\2\3")
        fallback_becomes("[10.77.0.1]")
        barrier()
        local BOGUS = 'resolvd: warn: Dns FallbackServers: ignoring malformed address "pt-rr-bogus"'
        local INVALID = "ControlSecurity is not a valid descriptor"

        -- A value that is not resolvd's, on the Network key itself. The
        -- log is quiet first, so the re-read that follows is the write's.
        quiesce()
        local mark = guest_ns()
        reg({ "set", KEY, "PtResolvdNudge", "sz:1" }):assert_ok()
        wait_until(function() return find(log_since(mark), BOGUS) ~= nil end,
            { timeout = 15, interval = 0.25, desc = "the Dns key to be read again" })
        barrier()
        local lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(count(lines, "configuration changed"), 0, "the reading did not change: nothing applied")
        t:assert_eq(count(lines, INVALID), 0, "the control object was not rebuilt")
        t:assert_eq(fallback(), "[10.77.0.1]", "the configuration in use stands")

        -- netd's own write: a pass in a new second rewrites a network's
        -- LastSeen under the watched key. `net reconcile` is a control
        -- request, not a registry write; the quiet log is the proof that
        -- nothing else is pending.
        quiesce()
        mark = guest_ns()
        sut:run("net reconcile"):assert_ok()
        wait_until(function() return find(log_since(mark), BOGUS) ~= nil end,
            { timeout = 15, interval = 0.25, desc = "netd's write to cause a re-read" })
        lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(count(lines, "configuration changed"), 0, "and that changed nothing either")
        unset(KEY, "PtResolvdNudge")
        unset(DNS, "ControlSecurity")
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
        barrier()
    end)

-- ---------------------------------------------------------------------------
-- Changes and the cache
-- ---------------------------------------------------------------------------

test("a change to FallbackServers applies to the next question and flushes the fallback scope's answers; a list in a new order flushes too; other changes keep them",
    { spec = "resolvd *config.fallback-server-change-flushes-fallback-cache resolvd *config.changes-apply-live" },
    function(t)
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.1]")
        sut:run("resolv flush"):assert_ok()
        local function q(what)
            local r = ask("www.example.test")
            t:log(what .. ": " .. r.stdout)
            t:assert_eq(r.outcome, "found", what .. ": found")
            return r
        end
        local r = q("first")
        t:assert_eq(r.source, "dns", "asked upstream")
        t:assert_eq(r.server, "10.77.0.1", "of the fallback server")
        t:assert_eq(r.iface, nil, "the fallback scope has no interface")
        t:assert_eq(q("again").source, "cache", "then cached")

        -- A change that is not to FallbackServers keeps the entry.
        reg({ "set", HOSTS, "pt-keep.test", "sz:10.77.0.61" }):assert_ok()
        barrier()
        t:assert((is_static("pt-keep.test")), "the Hosts change applied")
        t:assert_eq(q("after a Hosts change").source, "cache", "a Hosts change keeps the fallback cache")

        -- New content: applied at once, and the cache entry is gone.
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.2\0" .. "10.77.0.1\0\0")
        fallback_becomes("[10.77.0.2, 10.77.0.1]")
        r = q("after a new server")
        t:assert_eq(r.source, "dns", "the cached answer was discarded")
        t:assert_eq(r.server, "10.77.0.2", "and the new first server was asked")
        t:assert_eq(q("again").source, "cache", "cached again")

        -- Same servers, new order.
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0" .. "10.77.0.2\0\0")
        fallback_becomes("[10.77.0.1, 10.77.0.2]")
        r = q("after a reorder")
        t:assert_eq(r.source, "dns", "a new order discards it too")
        t:assert_eq(r.server, "10.77.0.1", "asked of the new first server")

        -- The same list written again is no change.
        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.1\0" .. "10.77.0.2\0\0")
        barrier()
        t:assert_eq(q("after the same list").source, "cache", "an unchanged list keeps the cache")
        unset(HOSTS, "pt-keep.test")
    end)

test("answers cached through an interface scope survive a registry change",
    { spec = "resolvd *config.registry-change-keeps-interface-cache" },
    function(t)
        -- Give eth0 a server: a renewal whose ACK carries option 6.
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" } })
        local rn = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(rn and rn.ok, "renew accepted")
        t:assert(gw:serve({ timeout = 30, until_ = function()
            local sc = scope(rstatus(), "eth0")
            return sc ~= nil and list_text(sc.servers) == "[10.77.0.1]"
        end }), "eth0's scope has the server")

        sut:run("resolv flush"):assert_ok()
        local r = ask("www.example.test")
        t:log(r.stdout)
        t:assert_eq(r.source, "dns", "asked upstream")
        t:assert_eq(r.iface, "eth0", "through eth0's scope")
        r = ask("www.example.test")
        t:assert_eq(r.source, "cache", "then cached")
        t:assert_eq(r.iface, "eth0", "under eth0's scope")

        set_raw(DNS, "FallbackServers", T.MULTI_SZ, "10.77.0.2\0\0")
        fallback_becomes("[10.77.0.2]")
        reg({ "set", HOSTS, "pt-iface.test", "sz:10.77.0.62" }):assert_ok()
        barrier()
        t:assert((is_static("pt-iface.test")), "the Hosts change applied")
        r = ask("www.example.test")
        t:log(r.stdout)
        t:assert_eq(r.source, "cache", "a FallbackServers and Hosts change keep eth0's cached answer")
        t:assert_eq(r.iface, "eth0", "still eth0's")
        reg({ "del", "-r", DNS })
    end)
