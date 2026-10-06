-- netd §9.2 — requests on the control socket: the framing and its
-- ceiling, the errors a request that cannot be read is answered with, the
-- four requests and the rights they need, `renew`'s own errors, and every
-- field of the status reply.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). Requests go out as raw frames from the agent
-- (SYSTEM), so a test can send what no client would: a length with no
-- payload, a duplicate key, bytes that are not MessagePack. A minted
-- ordinary user (helpers.token) shows the rights.
--
-- Own VMs: the status-field tests load the ipip module (its `tunl0` is a
-- link of kind `other`, so the shipped rules leave it to the backstop) and
-- write and remove a network record's Name and Trust and a refused
-- profile; they run last.
--
-- Non-obvious: helpers.msgpack drops a map entry whose value is nil, and
-- the status reply's optional fields are present-and-nil, so the field
-- tests read the reply with a local walker that keeps every key.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local token = require("helpers.token")
local msgpack = require("helpers.msgpack")
local sha1 = require("helpers.sha1")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- Guest CLOCK_MONOTONIC, in seconds.
local function mono()
    local r = sut:syscall(228, { args = { 1, 0 }, bufs = { string.rep("\0", 16) }, ptrs = { 1 } })
    assert(r.ret == 0, "clock_gettime")
    local s, ns = string.unpack("<i8i8", r.out_bufs[1])
    return s + ns / 1e9
end

local function read_exact(who, fd, n, timeout_ms)
    local got = ""
    while #got < n do
        local chunk, err = ntfe.recv(who, fd, timeout_ms or 5000, n - #got)
        if not chunk then return nil, tostring(err) end
        if #chunk == 0 then return nil, "closed" end
        got = got .. chunk
    end
    return got
end

--- Send `bytes` exactly as given on a fresh connection, read one framed
--- reply, then see whether netd closed the connection. Returns a table:
--- `len` (the reply's length prefix), `body`, `reply` (decoded), `eof`,
--- `took` (seconds from connect to the whole reply), or `err`.
local function raw(bytes, o)
    o = o or {}
    local who = o.who or sut
    local fd = assert(unixsock.socket(who, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    local start = mono()
    local c = unixsock.connect(who, fd, network.CONTROL)
    assert(c.ret == 0, "connect: " .. unixsock.errname(c.errno))
    ntfe.send(who, fd, bytes)
    local out = {}
    local head, err = read_exact(who, fd, 4, o.timeout_ms)
    if head then
        out.len = string.unpack("<I4", head)
        out.body, err = read_exact(who, fd, out.len, o.timeout_ms)
        out.took = mono() - start
        if out.body then
            out.reply = msgpack.decode(out.body)
            if not o.keep then
                local more = ntfe.recv(who, fd, o.eof_ms or 1500, 64)
                out.eof = more == ""
            end
        end
    end
    out.err = err
    if o.keep then out.fd = fd else sys.close(who, fd) end
    return out
end

local function frame(payload) return string.pack("<I4", #payload) .. payload end
local function request(t) return frame(msgpack.encode(t)) end

-- A MessagePack walker that keeps every map key, nil-valued ones too:
-- a map comes back as a table with its keys in `_keys`, in wire order.
local function walk(b, at)
    local tag = b:byte(at)
    local n, from, kind
    if tag >= 0x80 and tag <= 0x8f then n, from, kind = tag - 0x80, at + 1, "map"
    elseif tag == 0xde then n, from, kind = string.unpack(">I2", b, at + 1), at + 3, "map"
    elseif tag == 0xdf then n, from, kind = string.unpack(">I4", b, at + 1), at + 5, "map"
    elseif tag >= 0x90 and tag <= 0x9f then n, from, kind = tag - 0x90, at + 1, "array"
    elseif tag == 0xdc then n, from, kind = string.unpack(">I2", b, at + 1), at + 3, "array"
    elseif tag == 0xdd then n, from, kind = string.unpack(">I4", b, at + 1), at + 5, "array"
    end
    if kind == "map" then
        local m = { _keys = {} }
        for _ = 1, n do
            local k, v
            k, from = msgpack.decode(b, from)
            v, from = walk(b, from)
            m._keys[#m._keys + 1] = k
            m[k] = v
        end
        return m, from
    elseif kind == "array" then
        local a = {}
        for i = 1, n do a[i], from = walk(b, from) end
        return a, from
    end
    return msgpack.decode(b, at)
end

local function sorted(list)
    local c = {}
    for i, v in ipairs(list) do c[i] = v end
    table.sort(c)
    return table.concat(c, ",")
end

local function list_text(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

local function has(list, x)
    for _, v in ipairs(list or {}) do if v == x then return true end end
    return false
end

test("one length-prefixed MessagePack map each way, one per connection; unknown keys ignored, a duplicate refused, the 65536-byte ceiling enforced before the payload is read",
    { spec = "netd *control-req.framing" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")

        -- A request and its reply.
        local r = raw(request({ query = "status" }))
        t:assert(r.reply, "a status reply: " .. tostring(r.err))
        t:assert_eq(r.len, #r.body, "the 4-byte little-endian length is the payload's")
        t:assert_eq(r.body:byte(1) & 0xF0, 0x80, "the payload is a MessagePack map")
        t:assert_eq(r.reply.ok, true, "ok is the boolean true")
        t:assert(r.eof, "the connection ends after one reply")

        -- An error reply is the same shape with a string `error`.
        r = raw(request({ query = "bogus" }))
        local m = walk(r.body, 1)
        t:log("error reply keys: " .. sorted(m._keys))
        t:assert_eq(sorted(m._keys), "error,ok", "an error reply is {ok, error}")
        t:assert_eq(m.ok, false, "ok is the boolean false")
        t:assert_eq(type(m.error), "string", "error is a string")

        -- Unknown keys are ignored.
        r = raw(request({ query = "status", zzz = 7, aaa = { 1, 2, 3 }, nested = { x = "y" } }))
        t:assert(r.reply and r.reply.ok == true and r.reply.interfaces, "unknown keys are ignored")

        -- A key that appears twice refuses the request.
        local dup = "\x82\xa5query\xa6status\xa5query\xa6status"
        r = raw(frame(dup))
        t:log("duplicate: " .. tostring(r.reply and r.reply.error))
        t:assert_eq(r.reply and r.reply.error, "duplicate field query", "a duplicate key is refused")

        -- The ceiling: exactly 65536 is read and answered.
        local pad = 65536 - #msgpack.encode({ query = "status", pad = "" })
        local big
        for n = pad - 8, pad do
            big = msgpack.encode({ query = "status", pad = string.rep("p", n) })
            if #big == 65536 then break end
        end
        t:assert_eq(#big, 65536, "built a 65536-byte request")
        r = raw(frame(big))
        t:assert(r.reply and r.reply.ok == true, "a 65536-byte request is answered: " .. tostring(r.reply and r.reply.error))

        -- 65537 announced, nothing sent after the length: refused at once,
        -- without waiting for (or reading) a payload.
        r = raw(string.pack("<I4", 65537))
        t:log(string.format("65537 header only: %s after %.3f s", tostring(r.reply and r.reply.error), r.took or -1))
        t:assert_eq(r.reply and r.reply.error, "message of 65537 bytes exceeds the ceiling", "refused by length")
        t:assert(r.took < 1.0, "refused before any payload: no wait for the 2 s read timeout")
        t:assert(r.eof, "and the connection ends")
        -- The same with the payload actually sent.
        r = raw(frame(big .. "x"))
        t:assert_eq(r.reply and r.reply.error, "message of 65537 bytes exceeds the ceiling", "65537 with payload refused")
    end)

test("a request that cannot be read or decoded is answered with the tabled error and the connection ends",
    { spec = "netd *control-req.decode-errors netd *control-req.framing" }, function(t)
        local cases = {
            { "no query", request({ interface = "eth0" }), "missing field query" },
            { "an unknown query", request({ query = "frobnicate" }), 'unknown query "frobnicate"' },
            { "a duplicate key", frame("\x83\xa5query\xa5renew\xa9interface\xa4eth0\xa9interface\xa4eth1"),
                "duplicate field interface" },
            { "renew without interface", request({ query = "renew" }), "missing field interface" },
        }
        for _, c in ipairs(cases) do
            local r = raw(c[2])
            t:log(c[1] .. ": " .. tostring(r.reply and r.reply.error) .. " eof=" .. tostring(r.eof))
            t:assert(r.reply and r.reply.ok == false, c[1] .. ": an error reply")
            t:assert_eq(r.reply.error, c[3], c[1])
            t:assert(r.eof, c[1] .. ": the connection ends")
        end
        -- Malformed MessagePack: a reserved byte, a map cut short, a
        -- query that is not a string, a payload that is not a map.
        local malformed = {
            { "a reserved tag", frame("\xc1") },
            { "a truncated map", frame("\x82\xa5query") },
            { "a non-string query", frame("\x81\xa5query\x05") },
            { "not a map", frame("\x93\x01\x02\x03") },
        }
        for _, c in ipairs(malformed) do
            local r = raw(c[2])
            t:log(c[1] .. ": " .. tostring(r.reply and r.reply.error) .. " eof=" .. tostring(r.eof))
            t:assert(r.reply and r.reply.ok == false, c[1] .. ": an error reply")
            t:assert(r.reply.error:sub(1, #"malformed message: ") == "malformed message: ",
                c[1] .. ": malformed message: …")
            t:assert(r.eof, c[1] .. ": the connection ends")
        end
    end)

test("status, subscribe, reconcile and renew do what is tabled, under the rights tabled",
    { spec = "netd *control-req.requests" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
        t:assert(s, "netd bound")
        local eth0 = network.iface(s, "eth0")

        -- status: the status.
        local r = raw(request({ query = "status" }))
        t:assert(r.reply.ok == true and r.reply.level and r.reply.interfaces, "status answers with the status")

        -- reconcile: exactly {ok: true}.
        r = raw(request({ query = "reconcile" }))
        local m = walk(r.body, 1)
        t:assert_eq(sorted(m._keys), "ok", "reconcile answers a map holding only ok")
        t:assert_eq(m.ok, true, "reconcile: ok")

        -- renew, by kernel name and by interface id: {ok: true}, and the
        -- client renews (a REQUEST from the bound address, ciaddr set).
        for _, name in ipairs({ "eth0", eth0.ifid }) do
            gw:forget()
            r = raw(request({ query = "renew", interface = name }))
            m = walk(r.body, 1)
            t:assert_eq(sorted(m._keys), "ok", "renew " .. name .. " answers only ok")
            t:assert_eq(m.ok, true, "renew " .. name)
            local seen = gw:serve({ timeout = 10, until_ = function()
                for _, q in ipairs(gw:dhcp_messages(gateway.DHCP.REQUEST)) do
                    if q.ciaddr == "10.77.0.50" then return true end
                end
                return false
            end })
            t:assert(seen, "renew " .. name .. ": the client sent a renewing REQUEST")
            t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 20 }),
                "renew " .. name .. ": bound again")
        end

        -- subscribe: a snapshot now, and the connection kept.
        local sub = raw(request({ query = "subscribe" }), { keep = true })
        t:assert(sub.reply and sub.reply.ok == true, "subscribe answers")
        t:assert_eq(sub.reply.kind, "snapshot", "with a snapshot")
        local more, err = ntfe.recv(sut, sub.fd, 1500, 64)
        t:log("after the snapshot: " .. tostring(more and #more) .. " " .. tostring(err))
        t:assert(more == nil and err == "timeout", "the subscription stays open (no EOF, nothing more yet)")
        t:assert(raw(request({ query = "status" })).reply.ok, "and netd keeps serving others meanwhile")
        sys.close(sut, sub.fd)

        -- Rights: an ordinary user has NETWORK_QUERY only.
        token.as_principal(t, sut, {}, function(w)
            local function q(tbl) return raw(request(tbl), { who = w }).reply end
            t:assert_eq(q({ query = "status" }).ok, true, "user: status (NETWORK_QUERY)")
            local sr = raw(request({ query = "subscribe" }), { who = w, keep = true })
            t:assert(sr.reply and sr.reply.kind == "snapshot", "user: subscribe (NETWORK_QUERY)")
            sys.close(w, sr.fd)
            local rr = q({ query = "reconcile" })
            t:assert(rr.ok == false and rr.error == "access denied", "user: reconcile needs NETWORK_CONTROL")
            rr = q({ query = "renew", interface = "eth0" })
            t:assert(rr.ok == false and rr.error == "access denied", "user: renew needs NETWORK_CONTROL")
        end)
    end)

test("renew names an interface that does not exist, or one with no DHCPv4 client",
    { spec = "netd *control-req.renew-errors" }, function(t)
        local r = raw(request({ query = "renew", interface = "nope0" }))
        t:log("nope0: " .. tostring(r.reply.error))
        t:assert_eq(r.reply.ok, false, "an unknown interface is an error")
        t:assert_eq(r.reply.error, "no interface nope0", "no interface <name>")
        -- Loopback is an interface netd has seen, and never has a client.
        r = raw(request({ query = "renew", interface = "lo" }))
        t:log("lo: " .. tostring(r.reply.error))
        t:assert_eq(r.reply.error, "lo is not using DHCP", "<name> is not using DHCP")
    end)

-- The interface id of a link, from the TRM's byte string.
local function ifid_of(path, mac_or_name)
    return sha1.uuid5("peios-netd-ifid|" .. path .. "|" .. mac_or_name)
end

local function ifindex(name)
    return tonumber((sut:read_file("/sys/class/net/" .. name .. "/ifindex"):gsub("%s+", "")))
end

local IFACE_KEYS = "addresses,carrier,dns,driver,gateway,gateway6,ifid,index,lease,level,mac,name,network,network_name,network_trust,path,profile,rule,search,up,verdict,warning"

test("the status reply: hostname, level, refusal, and one map per non-loopback interface in kernel index order",
    { spec = "netd *control-req.status-fields" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        -- A second interface, of kind `other`: the backstop's.
        local mp = sut:run("modprobe ipip")
        t:log("modprobe ipip: exit " .. mp.exit_code .. " " .. mp.stderr)
        t:assert_eq(mp.exit_code, 0, "the ipip module loads (tunl0)")
        local seen = pcall(wait_until, function()
            return network.iface(network.status(sut), "tunl0") ~= nil
        end, { timeout = 15, interval = 0.3, desc = "netd to see tunl0" })
        t:assert(seen, "netd lists tunl0")

        local r = raw(request({ query = "status" }))
        local st = walk(r.body, 1)
        t:log("top-level keys: " .. sorted(st._keys))
        t:assert_eq(sorted(st._keys), "hostname,interfaces,level,ok,refusal", "the status reply's fields")
        t:assert_eq(st.hostname, "", "hostname: empty, netd has set none")
        t:assert_eq(st.level, "routed", "level: the machine level")
        t:assert_eq(st.refusal, nil, "refusal: nil while the newest generation stands")

        local names, indexes = {}, {}
        for _, i in ipairs(st.interfaces) do
            names[#names + 1] = i.name
            indexes[#indexes + 1] = i.index
        end
        t:log("interfaces: " .. list_text(names) .. " indexes " .. list_text(indexes))
        t:assert(not has(names, "lo"), "loopback is not listed")
        local expect = {}
        for _, n in ipairs(network.links(sut)) do expect[#expect + 1] = { n, ifindex(n) } end
        table.sort(expect, function(a, b) return a[2] < b[2] end)
        local want = {}
        for _, e in ipairs(expect) do want[#want + 1] = e[1] end
        t:assert_eq(table.concat(names, ","), table.concat(want, ","),
            "every non-loopback interface, in kernel index order")
        t:assert(has(names, "tunl0") and has(names, "eth0"), "joined (eth0) and not (tunl0) alike")

        -- refusal: a profile with a value netd does not know refuses the
        -- generation; the reply says why, and clears when it is gone.
        network.write(sut, "Profiles\\pt-refused", { ["Pt.Unknown"] = "dword:1" })
        local why
        local ok = pcall(wait_until, function()
            why = network.status(sut).refusal
            return why ~= nil
        end, { timeout = 15, interval = 0.3, desc = "a refusal" })
        t:log("refusal: " .. tostring(why))
        network.delete(sut, "Profiles\\pt-refused")
        t:assert(ok and type(why) == "string" and #why > 0, "refusal: why the newest generation was refused")
        local cleared = pcall(wait_until, function() return network.status(sut).refusal == nil end,
            { timeout = 15, interval = 0.3, desc = "the refusal to clear" })
        t:assert(cleared, "refusal: nil again once a generation builds")
    end)

test("each interface map carries every tabled field, from identity to lease",
    { spec = "netd *control-req.status-interface-fields" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
        t:assert(s, "netd bound")
        local mac_text = sut:read_file("/sys/class/net/eth0/address"):match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
        local mac = gateway.mac(mac_text)
        local ifid = ifid_of("pci-0000:00:02.0", mac)
        local netid = sha1.uuid5("peios-netd-network|wired|dhcp:10.77.0.1|10.77.0.0/24")

        -- Name and Trust on the network record, and an IPv6 router, so the
        -- fields that are often nil have something to show.
        network.write(sut, "Networks\\" .. netid, { Name = "sz:pt-office", Trust = "sz:pt-trusted" })
        gw:router({ lifetime = 1800 })
        local ll = gateway.ip6_text(gw.ll)
        local got = network.serve_until(gw, sut, function(i)
            return i.network_name == "pt-office" and i.gateway6 ~= nil
        end, { iface = "eth0", timeout = 40 })
        t:assert(got, "netd shows the record's name and the router")

        local r = raw(request({ query = "status" }))
        local st = walk(r.body, 1)
        local e, tun
        for _, i in ipairs(st.interfaces) do
            if i.name == "eth0" then e = i elseif i.name == "tunl0" then tun = i end
        end
        t:assert(e, "eth0 is listed")
        t:log("eth0 keys: " .. sorted(e._keys))
        t:assert_eq(sorted(e._keys), IFACE_KEYS, "eth0 carries every field")
        t:assert_eq(e.ifid, ifid, "ifid: the interface id")
        t:assert_eq(e.name, "eth0", "name")
        t:assert_eq(e.index, ifindex("eth0"), "index: the kernel index")
        t:assert_eq(e.mac, mac_text:lower(), "mac")
        t:assert_eq(e.path, "pci-0000:00:02.0", "path")
        t:assert_eq(e.driver, "virtio_net", "driver")
        t:assert_eq(e.verdict, "JOIN", "verdict")
        t:assert_eq(e.rule, "wired", "rule: the rule that spoke")
        t:assert_eq(e.profile, "default", "profile")
        t:assert_eq(e.network, netid, "network: the network identified now")
        t:assert_eq(e.network_name, "pt-office", "network_name")
        t:assert_eq(e.network_trust, "pt-trusted", "network_trust")
        t:assert_eq(e.warning, nil, "warning: nil")
        t:assert_eq(e.up, true, "up")
        t:assert_eq(e.carrier, true, "carrier")
        t:assert_eq(e.level, "routed", "level")
        t:log("eth0 addresses: " .. list_text(e.addresses))
        t:assert(has(e.addresses, "10.77.0.50/24"), "addresses: the lease's, address/prefix")
        local lladdr = gateway.ip6_text(gateway.link_local(mac))
        t:assert(has(e.addresses, lladdr .. "/64"), "addresses: the link-local one too")
        t:assert_eq(e.gateway, "10.77.0.1", "gateway: the first IPv4 default route's")
        t:assert_eq(e.gateway6, ll, "gateway6: the first IPv6 default route's (the router's link-local)")
        t:assert_eq(list_text(e.dns), "[10.77.0.1]", "dns: the merged servers")
        t:assert_eq(list_text(e.search), "[]", "search: none offered")
        t:assert(e.lease, "lease: present while bound")
        t:log(string.format("lease: server %s expires_in %s state %s", tostring(e.lease.server),
            tostring(e.lease.expires_in), tostring(e.lease.state)))
        -- A netd before the lease's length and T1/T2 reached status lacks
        -- the last three, as the table says; when they are there they are
        -- exact.
        local keys = sorted(e.lease._keys)
        t:assert(keys == "expires_in,server,state" or keys == "duration,expires_in,rebind_at,renew_at,server,state",
            "lease fields: " .. keys)
        t:assert_eq(e.lease.server, "10.77.0.1", "lease.server")
        t:assert_eq(e.lease.state, "bound", "lease.state")
        t:assert(math.type(e.lease.expires_in) == "integer" and e.lease.expires_in > 3000
            and e.lease.expires_in <= 3600, "lease.expires_in: whole seconds left of 3600")
        if e.lease.duration ~= nil then
            t:assert_eq(e.lease.duration, 3600, "lease.duration: the lease's length")
            t:assert_eq(e.lease.renew_at, 1800, "lease.renew_at: T1, half the lease (no option 58)")
            t:assert_eq(e.lease.rebind_at, 3150, "lease.rebind_at: T2, seven-eighths (no option 59)")
        end

        -- tunl0: no rule speaks for it, it has no MAC, path or driver, and
        -- it is down and not joined.
        t:assert(tun, "tunl0 is listed")
        t:log(string.format("tunl0: ifid %s verdict %s rule %s mac %q path %q driver %q level %s up %s lease %s",
            tostring(tun.ifid), tostring(tun.verdict), tostring(tun.rule), tostring(tun.mac), tostring(tun.path),
            tostring(tun.driver), tostring(tun.level), tostring(tun.up), tostring(tun.lease)))
        t:assert_eq(sorted(tun._keys), IFACE_KEYS, "tunl0 carries every field")
        t:assert_eq(tun.ifid, ifid_of("", "tunl0"), "a MAC-less link's id follows its name")
        t:assert_eq(tun.verdict, nil, "verdict: nil when the backstop answered")
        t:assert_eq(tun.rule, "backstop", "rule: backstop")
        t:assert_eq(tun.profile, nil, "profile: JOIN only")
        t:assert_eq(tun.mac, "", "mac: empty when absent")
        t:assert_eq(tun.path, "", "path: empty when absent")
        t:assert_eq(tun.driver, "", "driver: empty when absent")
        t:assert_eq(tun.up, false, "up: tunl0 is down")
        t:assert_eq(tun.level, "absent", "level: computed for every interface")
        t:assert_eq(list_text(tun.dns), "[]", "dns: empty for an interface not joined")
        t:assert_eq(list_text(tun.search), "[]", "search: empty for an interface not joined")
        t:assert_eq(tun.lease, nil, "lease: nil without a client")
        t:assert_eq(tun.gateway, nil, "gateway: nil without a default route")

        network.reg(sut, { "del", network.KEY .. "\\Networks\\" .. netid, "Name" })
        network.reg(sut, { "del", network.KEY .. "\\Networks\\" .. netid, "Trust" })
    end)
