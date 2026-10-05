-- netd TRM §4.3 "Reconciliation": what netd owns on an interface, the
-- order of its plan, flag changes as replacing adds, the empty plan of a
-- converged interface, how each operation is phrased to rtnetlink, and
-- which failures it carries on through.
--
-- Harness: the scripted gateway (DHCPv4 server and router: one on-link
-- fd77::/64 and one off-link fd78::/64) and one whole Peios machine.
-- eth0, joined by the shipped baseline, carries a lease and SLAAC
-- addresses; dummy links the test makes over rtnetlink (local functions
-- below; the image ships no `ip`) carry static profiles, each named by a
-- rule on its MAC at priority 20.
--
-- The order of a plan, and whether a pass sent anything at all, are read
-- from the kernel rather than from netd's log: a netlink socket in the
-- guest subscribed to the link, address and route groups records every
-- change the kernel announces, in the order it made them. Kernel-made
-- side effects (local and prefix routes, the v6 link-local) are filtered
-- out by protocol and address; what is left is netd's operations.
--
-- The `reconcile` control request runs a full pass and answers when it
-- is done, so it is the barrier before every "nothing changed" check.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
gw:router({ lifetime = 1800, prefixes = {
    { prefix = "fd77::", len = 64, valid = 86400, preferred = 14400 },
    { prefix = "fd78::", len = 64, L = false, valid = 86400, preferred = 14400 },
} })
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- rtnetlink, from the agent
-- ---------------------------------------------------------------------------

local RTM = { NEWLINK = 16, DELLINK = 17, NEWADDR = 20, DELADDR = 21, NEWROUTE = 24, DELROUTE = 25 }
local NLM_F = { REQUEST = 0x1, ACK = 0x4, REPLACE = 0x100, EXCL = 0x200, CREATE = 0x400 }
local IFA_F_NOPREFIXROUTE, IFA_F_DEPRECATED = 0x200, 0x20

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

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

local function ip_text(bytes)
    if #bytes == 4 then return ntfe.ip4_text(bytes) end
    return gateway.ip6_text(bytes)
end

local function nl_request(msg_type, flags, body)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    local fd = s.ret
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 16 + #body, msg_type,
        flags | NLM_F.REQUEST | NLM_F.ACK, 1, 0) .. body)
    local buf = ntfe.recv(sut, fd, 3000, 65536)
    sys.close(sut, fd)
    if not buf or #buf < 20 then return nil, "no ack" end
    local _, kind = string.unpack("<I4I2", buf)
    if kind ~= 2 then return nil, "reply type " .. kind end
    local err = string.unpack("<i4", buf, 17)
    if err ~= 0 then return nil, sys.errname(-err) end
    return true
end

local function dummy(name, mac)
    local body = string.pack("<I1I1I2i4I4I4", 0, 0, 0, 0, 0, 0)
        .. nla(3, name .. "\0") .. nla(1, gateway.mac(mac)) .. nla(18, nla(1, "dummy"))
    local ok, err = nl_request(RTM.NEWLINK, NLM_F.CREATE | NLM_F.EXCL, body)
    assert(ok, "dummy " .. name .. ": " .. tostring(err))
    return assert(ntfe.if_index(sut, name))
end

--- A route "as somebody else": `r` = dst, prefix, gateway, oif, metric,
--- protocol, table, type (1 unicast).
local function add_route(r)
    local v6 = (r.dst or r.gateway):find(":", 1, true) ~= nil
    local ip = v6 and ntfe.ip6 or ntfe.ip4
    local tbl = r.table or 254
    local body = string.pack("<I1I1I1I1I1I1I1I1I4", v6 and 10 or 2, r.prefix or 0, 0, 0,
        tbl < 256 and tbl or 252, r.protocol or 4, r.gateway and 0 or 253, r.type or 1, 0)
    if r.prefix and r.prefix > 0 then body = body .. nla(1, ip(r.dst)) end
    if r.gateway then body = body .. nla(5, ip(r.gateway)) end
    if r.oif then body = body .. nla(4, string.pack("<i4", r.oif)) end
    if r.metric then body = body .. nla(6, string.pack("<I4", r.metric)) end
    body = body .. nla(15, string.pack("<I4", tbl))
    return nl_request(RTM.NEWROUTE, NLM_F.CREATE | NLM_F.EXCL, body)
end

--- Every route in table `tbl` (all tables when nil), with its raw header.
local function all_routes(tbl)
    local out = {}
    for _, r in ipairs(rtnl.routes(sut)) do
        if not tbl or r.table == tbl then out[#out + 1] = r end
    end
    return out
end

--- Re-add an address as somebody else would, replacing it, with `flags`.
local function replace_v6(index, addr, prefix, flags)
    local body = string.pack("<I1I1I1I1i4", 10, prefix, 0, 0, index)
        .. nla(1, ntfe.ip6(addr)) .. nla(8, string.pack("<I4", flags))
        .. nla(6, string.pack("<I4I4I4I4", 0xFFFFFFFF, 0xFFFFFFFF, 0, 0))
    return nl_request(RTM.NEWADDR, NLM_F.CREATE | NLM_F.REPLACE, body)
end

--- Every IPv4/IPv6 address with its raw attributes: local, address,
--- broadcast, scope, flags, lifetimes.
local function raw_addresses(index)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    local fd = s.ret
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 24, 22, 0x301, 7, 0)
        .. string.pack("<I1I1I1I1i4", 0, 0, 0, 0, 0))
    local out, done = {}, false
    while not done do
        local buf = ntfe.recv(sut, fd, 3000, 65536)
        if not buf then break end
        local at = 1
        while at + 15 <= #buf do
            local len, kind = string.unpack("<I4I2", buf, at)
            if len < 16 or kind == 3 or kind == 2 then done = true; break end
            local body = buf:sub(at + 16, at + len - 1)
            if kind == RTM.NEWADDR then
                local family, prefix, flags8, scope, idx = string.unpack("<I1I1I1I1i4", body)
                if idx == index then
                    local a = attrs(body, 9)
                    local e = { family = family == 2 and 4 or 6, prefix = prefix, scope = scope,
                        flags = a[8] and string.unpack("<I4", a[8]) or flags8,
                        ["local"] = a[2] and ip_text(a[2]), address = a[1] and ip_text(a[1]),
                        broadcast = a[4] and ip_text(a[4]) }
                    if a[6] then e.preferred, e.valid = string.unpack("<I4I4", a[6]) end
                    e.name = e["local"] or e.address
                    out[e.name] = e
                end
            end
            at = at + ((len + 3) & ~3)
        end
    end
    sys.close(sut, fd)
    return out
end

-- ---------------------------------------------------------------------------
-- The monitor: what the kernel announces, in order
-- ---------------------------------------------------------------------------

local GROUPS = 0x1 | 0x10 | 0x40 | 0x100 | 0x400 -- link, v4/v6 address and route

local function monitor_open()
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    assert(s.ret >= 0, "monitor socket: " .. sys.errname(s.errno))
    local sa = string.pack("<I2I2I4I4", 16, 0, 0, GROUPS)
    local b = sut:syscall(ntfe.NR.bind, { args = { s.ret, 0, #sa }, bufs = { sa }, ptrs = { 1 } })
    assert(b.ret == 0, "monitor bind: " .. sys.errname(b.errno))
    return s.ret
end

--- Read every announcement until `quiet_ms` pass with none, close, and
--- return them decoded: { kind = "link"|"addr"|"route", op = "new"|"del",
--- index, ... }.
local function monitor_drain(fd, quiet_ms, max_s)
    local out = {}
    local deadline = os.time() + (max_s or 30)
    while os.time() <= deadline do
        local buf = ntfe.recv(sut, fd, quiet_ms or 500, 65536)
        if not buf then break end
        local at = 1
        while at + 15 <= #buf do
            local len, kind = string.unpack("<I4I2", buf, at)
            if len < 16 then break end
            local body = buf:sub(at + 16, at + len - 1)
            if kind == RTM.NEWLINK or kind == RTM.DELLINK then
                local _, _, _, index, flags = string.unpack("<I1I1I2i4I4", body)
                local a = attrs(body, 17)
                out[#out + 1] = { kind = "link", op = kind == RTM.NEWLINK and "new" or "del", index = index,
                    up = flags & 1 ~= 0, mtu = a[4] and string.unpack("<I4", a[4]) }
            elseif kind == RTM.NEWADDR or kind == RTM.DELADDR then
                local family, prefix, flags8, _, index = string.unpack("<I1I1I1I1i4", body)
                local a = attrs(body, 9)
                local addr = (family == 2 and (a[2] or a[1])) or a[1]
                out[#out + 1] = { kind = "addr", op = kind == RTM.NEWADDR and "new" or "del", index = index,
                    address = addr and ip_text(addr), prefix = prefix,
                    flags = a[8] and string.unpack("<I4", a[8]) or flags8 }
            elseif kind == RTM.NEWROUTE or kind == RTM.DELROUTE then
                local family, dst_len, _, _, tbl, proto = string.unpack("<I1I1I1I1I1I1", body)
                local a = attrs(body, 13)
                out[#out + 1] = { kind = "route", op = kind == RTM.NEWROUTE and "new" or "del",
                    index = a[4] and string.unpack("<i4", a[4]),
                    dst = a[1] and ip_text(a[1]) or (family == 2 and "0.0.0.0" or "::"), prefix = dst_len,
                    gateway = a[5] and ip_text(a[5]), metric = a[6] and string.unpack("<I4", a[6]) or 0,
                    protocol = proto, table = a[15] and string.unpack("<I4", a[15]) or tbl }
            end
            at = at + ((len + 3) & ~3)
        end
    end
    sys.close(sut, fd)
    return out
end

--- netd's operations on link `index` among `events`, starting from the
--- link's state `was` = {up, mtu}: "LinkUp", "Mtu 1400", "DelAddress a/p",
--- "AddAddress a/p", "DelRoute d/p via g metric m", "AddRoute …",
--- "LinkDown". IPv6 link-locals and every route not of protocol 200 in
--- the main table are the kernel's, and left out.
local function operations(events, index, was)
    local ops = {}
    local up, mtu = was.up, was.mtu
    for _, e in ipairs(events) do
        if e.index == index then
            if e.kind == "link" and e.op == "new" then
                if e.up ~= up then ops[#ops + 1] = e.up and "LinkUp" or "LinkDown"; up = e.up end
                if e.mtu and e.mtu ~= mtu then ops[#ops + 1] = "Mtu " .. e.mtu; mtu = e.mtu end
            elseif e.kind == "addr" and not e.address:match("^fe80:") then
                ops[#ops + 1] = string.format("%s %s/%d", e.op == "new" and "AddAddress" or "DelAddress",
                    e.address, e.prefix)
            elseif e.kind == "route" and e.protocol == 200 and e.table == 254 then
                ops[#ops + 1] = string.format("%s %s/%d via %s metric %d", e.op == "new" and "AddRoute" or "DelRoute",
                    e.dst, e.prefix, tostring(e.gateway), e.metric)
            end
        end
    end
    return ops
end

local RANK = { LinkUp = 1, Mtu = 2, DelAddress = 3, AddAddress = 4, DelRoute = 5, AddRoute = 6, LinkDown = 7 }

local function in_plan_order(ops)
    local last = 0
    for _, op in ipairs(ops) do
        local r = RANK[op:match("^%a+")]
        if r < last then return false, op end
        last = r
    end
    return true
end

local function has(list, item)
    for _, x in ipairs(list) do if x == item then return true end end
    return false
end

-- ---------------------------------------------------------------------------
-- The machine
-- ---------------------------------------------------------------------------

local function pass()
    local r, err = network.call(sut, { query = "reconcile" })
    assert(r and r.ok, "reconcile: " .. tostring(err or (r and r.error)))
end

--- Stand the link with MAC `mac` in `actions`, writing the condition and
--- priority before the actions, so no pass sees a half-written rule.
local function rule(name, mac, actions)
    local key = network.KEY .. "\\Rules\\Interface\\" .. name
    network.reg(sut, { "new", key })
    network.reg(sut, { "set", key, "Interface.Mac.Equal", "sz:" .. mac }):assert_ok()
    network.reg(sut, { "set", key, "Priority", "dword:20" }):assert_ok()
    network.reg(sut, { "set", key, "Actions", "multi:" .. actions }):assert_ok()
    return key
end

--- Wait until no address on `index` is tentative (DAD finished), so that
--- the kernel's own DAD announcements are over.
local function settled(index)
    wait_until(function()
        for _, a in ipairs(rtnl.addresses_of(sut, index)) do
            if a.tentative then return false end
        end
        return true
    end, { timeout = 20, interval = 0.25, desc = "DAD to finish on " .. index })
end

local function is_up(name) return (ntfe.if_flags(sut, name) or 0) & ntfe.IFF_UP ~= 0 end
local function mtu_of(name) return tonumber(sut:read_file("/sys/class/net/" .. name .. "/mtu"):match("%d+")) end

local function count_logged(fn)
    local n = 0
    for _, l in ipairs(network.logs(sut, { take = 1000 })) do if fn(l) then n = n + 1 end end
    return n
end

local function v4_on(index)
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, index, 4)) do out[a.address] = a end
    return out
end

local function v6_on(index)
    local out = {}
    for _, a in ipairs(rtnl.addresses_of(sut, index, 6)) do out[a.address] = a end
    return out
end

--- netd's routes (protocol 200) on `index`.
local function netd_routes_on(index)
    local out = {}
    for _, r in ipairs(rtnl.routes_of(sut, index)) do
        if r.protocol == 200 then out[#out + 1] = r end
    end
    return out
end

local eth = {} -- eth0's index, stable fd77 address

local function ready(i)
    if not network.bound(i) then return false end
    for _, a in ipairs(network.ipv6(i)) do if a:match("^fd77:") then return true end end
    return false
end

-- ---------------------------------------------------------------------------

test("on a joined interface every IPv4 address (169.254 included) and every non-link-local IPv6 address is netd's; a protocol-200 route is netd's, but only main-table unicast routes with an output interface are read; the kernel's fe80::/10 is never touched",
    { spec = "netd *reconcile.ownership" }, function(t)
    local s = network.serve_until(gw, sut, ready, { iface = true, timeout = 90 })
    t:assert(s, "eth0 bound, with an fd77 address")
    eth.index = network.iface(s, "eth0").index
    local i = eth.index
    t:assert(rtnl.add_address(sut, i, "169.254.9.9", { prefix = 16 }), "added 169.254.9.9/16")
    t:assert(rtnl.add_address(sut, i, "fe80::99", { prefix = 64 }), "added fe80::99/64")
    t:assert(add_route({ dst = "10.8.0.0", prefix = 16, gateway = "10.77.0.1", oif = i, protocol = 200 }),
        "added a protocol-200 route to the main table")
    t:assert(add_route({ dst = "10.7.0.0", prefix = 16, gateway = "10.77.0.1", oif = i, protocol = 200, table = 100 }),
        "added a protocol-200 route to table 100")
    t:assert(add_route({ dst = "10.6.0.0", prefix = 16, protocol = 200, type = 6 }),
        "added a protocol-200 blackhole route (no output interface)")
    wait_until(function()
        local v4 = v4_on(i)
        local gone = true
        for _, r in ipairs(all_routes(254)) do if r.dst == "10.8.0.0" then gone = false end end
        return v4["169.254.9.9"] == nil and gone
    end, { timeout = 20, interval = 0.25, desc = "netd to remove the 169.254 address and its stray route" })
    pass()
    t:assert_eq(v4_on(i)["169.254.9.9"], nil, "a 169.254 address netd does not desire is removed")
    t:assert(v6_on(i)["fe80::99"] ~= nil, "a link-local IPv6 address is never removed")
    local t100, black = false, false
    for _, r in ipairs(all_routes()) do
        if r.dst == "10.7.0.0" and r.table == 100 then t100 = true end
        if r.dst == "10.6.0.0" and r.type == 6 then black = true end
    end
    t:assert(t100, "a protocol-200 route in another table is not read, so stays")
    t:assert(black, "a protocol-200 non-unicast route without an output interface is not read, so stays")
end)

test("an address netd does not desire is removed, whoever added it",
    { spec = "netd *reconcile.foreign-address-removed" }, function(t)
    local i = assert(eth.index, "the first test found eth0")
    t:assert(rtnl.add_address(sut, i, "10.77.0.99", { prefix = 24 }), "added 10.77.0.99/24")
    t:assert(rtnl.add_address(sut, i, "fd99::5", { prefix = 64 }), "added fd99::5/64")
    wait_until(function() return v4_on(i)["10.77.0.99"] == nil and v6_on(i)["fd99::5"] == nil end,
        { timeout = 20, interval = 0.25, desc = "both foreign addresses removed" })
    t:assert(v4_on(i)["10.77.0.50"] ~= nil, "the lease's address stays")
end)

test("netd stamps protocol 200 on every route it adds and removes no route without it",
    { spec = "netd *reconcile.foreign-route-kept" }, function(t)
    local i = assert(eth.index, "the first test found eth0")
    t:assert(add_route({ dst = "10.9.0.0", prefix = 16, gateway = "10.77.0.1", oif = i, protocol = 4 }),
        "added a static-protocol route")
    pass()
    pass()
    local found, defaults = false, {}
    for _, r in ipairs(rtnl.routes_of(sut, i)) do
        if r.dst == "10.9.0.0" and r.prefix == 16 and r.protocol == 4 then found = true end
        if r.prefix == 0 then defaults[#defaults + 1] = r end
    end
    t:assert(found, "the foreign route is kept")
    t:assert_eq(#defaults, 2, "netd's IPv4 and IPv6 default routes")
    for _, r in ipairs(defaults) do
        t:assert_eq(r.protocol, 200, "netd's " .. r.dst .. " default carries protocol 200")
    end
end)

local R1 = "02:c0:00:00:03:01"

test("a plan runs link up, MTU, address deletions, address additions, route deletions, route additions, and link down last",
    { spec = "netd *reconcile.plan-order" }, function(t)
    -- The rule first, so the baseline never joins the new link.
    rule("ptc-r1", R1, "IGNORE")
    local d = dummy("ptr1", R1)
    wait_until(function() local x = network.iface(network.status(sut), "ptr1"); return x and x.verdict == "IGNORE" end,
        { timeout = 20, interval = 0.25, desc = "ptr1 ignored" })
    -- (Should netd have seen the link before the rule, the baseline
    -- joined it for a moment; IGNORE leaves it as it was, so put it down.)
    if is_up("ptr1") then t:assert(ntfe.if_down(sut, "ptr1"), "took ptr1 down") end
    t:assert(not is_up("ptr1"), "ptr1 starts down")
    t:assert(rtnl.add_address(sut, d, "10.44.0.9", { prefix = 24 }), "a foreign address on the down link")
    network.write(sut, "Profiles\\ptr-a", { ["Address.Static"] = "multi:10.55.0.2/24",
        ["Route.Gateway"] = "multi:10.55.0.1", ["Mtu.Value"] = "dword:1400", ["Route.Metric"] = "dword:300" })
    network.write(sut, "Profiles\\ptr-b", { ["Address.Static"] = "multi:10.55.0.2/24,10.56.0.2/24",
        ["Route.Gateway"] = "multi:10.55.0.1", ["Mtu.Value"] = "dword:1300", ["Route.Metric"] = "dword:250" })

    -- One plan with every kind of operation but two that cannot meet a
    -- down link (a route needs the link up).
    local m = monitor_open()
    rule("ptc-r1", R1, "JOIN(ptr-a)")
    wait_until(function() return #netd_routes_on(d) == 1 end,
        { timeout = 20, interval = 0.25, desc = "ptr-a's default route" })
    local ops = operations(monitor_drain(m), d, { up = false, mtu = 1500 })
    t:log("plan 1: " .. table.concat(ops, ", "))
    t:assert_eq(table.concat(ops, ", "),
        "LinkUp, Mtu 1400, DelAddress 10.44.0.9/24, AddAddress 10.55.0.2/24, AddRoute 0.0.0.0/0 via 10.55.0.1 metric 300",
        "up, MTU, delete, add, route")

    -- Deletions before additions, of both kinds.
    rule("ptc-r1", R1, "IGNORE")
    wait_until(function() return network.iface(network.status(sut), "ptr1").verdict == "IGNORE" end,
        { timeout = 20, interval = 0.25, desc = "ptr1 ignored again" })
    t:assert(rtnl.add_address(sut, d, "10.44.0.9", { prefix = 24 }), "a foreign address")
    t:assert(add_route({ dst = "10.45.0.0", prefix = 16, gateway = "10.55.0.1", oif = d, protocol = 200 }),
        "a stray protocol-200 route")
    m = monitor_open()
    rule("ptc-r1", R1, "JOIN(ptr-b)")
    wait_until(function() return mtu_of("ptr1") == 1300 and #netd_routes_on(d) == 1
        and netd_routes_on(d)[1].metric == 250 end,
        { timeout = 20, interval = 0.25, desc = "ptr-b in force" })
    ops = operations(monitor_drain(m), d, { up = true, mtu = 1400 })
    t:log("plan 2: " .. table.concat(ops, ", "))
    t:assert_eq(table.concat(ops, ", "),
        "Mtu 1300, DelAddress 10.44.0.9/24, AddAddress 10.56.0.2/24, "
        .. "DelRoute 0.0.0.0/0 via 10.55.0.1 metric 300, DelRoute 10.45.0.0/16 via 10.55.0.1 metric 0, "
        .. "AddRoute 0.0.0.0/0 via 10.55.0.1 metric 250",
        "MTU, delete, add, route deletions, route addition")

    -- DOWN: everything goes, and the link goes down last.
    local quiet_failures = count_logged(function(l) return l:find("reconcile: Del", 1, true) ~= nil end)
    m = monitor_open()
    rule("ptc-r1", R1, "DOWN")
    wait_until(function() return not is_up("ptr1") end, { timeout = 20, interval = 0.25, desc = "ptr1 down" })
    ops = operations(monitor_drain(m), d, { up = true, mtu = 1300 })
    t:log("plan 3: " .. table.concat(ops, ", "))
    local ok, bad = in_plan_order(ops)
    t:assert(ok, "out of order at " .. tostring(bad))
    t:assert_eq(ops[#ops], "LinkDown", "the link goes down last")
    t:assert_eq(table.concat(ops, ", "), "DelAddress 10.55.0.2/24, DelAddress 10.56.0.2/24, LinkDown",
        "both addresses, then the link")
    t:assert_eq(#netd_routes_on(d), 0, "no netd route is left")
    -- The route's delete is not in the kernel's announcements: when the
    -- last IPv4 address goes, the kernel flushes the routes through it
    -- without announcing them, and netd's own DelRoute then meets ESRCH,
    -- which it does not log. The plan itself is in netd's log line, the
    -- only place the planned-but-moot DelRoute shows.
    t:assert_eq(count_logged(function(l) return l:find("reconcile: Del", 1, true) ~= nil end), quiet_failures,
        "the moot delete's ESRCH was not logged")
    local line
    for _, l in ipairs(network.logs(sut, { take = 300 })) do
        if not line and l:find("interface ptr1: applying", 1, true) and l:find("LinkDown", 1, true) then line = l end
    end
    t:assert(line, "netd logged the DOWN plan")
    t:log("plan 3 as netd logged it: " .. line)
    local a1 = line:find("DelAddress(", 1, true)
    local r1 = line:find("DelRoute(", 1, true)
    local ld = line:find("LinkDown(", 1, true)
    t:assert(a1 and r1 and ld and a1 < r1 and r1 < ld, "planned: addresses, then the route, then link down")
end)

test("an address whose flags alone change is re-added in place (a replace), never deleted; DAD's tentative flag is no difference",
    { spec = "netd *reconcile.flag-change-is-a-replace" }, function(t)
    local i = assert(eth.index, "the first test found eth0")
    settled(i)
    local stable
    for a, e in pairs(v6_on(i)) do
        if a:match("^fd77:") and not e.tentative then stable = stable or a end
    end
    t:assert(stable, "an fd77 address on eth0")

    -- A router deprecates the prefix.
    local m = monitor_open()
    gw:send_ra({ lifetime = 1800, prefixes = {
        { prefix = "fd77::", len = 64, valid = 86400, preferred = 0 },
        { prefix = "fd78::", len = 64, L = false, valid = 86400, preferred = 14400 } } })
    wait_until(function() local e = v6_on(i)[stable]; return e and e.deprecated end,
        { timeout = 20, interval = 0.25, desc = stable .. " deprecated" })
    local events = monitor_drain(m)
    local adds, dels = 0, 0
    for _, e in ipairs(events) do
        if e.kind == "addr" and e.address == stable then
            if e.op == "new" then adds = adds + 1 else dels = dels + 1 end
        end
    end
    t:log(string.format("%s: %d NEWADDR, %d DELADDR", stable, adds, dels))
    t:assert_eq(dels, 0, "never deleted")
    t:assert(adds >= 1, "re-added with the deprecated flag")

    -- Somebody else sets a flag on it: netd puts it back, again by replacing.
    gw:send_ra({ lifetime = 1800, prefixes = {
        { prefix = "fd77::", len = 64, valid = 86400, preferred = 14400 },
        { prefix = "fd78::", len = 64, L = false, valid = 86400, preferred = 14400 } } })
    wait_until(function() local e = v6_on(i)[stable]; return e and not e.deprecated end,
        { timeout = 20, interval = 0.25, desc = stable .. " preferred again" })
    m = monitor_open()
    t:assert(replace_v6(i, stable, 64, IFA_F_NOPREFIXROUTE), "replaced it with no-prefix-route set")
    wait_until(function() local e = v6_on(i)[stable]; return e and not e.noprefixroute end,
        { timeout = 20, interval = 0.25, desc = "netd to clear the flag" })
    events = monitor_drain(m)
    adds, dels = 0, 0
    for _, e in ipairs(events) do
        if e.kind == "addr" and e.address == stable then
            if e.op == "new" then adds = adds + 1 else dels = dels + 1 end
        end
    end
    t:log(string.format("after the foreign flag: %d NEWADDR, %d DELADDR", adds, dels))
    t:assert_eq(dels, 0, "never deleted")
    t:assert(adds >= 2, "the foreign replace and netd's")
end)

test("an interface the kernel already matches gets an empty plan: a full pass sends nothing",
    { spec = "netd *reconcile.converged-plan-is-empty" }, function(t)
    local i = assert(eth.index, "the first test found eth0")
    settled(i)
    pass()
    local applying = count_logged(function(l) return l:find("applying", 1, true) ~= nil end)
    local m = monitor_open()
    pass()
    pass()
    local events = monitor_drain(m, 1000)
    local mine = {}
    for _, e in ipairs(events) do
        mine[#mine + 1] = string.format("%s %s index %s %s", e.op, e.kind, tostring(e.index),
            tostring(e.address or e.dst or ""))
    end
    t:log("announcements during two passes: " .. (#mine > 0 and table.concat(mine, "; ") or "none"))
    t:assert_eq(#events, 0, "the kernel announced no change")
    t:assert_eq(count_logged(function(l) return l:find("applying", 1, true) ~= nil end), applying,
        "and netd logged no plan")
    t:assert(network.bound(network.iface(network.status(sut), "eth0")), "eth0 still bound")
end)

test("phrasing: IPv4 carries local = address = itself, link scope for 169.254/16 and universe otherwise, and below /31 a broadcast (the lease's, else all-ones); IPv6 universe scope and no-prefix-route when off-link; gateway routes are universe scope in the main table with protocol 200",
    { spec = "netd *reconcile.apply" }, function(t)
    local i = assert(eth.index, "the first test found eth0")
    local lease = raw_addresses(i)["10.77.0.50"]
    t:assert(lease, "the lease's address")
    t:assert_eq(lease["local"], "10.77.0.50", "IFA_LOCAL is the address")
    t:assert_eq(lease.address, "10.77.0.50", "IFA_ADDRESS is the address")
    t:assert_eq(lease.scope, 0, "universe scope")
    t:assert_eq(lease.broadcast, "10.77.0.255", "no option 28: the subnet's all-ones broadcast")

    network.write(sut, "Profiles\\ptr-c", { ["Address.Static"] =
        "multi:169.254.10.10/16,10.60.0.0/31,10.61.0.1/32,10.62.0.1/24,fd62::1/64",
        ["Route.Gateway"] = "multi:10.62.0.254", ["Route.Metric"] = "dword:400" })
    rule("ptc-r2", "02:c0:00:00:03:02", "JOIN(ptr-c)")
    local d = dummy("ptr2", "02:c0:00:00:03:02")
    local got
    wait_until(function()
        got = raw_addresses(d)
        return got["169.254.10.10"] and got["10.60.0.0"] and got["10.61.0.1"] and got["10.62.0.1"]
            and got["fd62::1"] and #netd_routes_on(d) == 1
    end, { timeout = 20, interval = 0.25, desc = "ptr-c's addresses and route" })
    t:assert_eq(got["169.254.10.10"].scope, 253, "169.254/16: link scope")
    t:assert_eq(got["169.254.10.10"].broadcast, "169.254.255.255", "with its all-ones broadcast")
    t:assert_eq(got["10.62.0.1"].scope, 0, "universe scope")
    t:assert_eq(got["10.62.0.1"].broadcast, "10.62.0.255", "/24: all-ones broadcast")
    t:assert_eq(got["10.60.0.0"].broadcast, nil, "/31: no broadcast")
    t:assert_eq(got["10.61.0.1"].broadcast, nil, "/32: no broadcast")
    for _, n in ipairs({ "169.254.10.10", "10.60.0.0", "10.61.0.1", "10.62.0.1" }) do
        t:assert_eq(got[n]["local"], n, n .. ": IFA_LOCAL is itself")
        t:assert_eq(got[n].address, n, n .. ": IFA_ADDRESS is itself")
    end
    t:assert_eq(got["fd62::1"].scope, 0, "IPv6: universe scope")
    t:assert_eq(got["fd62::1"].flags & IFA_F_NOPREFIXROUTE, 0, "an on-link static: a prefix route")
    -- The off-link SLAAC prefix on eth0 carries no-prefix-route.
    local off
    for a, e in pairs(raw_addresses(i)) do if a:match("^fd78:") then off = e end end
    t:assert(off, "an fd78 address on eth0")
    t:assert(off.flags & IFA_F_NOPREFIXROUTE ~= 0, "an off-link prefix's address: no-prefix-route")
    t:assert_eq(off.scope, 0, "universe scope")

    local r = netd_routes_on(d)[1]
    local raw
    for _, x in ipairs(all_routes()) do
        if x.oif == d and x.protocol == 200 then raw = x end
    end
    t:assert_eq(raw.table, 254, "the main table")
    t:assert_eq(raw.scope, 0, "a route with a gateway: universe scope")
    t:assert_eq(raw.type, 1, "unicast")
    t:assert_eq(r.gateway, "10.62.0.254", "via the gateway")
end)

test("IPv6 lifetimes are netd's: the kernel is told valid forever and preferred forever, or zero when deprecated",
    { spec = "netd *reconcile.ipv6-lifetimes-forever-or-deprecated" }, function(t)
    local i = assert(eth.index, "the first test found eth0")
    local stable
    for a, e in pairs(v6_on(i)) do if a:match("^fd77:") and not e.deprecated then stable = stable or a end end
    t:assert(stable, "a preferred fd77 address")
    local e = v6_on(i)[stable]
    t:log(string.format("%s preferred %d valid %d (the router said 14400/86400)", stable, e.preferred, e.valid))
    t:assert_eq(e.valid, rtnl.FOREVER, "valid forever, not the router's 86400")
    t:assert_eq(e.preferred, rtnl.FOREVER, "preferred forever, not the router's 14400")
    gw:send_ra({ lifetime = 1800, prefixes = {
        { prefix = "fd77::", len = 64, valid = 86400, preferred = 0 },
        { prefix = "fd78::", len = 64, L = false, valid = 86400, preferred = 14400 } } })
    wait_until(function() local x = v6_on(i)[stable]; return x and x.deprecated end,
        { timeout = 20, interval = 0.25, desc = stable .. " deprecated" })
    e = v6_on(i)[stable]
    t:log(string.format("deprecated: preferred %d valid %d", e.preferred, e.valid))
    t:assert_eq(e.preferred, 0, "deprecated: preferred lifetime zero")
    t:assert_eq(e.valid, rtnl.FOREVER, "still valid forever")
    gw:send_ra({ lifetime = 1800, prefixes = {
        { prefix = "fd77::", len = 64, valid = 86400, preferred = 14400 },
        { prefix = "fd78::", len = 64, L = false, valid = 86400, preferred = 14400 } } })
    wait_until(function() local x = v6_on(i)[stable]; return x and not x.deprecated end,
        { timeout = 20, interval = 0.25, desc = stable .. " preferred again" })
end)

test("a failed operation is logged and the rest of the plan carries on; EEXIST on an add is the kernel getting there first, and is not logged",
    { spec = "netd *reconcile.failure-carries-on" }, function(t)
    -- An MTU the kernel refuses, first in the plan; the rest still lands.
    network.write(sut, "Profiles\\ptr-f", { ["Address.Static"] = "multi:10.63.0.2/24",
        ["Mtu.Value"] = "dword:4000000000", ["Route.Metric"] = "dword:500" })
    rule("ptc-r3", "02:c0:00:00:03:03", "JOIN(ptr-f)")
    local d = dummy("ptr3", "02:c0:00:00:03:03")
    wait_until(function() return v4_on(d)["10.63.0.2"] ~= nil end,
        { timeout = 20, interval = 0.25, desc = "the address after the failed MTU" })
    local function mtu_failures()
        return count_logged(function(l)
            return l:find("reconcile: Mtu(" .. d .. ", 4000000000) failed:", 1, true) ~= nil end)
    end
    wait_until(function() return mtu_failures() > 0 end,
        { timeout = 20, interval = 0.5, desc = "the MTU failure in the log" })
    t:assert(is_up("ptr3"), "the link came up before it")
    t:assert_eq(mtu_of("ptr3"), 1500, "the MTU did not change")

    -- A foreign route with the kernel key of the one netd wants (same
    -- destination, metric and table, another protocol): netd's add meets
    -- EEXIST, every pass, and says nothing.
    t:assert(add_route({ dst = "0.0.0.0", prefix = 0, gateway = "10.63.0.1", oif = d, protocol = 4, metric = 500 }),
        "a foreign default route at metric 500")
    local function route_failures()
        return count_logged(function(l) return l:find("reconcile: AddRoute", 1, true) ~= nil
            and l:find("10.63.0.1", 1, true) ~= nil end)
    end
    network.reg(sut, { "set", network.KEY .. "\\Profiles\\ptr-f", "Route.Gateway", "multi:10.63.0.1" }):assert_ok()
    local before_mtu = mtu_failures()
    wait_until(function() return mtu_failures() > before_mtu end,
        { timeout = 20, interval = 0.5, desc = "a pass under the new profile" })
    pass()
    pass()
    t:assert_eq(route_failures(), 0, "EEXIST on the route add is never logged")
    local foreign = 0
    for _, r in ipairs(rtnl.routes_of(sut, d)) do
        if r.prefix == 0 and r.protocol == 4 then foreign = foreign + 1 end
    end
    t:assert_eq(foreign, 1, "the foreign route stands")
    network.delete(sut, "Rules\\Interface\\ptc-r3")
end)

-- ---------------------------------------------------------------------------
-- Probes: code behaviour the TRM does not describe (no anchor; see the
-- report). Each asserts what the TRM's account implies would happen.
-- ---------------------------------------------------------------------------

test("PROBE: a second joined interface whose default route has the same metric as eth0's still gets it",
    { tags = { "known-bug" } }, function(t)
    -- PEI-1368: netd adds routes with NLM_F_EXCL, and
    -- the kernel's IPv4 route key (table, destination, tos, metric) has no
    -- device in it, so the add meets EEXIST from eth0's route. netd reads
    -- EEXIST as "the kernel got there first" and says nothing: the
    -- route never lands and every pass retries it in silence.
    local MAC4 = "02:c0:00:00:03:04"
    local function defaults()
        local by = {}
        for _, r in ipairs(all_routes(254)) do
            if r.prefix == 0 and r.family == 4 then
                by[#by + 1] = string.format("via %s oif %s metric %d proto %d", tostring(r.gateway),
                    tostring(r.oif), r.metric, r.protocol)
            end
        end
        return table.concat(by, "; ")
    end
    local eth_default = "via 10.77.0.1 oif " .. eth.index .. " metric 100 proto 200"
    local s = network.serve_until(gw, sut, function(i) return network.bound(i) and i.gateway == "10.77.0.1" end,
        { iface = "eth0", timeout = 30 })
    t:log("before: " .. defaults())
    t:assert(s and defaults():find(eth_default, 1, true), "eth0 is bound with its default route first")
    network.write(sut, "Profiles\\ptr-g", { ["Address.Static"] = "multi:10.64.0.2/24",
        ["Route.Gateway"] = "multi:10.64.0.1" })
    rule("ptc-r4", MAC4, "JOIN(ptr-g)")
    local d = dummy("ptr4", MAC4)
    wait_until(function() return v4_on(d)["10.64.0.2"] ~= nil end,
        { timeout = 20, interval = 0.25, desc = "ptr4's address" })
    pass()
    pass()
    local after = defaults()
    t:log("after: " .. after)
    local failures = count_logged(function(l) return l:find("reconcile: AddRoute", 1, true) ~= nil
        and l:find("10.64.0.1", 1, true) ~= nil end)
    t:log("failure lines naming 10.64.0.1: " .. failures)
    network.delete(sut, "Rules\\Interface\\ptc-r4")
    t:assert(after:find(eth_default, 1, true), "eth0 keeps its default route")
    t:assert(after:find("via 10.64.0.1 oif " .. d .. " metric 100 proto 200", 1, true),
        "ptr4 has its desired default route via 10.64.0.1")
end)

test("PROBE: an IPv6 route at Route.Metric 0 lands at the profile's metric and the interface converges",
    { tags = { "known-bug" } }, function(t)
    -- PEI-1369: netd sends no RTA_PRIORITY for metric 0, the
    -- kernel files an IPv6 route without one at 1024, and netd then sees a
    -- protocol-200 route at 1024 it does not desire and one at 0 it lacks:
    -- a delete and an add on every pass, each pass's changes waking the next.
    local MAC5 = "02:c0:00:00:03:05"
    network.write(sut, "Profiles\\ptr-z", { ["Address.Static"] = "multi:fd65::2/64",
        ["Route.Gateway"] = "multi:fd65::1", ["Route.Metric"] = "dword:0" })
    rule("ptc-r5", MAC5, "JOIN(ptr-z)")
    local d = dummy("ptr5", MAC5)
    wait_until(function() return v6_on(d)["fd65::2"] ~= nil and #netd_routes_on(d) > 0 end,
        { timeout = 20, interval = 0.25, desc = "ptr5's address and a route" })
    local m = monitor_open()
    local events = monitor_drain(m, 1000, 5)
    local churn = 0
    for _, e in ipairs(events) do
        if e.kind == "route" and e.index == d and e.protocol == 200 then churn = churn + 1 end
    end
    local metrics = {}
    for _, r in ipairs(netd_routes_on(d)) do metrics[#metrics + 1] = r.dst .. " metric " .. r.metric end
    t:log(string.format("ptr5: %s; %d route announcements in up to 5 s with nothing changing",
        table.concat(metrics, ", "), churn))
    -- Stop it either way: DOWN removes the route and the address.
    rule("ptc-r5", MAC5, "DOWN")
    wait_until(function() return #netd_routes_on(d) == 0 end, { timeout = 20, interval = 0.25 })
    t:assert_eq(churn, 0, "a converged interface: no route changes")
    t:assert_eq(metrics[1], ":: metric 0", "the route carries the profile's metric")
end)
