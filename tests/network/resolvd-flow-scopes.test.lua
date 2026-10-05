-- resolvd §4.1 — each candidate is routed on its own, so the expansions
-- of one single label can go to different scopes, and each has its own
-- attempt budget.
--
-- Two scopes need two interfaces, and a file may have only two VMs, so
-- the gateway VM is attached to both bridges and a second gateway object
-- drives its second NIC (the pattern of hostname-order.test.lua). Each
-- network leases its own search domain (option 15: `one.test` and
-- `two.test`) and its own DNS server. Both servers are addresses of the
-- gateway's first NIC, 10.77.0.1 and 10.77.0.2: the machine reaches
-- 10.77.0.2 through its first interface by subnet, the one DNS server
-- (helpers.dns) hears both, and the address each question was sent to
-- says which scope it was routed to.
--
-- Which machine interface sits on which network is read from resolvd's
-- status (each scope's domains and servers), and the order of candidates
-- from the scope order, so the test does not depend on the order the
-- NICs enumerate in.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local lan2 = network.bridge("wan")
local gw = gateway.boot({ bridges = { lan, lan2 } })

--- A second gateway object for the gateway VM's second NIC.
local function second_gateway(g, ifname, addr)
    assert(ntfe.if_addr(g.vm, ifname, addr, 24))
    local o = setmetatable({
        vm = g.vm, ifname = ifname, addr = addr, prefix = 24, addr6 = "fd78::1",
        seen = {}, handlers = {}, t0 = g.t0,
    }, getmetatable(g))
    o.ifindex = assert(ntfe.if_index(g.vm, ifname))
    o.mac = assert(ntfe.if_hwaddr(g.vm, ifname))
    o.ll = gateway.link_local(o.mac)
    o.ps = assert(ntfe.packet_socket(g.vm, ifname))
    return o
end

local gw2 = second_gateway(gw, "eth1", "10.78.0.1")
-- A second address beside the first (ntfe.if_addr would replace it).
assert(rtnl.add_address(gw.vm, gw.ifindex, "10.77.0.2", { prefix = 24 }), "gateway address 10.77.0.2")
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = { "10.77.0.1" }, options = { { 15, "one.test" } } })
gw2:dhcp({ pool = { "10.78.0.50" }, lease = 3600, dns = { "10.77.0.2" }, options = { { 15, "two.test" } } })

local behave, counts = {}, {}
local function key(name) return (name:lower():gsub("%.$", "")) end
dns.serve(gw, {
    zone = {
        ["x.two.test"] = { { type = "A", ttl = 60, data = "10.77.0.70" } },
    },
    soa = { name = "test", data = { minimum = 30 } },
    on = function(q, default, ctx)
        local qn = q.questions[1]
        if not qn then return nil end
        local k = key(qn.name)
        counts[k] = (counts[k] or 0) + 1
        local b = behave[k]
        if b then return b(counts[k], q, default, ctx) end
    end,
})
local sut = network.boot({ bridges = { lan, lan2 }, gateways = { gw, gw2 } })

local SOCK = "/run/resolvd/resolv.sock"

local function serve_both(timeout, pred)
    local deadline = os.time() + timeout
    repeat
        gw:pump(50)
        gw2:pump(50)
        if pred() then return true end
    until os.time() > deadline
    return pred() and true or false
end

local function ask(req, timeout)
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
    if not poll() then serve_both(timeout or 30, poll) end
    sys.close(sut, fd)
    assert(reply, "resolvd gave no reply to " .. tostring(req.name))
    return reply
end

local function rstatus()
    local s, err = network.call(sut, { query = "status" }, { path = SOCK })
    assert(s and s.ok, "resolvd status: " .. tostring(err))
    return s
end

--- The two scopes, in resolvd's candidate order (metric, then snapshot
--- order): each {interface, server, domain}.
local function scopes()
    local list = {}
    for i, sc in ipairs(rstatus().scopes or {}) do
        list[#list + 1] = { interface = sc.interface, server = sc.servers[1], domain = sc.domains[1],
            metric = sc.metric, at = i }
    end
    table.sort(list, function(a, b)
        if a.metric ~= b.metric then return a.metric < b.metric end
        return a.at < b.at
    end)
    return list
end

local function asked(name)
    return dns.queries(gw, function(q)
        local qn = q.msg and q.msg.questions[1]
        return qn ~= nil and dns.same_name(qn.name, name)
    end)
end

local function servers_asked(name)
    local out = {}
    for _, q in ipairs(asked(name)) do out[#out + 1] = q.server end
    return table.concat(out, " ")
end

test("each candidate of a single label is routed on its own: each search domain's expansion goes to its own scope, with its own attempt budget",
    { spec = "resolvd *engine-flow.each-candidate-routed-separately" }, function(t)
        local ok = serve_both(60, function()
            local s = rstatus()
            local n = 0
            for _, sc in ipairs(s.scopes or {}) do
                if #sc.servers == 1 and #sc.domains == 1 then n = n + 1 end
            end
            return n == 2
        end)
        t:assert(ok, "resolvd has two scopes, each with a server and a domain")
        local sc = scopes()
        for _, x in ipairs(sc) do
            t:log(string.format("%s: server %s, domain %s, metric %d", x.interface, x.server, x.domain, x.metric))
        end
        t:assert(sc[1].server ~= sc[2].server and sc[1].domain ~= sc[2].domain, "two different scopes")

        -- Both candidates NXDOMAIN: each is asked of its own scope's server.
        local r = ask({ query = "resolve", name = "ghost", type = dns.TYPE.A })
        t:log(string.format("ghost: %s from %s on %s", tostring(r.outcome), tostring(r.server), tostring(r.interface)))
        for _, x in ipairs(sc) do
            local name = "ghost." .. x.domain
            t:log(name .. " asked of " .. servers_asked(name))
            t:assert_eq(servers_asked(name), x.server, name .. " went to its own scope's server only")
        end
        t:assert_eq(r.outcome, "notfound", "ghost is notfound")
        t:assert_eq(r.interface, sc[2].interface, "reported on the last candidate's scope's interface")
        t:assert_eq(r.server, sc[2].server, "by the last candidate's scope's server")

        -- Each candidate gets three attempts: the first is silent twice
        -- and NXDOMAIN at its third; the second is silent twice and
        -- answered at its third. A shared budget would be spent by then.
        local first, second = "z." .. sc[1].domain, "z." .. sc[2].domain
        behave[first] = function(n) if n < 3 then return false end end
        behave[second] = function(n, q)
            if n < 3 then return false end
            return dns.answer(q, { [second] = { { type = "A", ttl = 60, data = "10.77.0.71" } } })
        end
        r = ask({ query = "resolve", name = "z", type = dns.TYPE.A }, 40)
        t:log(string.format("z: %s from %s on %s", tostring(r.outcome), tostring(r.server), tostring(r.interface)))
        t:log(first .. " asked of: " .. servers_asked(first) .. "; " .. second .. " asked of: " .. servers_asked(second))
        t:assert_eq(servers_asked(first), table.concat({ sc[1].server, sc[1].server, sc[1].server }, " "),
            "the first candidate: three attempts, to its scope's server")
        t:assert_eq(servers_asked(second), table.concat({ sc[2].server, sc[2].server, sc[2].server }, " "),
            "the second candidate: three more, to its own scope's server")
        t:assert_eq(r.outcome, "found", "found at the second candidate's third attempt")
        t:assert_eq(r.records and r.records[1] and r.records[1].text, "10.77.0.71", "with its address")
        t:assert_eq(r.interface, sc[2].interface, "on the second scope's interface")
    end)
