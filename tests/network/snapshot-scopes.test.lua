-- netd §8.3 "The snapshot" — which interfaces get a scope, and in what
-- order: one per joined interface whose level is above absent, ordered
-- by the interface's metric, then its kernel index.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network), plus two dummy links (the image's dummy module):
-- dummy0 joined to a profile with a static address and a Route.Metric,
-- dummy1 IGNOREd but given an address of its own. Snapshots are read
-- through a fresh subscription each time.
--
-- Own VMs: rules, a profile and links of its own, and a cable pull.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local msgpack = require("helpers.msgpack")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local function snapshot()
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    assert(unixsock.connect(sut, fd, network.CONTROL).ret == 0, "connect")
    local p = msgpack.encode({ query = "subscribe" })
    ntfe.send(sut, fd, string.pack("<I4", #p) .. p)
    local buf = ""
    while #buf < 4 or #buf < 4 + string.unpack("<I4", buf) do
        local chunk = ntfe.recv(sut, fd, 3000, 65536)
        assert(chunk and #chunk > 0, "no snapshot")
        buf = buf .. chunk
    end
    sys.close(sut, fd)
    return msgpack.decode(buf:sub(5, 4 + string.unpack("<I4", buf)))
end

local function names(snap)
    local out = {}
    for _, s in ipairs(snap.scopes) do out[#out + 1] = s.name end
    return table.concat(out, ",")
end

local function ifindex(name)
    return tonumber((sut:read_file("/sys/class/net/" .. name .. "/ifindex"):gsub("%s+", "")))
end

--- Pump until the snapshot's scopes are `want` (names, in order).
local function scopes_become(t, want, what)
    local last
    local ok = gw:serve({ timeout = 30, until_ = function()
        last = snapshot()
        return names(last) == want
    end })
    local detail = {}
    for _, s in ipairs(last.scopes) do
        detail[#detail + 1] = string.format("%s(metric %d, index %s, %s)", s.name, s.metric,
            tostring(ifindex(s.name)), s.level)
    end
    t:log(what .. ": " .. table.concat(detail, " "))
    t:assert(ok, what .. ": scopes " .. want .. " (got " .. names(last) .. ")")
    return last
end

test("one scope per joined interface above absent, ordered by metric then kernel index",
    { spec = "netd *snapshot.scope-order-and-membership" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        network.write(sut, "Profiles\\ptstatic", { ["Address.Static"] = "multi:10.99.0.1/24",
            ["Route.Metric"] = "dword:50" })
        network.write(sut, "Rules\\Interface\\pt-join", { ["Interface.Equal"] = "multi:dummy0",
            Priority = "dword:20", Actions = "multi:JOIN(ptstatic)" })
        network.write(sut, "Rules\\Interface\\pt-ignore", { ["Interface.Equal"] = "multi:dummy1",
            Priority = "dword:20", Actions = "multi:IGNORE" })
        wait_until(function() return network.logged(sut, "interface layer: 3 rule tree(s), 2 profile(s)") end,
            { timeout = 15, interval = 0.3, desc = "the rules taken" })
        local mp = sut:run("modprobe dummy numdummies=2")
        t:assert_eq(mp.exit_code, 0, "dummy loads: " .. mp.stderr)

        -- dummy1 is not joined, but holds an address and is up: it would
        -- be addressed, and still gets no scope.
        wait_until(function()
            local i = network.iface(network.status(sut), "dummy1")
            return i ~= nil and i.verdict == "IGNORE"
        end, { timeout = 15, interval = 0.25, desc = "dummy1 IGNOREd" })
        assert(ntfe.if_up(sut, "dummy1"))
        t:assert(rtnl.add_address(sut, ifindex("dummy1"), "10.98.0.1", { prefix = 24 }), "dummy1's address")
        wait_until(function() return network.iface(network.status(sut), "dummy1").level == "addressed" end,
            { timeout = 15, interval = 0.25, desc = "dummy1 addressed" })

        -- dummy0 (metric 50) before eth0 (metric 100), though its index
        -- is higher.
        t:assert(ifindex("dummy0") > ifindex("eth0"), "dummy0's index is above eth0's")
        local snap = scopes_become(t, "dummy0,eth0", "metric 50 vs 100")
        t:assert_eq(snap.scopes[1].metric, 50, "dummy0's metric is its Route.Metric")
        t:assert_eq(snap.scopes[1].level, "addressed", "dummy0 is addressed (a scope needs only above absent)")

        -- Equal metrics: kernel index decides.
        network.reg(sut, { "set", network.KEY .. "\\Profiles\\ptstatic", "Route.Metric", "dword:100" }):assert_ok()
        scopes_become(t, "eth0,dummy0", "metric 100 vs 100")

        -- A joined interface at absent has no scope.
        local nic = lan:nic(sut)
        nic:disconnect()
        snap = scopes_become(t, "dummy0", "eth0's cable pulled")
        local e = network.iface(network.status(sut), "eth0")
        t:assert_eq(e.level, "absent", "eth0 is absent")
        t:assert_eq(e.verdict, "JOIN", "and still joined")
        nic:reconnect()
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "bound again")
        scopes_become(t, "eth0,dummy0", "cable back")
    end)
