-- netd §8.2 "Publishing it" — the notify half: the machine level sent as
-- `LEVEL=<level>` on the socket `NOTIFY_SOCKET` names, at the first
-- publish (before `READY=1`) and then on every change and only on a
-- change. The log and registry halves are in readiness.test.lua.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). peinit does not show what a service sent it, so the
-- test stops the netd service and runs the same binary from the agent
-- with `NOTIFY_SOCKET` naming a datagram socket the test bound, reads
-- every datagram, and compares them with the `machine readiness is …`
-- lines that process wrote to its stderr. The service is started again
-- at the end.
--
-- Own VMs: the service is stopped for the length of the test. Whether
-- peinit gates dependents on the level is peinit's testset, not this one.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local unixsock = require("helpers.unixsock")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local NOTIFY = "/run/pt-netd-notify.sock"

local function list_text(l) return "[" .. table.concat(l or {}, ", ") .. "]" end

test("LEVEL=<level> goes to NOTIFY_SOCKET at the first publish, before READY=1, and afterwards on each change and only then",
    { spec = "netd *readiness.publish-on-change" }, function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "the service bound")
        sut:run("svctl stop netd"):assert_ok()
        wait_until(function() return network.netd_pid(sut) == nil end,
            { timeout = 15, interval = 0.25, desc = "the service stopped" })

        local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.DGRAM))
        local b = unixsock.bind(sut, fd, NOTIFY)
        t:assert_eq(b.ret, 0, "bound the notify socket")
        local got = {}
        local function drain(ms)
            while true do
                local d = ntfe.recv(sut, fd, ms or 50, 512)
                if not d then return end
                got[#got + 1] = d
            end
        end

        local proc = sut:run_async("/usr/sbin/netd", { env = { NOTIFY_SOCKET = NOTIFY } })
        local ok, err = pcall(function()
            t:assert(network.serve_until(gw, sut, function(i) drain(20); return network.bound(i) end,
                { iface = "eth0", timeout = 60 }), "the hand-run netd bound")
            drain(1500)
            t:log("first datagrams: " .. list_text(got))
            t:assert(#got >= 3, "a level, READY=1, and the level after binding")
            t:assert(got[1]:match("^LEVEL=%a+$") ~= nil, "the first datagram is a LEVEL= (sent before READY=1)")
            t:assert_eq(got[2], "READY=1", "READY=1 follows the first level")
            t:assert_eq(got[#got], "LEVEL=routed", "the latest level is routed")

            -- Passes that change nothing send nothing.
            local n = #got
            t:assert(network.call(sut, { query = "reconcile" }).ok, "a full pass")
            t:assert(network.call(sut, { query = "reconcile" }).ok, "another")
            drain(2000)
            t:assert_eq(#got, n, "no datagram without a change")

            -- Changes: the cable out, and back.
            local nic = lan:nic(sut)
            nic:disconnect()
            wait_until(function() drain(20); return got[#got] == "LEVEL=absent" end,
                { timeout = 20, interval = 0.25, desc = "LEVEL=absent" })
            nic:reconnect()
            t:assert(network.serve_until(gw, sut, function(i) drain(20); return network.bound(i) end,
                { iface = "eth0", timeout = 60 }), "bound again")
            drain(1500)
            t:log("all datagrams: " .. list_text(got))
            t:assert_eq(got[#got], "LEVEL=routed", "routed again")
        end)

        proc:kill("term")
        local res = proc:wait(10)
        sys.close(sut, fd)
        sut:run("rm -f " .. NOTIFY)
        sut:run("svctl start netd")
        wait_until(function()
            local s = network.call(sut, { query = "status" })
            return s ~= nil and s.ok == true
        end, { timeout = 30, interval = 0.25, desc = "the service back" })
        if not ok then error(err, 0) end

        local logged = {}
        for lvl in tostring(res.stderr):gmatch("machine readiness is (%a+)") do logged[#logged + 1] = lvl end
        local levels = {}
        for _, d in ipairs(got) do
            local lvl = d:match("^LEVEL=(%a+)$")
            if lvl then levels[#levels + 1] = lvl
            else t:assert_eq(d, "READY=1", "the only other datagram is READY=1") end
        end
        t:log("LEVEL= sent: " .. list_text(levels))
        t:log("levels logged: " .. list_text(logged))
        t:assert_eq(table.concat(levels, " "), table.concat(logged, " "),
            "one LEVEL= for every 'machine readiness is' line, in the same order")
        for k = 2, #levels do
            t:assert(levels[k] ~= levels[k - 1], "LEVEL=" .. levels[k] .. " sent twice in a row")
        end
        local text = table.concat(levels, " ")
        t:assert(text:find("routed absent", 1, true) ~= nil, "the cable pull was sent as absent")
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "the service bound again")
    end)
