-- netd §5.2 "Retransmission while renewing and rebinding": the next
-- REQUEST after half the time remaining to the state's next boundary,
-- when that is more than the 60 s floor.
--
-- Harness: the scripted gateway and one whole Peios machine on a private
-- bridge. The operator's `renew` is answered with a 150 s lease whose T1
-- is 4 s and T2 144 s; the gateway then ignores the client's renewal at
-- T1, so the client retransmits after half of the 140 s left to T2, 70 s
-- later, where the floor alone would give 60 s. (The floor itself, a
-- short lease's boundary arriving before any second REQUEST, is in
-- dhcp4-timers.)
--
-- Own VMs, and a file to itself because the one observation takes about
-- 75 s of waiting.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local D = gateway.DHCP
local LEASED = "10.77.0.50"
local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))

local function ack(m, lease, t1, t2)
    local opts = { { 53, string.char(D.ACK) }, { 54, gateway.ip4(gw.addr) }, { 51, gateway.opt.u32(lease) } }
    if t1 then opts[#opts + 1] = { 58, gateway.opt.u32(t1) } end
    if t2 then opts[#opts + 1] = { 59, gateway.opt.u32(t2) } end
    opts[#opts + 1] = { 1, gateway.ip4("255.255.255.0") }
    opts[#opts + 1] = { 3, gateway.ip4(gw.addr) }
    return gateway.dhcp_encode({ op = 2, xid = m.xid, flags = m.flags, chaddr = MAC, yiaddr = LEASED,
        siaddr = gw.addr, options = opts })
end

test("a renewing client retransmits after half the time left to T2 when that exceeds 60 s, on the same xid",
    { spec = "netd *dhcp4-timers.renewal-retransmit netd *dhcp4-client.transaction-ids" },
    function(t)
        assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "bound")
        local caught = {}
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
            renew = function(m)
                local f = gw.seen[#gw.seen]
                caught[#caught + 1] = { m = m, at = f.at, dst = f.dst_ip }
                return false
            end,
        } })
        local r, err = network.call(sut, { query = "renew", interface = "eth0" })
        assert(r and r.ok, "renew: " .. tostring(err))
        assert(gw:serve({ timeout = 10, until_ = function() return #caught >= 1 end }), "no renewing REQUEST")
        local sent = gw:now()
        gw:send_udp4(MAC, LEASED, 67, 68, ack(caught[1].m, 150, 4, 144))
        local ok = gw:serve({ timeout = 95, until_ = function() return #caught >= 3 end })
        local times = {}
        for k, c in ipairs(caught) do
            times[#times + 1] = string.format("#%d at %+d secs %d xid %08x to %s", k, c.at - sent, c.m.secs, c.m.xid, c.dst)
        end
        t:log("ACK at " .. sent .. "; " .. table.concat(times, "; "))
        t:assert(ok, "a renewal at T1 and its retransmission")
        local t1, again = caught[2], caught[3]
        t:assert(math.abs((t1.at - sent) - 4) <= 2, "the renewal at T1, 4 s after the ACK")
        local gap = again.m.secs - t1.m.secs
        t:assert(math.abs(gap - 70) <= 1, string.format("retransmitted %d s later by the client's clock, expected 70 (half of 140) ± 1", gap))
        t:assert(math.abs((again.at - t1.at) - 70) <= 2, "and by the gateway's")
        t:assert_eq(again.m.xid, t1.m.xid, "a retransmission keeps the Renewing xid")
        t:assert_eq(again.dst, gw.addr, "still unicast to the server")
        t:assert_eq(again.m.ciaddr, LEASED, "for the lease")
        gw:send_udp4(MAC, LEASED, 67, 68, ack(again.m, 3600))
        assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and i.lease.expires_in > 100 end, { iface = true, timeout = 10 }), "bound again")
    end)
