-- netd §5.2 — retransmission while acquiring: Selecting's backoff from
-- 4 s, doubling to the 64 s ceiling, with ±1 s of jitter, and never
-- giving up.
--
-- Harness: the scripted gateway, silent from the start (it records and
-- answers nothing), and one whole Peios machine. Its first client starts
-- during boot with no previous address, so it is in Selecting from its
-- first message, and stays there.
--
-- Own VMs, and longer than the usual three minutes: the ceiling shows only
-- at the sixth gap (64 s where an uncapped doubling would give 128), which
-- is about 188 s into Selecting. That cannot be split or shortened: every
-- timer is the client's own, on its monotonic clock.
--
-- Gaps are read from `secs` (whole seconds since the client started),
-- which the client stamps itself, so the DISCOVERs sent while the machine
-- was still booting, before the gateway first read its socket, are timed
-- as exactly as the rest. Each gap is the backoff ±1 s of jitter, ±1 s
-- for flooring.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ silent = true })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local D = gateway.DHCP

test("Selecting retransmits after 4, 8, 16, 32, 64 and then 64 s again, on one xid, and never gives up",
    { spec = "netd *dhcp4-timers.backoff netd *dhcp4-timers.give-up-schedule" },
    function(t)
        local ds
        local ok = gw:serve({ timeout = 210, until_ = function()
            ds = gw:dhcp_messages(D.DISCOVER)
            return #ds >= 7
        end })
        local secs = {}
        for _, m in ipairs(ds) do secs[#secs + 1] = m.secs end
        t:log("DISCOVER secs: " .. table.concat(secs, ","))
        t:assert(ok, "seven DISCOVERs (the client never stopped)")
        t:assert_eq(#gw:dhcp_messages(), #ds, "nothing but DISCOVERs: Selecting never gives up")
        t:assert_eq(ds[1].secs, 0, "the first at the client's start")
        local want = { 4, 8, 16, 32, 64, 64 }
        for k = 1, 6 do
            local gap = ds[k + 1].secs - ds[k].secs
            t:assert(math.abs(gap - want[k]) <= 2,
                string.format("gap %d is %d s, expected %d ± 2", k, gap, want[k]))
        end
        for _, m in ipairs(ds) do
            t:assert_eq(m.xid, ds[1].xid, "one transaction id throughout")
        end
        local i = network.iface(network.status(sut), "eth0")
        t:assert_eq(i.lease, nil, "no lease")
    end)
