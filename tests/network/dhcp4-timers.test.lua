-- netd §5.2 — timers: the lease boundaries T1, T2 and the lease's end,
-- the 60 s floor on renewal retransmission, and how Requesting and
-- Rebooting give up.
--
-- Harness: the scripted gateway and one whole Peios machine on a private
-- bridge. Short leases come from re-arming the gateway and taking the new
-- lease with the operator's `renew`; giving up is provoked by a gateway
-- that answers some messages and ignores others.
--
-- Two clocks are used, and neither is trusted alone. The gateway stamps
-- each frame with the whole second it read it (`at`), which is accurate
-- to about a second while the test is pumping. The client stamps each
-- message with `secs`, whole seconds since it started, which is exact on
-- the client's side however late the frame is read. Gaps are asserted on
-- `secs` with ±2 s (±1 s of jitter, ±1 s of flooring) and boundaries on
-- `at` against the moment the gateway sent the ACK, with ±2 s.
--
-- Own VMs: leases are expired and clients made to give up; the tests run
-- in order on one pair and each leaves the machine bound.
--
-- Not separately observable: "a boundary is acted on before any
-- retransmission due at the same moment". With the 60 s floor a
-- retransmission never falls due on a boundary in practice; the tests
-- show each boundary acted on alone, with no retransmission beside it.
-- The 64 s backoff ceiling and the "nobody answered" report have files of
-- their own (dhcp4-timers-backoff, dhcp4-timers-nooffer), as does a
-- renewal retransmission at half the remaining time (dhcp4-timers-retransmit).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local D = gateway.DHCP
local LEASED = "10.77.0.50"

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function await(pred, timeout, desc)
    local found
    gw:serve({ timeout = timeout or 30, until_ = function()
        for _, m in ipairs(gw:dhcp_messages()) do
            if pred(m) then found = m; return true end
        end
        return false
    end })
    assert(found, "no message on the wire: " .. (desc or "?"))
    return found
end

local function bound(timeout)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = timeout or 60 })
    assert(s, "netd did not bind a lease")
    return network.iface(s, "eth0")
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(err or (r and r.error)))
end

local function near(t, got, want, tol, what)
    t:assert(math.abs(got - want) <= tol,
        string.format("%s: %s, expected %s ± %s", what, tostring(got), tostring(want), tostring(tol)))
end

local function describe(list)
    local out = {}
    for _, m in ipairs(list) do
        out[#out + 1] = string.format("%s(xid %08x secs %d at %d %s%s)", gateway.DHCP_NAME[m.type], m.xid,
            m.secs, m.at, m.frame.dst_ip, m.opt[50] and (" 50=" .. gateway.ip4_text(m.opt[50])) or "")
    end
    return table.concat(out, " ")
end

local function nak(m)
    return { op = 2, xid = m.xid, flags = m.flags, chaddr = m.chaddr, yiaddr = "0.0.0.0",
             siaddr = gw.addr, options = { { 53, string.char(D.NAK) }, { 54, gateway.ip4(gw.addr) } } }
end

-- ---------------------------------------------------------------------------
-- Lease boundaries
-- ---------------------------------------------------------------------------

test("T1 renews by unicast, T2 rebinds by broadcast, the lease's end loses it — each timed from the ACK, one REQUEST per state",
    { spec = "netd *dhcp4-timers.lease-boundaries netd *dhcp4-timers.renewal-retransmit" },
    function(t)
        bound()
        -- Take a 20 s lease (T1 10, T2 17) and then answer nothing.
        local acked_at
        local answered = false
        gw:dhcp({ pool = { LEASED }, lease = 20, on = {
            renew = function()
                if answered then return false end
                answered = true
                acked_at = gw:now()
                return nil
            end,
            discover = function() return false end,
        } })
        gw:forget()
        renew()
        local s = network.serve_until(gw, sut, function(i) return i.lease == nil end,
            { iface = true, timeout = 40 })
        t:assert(s, "the lease ran out")
        await(function(m) return m.type == D.DISCOVER end, 5, "the DISCOVER after the loss")
        local msgs = gw:dhcp_messages()
        t:log("ACK at " .. tostring(acked_at) .. ": " .. describe(msgs))
        local renewing, rebinding, discover = {}, {}, nil
        for k, m in ipairs(msgs) do
            if k > 1 and m.type == D.REQUEST and m.frame.dst_ip == gw.addr then renewing[#renewing + 1] = m end
            if m.type == D.REQUEST and m.frame.dst_ip == "255.255.255.255" then rebinding[#rebinding + 1] = m end
            if m.type == D.DISCOVER then discover = discover or m end
        end
        t:assert_eq(#renewing, 1, "exactly one Renewing REQUEST (the next is 60 s away, past T2)")
        t:assert_eq(#rebinding, 1, "exactly one Rebinding REQUEST (the next is 60 s away, past the end)")
        t:assert(discover, "a DISCOVER once the lease ended")
        near(t, renewing[1].at - acked_at, 10, 2, "T1 after the ACK")
        near(t, rebinding[1].at - acked_at, 17, 2, "T2 after the ACK")
        near(t, discover.at - acked_at, 20, 2, "the lease's end after the ACK")
        -- The client's own clock agrees, independent of read lag.
        near(t, rebinding[1].secs - renewing[1].secs, 7, 1, "T2 − T1 by secs")
        near(t, discover.secs - rebinding[1].secs, 3, 1, "end − T2 by secs")
        t:assert_eq(renewing[1].ciaddr, LEASED, "Renewing REQUEST for the lease")
        t:assert_eq(rebinding[1].ciaddr, LEASED, "Rebinding REQUEST for the lease")
    end)

test("an ACK while renewing starts the lease's clock again",
    { spec = "netd *dhcp4-timers.renewal-retransmit netd *dhcp4-timers.lease-boundaries" },
    function(t)
        -- Selecting from the last test; bind a 20 s lease and let T1 come.
        local acks = {}
        gw:dhcp({ pool = { LEASED }, lease = 20, on = {
            request = function() acks[#acks + 1] = gw:now() end,
            renew = function() acks[#acks + 1] = gw:now() end,
        } })
        gw:forget()
        bound()
        -- Two renewals: at T1 of the first lease, then at T1 of the renewed one.
        local renewals = {}
        local ok = gw:serve({ timeout = 30, until_ = function()
            renewals = {}
            for _, m in ipairs(gw:dhcp_messages(D.REQUEST)) do
                if m.ciaddr == LEASED then renewals[#renewals + 1] = m end
            end
            return #renewals >= 2
        end })
        t:log("ACKs at " .. table.concat(acks, ",") .. "; " .. describe(gw:dhcp_messages()))
        t:assert(ok, "two renewals")
        local s = network.status(sut)
        local i = network.iface(s, "eth0")
        near(t, renewals[1].at - acks[1], 10, 2, "first renewal at T1 of the first ACK")
        near(t, renewals[2].at - acks[2], 10, 2, "second renewal at T1 of the renewal's ACK")
        near(t, renewals[2].secs - renewals[1].secs, 10, 1, "ten client seconds apart")
        t:assert_eq(i.lease.state, "bound", "bound after the renewal")
        -- Back to a long lease.
        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        renew()
        assert(network.serve_until(gw, sut, function(x)
            return network.bound(x) and x.lease.expires_in > 100 end, { iface = true, timeout = 20 }))
    end)

-- ---------------------------------------------------------------------------
-- Giving up
-- ---------------------------------------------------------------------------

test("Rebooting sends two REQUESTs about 4 s apart, then about 12 s in discovers afresh without option 50",
    { spec = "netd *dhcp4-timers.give-up-schedule netd *dhcp4-timers.backoff" },
    function(t)
        bound()
        gw:dhcp({ silent = true })
        nic:disconnect()
        assert(network.serve_until(gw, sut, function(i) return i.carrier == false end,
            { iface = true, timeout = 20 }), "carrier did not drop")
        gw:forget()
        nic:reconnect()
        local d = await(function(m) return m.type == D.DISCOVER end, 30, "the DISCOVER after the reboot gave up")
        local msgs = gw:dhcp_messages()
        t:log(describe(msgs))
        local reqs = {}
        for _, m in ipairs(msgs) do
            if m.type == D.REQUEST then reqs[#reqs + 1] = m end
            if m == d then break end
        end
        t:assert_eq(#reqs, 2, "two REQUESTs before giving up")
        t:assert_eq(msgs[1].type, D.REQUEST, "it opened with a REQUEST")
        for _, r in ipairs(reqs) do
            t:assert_eq(gateway.ip4_text(r.opt[50] or "\0\0\0\0"), LEASED, "INIT-REBOOT for the previous address")
            t:assert_eq(r.opt[54], nil, "no server identifier")
            t:assert_eq(r.xid, reqs[1].xid, "one transaction")
        end
        near(t, reqs[2].secs - reqs[1].secs, 4, 2, "the second REQUEST after the 4 s backoff")
        near(t, d.secs - reqs[2].secs, 8, 2, "the DISCOVER at the next timer, 8 s after the second")
        near(t, d.secs - reqs[1].secs, 12, 3, "about 12 s in")
        t:assert_eq(d.opt[50], nil, "the DISCOVER has no option 50")
        t:assert(d.xid ~= reqs[1].xid, "Selecting draws a new xid")
        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        bound()
    end)

test("Requesting sends four REQUESTs at about 0, 4, 12 and 28 s, then about 60 s in discovers with a new xid",
    { spec = "netd *dhcp4-timers.give-up-schedule netd *dhcp4-timers.backoff" },
    function(t)
        bound()
        -- NAK the operator's renew (the lease is lost: Selecting), offer
        -- on DISCOVER, and ignore every REQUEST that follows the offer.
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
            renew = function(m) return nak(m) end,
            request = function() return false end,
        } })
        gw:forget()
        renew()
        -- The first DISCOVER of a fresh Selecting, its REQUESTs, and the
        -- DISCOVER that ends Requesting.
        local first, reqs, after
        local ok = gw:serve({ timeout = 80, until_ = function()
            first, reqs, after = nil, {}, nil
            for _, m in ipairs(gw:dhcp_messages()) do
                if m.type == D.DISCOVER and not first then first = m
                elseif m.type == D.REQUEST and m.opt[54] then reqs[#reqs + 1] = m
                elseif m.type == D.DISCOVER and #reqs > 0 then after = m; return true end
            end
            return false
        end })
        t:log(describe(gw:dhcp_messages()))
        t:assert(ok, "Requesting gave up and discovered again")
        t:assert_eq(#reqs, 4, "four REQUESTs for the offer")
        for _, r in ipairs(reqs) do
            t:assert_eq(r.xid, first.xid, "Requesting keeps the Selecting xid")
            t:assert_eq(gateway.ip4_text(r.opt[50]), LEASED, "each for the offered address")
        end
        -- Each gap is one backoff (4, 8, 16, 32: it restarted at 4 on
        -- entering Requesting) ±1 s jitter, ±1 s for flooring `secs`; the
        -- totals carry every gap's jitter.
        local r0 = reqs[1].secs
        near(t, reqs[2].secs - reqs[1].secs, 4, 2, "second REQUEST 4 s after the first")
        near(t, reqs[3].secs - reqs[2].secs, 8, 2, "third 8 s after the second")
        near(t, reqs[4].secs - reqs[3].secs, 16, 2, "fourth 16 s after the third")
        near(t, after.secs - reqs[4].secs, 32, 2, "the DISCOVER at the next timer, 32 s after the fourth")
        near(t, reqs[4].secs - r0, 28, 4, "the fourth about 28 s in")
        near(t, after.secs - r0, 60, 5, "the new DISCOVER about 60 s in")
        t:assert(after.xid ~= first.xid, "with a new transaction id")
        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        bound()
    end)
