-- netd TRM §5.6 — what the DHCPv4 packet socket lets through: its classic
-- BPF filter passes only an IPv4 UDP datagram, not a fragment, addressed
-- to port 68.
--
-- The gateway's DHCP server answers no DISCOVER here; the test answers by
-- hand, with OFFER frames built byte by byte, so each one can be wrong in
-- exactly one way. Every OFFER is a correct answer to the DISCOVER it
-- follows (its xid, the machine's chaddr, a server identifier, a lease),
-- so the only reason netd could have for ignoring it is the one under
-- test. The proof that an OFFER was ignored is not a quiet interval but
-- the client's next DISCOVER with the same xid: a client that had taken
-- the OFFER would have sent a REQUEST instead and left Selecting. The
-- positive control is the same OFFER, sent correctly, drawing a REQUEST.
-- REQUESTs are NAKed, which puts the client straight back in Selecting
-- with a new DISCOVER.
--
-- Its own pair: the client must be in Selecting from its first DISCOVER,
-- and stay there, which no shared file can promise.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local ntfe = require("helpers.ntfe")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({
    pool = { "10.77.0.50" }, lease = 3600,
    on = {
        discover = function() return false end,
        request = function(m)
            return { op = 2, xid = m.xid, flags = m.flags, chaddr = m.chaddr, yiaddr = "0.0.0.0",
                     options = { { 53, string.char(gateway.DHCP.NAK) }, { 54, gateway.ip4("10.77.0.1") } } }
        end,
    },
})
local sut = network.boot({ bridges = { lan }, gateway = gw })

--- A correct OFFER for DISCOVER `m`, as UDP payload.
local function offer_for(m)
    return gateway.dhcp_encode({
        op = 2, xid = m.xid, flags = m.flags, chaddr = m.chaddr,
        yiaddr = "10.77.0.50", siaddr = "10.77.0.1",
        options = {
            { 53, string.char(gateway.DHCP.OFFER) }, { 54, gateway.ip4("10.77.0.1") },
            { 51, gateway.opt.u32(3600) }, { 1, "\255\255\255\0" }, { 3, gateway.ip4("10.77.0.1") },
        },
    })
end

--- Send `payload` from 10.77.0.1:67 to the broadcast address and `dport`,
--- with IPv4 flags+fragment word `frag`.
local function send_offer(payload, dport, frag)
    local seg = ntfe.udp("10.77.0.1", "255.255.255.255", 67, dport, payload)
    gw:send(ntfe.eth(ntfe.MAC_BROADCAST, gw.mac, ntfe.ETH_P.IP)
        .. ntfe.ipv4("10.77.0.1", "255.255.255.255", 17, #seg, { frag = frag }) .. seg)
end

local function discovers(xid)
    local out = {}
    for _, m in ipairs(gw:dhcp_messages(gateway.DHCP.DISCOVER)) do
        if not xid or m.xid == xid then out[#out + 1] = m end
    end
    return out
end

local function requests(xid)
    local out = {}
    for _, m in ipairs(gw:dhcp_messages(gateway.DHCP.REQUEST)) do
        if not xid or m.xid == xid then out[#out + 1] = m end
    end
    return out
end

--- Answer the newest DISCOVER of `xid` with an OFFER sent to `dport` with
--- fragment word `frag`, then pump until either the client's next DISCOVER
--- of that xid or a REQUEST arrives. Returns "ignored" or "taken".
local function try_offer(t, xid, dport, frag, what)
    local d = discovers(xid)
    local n = #d
    send_offer(offer_for(d[n]), dport, frag)
    local ok = gw:serve({ timeout = 40, until_ = function()
        return #discovers(xid) > n or #requests(xid) > 0
    end })
    t:assert(ok, what .. ": the client did something after the OFFER")
    local verdict = #requests(xid) > 0 and "taken" or "ignored"
    t:log(string.format("%s (dport %d, frag word 0x%04x): %s", what, dport, frag, verdict))
    return verdict
end

local IP_MF = 0x2000

local second_xid

test("the packet socket passes only an unfragmented IPv4 UDP datagram to port 68",
    { spec = "netd *dhcp4-sockets.packet-socket" }, function(t)
        t:assert(gw:serve({ timeout = 30, until_ = function() return #discovers() >= 1 end }),
            "the client's first DISCOVER arrives")
        local xid = discovers()[1].xid
        t:assert_eq(#requests(), 0, "no REQUEST yet: the server is silent")

        t:assert_eq(try_offer(t, xid, 68, 1, "a non-first fragment (offset 8 bytes)"), "ignored",
            "an OFFER in a datagram with a non-zero fragment offset is not read")
        t:assert_eq(try_offer(t, xid, 69, 0, "an OFFER to port 69"), "ignored",
            "an OFFER addressed to another port is not read")
        -- The control: the same OFFER, sent correctly, is taken.
        t:assert_eq(try_offer(t, xid, 68, 0, "a correct OFFER"), "taken",
            "the same OFFER to port 68, unfragmented, is read and answered with a REQUEST")
        local r = requests(xid)[1]
        t:assert_eq(gateway.ip4_text(r.opt[50]), "10.77.0.50", "the REQUEST asks for the offered address")

        -- The REQUEST is NAKed: the client is back in Selecting.
        t:assert(gw:serve({ timeout = 10, until_ = function()
            local d = discovers()
            return d[#d].xid ~= xid
        end }), "after the NAK the client discovers again with a new xid")
        local d = discovers()
        second_xid = d[#d].xid
    end)

-- TRM-first-fragment: the filter tests only the fragment-offset bits
-- (`jset #0x1fff` on bytes 6-7 of the IPv4 header), so a first fragment
-- (more-fragments set, offset 0) passes it, and the re-check after the
-- read does not look at fragmentation at all: netd decodes and acts on
-- the OFFER in it.
test("a first fragment (more-fragments set, offset 0) is not passed either",
    { spec = "netd *dhcp4-sockets.packet-socket", tags = { "known-bug" } }, function(t)
        t:assert(second_xid, "the first test left the client in Selecting")
        t:assert_eq(try_offer(t, second_xid, 68, IP_MF, "a first fragment (MF set, offset 0)"), "ignored",
            "an OFFER in a datagram with more-fragments set is not read")
    end)
