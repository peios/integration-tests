-- netd §5.1 — the DHCPv4 client: when one runs, what it is configured
-- with, its states, and exactly what each message it sends carries.
--
-- Harness: the scripted gateway (helpers.gateway) on its own bridge, and
-- one whole Peios machine joined to it by the shipped baseline. Every
-- message netd sends is read off the wire by the gateway and decoded, so
-- the assertions are on the frames themselves: header fields, the option
-- list in order, the padding, the IP source and destination.
--
-- Own VMs: the first test needs the machine's first DHCP exchange, which
-- only a fresh boot gives. The tests after it run in order on the same
-- pair and leave the machine bound to 10.77.0.50 for the next:
--   * the operator's `renew` gives a Renewing REQUEST on demand;
--   * a cable pull (`lan:nic(sut)`) restarts the client with a previous
--     address, so it opens in Rebooting;
--   * editing any value of `Profiles\default` restarts it the same way,
--     after a RELEASE (a profile edit is an outcome change, §3.3);
--   * a re-armed 20 s lease with a silent server reaches Rebinding.
--
-- `secs` is the client's own clock, whole seconds since it started; it is
-- asserted as monotone, never against the gateway's clock.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

local D = gateway.DHCP
local PROFILE = "Profiles\\default"
local PRL = string.char(1, 3, 6, 12, 15, 26, 28, 42, 51, 58, 59, 119, 121)
local LEASED = "10.77.0.50"

local MAC = gateway.mac(sut:read_file("/sys/class/net/eth0/address"))
local INDEX = tonumber((sut:read_file("/sys/class/net/eth0/ifindex"):match("%d+")))

-- ---------------------------------------------------------------------------
-- Local helpers
-- ---------------------------------------------------------------------------

local function iface() return network.iface(network.status(sut), "eth0") end

--- §5.7's generated client identifier for a fresh machine: ff, the
--- interface id folded into 4 bytes by XOR, then the DUID-LL of the MAC.
local function expected_client_id(ifid)
    local iaid = { 0, 0, 0, 0 }
    for i = 1, #ifid do
        local k = (i - 1) % 4 + 1
        iaid[k] = iaid[k] ~ ifid:byte(i)
    end
    return "\xff" .. string.char(table.unpack(iaid)) .. "\0\3\0\1" .. MAC
end

local function codes(m)
    local out = {}
    for _, o in ipairs(m.options) do out[#out + 1] = o[1] end
    return table.concat(out, ",")
end

--- Pump until `pred(m)` holds for some DHCP message the machine sent
--- (in `gw.seen`), and return the first such message.
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
    return s
end

local function renew()
    local r, err = network.call(sut, { query = "renew", interface = "eth0" })
    assert(r and r.ok, "renew: " .. tostring(err or (r and r.error)))
end

--- Delete one value (`key` relative to Machine\System\Network, or "").
local function unset(key, name)
    local full = key == "" and network.KEY or (network.KEY .. "\\" .. key)
    network.reg(sut, { "del", full, name }):assert_ok()
end

local function cable_cycle()
    nic:disconnect()
    assert(network.serve_until(gw, sut, function(i) return i.carrier == false end,
        { iface = true, timeout = 20 }), "carrier did not drop")
    gw:forget()
    nic:reconnect()
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { since = "30m ago", take = 2000 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

--- What every message but a RELEASE carries (§5.1): the BOOTREQUEST
--- header, chaddr, and options 53, 61, 57, 55 (and 12) first, in order;
--- then the end option and zero padding to 300 bytes.
local function check_common(t, m, kind, cid, hostname)
    local what = gateway.DHCP_NAME[kind]
    t:assert_eq(m.op, 1, what .. " is a BOOTREQUEST")
    t:assert_eq(m.htype, 1, what .. " hardware type 1")
    t:assert_eq(m.hlen, 6, what .. " hardware length 6")
    t:assert_eq(m.chaddr, MAC, what .. " chaddr is the interface's MAC")
    t:assert(m.secs >= 0 and m.secs <= 65535, what .. " secs in range")
    t:assert_eq(m.type, kind, what .. " option 53")
    t:assert_eq(m.options[1][1], 53, what .. ": 53 first")
    t:assert_eq(m.options[2][1], 61, what .. ": 61 second")
    t:assert_eq(m.options[2][2], cid, what .. ": option 61 is the client identifier")
    t:assert_eq(m.options[3][1], 57, what .. ": 57 third")
    t:assert_eq(m.options[3][2], "\x05\xdc", what .. ": maximum message size 1500")
    t:assert_eq(m.options[4][1], 55, what .. ": 55 fourth")
    t:assert_eq(m.options[4][2], PRL, what .. ": the parameter request list")
    if hostname then
        t:assert_eq(m.options[5][1], 12, what .. ": 12 fifth")
        t:assert_eq(m.options[5][2], hostname, what .. ": the hostname")
    else
        t:assert_eq(m.opt[12], nil, what .. ": no option 12")
    end
    -- The end option, then zeros to 300.
    local p = m.frame.payload
    local at = 241
    for _, o in ipairs(m.options) do at = at + 2 + #o[2] end
    t:assert_eq(p:byte(at), 255, what .. ": option 255 ends the options")
    t:assert_eq(#p, 300, what .. ": padded to 300 bytes")
    t:assert_eq(p:sub(at + 1), string.rep("\0", 300 - at), what .. ": padding is zeros")
end

local function check_broadcast_path(t, m, what)
    t:assert_eq(m.frame.src_ip, "0.0.0.0", what .. " leaves from 0.0.0.0")
    t:assert_eq(m.frame.dst_ip, "255.255.255.255", what .. " to 255.255.255.255")
    t:assert_eq(m.frame.dst, string.rep("\xff", 6), what .. " to the Ethernet broadcast")
end

local function check_unicast_path(t, m, what)
    t:assert_eq(m.frame.src_ip, LEASED, what .. " leaves from the lease address")
    t:assert_eq(m.frame.dst_ip, gw.addr, what .. " to the server")
    t:assert_eq(m.frame.dst, gw.mac, what .. " to the server's MAC")
end

-- ---------------------------------------------------------------------------
-- The first exchange
-- ---------------------------------------------------------------------------

local CID

test("a fresh client starts in Selecting; DISCOVER and the Requesting REQUEST carry exactly the documented fields",
    { spec = "netd *dhcp4-client.common-fields netd *dhcp4-client.messages netd *dhcp4-client.transaction-ids" },
    function(t)
        local s = bound()
        local i = network.iface(s, "eth0")
        CID = expected_client_id(i.ifid)
        t:log("ifid " .. i.ifid)
        local discovers = gw:dhcp_messages(D.DISCOVER)
        local requests = gw:dhcp_messages(D.REQUEST)
        t:assert(#discovers >= 1, "a DISCOVER was sent")
        t:assert(#requests >= 1, "a REQUEST was sent")
        local first = gw:dhcp_messages()[1]
        t:assert_eq(first.type, D.DISCOVER, "with no previous address the first message is a DISCOVER")

        local d = discovers[1]
        t:log(string.format("DISCOVER xid %08x secs %d options %s", d.xid, d.secs, codes(d)))
        check_common(t, d, D.DISCOVER, CID, nil)
        t:assert_eq(d.secs, 0, "the first DISCOVER goes out the moment the client starts")
        t:assert_eq(codes(d), "53,61,57,55", "DISCOVER: no option 50 before any lease, no 54")
        t:assert(d.broadcast, "DISCOVER: broadcast flag set")
        t:assert_eq(d.ciaddr, "0.0.0.0", "DISCOVER: ciaddr 0")
        check_broadcast_path(t, d, "DISCOVER")
        for _, x in ipairs(discovers) do
            t:assert_eq(x.xid, d.xid, "a retransmitted DISCOVER keeps the Selecting xid")
        end

        local r = requests[1]
        t:log(string.format("REQUEST xid %08x secs %d options %s", r.xid, r.secs, codes(r)))
        check_common(t, r, D.REQUEST, CID, nil)
        t:assert_eq(r.xid, d.xid, "Requesting keeps the xid of the Selecting exchange")
        t:assert_eq(codes(r), "53,61,57,55,50,54", "REQUEST (Requesting): 50 and 54 after the common options")
        t:assert_eq(gateway.ip4_text(r.opt[50]), LEASED, "option 50 is the offered address")
        t:assert_eq(gateway.ip4_text(r.opt[54]), gw.addr, "option 54 is the offer's server")
        t:assert(r.broadcast, "REQUEST (Requesting): broadcast flag set")
        t:assert_eq(r.ciaddr, "0.0.0.0", "REQUEST (Requesting): ciaddr 0")
        t:assert(r.secs >= d.secs, "secs counts up from the client's start")
        check_broadcast_path(t, r, "REQUEST (Requesting)")
    end)

test("the operator's renew sends a Renewing REQUEST: new xid, ciaddr, no 50 or 54, unicast from the lease address",
    { spec = "netd *dhcp4-client.messages netd *dhcp4-client.transaction-ids netd *dhcp4-client.common-fields" },
    function(t)
        bound()
        local before = gw:dhcp_messages(D.REQUEST)
        local old_xid = before[#before].xid
        gw:forget()
        renew()
        local r = await(function(m) return m.type == D.REQUEST end, 10, "the renewing REQUEST")
        bound()
        t:log(string.format("renew xid %08x (was %08x) options %s", r.xid, old_xid, codes(r)))
        check_common(t, r, D.REQUEST, CID, nil)
        t:assert(r.xid ~= old_xid, "Renewing draws a new xid")
        t:assert_eq(codes(r), "53,61,57,55", "REQUEST (Renewing): no 50, no 54")
        t:assert(not r.broadcast, "REQUEST (Renewing): broadcast flag clear")
        t:assert_eq(r.ciaddr, LEASED, "REQUEST (Renewing): ciaddr is the lease address")
        check_unicast_path(t, r, "REQUEST (Renewing)")
    end)

-- ---------------------------------------------------------------------------
-- A previous address, and the hostname
-- ---------------------------------------------------------------------------

test("a restarted client with a previous address opens in Rebooting; a Hostname without Hostname.Announce is not sent",
    { spec = "netd *dhcp4-client.previous-address-starts-in-rebooting netd *dhcp4-client.messages netd *dhcp4-client.start-stop" },
    function(t)
        bound()
        network.write(sut, "Machine\\System\\Network", { Hostname = "sz:pt-dhost" })
        assert(network.serve_until(gw, sut, function(s) return s.hostname == "pt-dhost" end,
            { timeout = 20 }), "netd did not read Hostname")
        local starting = count_logged("interface eth0: dhcp starting")
        cable_cycle()
        local r = await(function(m) return m.type == D.REQUEST end, 20, "the INIT-REBOOT REQUEST")
        bound()
        local first = gw:dhcp_messages()[1]
        t:log(string.format("first after reconnect: %s xid %08x options %s",
            gateway.DHCP_NAME[first.type], first.xid, codes(first)))
        t:assert_eq(first.type, D.REQUEST, "the first message after the restart is a REQUEST, not a DISCOVER")
        check_common(t, r, D.REQUEST, CID, nil)
        t:assert_eq(codes(r), "53,61,57,55,50", "REQUEST (Rebooting): 50, no 54, and no 12 without Hostname.Announce")
        t:assert_eq(gateway.ip4_text(r.opt[50]), LEASED, "option 50 is the previous address")
        t:assert(r.broadcast, "REQUEST (Rebooting): broadcast flag set")
        t:assert_eq(r.ciaddr, "0.0.0.0", "REQUEST (Rebooting): ciaddr 0")
        check_broadcast_path(t, r, "REQUEST (Rebooting)")
        t:assert(count_logged("interface eth0: dhcp starting") > starting,
            "the new client was logged as `dhcp starting`")
    end)

test("editing the profile sends a RELEASE (53, 54, 61 only) and the restarted client announces Hostname in option 12",
    { spec = "netd *dhcp4-client.common-fields netd *dhcp4-client.messages netd *dhcp4-client.transaction-ids" },
    function(t)
        local before = bound()
        t:assert_eq(network.iface(before, "eth0").lease.state, "bound", "bound before the edit")
        local prior = gw:dhcp_messages(D.REQUEST)
        assert(#prior > 0, "the previous test's REQUEST is on record")
        local old_xid = prior[#prior].xid
        gw:forget()
        network.write(sut, PROFILE, { ["Hostname.Announce"] = "dword:1" })
        local rel = await(function(m) return m.type == D.RELEASE end, 20, "the RELEASE")
        local r = await(function(m) return m.type == D.REQUEST end, 20, "the INIT-REBOOT REQUEST")
        bound()
        t:log(string.format("RELEASE options %s; REQUEST xid %08x options %s", codes(rel), r.xid, codes(r)))
        t:assert_eq(rel.op, 1, "RELEASE is a BOOTREQUEST")
        t:assert_eq(rel.htype, 1, "RELEASE hardware type 1")
        t:assert_eq(rel.hlen, 6, "RELEASE hardware length 6")
        t:assert_eq(rel.chaddr, MAC, "RELEASE chaddr")
        t:assert_eq(codes(rel), "53,54,61", "RELEASE carries only 53, 54 and 61")
        t:assert_eq(gateway.ip4_text(rel.opt[54]), gw.addr, "RELEASE option 54 is the server")
        t:assert_eq(rel.opt[61], CID, "RELEASE option 61 is the client identifier")
        t:assert(not rel.broadcast, "RELEASE: broadcast flag clear")
        t:assert_eq(rel.ciaddr, LEASED, "RELEASE: ciaddr is the lease address")
        t:assert_eq(#rel.frame.payload, 300, "RELEASE padded to 300 bytes")
        check_unicast_path(t, rel, "RELEASE")

        check_common(t, r, D.REQUEST, CID, "pt-dhost")
        t:assert_eq(codes(r), "53,61,57,55,12,50", "REQUEST (Rebooting) with the hostname: 12 after 55, before 50")
        t:assert(r.xid ~= old_xid, "Rebooting draws a new xid")
    end)

test("with Hostname.Announce but no Hostname, option 12 is not sent",
    { spec = "netd *dhcp4-client.common-fields" },
    function(t)
        bound()
        unset("", "Hostname")
        -- Hostname alone is not a profile edit: the client keeps its
        -- configuration until it restarts, so pull the cable.
        gw:serve({ timeout = 2 })
        cable_cycle()
        local r = await(function(m) return m.type == D.REQUEST end, 20, "the INIT-REBOOT REQUEST")
        bound()
        t:log("REQUEST options " .. codes(r))
        check_common(t, r, D.REQUEST, CID, nil)
        t:assert_eq(codes(r), "53,61,57,55,50", "no option 12 without a Hostname")
        -- Put the profile back (another restart).
        gw:forget()
        network.write(sut, PROFILE, { ["Hostname.Announce"] = "dword:0" })
        await(function(m) return m.type == D.REQUEST end, 20, "the restart after the clean-up")
        bound()
    end)

-- ---------------------------------------------------------------------------
-- Renewing, Rebinding, and the states
-- ---------------------------------------------------------------------------

test("a 20 s lease moves bound → renewing → rebinding → bound; the Rebinding REQUEST is broadcast with ciaddr",
    { spec = "netd *dhcp4-client.states netd *dhcp4-client.messages netd *dhcp4-client.transaction-ids" },
    function(t)
        bound()
        -- A 20 s lease (T1 10 s, T2 17 s). Renewing REQUESTs (unicast to
        -- the server) go unanswered; the Rebinding one (broadcast) is held
        -- until the status reply has shown `rebinding`, then ACKed, since
        -- an immediate answer would end Rebinding between two polls.
        local answered_operator, pending, sent = false, nil, false
        gw:dhcp({ pool = { LEASED }, lease = 20, on = {
            renew = function(m, default)
                -- The handler runs on the frame just recorded.
                local f = gw.seen[#gw.seen]
                if f.dst_ip == "255.255.255.255" then
                    pending = pending or { ciaddr = m.ciaddr, reply = default }
                    return false
                end
                if answered_operator then return false end
                answered_operator = true
                return nil
            end,
        } })
        gw:forget()
        renew()
        local states, last = {}, nil
        local function track(i)
            local st = i.lease and i.lease.state or "none"
            if st ~= last then states[#states + 1] = st; last = st end
        end
        -- The operator's renew gets the 20 s lease; then wait for the
        -- Rebinding REQUEST and answer it, recording every state seen.
        local s = network.serve_until(gw, sut, function(i)
            track(i)
            if pending and not sent and last == "rebinding" then
                gw:send_udp4(MAC, pending.ciaddr, 67, 68, gateway.dhcp_encode(pending.reply))
                sent = true
            end
            return sent and i.lease and i.lease.state == "bound"
        end, { iface = true, timeout = 40 })
        t:log("states seen: " .. table.concat(states, " → "))
        t:assert(s, "the rebinding REQUEST was answered and the client bound again")
        local reqs = gw:dhcp_messages(D.REQUEST)
        local renewing, rebinding
        for _, m in ipairs(reqs) do
            if m.frame.dst_ip == "255.255.255.255" then rebinding = rebinding or m
            elseif m ~= reqs[1] then renewing = renewing or m end
        end
        t:assert(renewing, "a Renewing REQUEST at T1")
        t:assert(rebinding, "a Rebinding REQUEST at T2")
        local seq = table.concat(states, ",")
        t:assert(seq:find("bound,renewing,rebinding,bound", 1, true),
            "the status reply showed bound → renewing → rebinding → bound")
        check_common(t, rebinding, D.REQUEST, CID, nil)
        t:assert_eq(codes(rebinding), "53,61,57,55", "REQUEST (Rebinding): no 50, no 54")
        t:assert(not rebinding.broadcast, "REQUEST (Rebinding): broadcast flag clear")
        t:assert_eq(rebinding.ciaddr, LEASED, "REQUEST (Rebinding): ciaddr is the lease address")
        check_broadcast_path(t, rebinding, "REQUEST (Rebinding)")
        t:assert(rebinding.xid ~= renewing.xid, "Rebinding draws a new xid")
        t:assert(renewing.xid ~= reqs[1].xid, "T1's Renewing draws a new xid")
        -- Back to a long lease for the rest of the file.
        gw:dhcp({ pool = { LEASED }, lease = 3600 })
        renew()
        assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and i.lease.expires_in > 100 end, { iface = true, timeout = 20 }),
            "back on a long lease")
    end)

-- The state appears only inside `lease`, which is nil unless the client
-- holds a lease (§9.2), so a client in Rebooting shows no state at all;
-- bound, renewing and rebinding are shown by the test above.
test("the status reply shows a client's state only inside `lease`: a client in Rebooting shows none",
    { spec = "netd *dhcp4-client.states" },
    function(t)
        bound()
        local hold = true
        gw:dhcp({ pool = { LEASED }, lease = 3600, on = {
            reboot = function() if hold then return false end end,
        } })
        cable_cycle()
        await(function(m) return m.type == D.REQUEST and m.opt[50] and not m.opt[54] end, 20,
            "the INIT-REBOOT REQUEST")
        local i = iface()
        hold = false
        local lease = i.lease
        t:log("lease while rebooting: " .. (lease and (lease.state .. " " .. lease.server) or "nil"))
        local after = network.iface(bound(), "eth0")
        t:assert_eq(lease, nil, "while the INIT-REBOOT REQUEST is unanswered, `lease` (and so the state) is nil")
        t:assert_eq(after.lease.state, "bound", "once the ACK binds it, `lease` shows `bound`")
    end)

-- ---------------------------------------------------------------------------
-- Starting and stopping
-- ---------------------------------------------------------------------------

test("a profile that stops wanting IPv4 stops the client (RELEASE, address gone); wanting it again starts one",
    { spec = "netd *dhcp4-client.start-stop" },
    function(t)
        bound()
        local starting = count_logged("interface eth0: dhcp starting")
        gw:forget()
        network.write(sut, PROFILE, { ["Address.Families"] = "sz:ipv6" })
        local rel = await(function(m) return m.type == D.RELEASE end, 20, "the RELEASE")
        local gone = network.serve_until(gw, sut, function(i)
            return i.lease == nil and not network.has_address(i, LEASED) end, { iface = true, timeout = 20 })
        t:assert(gone, "the lease and its address are gone")
        t:assert_eq(rel.ciaddr, LEASED, "the RELEASE was for the lease")
        -- No client: nothing more on the wire for longer than a backoff.
        gw:forget()
        gw:serve({ timeout = 6 })
        t:assert_eq(#gw:dhcp_messages(), 0, "no client runs while IPv4 is out of the families")
        local v4 = rtnl.addresses_of(sut, INDEX, 4)
        t:assert_eq(#v4, 0, "no IPv4 address on eth0")
        t:assert_eq(count_logged("interface eth0: dhcp starting"), starting, "no client was started")

        unset(PROFILE, "Address.Families")
        local r = await(function(m) return m.type == D.REQUEST end, 20, "the new client's first REQUEST")
        bound()
        t:assert_eq(gw:dhcp_messages()[1].type, D.REQUEST, "it opens in Rebooting (a previous address is known)")
        t:assert_eq(gateway.ip4_text(r.opt[50]), LEASED, "for the previous address")
        t:assert(count_logged("interface eth0: dhcp starting") > starting, "`dhcp starting` was logged")
    end)

-- Every stop is made in the link pass (main.rs sync_links), before
-- clients are started: a carrier loss logged `carrier lost`, an outcome
-- change logged as the verdict. Outcome compares the whole Profile, so
-- an edit that leaves the profile wanting a client still stops it, and
-- the same pass starts a new one.
local VERDICT = "interface eth0: JOIN(default) by wired"

test("a stop is logged as `carrier lost` or as the verdict; a profile edit that still wants a client restarts it",
    { spec = "netd *dhcp4-client.start-stop" },
    function(t)
        bound()
        -- A carrier loss.
        local lost, starting = count_logged("interface eth0: carrier lost"), count_logged("interface eth0: dhcp starting")
        cable_cycle()
        await(function(m) return m.type == D.REQUEST end, 20, "the restarted client's REQUEST")
        bound()
        t:assert(count_logged("interface eth0: carrier lost") > lost, "the carrier-loss stop was logged `carrier lost`")
        t:assert(count_logged("interface eth0: dhcp starting") > starting, "and the new client `dhcp starting`")

        -- A profile edit that leaves Address.Offered and IPv4 in place.
        local verdicts, starting2 = count_logged(VERDICT), count_logged("interface eth0: dhcp starting")
        gw:forget()
        network.write(sut, PROFILE, { ["Address.OnExpiry"] = "sz:Keep" })
        local rel = await(function(m) return m.type == D.RELEASE end, 20, "the RELEASE")
        local r = await(function(m) return m.type == D.REQUEST end, 20, "the new client's REQUEST")
        bound()
        t:assert_eq(rel.ciaddr, LEASED, "the edit stopped the client: a RELEASE for the lease")
        t:assert_eq(gateway.ip4_text(r.opt[50]), LEASED, "and a new client asked for the address again")
        t:assert(count_logged(VERDICT) > verdicts, "the stop was logged as the verdict `" .. VERDICT .. "`")
        t:assert(count_logged("interface eth0: dhcp starting") > starting2, "and the new client `dhcp starting`")
        t:log("`dhcp stopping` lines in this boot: " .. count_logged("interface eth0: dhcp stopping"))

        -- Put the profile back (another restart).
        gw:forget()
        unset(PROFILE, "Address.OnExpiry")
        await(function(m) return m.type == D.REQUEST end, 20, "the restart after the clean-up")
        bound()
    end)
