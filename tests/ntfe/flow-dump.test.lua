-- PKM §6.8 — The flows dump: `PEIOS_NTFE_IOC_FLOWS` walks conntrack's
-- table for the live, original-direction entries of the initial
-- namespace, and fills one record per flow with conntrack's view of it
-- (tuple, state, lifetime, the packet and byte counts NTFE's init turns
-- on) and NTFE's extension (start, first-judgment facts, both sentences,
-- up to eight tags); records reach the caller between buckets in
-- batches, and the walk counts every flow it saw, so a short buffer is
-- visible.
--
-- Entries are made both by traffic from a peer on a veth pair and
-- directly through ctnetlink, which can make many at once, make them in
-- another namespace, and make them short-lived.
--
-- Own VM: the policy and the conntrack table are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local nf = require("helpers.ntfe_flow")

local vm = provium:vm("vntfeflowdump", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

local function flow_policy(flow)
    local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = flow })
    assert(s.last_ingest_error == 0, "the policy is accepted: " .. s.last_ingest_error)
    return s
end

test("the dump walks the live, original-direction entries of the initial namespace",
    { spec = "PKM *ntfe-flow.dump-walks-live-original-entries" },
    function(t)
        flow_policy(PASS_ALL)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7300))
        local c = assert(ntfe.tcp_connect(peer, net.addr, 7300, 1000, { bind = { net.peer_addr, 9300 } }))
        local a = assert(ntfe.tcp_accept(vm, l))
        ntfe.send(vm, a, "both ways")
        t:assert_eq(ntfe.recv(peer, c), "both ways", "a connection carries traffic both ways")
        local flows = assert(E:flows())
        t:assert_eq(#nf.flows_matching(flows, { src = net.peer_addr, src_port = 9300, dst_port = 7300 }), 1,
            "it is in the dump once, by its original tuple")
        t:assert_eq(#nf.flows_matching(flows, { src = net.addr, src_port = 7300, dst_port = 9300 }), 0,
            "and not again by its reply")
        sys.close(peer, c); sys.close(vm, a); sys.close(vm, l)

        -- The peer's namespace has a conntrack table of its own in the
        -- same hash.
        assert(nf.ct_create(peer, { src = net.peer_addr, dst = "10.9.0.77", sport = 9301, dport = 9302 }))
        assert(nf.ct_create(vm, { src = net.peer_addr, dst = "10.9.0.77", sport = 9303, dport = 9302 }))
        flows = assert(E:flows())
        t:assert_eq(#nf.flows_matching(flows, { dst = "10.9.0.77", src_port = 9303 }), 1,
            "an entry of this namespace is listed")
        t:assert_eq(#nf.flows_matching(flows, { dst = "10.9.0.77", src_port = 9301 }), 0,
            "one of another namespace is not")

        assert(nf.ct_create(vm, { src = net.peer_addr, dst = "10.9.0.78", sport = 9304, dport = 9305, timeout = 1 }))
        t:assert_eq(#nf.flows_matching(assert(E:flows()), { dst = "10.9.0.78" }), 1,
            "an entry with a second to live is listed")
        local gone = false
        for _ = 1, 20 do
            vm:clock():sleep(0.25)
            if #nf.flows_matching(assert(E:flows()), { dst = "10.9.0.78" }) == 0 then
                gone = true
                break
            end
        end
        t:assert(gone, "and once expired, is not")
    end)

test("NTFE turns conntrack's accounting on, and the dump carries its counts",
    { spec = "PKM *ntfe-flow.init-enables-conntrack-acct" },
    function(t)
        local acct = nf.read_file(vm, "/proc/sys/net/netfilter/nf_conntrack_acct")
        t:assert_eq(acct, "1\n", "accounting is on, with nothing but NTFE to turn it on")
        flow_policy(PASS_ALL)
        local rx = assert(ntfe.udp_bind(vm, net.addr, 7310))
        local tx = assert(ntfe.udp_bind(peer, net.peer_addr, 9310))
        for i = 1, 3 do
            ntfe.sendto(peer, tx, "datagram-" .. i, net.addr, 7310)
            t:assert(ntfe.recv(vm, rx), "datagram " .. i .. " arrives")
        end
        ntfe.sendto(vm, rx, "answer", net.peer_addr, 9310)
        t:assert(ntfe.recv(peer, tx), "and an answer")
        local f = assert(nf.flow(E, { src = net.peer_addr, src_port = 9310, dst_port = 7310 }))
        t:assert_eq(f.packets[1], 3, "the dump counts the original direction's packets")
        t:assert_eq(f.bytes[1], 3 * (20 + 8 + 10), "and bytes")
        t:assert_eq(f.packets[2], 1, "and the reply direction's packets")
        t:assert_eq(f.bytes[2], 20 + 8 + 6, "and bytes")
        sys.close(vm, rx); sys.close(peer, tx)
    end)

test("a flow record carries conntrack's view of the flow and NTFE's extension",
    { spec = "PKM *ntfe-flow.dump-record-contents" },
    function(t)
        local tags = {}
        for i = 1, 9 do tags[#tags + 1] = "TAG(t" .. i .. ", Set, " .. (100 + i) .. ")" end
        tags[#tags + 1] = "PASS"
        local s = flow_policy({
            all = { Actions = { "PASS" } },
            tagger = { ["DstPort.Equal"] = 7320, Priority = 10, Actions = tags },
        })
        local now = math.floor(vm:clock():get())
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7320))
        local c = assert(ntfe.tcp_connect(peer, net.addr, 7320, 1000, { bind = { net.peer_addr, 9320 } }))
        local a = assert(ntfe.tcp_accept(vm, l))
        ntfe.send(peer, c, "request")
        t:assert_eq(ntfe.recv(vm, a), "request", "a connection carries a request")
        ntfe.send(vm, a, "response")
        t:assert_eq(ntfe.recv(peer, c), "response", "and its response")

        local f = assert(nf.flow(E, { protocol = ntfe.IPPROTO.TCP, src_port = 9320, dst_port = 7320 }))
        t:assert(f.id ~= 0, "the record has conntrack's id")
        t:assert_eq(f.family, 4, "the family")
        t:assert_eq(f.src, net.peer_addr, "the original tuple's source")
        t:assert_eq(f.dst, net.addr, "and destination")
        t:assert_eq(f.seen_reply, 1, "conntrack's seen-reply")
        t:assert_eq(f.assured, 1, "and assured bits")
        t:assert_eq(f.related, 0, "and that no other flow expected it")
        t:assert(f.timeout_secs > 3600, "the remaining lifetime of an established TCP flow: " .. f.timeout_secs)
        t:assert(f.packets[1] >= 3 and f.packets[2] >= 2, "packet counts both ways")
        t:assert(f.bytes[1] > 0 and f.bytes[2] > 0, "and byte counts")
        t:assert(math.abs(f.start_secs - now) <= 2, "the start time")
        t:assert_eq(f.judged, 1, "the first judgment's record")
        t:assert_eq(f.ifindex, net.ifindex, "interface")
        t:assert_eq(f.direction, ntfe.DIR.IN, "and direction")
        t:assert_eq(f.loopback, 0, "that it is not loopback")
        t:assert_eq(f.sentences[0].generation, s.generation, "the sentence in slot 0")
        t:assert_eq(f.sentences[0].rule_hash, ntfe.name_hash("tagger"), "naming its rule")
        t:assert_eq(f.sentences[1].generation, 0, "an empty slot 1")
        t:assert_eq(f.n_tags, 9, "and the nine tags it carries, by count")
        local listed = 0
        for hash, value in pairs(f.tags) do
            listed = listed + 1
            t:assert_eq(hash, ntfe.name_hash("t" .. (value - 100)), "each by its name's hash, with its value")
        end
        t:assert_eq(listed, 8, "of which the record lists eight")
        sys.close(peer, c); sys.close(vm, a); sys.close(vm, l)

        -- ICMP: the identifier stands where the source port would, and
        -- the original tuple's type and code are given.
        local ps = assert(ntfe.packet_socket(peer, net.peer))
        local echo = ntfe.icmp(8, 0, (0x1234 << 16) | 1, "dump")
        ntfe.send_frame(peer, ps, ntfe.eth(net.mac, net.peer_mac, ntfe.ETH_P.IP)
            .. ntfe.ipv4(net.peer_addr, net.addr, ntfe.IPPROTO.ICMP, #echo) .. echo)
        local answered = false
        for _, fr in ipairs(ntfe.frames(peer, ps, 300)) do
            if fr.icmp and fr.icmp.type == 0 then answered = true end
        end
        sys.close(peer, ps)
        t:assert(answered, "an echo request from the peer is answered")
        local ping = assert(nf.flow(E, { protocol = ntfe.IPPROTO.ICMP, src = net.peer_addr }))
        t:assert_eq(ping.src_port, 0x1234, "an ICMP record carries the echo identifier")
        t:assert_eq(ping.icmp_type, 8, "the type")
        t:assert_eq(ping.icmp_code, 0, "and the code")
        t:assert_eq(ping.seen_reply, 1, "and saw our answer")
    end)

test("records are batched and copied out between buckets, so a dump bigger than a batch arrives whole",
    { spec = "PKM *ntfe-flow.dump-copies-out-between-buckets" },
    function(t)
        for i = 0, 79 do
            assert(nf.ct_create(vm, { src = net.peer_addr, dst = "10.9.0.88", sport = 9400 + i, dport = 9500 }))
        end
        local flows = assert(E:flows())
        t:assert_eq(#flows, flows.total, "every live flow walked was written")
        local seen = {}
        for _, f in ipairs(nf.flows_matching(flows, { dst = "10.9.0.88" })) do
            seen[f.src_port] = (seen[f.src_port] or 0) + 1
        end
        for i = 0, 79 do
            t:assert_eq(seen[9400 + i], 1, "entry " .. i .. " of eighty, more than two batches, is there once")
        end
    end)

test("the walk counts every live flow it saw, so a short buffer is visible",
    { spec = "PKM *ntfe-flow.dump-counts-every-live-flow" },
    function(t)
        for i = 0, 9 do
            assert(nf.ct_create(vm, { src = net.peer_addr, dst = "10.9.0.89", sport = 9600 + i, dport = 9700 }))
        end
        local full = assert(E:flows())
        local short = assert(E:flows(2))
        t:assert(#full >= 10, "the table holds at least ten flows: " .. #full)
        t:assert_eq(#short, 2, "a buffer with room for two gets two records")
        t:assert_eq(short.total, #full, "and the total the walk saw, which says what was left out")
    end)
