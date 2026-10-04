-- PKM §6.8 — The sentence: what a flow's cached judgment holds (the
-- generation, the expiry, the attributing rule's path hash, the verdict
-- and the reject kind) and what sits beside it in NTFE's conntrack
-- extension (the flow's start, and the first judgment's interface,
-- direction and loopbackness); that the cache holds the verdict and
-- never the effects; that DROP and REJECT sentences persist on a flow
-- that lives, while a new flow they refuse is killed; and the flow with
-- no extension, which is evaluated on every packet.
--
-- The flows are a peer's on a veth pair, and the dump (§6.8, "The flows
-- dump") is how the sentence is read back.
--
-- Own VM: the policy and the clock are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local nf = require("helpers.ntfe_flow")

local vm = provium:vm("vntfeflowsent", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

local function flow_policy(flow)
    local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = flow })
    assert(s.last_ingest_error == 0, "the policy is accepted: " .. s.last_ingest_error)
    return s
end

-- A UDP flow from the peer: unconnected sockets, so no refusal parks an
-- error that stops the next send.
local function udp_from_peer(sport, dport)
    local rx = assert(ntfe.udp_bind(vm, net.addr, dport))
    local tx = assert(ntfe.udp_bind(peer, net.peer_addr, sport))
    return rx, function(data)
        return ntfe.sendto(peer, tx, data, net.addr, dport)
    end
end

local function peer_flow(sport, dport)
    return nf.flow(E, { protocol = ntfe.IPPROTO.UDP, src = net.peer_addr,
                        src_port = sport, dst_port = dport })
end

test("a sentence holds the judging generation, the expiry, the rule's path hash, the verdict and the reject kind",
    { spec = "PKM *ntfe-flow.sentence-fields" },
    function(t)
        -- A fixed clock, so the expiry is known: 10 minutes into an hour.
        local now = math.floor(vm:clock():get())
        local t0 = now - now % 3600 + 3600 + 600
        vm:clock():set(t0)
        flow_policy(PASS_ALL)
        local flows = {}
        for _, port in ipairs({ 7100, 7101, 7102 }) do
            local rx, send = udp_from_peer(port + 1000, port)
            send("open")
            t:assert_eq(ntfe.recv(vm, rx), "open", "the flow to " .. port .. " is opened")
            flows[port] = send
        end
        -- Refusals are read back from flows that live: a refused new flow
        -- leaves no entry to read.
        local s = flow_policy({
            accept = { ["DstPort.Equal"] = 7100, ["Time.Year.GreaterThan"] = 2000, Actions = { "PASS" } },
            prohibit = { ["DstPort.Equal"] = 7101, Actions = { "REJECT(Prohibited)" } },
            svc = {
                ["Protocol.Equal"] = "udp", Actions = { "PASS" },
                children = { deny = { ["DstPort.Equal"] = 7102, Actions = { "DROP" } } },
            },
        })
        local _, events = E:during(function()
            for _, port in ipairs({ 7100, 7101, 7102 }) do flows[port]("again") end
        end)

        local pass = assert(peer_flow(8100, 7100))
        local p = pass.sentences[0]
        t:assert_eq(p.generation, s.generation, "the sentence carries the generation that judged it")
        t:assert_eq(p.expires_at, t0 - t0 % 86400 + 86400,
            "an expiry: a consulted year condition re-judges at the next midnight")
        t:assert_eq(p.rule_hash, ntfe.name_hash("accept"), "the FNV-1a-64 hash of the attributing rule's path")
        t:assert_eq(p.verdict, ntfe.VERDICT.PASS, "the verdict")

        local refused = assert(peer_flow(8101, 7101)).sentences[0]
        t:assert_eq(refused.verdict, ntfe.VERDICT.REJECT, "a REJECT sentence keeps its verdict")
        t:assert_eq(refused.reject_kind, ntfe.REJECT.PROHIBITED, "and its reject kind")
        t:assert_eq(refused.expires_at, 0, "and with no time condition consulted, no expiry")

        local denied = assert(peer_flow(8102, 7102)).sentences[0]
        local e = nf.flow_events(events, { dst_port = 7102 })[1]
        t:assert(e, "the exception judged its flow: " .. ntfe.describe(events))
        t:assert_eq(e.attributed, "svc/deny", "an exception is attributed by its path")
        t:assert_eq(denied.rule_hash, ntfe.name_hash("svc/deny"),
            "which is what its sentence hashes, the identity the viewer resolves against the policy")
        t:assert_eq(denied.verdict, ntfe.VERDICT.DROP, "as a DROP")
    end)

test("the flow's start is stamped when conntrack creates the entry, not when it is judged",
    { spec = "PKM *ntfe-flow.start-secs-stamped-at-ct-creation" },
    function(t)
        local now = math.floor(vm:clock():get())
        local born = now - now % 3600 + 3600 + 600
        vm:clock():set(born)
        -- No Flow forest: the flow is created, and nothing judges it.
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        local rx, send = udp_from_peer(8110, 7110)
        send("born")
        t:assert_eq(ntfe.recv(vm, rx), "born", "the flow is created")
        local f = assert(peer_flow(8110, 7110))
        t:assert_eq(f.judged, 0, "unjudged")
        t:assert(math.abs(f.start_secs - born) <= 2, "with its start stamped all the same: "
            .. f.start_secs .. " vs " .. born)

        -- Two hours on, its first judgment reads that start, not the
        -- moment of judging.
        vm:clock():set(born + 7200)
        flow_policy({ ["started-then"] = {
            ["Start.Hour.Equal"] = (born // 3600) % 24, Actions = { "PASS" },
        } })
        local _, events = E:during(function()
            send("judged")
            t:assert_eq(ntfe.recv(vm, rx), "judged", "the flow is passed at its first judgment")
        end)
        local e = nf.flow_events(events, { dst_port = 7110 })[1]
        t:assert(e and e.attributed == "started-then",
            "by the rule for the hour it began in: " .. ntfe.describe(events))
        f = assert(peer_flow(8110, 7110))
        t:assert(math.abs(f.start_secs - born) <= 2, "and the dump's start is still the creation time")
    end)

test("the extension records the first judgment's interface, direction and loopbackness",
    { spec = "PKM *ntfe-flow.extension-records-first-judgment-facts" },
    function(t)
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        local rx, send = udp_from_peer(8120, 7120)
        send("unjudged")
        t:assert_eq(ntfe.recv(vm, rx), "unjudged", "a flow no Flow forest judged")
        local f = assert(peer_flow(8120, 7120))
        t:assert_eq(f.judged, 0, "records no judgment")
        t:assert_eq(f.ifindex, 0, "and no interface")

        flow_policy(PASS_ALL)
        send("judged")
        t:assert_eq(ntfe.recv(vm, rx), "judged", "once judged")
        f = assert(peer_flow(8120, 7120))
        t:assert_eq(f.judged, 1, "it records that it was")
        t:assert_eq(f.ifindex, net.ifindex, "the interface it was judged on")
        t:assert_eq(f.direction, ntfe.DIR.IN, "the direction")
        t:assert_eq(f.loopback, 0, "and that it is not loopback")

        -- A later judgment, on a packet going the other way out of
        -- another seat, does not overwrite them.
        flow_policy({ again = { Actions = { "PASS" } } })
        local _, events = E:during(function()
            ntfe.sendto(vm, rx, "back", net.peer_addr, 8120)
        end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 7120 }), 1,
            "a reply re-judged the flow: " .. ntfe.describe(events))
        f = assert(peer_flow(8120, 7120))
        t:assert_eq(f.direction, ntfe.DIR.IN, "and the recorded direction is the first judgment's")
        t:assert_eq(f.ifindex, net.ifindex, "as is the interface")
        sys.close(vm, rx)
    end)

test("the cache holds the verdict only: effects run once per evaluation, never per cached packet",
    { spec = "PKM *ntfe-flow.cache-holds-verdict-only PKM *ntfe-flow.effects-per-evaluation-not-per-packet" },
    function(t)
        flow_policy({ seen = { Actions = { "TAG(seen, Add)", "PASS" } } })
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7130))
        local c, a
        local delta = E:during(function()
            c = assert(ntfe.tcp_connect(peer, net.addr, 7130))
            a = assert(ntfe.tcp_accept(vm, l))
            for i = 1, 4 do
                ntfe.send(peer, c, "ping" .. i)
                t:assert_eq(ntfe.recv(vm, a), "ping" .. i, "the connection carries data")
            end
        end)
        local function tag()
            local f = assert(nf.flow(E, { protocol = ntfe.IPPROTO.TCP, dst_port = 7130 }))
            return f.tags[ntfe.name_hash("seen")]
        end
        t:assert(delta.flow_cached >= 5, "many packets read the sentence: " .. delta.flow_cached)
        t:assert_eq(delta.fx_tags, 1, "the TAG ran once")
        t:assert_eq(tag(), 1, "so the flow's tag counted one evaluation, not one per packet")

        flow_policy({ ["seen-again"] = { Actions = { "TAG(seen, Add)", "PASS" } } })
        local d2 = E:during(function()
            for i = 5, 8 do
                ntfe.send(peer, c, "ping" .. i)
                t:assert_eq(ntfe.recv(vm, a), "ping" .. i, "the connection carries on")
            end
        end)
        t:assert_eq(d2.flow_rejudged, 1, "a new generation re-judged it")
        t:assert_eq(d2.fx_tags, 1, "and the effects ran again, once")
        t:assert_eq(tag(), 2, "so the tag is two")
        sys.close(peer, c); sys.close(vm, a); sys.close(vm, l)
    end)

test("DROP and REJECT sentences persist for the flow's life, answering every later packet",
    { spec = "PKM *ntfe-flow.drop-reject-sentences-persist" },
    function(t)
        flow_policy(PASS_ALL)
        local rrx, refuse_send = udp_from_peer(8140, 7140)
        local drx, drop_send = udp_from_peer(8141, 7141)
        refuse_send("open"); drop_send("open")
        t:assert(ntfe.recv(vm, rrx) and ntfe.recv(vm, drx), "both flows are opened")

        flow_policy({
            all = { Actions = { "PASS" } },
            refuse = { ["DstPort.Equal"] = 7140, Actions = { "REJECT" } },
            drop = { ["DstPort.Equal"] = 7141, Actions = { "DROP" } },
        })
        local d1, e1 = E:during(function() refuse_send("judged"); drop_send("judged") end)
        t:assert_eq(#nf.flow_events(e1, { dst_port = 7140 }) + #nf.flow_events(e1, { dst_port = 7141 }), 2,
            "the next packet of each is re-judged: " .. ntfe.describe(e1))
        t:assert_eq(d1.refusals_emitted, 1, "the REJECT answers")

        local delta, events = E:during(function()
            for i = 1, 3 do refuse_send("again" .. i); drop_send("again" .. i) end
        end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 7140 }), 0, "later packets are not judged")
        t:assert_eq(#nf.flow_events(events, { dst_port = 7141 }), 0, "on either flow")
        t:assert(delta.flow_cached >= 6, "they read the sentences: " .. delta.flow_cached)
        t:assert_eq(delta.refusals_emitted, 3, "every packet of the refused flow is refused again")
        t:assert_eq(select(2, ntfe.recv(vm, rrx, 100)), "timeout", "none arrives")
        t:assert_eq(select(2, ntfe.recv(vm, drx, 100)), "timeout", "nor on the dropped flow")
        t:assert_eq(assert(peer_flow(8140, 7140)).sentences[0].verdict, ntfe.VERDICT.REJECT,
            "the REJECT sentence is still there")
        t:assert_eq(assert(peer_flow(8141, 7141)).sentences[0].verdict, ntfe.VERDICT.DROP,
            "and the DROP one")
        sys.close(vm, rrx); sys.close(vm, drx)
    end)

test("a DROP or REJECT on a new flow kills the entry, so a retry is a fresh flow judged again",
    { spec = "PKM *ntfe-flow.new-flow-drop-reject-kills-entry" },
    function(t)
        flow_policy({
            all = { Actions = { "PASS" } },
            drop = { ["DstPort.Equal"] = { "7150", "7152" }, Actions = { "DROP" } },
            refuse = { ["DstPort.Equal"] = 7151, Actions = { "REJECT" } },
        })
        local pl = assert(ntfe.tcp_listen(peer, net.peer_addr, 7150))
        local pl2 = assert(ntfe.tcp_listen(peer, net.peer_addr, 7151))
        -- The same source port each time, so a surviving entry would be
        -- found again.
        for _, c in ipairs({
            { port = 7150, sport = 40150, why = "timeout", what = "DROP" },
            { port = 7151, sport = 40151, why = sys.E.CONNREFUSED, what = "REJECT" },
        }) do
            local delta, events = E:during(function()
                for try = 1, 2 do
                    local _, why = ntfe.tcp_connect(vm, net.peer_addr, c.port, 300,
                        { bind = { net.addr, c.sport } })
                    t:assert_eq(why, c.why, "attempt " .. try .. " is refused by the " .. c.what)
                    t:assert_eq(#nf.flows_matching(assert(E:flows()), { src_port = c.sport }), 0,
                        "and leaves no entry behind")
                end
            end)
            local judged = nf.flow_events(events, { dst_port = c.port })
            t:assert_eq(#judged, 2, "each attempt was judged afresh: " .. ntfe.describe(judged))
            t:assert(not judged[1].rejudged and not judged[2].rejudged, "as a new flow, not a re-judgment")
            t:assert_eq(delta.flow_rejudged, 0, "nothing was re-judged")
        end
        sys.close(peer, pl); sys.close(peer, pl2)

        -- Inbound, the same at LOCAL_IN.
        local rx, send = udp_from_peer(8152, 7152)
        local _, events = E:during(function() send("one"); send("two") end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 7152 }), 2,
            "an inbound datagram the Flow layer drops leaves nothing for the next to read")
        t:assert(not peer_flow(8152, 7152), "and no entry")
        sys.close(vm, rx)
    end)

test("a flow with no extension has nowhere to hold a sentence and is evaluated on every packet",
    { spec = "PKM *ntfe-flow.no-extension-evaluated-per-packet PKM *ntfe-stream.confess-flow-uncached" },
    function(t)
        flow_policy(PASS_ALL)
        -- ctnetlink creates its entries without init_conntrack(), the only
        -- place the NTFE extension is added.
        assert(nf.ct_create(vm, { src = net.peer_addr, dst = net.addr, sport = 8160, dport = 7160 }))
        local rx, send = udp_from_peer(8160, 7160)
        local delta, events = E:during(function()
            for i = 1, 3 do
                send("each" .. i)
                t:assert_eq(ntfe.recv(vm, rx), "each" .. i, "the datagram is passed")
            end
        end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 7160 }), 3,
            "and judged, every one: " .. ntfe.describe(events))
        t:assert_eq(delta.flow_uncached, 3, "each evaluation counted as one with nowhere to cache")
        local f = assert(peer_flow(8160, 7160))
        t:assert_eq(f.judged, 0, "the dump shows no extension's record")
        t:assert_eq(f.sentences[0].generation, 0, "no sentence")
        t:assert_eq(f.start_secs, 0, "and no start")
        sys.close(vm, rx)
    end)

-- The sentence's concurrency protocol is a property of interleavings no
-- guest can arrange on demand.
test("a sentence write zeroes the generation, writes the fields, and publishes the generation last",
    { spec = "PKM *ntfe-flow.sentence-write-publishes-generation-last",
      covered_by = "kunit:TODO",
      skip = "the write's ordering is visible only to a reader racing it on another CPU, " ..
             "which no guest traffic can schedule; wanted: a KUnit case in pkm/ntfe/kunit.c " ..
             "that writes a sentence through peios_ntfe_flow_dispatch and checks that a " ..
             "slot read mid-write (generation zeroed, fields set) is not applied" },
    function(t) end)

test("a torn sentence reads as absent and the flow is simply evaluated",
    { spec = "PKM *ntfe-flow.torn-sentence-reads-absent",
      covered_by = "kunit:TODO",
      skip = "a torn read needs a writer between the reader's two loads of the generation, " ..
             "which no guest traffic can arrange; wanted: a KUnit case that sets a slot's " ..
             "fields with generation 0 (and one whose generation changes between reads) and " ..
             "checks the dispatch evaluates the forest (flow_judged moves, flow_cached does not)" },
    function(t) end)

test("two packets of a new flow racing on two CPUs may both evaluate; the second write wins",
    { spec = "PKM *ntfe-flow.first-packet-race-second-write-wins",
      covered_by = "kunit:TODO",
      skip = "the race needs a flow's first two packets in the hook concurrently on two CPUs, " ..
             "which the guest cannot schedule deterministically; wanted: a KUnit case that " ..
             "dispatches the same new flow twice with no sentence between the evaluations " ..
             "(two snapshots, one ct) and checks both evaluated (effects counted twice) and " ..
             "the slot holds the second outcome" },
    function(t) end)
