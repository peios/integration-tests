-- PKM §6.8 — Staleness: a sentence goes stale when the generation moves
-- (a policy or a network context published) or the clock passes its
-- expiry, and is re-judged lazily on the flow's next packet; a refused
-- packet of an established TCP flow tears down both ends; and the
-- expiry itself, the earliest flip of a time condition the judgment
-- consulted, to which `Start.*` never contributes.
--
-- The guest clock is set to whole hours so the expected expiry is
-- arithmetic, and moved forward only.
--
-- Own VM: the policy and the clock are machine-wide state.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local nf = require("helpers.ntfe_flow")

local vm = provium:vm("vntfeflowstale", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

local PASS_ALL = { all = { Actions = { "PASS" } } }
local E = ntfe.engine(vm, { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })

local function flow_policy(flow)
    local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = flow })
    assert(s.last_ingest_error == 0, "the policy is accepted: " .. s.last_ingest_error)
    return s
end

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

-- The start of the next whole hour, with the clock set `offset` seconds
-- into it.
local function next_hour(offset)
    local now = math.floor(vm:clock():get())
    local base = now - now % 3600 + 3600
    vm:clock():set(base + (offset or 0))
    return base, (base // 3600) % 24
end

test("a published policy leaves every sentence alone until its flow next speaks",
    { spec = "PKM *ntfe-flow.staleness-checked-lazily PKM *ntfe-flow.stale-by-generation-or-expiry" },
    function(t)
        local s = flow_policy(PASS_ALL)
        local rx, send = udp_from_peer(8200, 7200)
        send("open")
        t:assert_eq(ntfe.recv(vm, rx), "open", "the flow is passed")
        local before = E:status()
        local s2 = flow_policy({
            all = { Actions = { "PASS" } },
            ["kill-7200"] = { ["DstPort.Equal"] = 7200, Actions = { "DROP" } },
        })
        t:assert_eq(s2.generation, s.generation + 1, "a policy that drops it is published")
        t:assert_eq(s2.flow_rejudged - before.flow_rejudged, 0, "and no flow was walked at publication")
        local f = assert(peer_flow(8200, 7200))
        t:assert_eq(f.sentences[0].generation, s.generation, "the idle flow's sentence is the old generation's")
        t:assert_eq(f.sentences[0].verdict, ntfe.VERDICT.PASS, "still saying PASS")

        local delta, events = E:during(function() send("speaks") end)
        t:assert_eq(select(2, ntfe.recv(vm, rx, 200)), "timeout", "when the flow next speaks it is killed")
        local judged = nf.flow_events(events, { dst_port = 7200 })
        t:assert(#judged == 1 and judged[1].rejudged and judged[1].attributed == "kill-7200",
            "by a re-judgment of its stale sentence: " .. ntfe.describe(events))
        t:assert_eq(delta.flow_rejudged, 1, "counted as stale by generation")
        f = assert(peer_flow(8200, 7200))
        t:assert_eq(f.sentences[0].generation, s2.generation, "and the sentence is now the new generation's")
        sys.close(vm, rx)
    end)

test("a published network context advances the same generation, and the next packet re-judges",
    { spec = "PKM *ntfe-flow.stale-by-generation-or-expiry" },
    function(t)
        local s = flow_policy({
            all = { Actions = { "PASS" } },
            ["home-only"] = { ["Network.Trust.Equal"] = "home", ["DstPort.Equal"] = 7210,
                              Priority = 10, Actions = { "DROP" } },
        })
        local rx, send = udp_from_peer(8210, 7210)
        send("before")
        t:assert_eq(ntfe.recv(vm, rx), "before", "with no network identified the flow is passed")
        local s2 = E:replace_inventory(
            { home = { Name = "Home", Trust = "home" } },
            { veth = { Name = net.name, Network = "home" } })
        t:assert_eq(s2.generation, s.generation + 1, "identifying a network publishes a generation")
        local delta, events = E:during(function() send("after") end)
        t:assert_eq(select(2, ntfe.recv(vm, rx, 200)), "timeout", "and the flow's next packet")
        local judged = nf.flow_events(events, { dst_port = 7210 })
        t:assert(#judged == 1 and judged[1].rejudged and judged[1].attributed == "home-only",
            "is re-judged in the new context: " .. ntfe.describe(events))
        t:assert_eq(delta.flow_rejudged, 1, "stale by generation, the one counter")
        E:replace_inventory({}, {})
        sys.close(vm, rx)
    end)

test("a sentence expires at the earliest flip of a time condition the judgment consulted",
    { spec = "PKM *ntfe-flow.expiry-earliest-consulted-flip PKM *ntfe-flow.stale-by-generation-or-expiry" },
    function(t)
        local h0, hour = next_hour(607) -- hh:10:07
        flow_policy({
            -- Consulted and true: flips at the next hour.
            ["in-hours"] = { ["Time.Hour.Equal"] = hour, Actions = { "PASS" } },
            -- Consulted and false: flips at minute 15.
            curfew = { ["Time.Minute.Equal"] = 15, Priority = 10, Actions = { "DROP" } },
            -- Never consulted (its address fails first): would flip at 11.
            ["one-host"] = { ["SrcAddr.Equal"] = "10.9.0.99", ["Time.Minute.Equal"] = 11,
                             Priority = 20, Actions = { "DROP" } },
        })
        local rx, send = udp_from_peer(8220, 7220)
        send("opened")
        t:assert_eq(ntfe.recv(vm, rx), "opened", "the flow is passed by the hour")
        local f = assert(peer_flow(8220, 7220))
        t:assert_eq(f.sentences[0].expires_at, h0 + 900,
            "and its sentence expires at minute 15, the false curfew's flip, not the hour's or minute 11's")

        vm:clock():set(h0 + 890)
        local d1, e1 = E:during(function() send("still") end)
        t:assert_eq(ntfe.recv(vm, rx), "still", "before the edge the sentence holds")
        t:assert_eq(#nf.flow_events(e1, { dst_port = 7220 }), 0, "unevaluated")
        t:assert_eq(d1.flow_expired, 0, "and unexpired")

        vm:clock():set(h0 + 903)
        local delta, events = E:during(function() send("curfew") end)
        t:assert_eq(select(2, ntfe.recv(vm, rx, 200)), "timeout", "past it, the next packet is judged again")
        local judged = nf.flow_events(events, { dst_port = 7220 })
        t:assert(#judged == 1 and judged[1].rejudged and judged[1].attributed == "curfew",
            "re-judged into the curfew: " .. ntfe.describe(events))
        t:assert_eq(delta.flow_expired, 1, "counted as stale by time")
        t:assert_eq(delta.flow_rejudged, 0, "not by generation")
        sys.close(vm, rx)
    end)

test("a forest with no time conditions never expires a sentence",
    { spec = "PKM *ntfe-flow.no-time-conditions-never-expires" },
    function(t)
        next_hour(0)
        flow_policy({
            all = { Actions = { "PASS" } },
            ["no-telnet"] = { ["DstPort.Equal"] = 23, Actions = { "DROP" } },
        })
        local rx, send = udp_from_peer(8230, 7230)
        send("opened")
        t:assert_eq(ntfe.recv(vm, rx), "opened", "the flow is passed")
        t:assert_eq(assert(peer_flow(8230, 7230)).sentences[0].expires_at, 0, "with a sentence that never expires")
        vm:clock():set(math.floor(vm:clock():get()) + 3 * 86400)
        local delta, events = E:during(function()
            send("days later")
            t:assert_eq(ntfe.recv(vm, rx), "days later", "three days on the flow is passed")
        end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 7230 }), 0, "by its sentence, unevaluated")
        t:assert_eq(delta.flow_expired, 0, "and nothing expired")
        sys.close(vm, rx)
    end)

test("Start.* conditions never contribute an expiry",
    { spec = "PKM *ntfe-flow.start-conditions-never-contribute-expiry" },
    function(t)
        local h0, hour = next_hour(600)
        local later = (hour + 1) % 24
        flow_policy({
            ["started-now"] = { ["Start.Hour.Equal"] = hour, Actions = { "PASS" } },
            -- Consulted and false, and its fact can never change.
            ["started-later"] = { ["Start.Hour.Equal"] = later, Priority = 10, Actions = { "DROP" } },
        })
        local rx, send = udp_from_peer(8240, 7240)
        send("opened")
        t:assert_eq(ntfe.recv(vm, rx), "opened", "a flow started this hour is passed")
        t:assert_eq(assert(peer_flow(8240, 7240)).sentences[0].expires_at, 0,
            "and its sentence never expires, though two Start.Hour conditions were consulted")

        vm:clock():set(h0 + 3600 + 600)
        local delta, events = E:during(function()
            send("next hour")
            t:assert_eq(ntfe.recv(vm, rx), "next hour", "an hour on, the flow carries on")
        end)
        t:assert_eq(#nf.flow_events(events, { dst_port = 7240 }), 0, "unevaluated")
        t:assert_eq(delta.flow_expired, 0, "unexpired")
        local rx2, send2 = udp_from_peer(8241, 7241)
        send2("new")
        t:assert_eq(select(2, ntfe.recv(vm, rx2, 200)), "timeout",
            "while a flow that starts in this hour is dropped by the same forest")
        sys.close(vm, rx); sys.close(vm, rx2)
    end)

-- An established connection, quiet: data both ways, then time for the
-- last acknowledgement to land, so the next packet is the one a test
-- sends.
local function established(port)
    flow_policy(PASS_ALL)
    local l = assert(ntfe.tcp_listen(vm, net.addr, port))
    local c = assert(ntfe.tcp_connect(peer, net.addr, port))
    local a = assert(ntfe.tcp_accept(vm, l))
    ntfe.send(peer, c, "hello")
    assert(ntfe.recv(vm, a) == "hello")
    ntfe.send(vm, a, "welcome")
    assert(ntfe.recv(peer, c) == "welcome")
    vm:clock():sleep(0.3)
    sys.close(vm, l)
    return c, a
end

test("a refused packet of an established TCP flow tears down both ends at once",
    { spec = "PKM *ntfe-flow.refused-established-tcp-teardown-both-ends" },
    function(t)
        for _, c in ipairs({
            { port = 7250, speaker = "us", why = "the packet our end sent" },
            { port = 7251, speaker = "peer", why = "the packet the peer sent" },
        }) do
            local theirs, ours = established(c.port)
            flow_policy({
                all = { Actions = { "PASS" } },
                cut = { ["DstPort.Equal"] = c.port, Actions = { "REJECT" } },
            })
            local delta, events = E:during(function()
                if c.speaker == "us" then
                    ntfe.send(vm, ours, "after")
                else
                    ntfe.send(peer, theirs, "after")
                end
                t:assert_eq(select(2, ntfe.recv(vm, ours, 500)), sys.E.CONNRESET,
                    "refusing " .. c.why .. " resets our socket")
                t:assert_eq(select(2, ntfe.recv(peer, theirs, 500)), sys.E.CONNRESET,
                    "and the peer's")
            end)
            local judged = nf.flow_events(events, { dst_port = c.port })
            t:assert(#judged == 1 and judged[1].attributed == "cut" and judged[1].rejudged,
                "the established flow was re-judged and refused: " .. ntfe.describe(events))
            t:assert_eq(delta.refusals_emitted, 1, "the sender got the refusal")
            t:assert_eq(delta.teardowns_emitted, 1, "and the other end the packet, turned into a reset")
            sys.close(vm, ours); sys.close(peer, theirs)
        end
    end)
