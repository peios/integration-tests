-- PKM §6.B — "Flow records": what each member of `struct
-- peios_ntfe_flow_rec` means. The conntrack id, the original-direction
-- tuple and the ICMP fields, the first-judgment fields `judged` gates,
-- the sentence slots as parallel arrays, the rule hash, conntrack's
-- accounting and lifetime, the start time, the tags and their count, the
-- per-slot identities and the strides they are flattened at; with the
-- bounds of two sentences a flow and 32 records a copy-out.
--
-- Where a statement is about layout, the record's raw bytes are indexed
-- directly; elsewhere helpers/ntfe's decoding is used.
--
-- Own VM: the policy and the clock are machine-wide state, and the
-- first flow here must be made while nothing has ever been ingested.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local raw = require("helpers.ntfe_abi_notes")
local token = require("helpers.token")

local vm = provium:vm("vntfeabiflow", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))
local peer, net = ntfe.peer(vm)

-- A loopback connection made at generation 0, then left idle: no packet
-- of it crosses a seat once a policy exists, so it is never judged.
local gen0_listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7700))
local gen0_client = assert(ntfe.tcp_connect(vm, "127.0.0.1", 7700))
local gen0_server = assert(ntfe.tcp_accept(vm, gen0_listener))

local PASS_ALL = { all = { Actions = { "PASS" } } }
local BASE = { RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL }
local E = ntfe.engine(vm, BASE)

local function flow_policy(flow)
    local s = E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = flow })
    assert(s.last_ingest_error == 0, "the policy is accepted: " .. s.last_ingest_error)
    return s
end

--- The live flows matching every field of `want`, decoded.
local function flows(want)
    local out = {}
    for _, f in ipairs(assert(E:flows(512))) do
        local ok = true
        for k, v in pairs(want) do
            if f[k] ~= v then ok = false; break end
        end
        if ok then out[#out + 1] = f end
    end
    return out
end

--- The one flow matching `want`, decoded, with its raw record as `raw`.
local function flow(want)
    local list = flows(want)
    if #list ~= 1 then return nil, #list end
    local d = raw.dump(vm, E.dev, "flows", 512)
    list[1].raw = raw.flow_record(d, list[1].id)
    return list[1]
end

local function all_zero(bytes) return not bytes:find("[^%z]") end
local function bytes_at(f, off, len) return f.raw:sub(off + 1, off + len) end

--- A loopback TCP connection to `port`, left open. Returns a closer.
local function loopback_tcp(port, server_who)
    server_who = server_who or vm
    local l = assert(ntfe.tcp_listen(server_who, "127.0.0.1", port))
    local c = assert(ntfe.tcp_connect(vm, "127.0.0.1", port))
    return function() sys.close(vm, c); sys.close(server_who, l) end, c
end

--- A UDP flow from this machine to the peer, from `sport` to `dport`.
local function udp_to_peer(sport, dport, data)
    local rx = assert(ntfe.udp_bind(peer, net.peer_addr, dport))
    local tx = assert(ntfe.udp_connect(vm, net.peer_addr, dport, { bind = { net.addr, sport } }))
    ntfe.send(vm, tx, data or "x")
    return rx, tx
end

-- ---- identity of the record ----

test("`id` is conntrack's id for the flow, stable for its life",
    { spec = "PKM *ntfe-abi-notes.flow-rec-id-stable" }, function(t)
        local rx, tx = udp_to_peer(7710, 7711)
        local first = flow({ dst_port = 7711 })
        t:assert(first, "the flow is listed")
        t:assert(first.id ~= 0, "with an id")
        ntfe.send(vm, tx, "more")
        local again = flow({ dst_port = 7711 })
        t:assert_eq(again.id, first.id, "the next dump lists it under the same id")
        t:assert(again.packets[1] > first.packets[1], "though the flow itself moved on")
        local rx2, tx2 = udp_to_peer(7712, 7713)
        t:assert(flow({ dst_port = 7713 }).id ~= first.id, "another flow has another id")
        for _, fd in ipairs({ tx, tx2 }) do sys.close(vm, fd) end
        for _, fd in ipairs({ rx, rx2 }) do sys.close(peer, fd) end
    end)

test("the addresses and ports are the original direction's: the originator first",
    { spec = "PKM *ntfe-abi-notes.flow-rec-original-direction-tuple" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7714))
        local c = assert(ntfe.tcp_connect(peer, net.addr, 7714))
        local s = assert(ntfe.tcp_accept(vm, l))
        ntfe.send(vm, s, "the reply direction speaks")
        local f = flow({ dst_port = 7714 })
        t:assert(f, "the peer's connection is listed by its destination port")
        t:assert_eq(f.src, net.peer_addr, "`src_addr` is the originator, the peer")
        t:assert_eq(f.dst, net.addr, "`dst_addr` the machine it connected to")
        t:assert(f.src_port ~= 7714, "`src_port` is the originator's own port")
        t:assert_eq(f.seen_reply, 1, "though the reply direction has carried traffic")
        sys.close(peer, c); sys.close(vm, s); sys.close(vm, l)
    end)

test("for ICMP, `src_port` carries the echo id, `icmp_type`/`icmp_code` the type and code, `dst_port` is 0",
    { spec = "PKM *ntfe-abi-notes.flow-rec-icmp-fields" }, function(t)
        local rs = vm:syscall(ntfe.NR.socket, ntfe.AF_INET, ntfe.SOCK_RAW, ntfe.IPPROTO.ICMP)
        t:assert(rs.ret >= 0, "a raw ICMP socket opens")
        ntfe.sendto(vm, rs.ret, ntfe.icmp(8, 0, 0x5A5A << 16 | 7, "ping"), net.peer_addr, 0)
        local f = flow({ protocol = ntfe.IPPROTO.ICMP, src_port = 0x5A5A })
        sys.close(vm, rs.ret)
        t:assert(f, "the echo is a flow keyed by its id")
        t:assert_eq(f.icmp_type, 8, "`icmp_type` is the echo request's")
        t:assert_eq(f.icmp_code, 0, "`icmp_code` its code")
        t:assert_eq(f.dst_port, 0, "and `dst_port` is 0")
    end)

-- ---- judged ----

test("`direction`, `ifindex` and `loopback` are those of the first judgment, and meaningful only when `judged` is 1",
    { spec = "PKM *ntfe-abi-notes.flow-rec-judged-gates-first-judgment-fields" }, function(t)
        local l = assert(ntfe.tcp_listen(vm, net.addr, 7715))
        local c = assert(ntfe.tcp_connect(peer, net.addr, 7715))
        local inbound = flow({ dst_port = 7715 })
        t:assert_eq(inbound.judged, 1, "a judged flow")
        t:assert_eq(inbound.direction, ntfe.DIR.IN, "records the direction it was judged in")
        t:assert_eq(inbound.ifindex, net.ifindex, "the interface it arrived on")
        t:assert_eq(inbound.loopback, 0, "and that it is not a loopback flow")
        sys.close(peer, c); sys.close(vm, l)
        local close = loopback_tcp(7716)
        local lo = flow({ dst_port = 7716 })
        t:assert_eq(lo.loopback, 1, "a judged loopback flow says so")
        t:assert_eq(lo.ifindex, assert(ntfe.if_index(vm, "lo")), "on the loopback")
        close()
        local never = flow({ dst_port = 7700 })
        t:assert(never, "the generation-0 connection is still listed")
        t:assert_eq(never.judged, 0, "never judged")
        t:assert_eq(never.loopback, 0, "so its `loopback` is unset, though it is one")
        t:assert_eq(never.ifindex, 0, "its `ifindex` is unset")
        t:assert_eq(never.direction, 0, "and its `direction` means nothing")
    end)

test("a flow with `judged` 0 began under a permissive generation",
    { spec = "PKM *ntfe-abi-notes.flow-rec-unjudged-began-permissive" }, function(t)
        local never = flow({ dst_port = 7700 })
        t:assert_eq(never.judged, 0, "the connection made at generation 0 is unjudged")
        t:assert_eq(never.sentences[0].generation, 0, "and holds no sentence")
        -- A generation without a Flow forest is permissive in that layer.
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL })
        local rx, tx = udp_to_peer(7717, 7718)
        local f = flow({ dst_port = 7718 })
        E:replace(BASE)
        t:assert(f, "a flow begun while no Flow forest stood is listed")
        t:assert_eq(f.judged, 0, "unjudged too")
        sys.close(vm, tx); sys.close(peer, rx)
    end)

-- ---- sentences ----

test("the sentences are parallel arrays by slot: slot 0 the flow's, slot 1 a loopback flow's inbound end",
    { spec = "PKM *ntfe-abi-notes.flow-rec-sentence-slots" }, function(t)
        local gen = E:status().generation
        local rx, tx = udp_to_peer(7719, 7720)
        local far = flow({ dst_port = 7720 })
        t:assert_eq(far.sentences[0].generation, gen, "a flow to the peer has its sentence in slot 0")
        t:assert_eq(far.sentences[1].generation, 0, "and nothing in slot 1")
        sys.close(vm, tx); sys.close(peer, rx)
        local close = loopback_tcp(7721)
        local lo = flow({ dst_port = 7721 })
        t:assert_eq(lo.sentences[0].generation, gen, "a loopback flow's outbound end is slot 0")
        t:assert_eq(lo.sentences[1].generation, gen, "its inbound end slot 1")
        t:assert_eq(string.unpack("<I8", lo.raw, 105), gen, "`sentence_generation[0]` at byte 104")
        t:assert_eq(string.unpack("<I8", lo.raw, 113), gen, "`sentence_generation[1]` right after it")
        t:assert_eq(lo.raw:byte(153), ntfe.VERDICT.PASS, "`sentence_verdict[0]`")
        t:assert_eq(lo.raw:byte(154), ntfe.VERDICT.PASS, "and `sentence_verdict[1]` beside it")
        close()
    end)

test("a slot whose `sentence_generation` is 0 is empty",
    { spec = "PKM *ntfe-abi-notes.flow-rec-generation-0-empty" }, function(t)
        local rx, tx = udp_to_peer(7722, 7723)
        local f = flow({ dst_port = 7723 })
        t:assert_eq(f.sentences[1].generation, 0, "slot 1 of a flow to the peer reads generation 0")
        t:assert_eq(string.unpack("<i8", f.raw, 129), 0, "and holds no expiry")
        t:assert_eq(string.unpack("<I8", f.raw, 145), 0, "no rule hash")
        t:assert_eq(f.raw:byte(154), 0, "no verdict")
        t:assert_eq(f.raw:byte(156), 0, "and no reject kind: it is empty")
        sys.close(vm, tx); sys.close(peer, rx)
    end)

test("`sentence_expires_at` 0 means never",
    { spec = "PKM *ntfe-abi-notes.flow-rec-expires-0-never" }, function(t)
        local rx, tx = udp_to_peer(7724, 7725)
        local plain = flow({ dst_port = 7725 })
        t:assert_eq(plain.sentences[0].expires_at, 0,
            "a judgment that consulted no clock never expires: 0")
        sys.close(vm, tx); sys.close(peer, rx)
        local t0 = 2000000000 -- 03:33:20 UTC
        vm:clock():set(t0)
        flow_policy({ all = { Actions = { "PASS" } },
                      timed = { ["DstPort.Equal"] = 7727, ["Time.Hour.Equal"] = 3,
                                Actions = { "PASS" } } })
        rx, tx = udp_to_peer(7726, 7727)
        local timed = flow({ dst_port = 7727 })
        E:replace(BASE)
        t:assert(timed.sentences[0].expires_at > t0,
            "one that consulted the hour expires when it flips: " .. timed.sentences[0].expires_at)
        t:assert(timed.sentences[0].expires_at <= t0 + 3600, "within the hour")
        sys.close(vm, tx); sys.close(peer, rx)
    end)

test("`sentence_rule_hash` is FNV-1a-64 of the attributing path relative to the layer key",
    { spec = "PKM *ntfe-abi-notes.flow-rec-rule-hash-fnv1a-64" }, function(t)
        flow_policy({ all = { Actions = { "PASS" } },
                      outer = { ["DstPort.Equal"] = 7729, Priority = 10, Actions = { "PASS" },
                                children = { inner = { ["Protocol.Equal"] = "udp",
                                                       Actions = { "PASS" } } } } })
        local rx, tx = udp_to_peer(7728, 7729)
        local f = flow({ dst_port = 7729 })
        t:assert_eq(f.sentences[0].rule_hash, ntfe.name_hash("outer/inner"),
            "the hash is of `outer/inner`")
        t:assert_eq(ntfe.name_hash(""), 0xcbf29ce484222325, "(the offset basis is 0xcbf29ce484222325)")
        sys.close(vm, tx); sys.close(peer, rx)
        -- `backstop` hashes like a path: re-judge a live flow under a
        -- policy nothing in which speaks for it.
        local close, c = loopback_tcp(7730)
        flow_policy({ only = { ["DstPort.Equal"] = 1, Actions = { "PASS" } } })
        ntfe.send(vm, c, "judged again")
        local b = flow({ dst_port = 7730 })
        E:replace(BASE)
        t:assert_eq(b.sentences[0].rule_hash, ntfe.name_hash("backstop"),
            "a backstop sentence hashes the word `backstop`")
        close()
    end)

test("`sentence_rule_hash` of a path longer than the event's field is of the whole path",
    { spec = "PKM *ntfe-abi-notes.flow-rec-rule-hash-fnv1a-64",
      -- The hash was once taken over the event's 95-byte copy of the
      -- path (PEI-1308).
    }, function(t)
        local a, b = string.rep("a", 60), string.rep("b", 60)
        flow_policy({ all = { Actions = { "PASS" } },
                      [a] = { ["DstPort.Equal"] = 7732, Priority = 10, Actions = { "PASS" },
                              children = { [b] = { ["Protocol.Equal"] = "udp",
                                                   Actions = { "PASS" } } } } })
        local rx, tx = udp_to_peer(7731, 7732)
        local f = flow({ dst_port = 7732 })
        E:replace(BASE)
        sys.close(vm, tx); sys.close(peer, rx)
        t:assert_eq(f.sentences[0].rule_hash, ntfe.name_hash(a .. "/" .. b),
            "the hash is of the attributing path, all 121 bytes of it")
    end)

test("`fail-closed` is never a sentence's: a failed evaluation is not cached",
    { spec = "PKM *ntfe-abi-notes.flow-rec-fail-closed-never-cached", covered_by = "kunit:pkm_kunit_ntfe",
      skip = "an evaluation fails only when its GFP_ATOMIC allocation is refused, which " ..
             "the kernel under test cannot be made to do (CONFIG_FAULT_INJECTION is not " ..
             "set), so no guest flow can carry the outcome; runs under " ..
             "ntfe_kunit_eval_failure_fails_closed, which fails a Flow dispatch's " ..
             "evaluation, finds slot 0's generation still 0, and sees the flow's next " ..
             "packet judged and sentenced" },
    function(t) end)

-- ---- conntrack's view ----

test("`packets` and `bytes` are conntrack's accounting, original direction then reply",
    { spec = "PKM *ntfe-abi-notes.flow-rec-accounting-original-then-reply" }, function(t)
        local rx = assert(ntfe.udp_bind(peer, net.peer_addr, 7734))
        local tx = assert(ntfe.udp_connect(vm, net.peer_addr, 7734, { bind = { net.addr, 7733 } }))
        for _ = 1, 3 do ntfe.send(vm, tx, string.rep("o", 10)) end
        ntfe.sendto(peer, rx, string.rep("r", 20), net.addr, 7733)
        t:assert(ntfe.recv(vm, tx), "the reply arrives")
        local f = flow({ dst_port = 7734 })
        t:assert_eq(f.packets[1], 3, "three packets went the original way")
        t:assert_eq(f.packets[2], 1, "one came back")
        t:assert_eq(f.bytes[1], 3 * (20 + 8 + 10), "the original direction's bytes, IP headers included")
        t:assert_eq(f.bytes[2], 20 + 8 + 20, "and the reply's")
        sys.close(vm, tx); sys.close(peer, rx)
    end)

test("NTFE enables conntrack's accounting at init",
    { spec = "PKM *ntfe-abi-notes.init-enables-conntrack-acct" }, function(t)
        -- Linux defaults nf_conntrack_acct to 0, and nothing on this
        -- machine has written it: only NTFE's init can have.
        t:assert_eq(raw.readfile(vm, "/proc/sys/net/netfilter/nf_conntrack_acct"), "1\n",
            "nf_conntrack_acct reads 1")
        local rx, tx = udp_to_peer(7735, 7736)
        t:assert_eq(flow({ dst_port = 7736 }).packets[1], 1, "and a flow's packets are counted")
        sys.close(vm, tx); sys.close(peer, rx)
    end)

test("`timeout_secs` is the entry's remaining lifetime as conntrack sees it",
    { spec = "PKM *ntfe-abi-notes.flow-rec-timeout-remaining" }, function(t)
        local udp_timeout = tonumber(raw.readfile(vm, "/proc/sys/net/netfilter/nf_conntrack_udp_timeout"))
        local rx, tx = udp_to_peer(7737, 7738)
        local f = flow({ dst_port = 7738 })
        t:assert(f.timeout_secs <= udp_timeout and f.timeout_secs >= udp_timeout - 5,
            "an unanswered UDP flow has about nf_conntrack_udp_timeout left: "
            .. f.timeout_secs .. " of " .. udp_timeout)
        sys.close(vm, tx); sys.close(peer, rx)
        local established = tonumber(raw.readfile(vm,
            "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established"))
        local close = loopback_tcp(7739)
        local tcp = flow({ dst_port = 7739 })
        t:assert(tcp.timeout_secs <= established and tcp.timeout_secs >= established - 5,
            "an established TCP flow has about its established timeout left: "
            .. tcp.timeout_secs .. " of " .. established)
        close()
    end)

test("`start_secs` is the CLOCK_REALTIME second conntrack created the flow",
    { spec = "PKM *ntfe-abi-notes.flow-rec-start-secs" }, function(t)
        local t0 = 2100000000
        vm:clock():set(t0)
        local rx, tx = udp_to_peer(7740, 7741)
        vm:clock():set(t0 + 500)
        ntfe.send(vm, tx, "later")
        local f = flow({ dst_port = 7741 })
        t:assert(f.start_secs >= t0 and f.start_secs <= t0 + 5,
            "the wall-clock second it began: " .. f.start_secs)
        sys.close(vm, tx); sys.close(peer, rx)
    end)

-- ---- tags ----

--- A Flow policy that sets `n` tags t1..tn, tag i to value 11 × i.
local function tagging(port, n)
    local actions = { "PASS" }
    for i = 1, n do actions[#actions + 1] = string.format("TAG(t%d, Set, %d)", i, 11 * i) end
    flow_policy({ all = { Actions = { "PASS" } },
                  tagger = { ["DstPort.Equal"] = port, Actions = actions } })
end

test("`tag_hash` and `tag_value` hold up to 8 present tags by name hash and value",
    { spec = "PKM *ntfe-abi-notes.flow-rec-up-to-8-tags" }, function(t)
        tagging(7743, 3)
        local rx, tx = udp_to_peer(7742, 7743)
        local f = flow({ dst_port = 7743 })
        sys.close(vm, tx); sys.close(peer, rx)
        for i = 1, 3 do
            t:assert_eq(f.tags[ntfe.name_hash("t" .. i)], 11 * i,
                "tag t" .. i .. " is listed by its name's hash, with its value")
        end
        tagging(7745, 10)
        rx, tx = udp_to_peer(7744, 7745)
        local many = flow({ dst_port = 7745 })
        E:replace(BASE)
        sys.close(vm, tx); sys.close(peer, rx)
        local listed = 0
        for hash, value in pairs(many.tags) do
            listed = listed + 1
            local known = false
            for i = 1, 10 do
                if hash == ntfe.name_hash("t" .. i) and value == 11 * i then known = true end
            end
            t:assert(known, "each listed tag is one of the flow's, with its value")
        end
        t:assert_eq(listed, 8, "a flow with ten tags lists eight")
    end)

test("`n_tags` is the flow's total, so above 8 some are not listed",
    { spec = "PKM *ntfe-abi-notes.flow-rec-n-tags-is-total",
      -- `n_tags` was once clamped to the 8 listed (PEI-1308).
    }, function(t)
        tagging(7747, 10)
        local rx, tx = udp_to_peer(7746, 7747)
        local f = flow({ dst_port = 7747 })
        E:replace(BASE)
        sys.close(vm, tx); sys.close(peer, rx)
        t:assert_eq(f.n_tags, 10, "a flow with ten tags says ten")
    end)

-- ---- identities ----

test("`owner_kind[slot]` is the end's kind per sentence slot, ABSENT until resolved",
    { spec = "PKM *ntfe-abi-notes.flow-rec-owner-kind-per-slot" }, function(t)
        local close = loopback_tcp(7748)
        local lo = flow({ dst_port = 7748 })
        t:assert_eq(lo.owners[0].kind, ntfe.LOCAL.PROGRAM, "slot 0, the connecting end, is a program")
        t:assert_eq(lo.owners[1].kind, ntfe.LOCAL.PROGRAM, "slot 1, the listening end, is a program")
        t:assert_eq(lo.raw:byte(289), ntfe.LOCAL.PROGRAM, "`owner_kind[0]` at byte 288")
        t:assert_eq(lo.raw:byte(290), ntfe.LOCAL.PROGRAM, "`owner_kind[1]` beside it")
        close()
        local never = flow({ dst_port = 7700 })
        t:assert_eq(never.owners[0].kind, ntfe.LOCAL.ABSENT, "a flow never judged has resolved nobody")
        t:assert_eq(never.owners[1].kind, ntfe.LOCAL.ABSENT, "in either slot")
    end)

test("the per-slot identity arrays are flattened at fixed strides: slot 1's user SID starts at byte 68",
    { spec = "PKM *ntfe-abi-notes.flow-rec-owner-array-strides" }, function(t)
        -- A datagram injected onto the loopback is judged only at the
        -- inbound seat: slot 1 holds the receiver and slot 0 stays empty,
        -- so whatever is found in slot 1's place can only have been put
        -- there as slot 1. The receiver is bound by a worker that then
        -- becomes a principal with a service SID and restamps the socket
        -- (an ordinary user may not bind the port itself).
        local service = token.sid(5, 80, 1, 2, 3, 4, 5)
        local w = vm:spawn_worker()
        local wpid = w:syscall(sys.NR.getpid).ret
        local rx = assert(ntfe.udp_bind(w, "127.0.0.1", 7749))
        local tok = assert(token.mint(w, {
            groups = { { sid = token.SID.EVERYONE, attributes = 0x7 },
                       { sid = service, attributes = 0x7 } },
        }))
        t:assert_eq(token.install(w, tok).ret, 0, "the worker becomes the principal")
        t:assert_eq(raw.restamp(w, rx).ret, 0, "and restamps its socket as its own")
        raw.inject_lo_udp(vm, 7748, 7749, "stride")
        local f = flow({ dst_port = 7749 })
        sys.close(w, rx)
        t:assert(f, "the injected loopback flow is listed")
        t:assert_eq(f.loopback, 1, "as a loopback flow")
        local USER, SVC, GUID, COMM, PID = 368, 504, 304, 336, 296
        t:assert(all_zero(bytes_at(f, USER, 68)), "slot 0's user SID, bytes 0..67 of `owner_user`, is empty")
        t:assert_eq(bytes_at(f, USER + 68, #token.SID.TEST_USER), token.SID.TEST_USER,
            "slot 1's user SID starts at byte 68")
        t:assert(all_zero(bytes_at(f, SVC, 32)), "slot 0's service SID is empty")
        t:assert_eq(bytes_at(f, SVC + 32, #service), service,
            "slot 1's service SID starts at byte 32 of `owner_service`")
        t:assert(all_zero(bytes_at(f, COMM, 16)), "slot 0's comm is empty")
        t:assert_eq(bytes_at(f, COMM + 16, 16):match("^[^%z]*"), raw.comm(vm, wpid),
            "slot 1's starts at byte 16 of `owner_comm`")
        t:assert(all_zero(bytes_at(f, GUID, 16)), "slot 0's GUID is empty")
        t:assert(not all_zero(bytes_at(f, GUID + 16, 16)),
            "slot 1's starts at byte 16 of `owner_guid`")
        t:assert_eq(string.unpack("<i4", f.raw, PID + 4 + 1), wpid,
            "and `owner_pid[1]` is the receiver's pid, 4 bytes on")
    end)

test("each slot of a loopback flow holds its own end's identity",
    { spec = "PKM *ntfe-abi-notes.flow-rec-owner-kind-per-slot",
      -- Slot 1 once recorded the sender (PEI-1301).
    }, function(t)
        local W = vm:spawn_worker()
        local wpid = W:syscall(sys.NR.getpid).ret
        local agent = vm:syscall(sys.NR.getpid).ret
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 7759))
        local c = assert(ntfe.tcp_connect(W, "127.0.0.1", 7759))
        local f = flow({ dst_port = 7759 })
        sys.close(W, c); sys.close(vm, l)
        t:assert_eq(f.owners[0].pid, wpid, "slot 0 is the connecting process")
        t:assert_eq(f.owners[1].pid, agent, "slot 1 is the listening process")
    end)

test("slot 1's identity is filled only for a loopback flow",
    { spec = "PKM *ntfe-abi-notes.flow-rec-owner-slot-1-loopback-only" }, function(t)
        local rx, tx = udp_to_peer(7750, 7751)
        local f = flow({ dst_port = 7751 })
        sys.close(vm, tx); sys.close(peer, rx)
        t:assert_eq(f.owners[0].kind, ntfe.LOCAL.PROGRAM, "a flow to the peer has its own end in slot 0")
        for _, r in ipairs({ { 289, 1 }, { 291, 1 }, { 300, 4 }, { 320, 16 }, { 352, 16 },
                             { 436, 68 }, { 536, 32 } }) do
            t:assert(all_zero(bytes_at(f, r[1], r[2])),
                "and every slot-1 identity byte at offset " .. r[1] .. " is zero")
        end
    end)

-- ---- bounds ----

test("a flow holds at most two sentences, the second only when it is a loopback flow",
    { spec = "PKM *ntfe-abi-notes.bound-sentences-per-flow-2" }, function(t)
        local gen = E:status().generation
        local close = loopback_tcp(7752)
        local lo = flow({ dst_port = 7752 })
        close()
        t:assert(lo.sentences[0].generation == gen and lo.sentences[1].generation == gen,
            "a loopback flow fills both slots: one per local end")
        local rx, tx = udp_to_peer(7753, 7754)
        local far = flow({ dst_port = 7754 })
        sys.close(vm, tx); sys.close(peer, rx)
        t:assert_eq(far.sentences[1].generation, 0, "any other flow fills only slot 0")
    end)

test("flows are copied out 32 at a time, and a dump of more is whole",
    { spec = "PKM *ntfe-abi-notes.bound-flow-batch-32" }, function(t)
        local fds = {}
        for port = 7800, 7869 do
            local fd = assert(ntfe.udp_connect(vm, "127.0.0.1", port))
            ntfe.send(vm, fd, "b")
            fds[#fds + 1] = fd
        end
        local d = raw.dump(vm, E.dev, "flows", 512)
        t:assert_eq(d.ret, 0, "the dump succeeds")
        t:assert(d.total >= 70, "seventy flows and more are live: " .. d.total)
        t:assert_eq(d.count, d.total, "every one is written, across more than two batches")
        local ids, ours = {}, 0
        for i = 1, d.count do
            local rec = raw.record(d, "flows", i)
            local id = string.unpack("<I4", rec, 1)
            t:assert(not ids[id], "no record is written twice")
            ids[id] = true
            local dport = string.unpack("<I2", rec, 55)
            if dport >= 7800 and dport <= 7869 then ours = ours + 1 end
        end
        t:assert_eq(ours, 70, "and none is missing")
        local cut = raw.dump(vm, E.dev, "flows", 33)
        t:assert_eq(cut.count, 33, "a buffer one past a batch holds 33")
        for _, fd in ipairs(fds) do sys.close(vm, fd) end
    end)
