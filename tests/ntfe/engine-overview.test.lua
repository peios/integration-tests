-- PKM §6.1 — NTFE as a whole: the kernel reads its own policy from the
-- registry and enforces it with nobody else in the path, on a netfilter
-- that keeps the hook framework and conntrack and none of the old
-- frontends; generation 0 is permissive, and every ingestion advances
-- the generation.
--
-- The statements of §6.1 about how the source is divided between C and
-- Rust are properties of the tree, not of a running kernel; they are
-- cited here as skips naming where each is held.
--
-- Own VM: the policy is machine-wide state, and the first tests need a
-- kernel that has never ingested one.

local sys = require("helpers.sys")
local fixtures = require("helpers.fixtures")
local ntfe = require("helpers.ntfe")

local vm = provium:vm("vntfeov", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

-- Before any hive exists: a status fd, and one connection made while
-- nothing has ever been ingested.
local dev = assert(ntfe.open(vm))
local at_boot = assert(ntfe.status(vm, dev))
local boot_listener = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6100))
local boot_conn, boot_why = ntfe.tcp_connect(vm, "127.0.0.1", 6100)
local after_boot_traffic = assert(ntfe.status(vm, dev))

local PASS_ALL = { all = { Actions = { "PASS" } } }

-- The hive, holding a policy that passes everything but one port.
local E = ntfe.engine(vm, {
    RawPacket = PASS_ALL,
    Packet = PASS_ALL,
    Flow = {
        all = { Actions = { "PASS" } },
        ["closed-port"] = { ["DstPort.Equal"] = 6101, Actions = { "DROP" } },
    },
})

test("generation 0 means nothing was ever ingested, and every layer is permissive",
    { spec = "PKM *ntfe-engine.generation-zero-is-permissive" }, function(t)
        t:assert_eq(at_boot.generation, 0, "a kernel with no registry source is at generation 0")
        t:assert_eq(at_boot.enforcing, 0, "and says it is not enforcing")
        t:assert(boot_conn, "a connection made then is let through: " .. tostring(boot_why))
        t:assert_eq(after_boot_traffic.judged, 0, "judged by no forest")
        t:assert(after_boot_traffic.permissive > at_boot.permissive,
            "and counted as permissive, which is the loud part")
    end)

test("the engine judges traffic against the policy it reads from the registry itself",
    { spec = "PKM *ntfe-engine.judges-from-registry-policy-itself" }, function(t)
        local s = E:status()
        t:assert_eq(s.enforcing, 1, "registering a hive that holds rules is enough to enforce them")
        t:assert_eq(s.last_ingest_error, 0, "the walk that read them succeeded")
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6101))
        local delta, events = E:during(function()
            local fd, why = ntfe.tcp_connect(vm, "127.0.0.1", 6101, 500)
            t:assert_eq(why, "timeout", "the port the policy drops does not answer")
            if fd then sys.close(vm, fd) end
        end)
        sys.close(vm, l)
        local dropped = ntfe.matching(events, { attributed = "closed-port" })
        t:assert(#dropped >= 1, "the drop is attributed to the rule in the registry: "
            .. ntfe.describe(events))
        t:assert_eq(dropped[1].verdict, ntfe.VERDICT.DROP, "as a DROP")
        t:assert(delta.verdict_drop >= 1, "and counted")
    end)

test("no userspace process is in the enforcement path",
    { spec = "PKM *ntfe-engine.no-userspace-in-enforcement-path" }, function(t)
        -- The source worker answers only when this test pumps it, and
        -- nothing pumps it here: with every userspace party to the
        -- policy silent, the verdicts still come.
        local served = #E.src.log
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6102))
        local fd, why = ntfe.tcp_connect(vm, "127.0.0.1", 6102)
        t:assert(fd, "a passed connection connects: " .. tostring(why))
        if fd then sys.close(vm, fd) end
        sys.close(vm, l)
        local _, drop_why = ntfe.tcp_connect(vm, "127.0.0.1", 6101, 500)
        t:assert_eq(drop_why, "timeout", "a dropped one is dropped")
        t:assert_eq(#E.src.log, served,
            "and the registry source was asked nothing while they were judged")
    end)

test("every successful ingestion advances the generation",
    { spec = "PKM *ntfe-engine.generation-advances-per-ingestion" }, function(t)
        local before = E:status().generation
        local s = E:replace({
            RawPacket = PASS_ALL, Packet = PASS_ALL,
            Flow = {
                all = { Actions = { "PASS" } },
                ["closed-port"] = { ["DstPort.Equal"] = 6101, Actions = { "DROP" } },
                ["another"] = { ["DstPort.Equal"] = 6103, Actions = { "DROP" } },
            },
        })
        t:assert_eq(s.last_ingest_error, 0, "a changed policy is accepted")
        t:assert_eq(s.generation, before + 1, "and is exactly one generation later")
    end)

test("the hook framework and conntrack are kept",
    { spec = "PKM *ntfe-engine.keeps-hooks-conntrack-defrag-reject" }, function(t)
        t:assert(fixtures.present(vm, "/proc/sys/net/netfilter/nf_conntrack_max"),
            "conntrack is built in: its sysctls are there with no module loaded")
        t:assert(fixtures.present(vm, "/proc/sys/net/netfilter/nf_conntrack_events"),
            "with events")
        -- The reject machinery is witnessed by use: a REJECT is answered.
        E:replace({
            RawPacket = PASS_ALL, Packet = PASS_ALL,
            Flow = {
                all = { Actions = { "PASS" } },
                refused = { ["DstPort.Equal"] = 6104, Actions = { "REJECT" } },
            },
        })
        local _, why = ntfe.tcp_connect(vm, "127.0.0.1", 6104, 500)
        t:assert_eq(why, sys.E.CONNREFUSED,
            "a REJECT is phrased as a reset: " .. tostring(why))
    end)

test("with conntrack's helpers off no flow is expected by another, and Related is false on every one",
    { spec = "PKM *ntfe-engine.helpers-off-related-never-true" }, function(t)
        -- An FTP control connection is where a helper would read a PORT
        -- command and expect the data connection it names. With none,
        -- that connection is a flow of its own like any other.
        E:replace({
            RawPacket = PASS_ALL, Packet = PASS_ALL,
            Flow = {
                all = { Actions = { "PASS" } },
                related = { ["Related.Equal"] = 1, Priority = 10, Actions = { "REJECT" } },
            },
        })
        local ctl_l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 21))
        local data_l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6106))
        local fds = {}
        local _, events = E:during(function()
            local ctl = assert(ntfe.tcp_connect(vm, "127.0.0.1", 21))
            local srv = assert(ntfe.tcp_accept(vm, ctl_l))
            fds = { ctl, srv }
            -- 23 * 256 + 218 = 6106.
            ntfe.send(vm, ctl, "PORT 127,0,0,1,23,218\r\n")
            t:assert(ntfe.recv(vm, srv), "a PORT command crosses the control connection")
            ntfe.send(vm, srv, "200 PORT command successful.\r\n")
            ntfe.recv(vm, ctl)
            local data, why = ntfe.tcp_connect(vm, "127.0.0.1", 6106, 500)
            t:assert(data, "the data connection it names is made: " .. tostring(why))
            if data then fds[#fds + 1] = data end
            local u = assert(ntfe.udp_connect(vm, "127.0.0.1", 69))
            ntfe.send(vm, u, "\0\1file\0octet\0")
            fds[#fds + 1] = u
        end)
        local flow_judged = ntfe.matching(events, { layer = ntfe.LAYER.FLOW })
        t:assert(#ntfe.matching(flow_judged, { dst_port = 6106 }) >= 1,
            "the data connection was judged by the Flow layer: " .. ntfe.describe(flow_judged))
        t:assert_eq(#ntfe.matching(events, { attributed = "related" }), 0,
            "and no flow, control, data or TFTP, was Related: " .. ntfe.describe(flow_judged))
        local flows = assert(E:flows())
        t:assert(#flows > 0, "conntrack holds the flows")
        for _, f in ipairs(flows) do
            t:assert_eq(f.related, 0, string.format(
                "and the dump calls none of them related (%d -> %d)", f.src_port, f.dst_port))
        end
        for _, fd in ipairs(fds) do sys.close(vm, fd) end
        sys.close(vm, ctl_l); sys.close(vm, data_l)
    end)

test("every policy frontend is configured out",
    { spec = "PKM *ntfe-engine.policy-frontends-configured-out" }, function(t)
        for _, path in ipairs({
            "/proc/net/ip_tables_names",        -- xtables, IPv4
            "/proc/net/ip6_tables_names",       -- xtables, IPv6
            "/proc/net/arp_tables_names",       -- arptables
            "/proc/net/netfilter/nfnetlink_queue", -- NFQUEUE
            "/proc/net/netfilter/nfnetlink_log",   -- NFLOG
            "/proc/net/ip_vs",                  -- IPVS
            "/proc/sys/net/bridge",             -- bridge netfilter
            "/sys/module/nf_tables", "/sys/module/x_tables",
            "/sys/module/ip_set", "/sys/module/nf_flow_table",
        }) do
            t:assert(not fixtures.present(vm, path), path .. " does not exist")
        end
    end)

test("NF_NAT is built but dormant",
    { spec = "PKM *ntfe-engine.nf-nat-built-but-dormant",
      covered_by = "build:pkm/kernel/verify-kernel-config.sh",
      skip = "a dormant NAT has no surface: with every frontend gone nothing " ..
             "can install a NAT rule and nothing reports that the core is " ..
             "linked in; the config gate asserts CONFIG_NF_NAT at build time" },
    function(t) end)

test("the kernel config gate asserts both halves",
    { spec = "PKM *ntfe-engine.config-gate-asserts-both-halves",
      covered_by = "build:pkm/kernel/verify-kernel-config.sh",
      skip = "a property of the kernel build, which fails when the gate does; " ..
             "the kernel under test exists because it passed" },
    function(t) end)

test("NTFE pins conntrack's hooks itself, so flows are tracked with no frontend",
    { spec = "PKM *ntfe-engine.pins-conntrack-hooks-at-init" }, function(t)
        E:replace({ RawPacket = PASS_ALL, Packet = PASS_ALL, Flow = PASS_ALL })
        local l = assert(ntfe.tcp_listen(vm, "127.0.0.1", 6105))
        local _, events = E:during(function()
            local fd = ntfe.tcp_connect(vm, "127.0.0.1", 6105)
            t:assert(fd, "a connection is made")
            if fd then sys.close(vm, fd) end
        end)
        sys.close(vm, l)
        local syn = ntfe.matching(events, {
            seat = ntfe.SEAT.LOCAL_IN, layer = ntfe.LAYER.PACKET, dst_port = 6105,
        })
        t:assert(#syn >= 1, "the inbound seat judged it: " .. ntfe.describe(events))
        t:assert_eq(syn[1].flow_state, ntfe.FLOW_STATE.NEW,
            "and its first packet reads `new`, not `untracked`")
        local established = false
        for _, e in ipairs(syn) do
            if e.flow_state == ntfe.FLOW_STATE.ESTABLISHED then established = true end
        end
        t:assert(established, "later packets read `established`")
    end)

test("effects are applied after collation, so a REPORT can carry the verdict",
    { spec = "PKM *ntfe-engine.effects-applied-after-collation",
      covered_by = "kunit:pkm_kunit_ntfe",
      skip = "the ordering inside one evaluation is not separable from " ..
             "outside it; the two consequences that are — a COUNT cannot " ..
             "trip its own rule's threshold, a report names the verdict — " ..
             "are tested live under §6.4 and §6.6; the bridge's ordering " ..
             "runs under ntfe_kunit_counter_store and ntfe_kunit_report_lands_in_kmes" },
    function(t) end)

test("nothing in NTFE fails silently: a refused policy is confessed in the status",
    { spec = "PKM *ntfe-engine.nothing-fails-silently" }, function(t)
        local before = E:status()
        local s = E:replace({
            RawPacket = PASS_ALL, Packet = PASS_ALL,
            Flow = { broken = { ["NoSuchFact.Equal"] = "x", Actions = { "PASS" } } },
        })
        t:assert(s.last_ingest_error ~= 0, "a policy the engine cannot accept is counted against the walk")
        t:assert_eq(s.generation, before.generation, "and the previous generation stands")
        t:assert_eq(s.enforcing, 1, "still enforced")
    end)

-- The division of the source (§6.1, "Two halves") is not behaviour.
for _, c in ipairs({
    { "PKM *ntfe-engine.c-glue-owns-kernel-facing-work",
      "the C half owns everything that touches the kernel" },
    { "PKM *ntfe-engine.core-owns-policy-meaning",
      "pnp-core owns everything the policy means" },
    { "PKM *ntfe-engine.core-no-std-fallible-alloc-no-io",
      "pnp-core is no_std, allocates fallibly and has no I/O" },
    { "PKM *ntfe-engine.core-compiles-for-cargo-and-kernel",
      "the same core source compiles under cargo and into the kernel" },
    { "PKM *ntfe-engine.no-rule-semantics-in-c",
      "nothing about a rule's semantics exists in C" },
    { "PKM *ntfe-engine.bridge-is-only-meeting-point",
      "the bridge is the only place the two halves meet" },
}) do
    test(c[2], {
        spec = c[1],
        covered_by = "build:pkm/kernel/stage-rust-core.sh",
        skip = "a statement about how the source tree is divided, which a " ..
               "running kernel cannot show; the staging script and the " ..
               "pnp-core crate's own `cargo test` are where it is held",
    }, function(t) end)
end
