-- PEI-1357: an IPv6-only DNS offer, using the router's link-local address.
local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local dns = require("helpers.dns")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local unixsock = require("helpers.unixsock")
local msgpack = require("helpers.msgpack")
peinit.claim(2)
local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local server = gateway.ip6_text(gw.ll)
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, dns = false })
gw:router({ lifetime = 1800,
    prefixes = { { prefix = "fd77::", len = 64, L = true, A = true, valid = 3600, preferred = 3600 } },
    rdnss = { lifetime = 3600, servers = { server } } })
dns.serve(gw, { on = function(q, default, ctx)
    local question = q.questions[1]
    if not question or not question.name:lower():find("ll.test", 1, true) then return nil end
    default.rcode, default.authority = 0, {}
    default.answers = { { name = question.name, type = "A", ttl = 0, data = "192.0.2.57" } }
    if question.name:lower():find("tcp", 1, true) and ctx.transport == "udp" then
        default.tc, default.no_truncate = true, true
    end
    return default
end })
local files = network.test_binary("netd", network.test_binary("resolvd", {}))
local sut = network.boot({ bridges = { lan }, gateway = gw, files = files })
local SOCK = "/run/resolvd/resolv.sock"
local function resolve(name)
    local body = msgpack.encode({ query = "resolve", name = name, type = 1, no_cache = true })
    local fd = assert(unixsock.socket(sut, unixsock.AF_UNIX, unixsock.SOCK.STREAM))
    assert(unixsock.connect(sut, fd, SOCK).ret == 0)
    assert(ntfe.send(sut, fd, string.pack("<I4", #body) .. body).ret > 0)
    local buf, reply = "", nil
    gw:serve({ timeout = 20, until_ = function()
        local chunk = ntfe.recv(sut, fd, 0, 65536)
        if chunk then buf = buf .. chunk end
        if #buf >= 4 then
            local size = string.unpack("<I4", buf)
            if #buf >= size + 4 then reply = msgpack.decode(buf:sub(5, size + 4)); return true end
        end
        return false
    end })
    sys.close(sut, fd)
    return reply
end

test("RDNSS link-local servers resolve over UDP and TCP on their advertised interface",
    { spec = "resolvd *engine-query.link-local-server-uses-scope netd *snapshot.dns-merge" }, function(t)
        t:assert(gw:serve({ timeout = 60, until_ = function()
            local status = network.call(sut, { query = "status" }, { path = SOCK })
            for _, scope in ipairs(status and status.scopes or {}) do
                if scope.interface == "eth0" and #scope.servers == 1 and scope.servers[1] == server then return true end
            end
            return false
        end }), "the RDNSS server reaches resolvd as the only upstream")
        for _, prefix in ipairs({ "udp", "tcp" }) do
            dns.forget(gw)
            local name = prefix .. ".ll.test"
            local reply = resolve(name)
            t:assert(reply and reply.outcome == "found", prefix .. " query succeeded")
            t:assert_eq(reply.records[1].text, "192.0.2.57", "the gateway's answer")
            local transports = {}
            for _, q in ipairs(dns.queries(gw)) do
                if q.msg and q.msg.questions[1] and dns.same_name(q.msg.questions[1].name, name) then
                    t:assert_eq(q.server, server, "sent to the advertised link-local server")
                    transports[q.transport] = true
                end
            end
            t:assert(transports.udp, "UDP reached the gateway")
            if prefix == "tcp" then t:assert(transports.tcp, "truncation retry also reached it over TCP") end
        end
    end)

test("explicit snapshot zones must match their containing interface",
    { spec = "resolvd *engine-query.snapshot-zone-matches-interface",
      covered_by = "cargo:resolvd:upstream::scoped_server_tests::link_local_zones_match_the_snapshot_and_survive_address_construction",
      skip = "host test injects named/numeric zones, mismatches and absent interfaces at the snapshot boundary" }, function(t) end)
