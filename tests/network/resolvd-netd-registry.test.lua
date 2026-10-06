-- PSPU §6.9 — what of the registry the resolver reads: exactly
-- `Machine\System\Network\Dns` and its subkeys (it may watch the parent),
-- and nothing under `Profiles\`; the manager merges the profiles.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network), with LCS's key-open auditing (PKM §5.4.4) as the
-- instrument. A success-audit ACE for Everyone in a key's SACL makes LCS
-- emit lcs.audit.key.opened, carrying the opener's user SID, for every
-- open of that key; the events are read from a KMES ring (helpers.kmes).
-- The ACE goes on each key in turn (`reg sd --sacl --set`), and resolvd
-- is made to read its configuration twice — a restart, then a registry
-- write under the watched `Machine\System\Network` — while the ring
-- records.
--
-- First the instrument is shown to see resolvd: audited, `Dns` and
-- `Dns\Hosts` are opened by resolvd's SID. Then every key under
-- `Machine\System\Network` other than `Dns` is audited instead; SYSTEM's
-- opens of them (netd re-reading its configuration, and the agent's own
-- `reg` writes — both run as SYSTEM) show the auditing is live, and
-- resolvd's SID must not appear.
--
-- Own VMs: SACLs are written across the network subtree.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local kmes = require("helpers.kmes")
local token = require("helpers.token")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local RSOCK = "/run/resolvd/resolv.sock"
local RESTART = "svctl stop resolvd; rm -rf /run/resolvd; svctl start resolvd"
local AUDIT = "S:(AU;SA;KA;;;WD)"
local NO_AUDIT = "S:"

local function audit(key, on)
    local r = network.reg(sut, { "sd", key, "--sacl", "--set", on and AUDIT or NO_AUDIT })
    return r
end

local function resolvd_ready()
    wait_until(function()
        local s = network.call(sut, { query = "status" }, { path = RSOCK })
        return s ~= nil and s.ok == true
    end, { timeout = 20, interval = 0.25, desc = "resolvd answering" })
end

--- The user SID of the process named `comm`.
local function sid_of(comm)
    local pid = assert(peinit.pid_of_comm(sut, comm), comm .. "'s pid")
    return peinit.token(sut, pid).principal.user
end

--- Make resolvd read its configuration: a restart, then a write under
--- the watched subtree (a value it does not use). Returns the key-open
--- events seen, as {sid, key_guid}.
local function provoke(t)
    local events = kmes.recording(t, sut, function()
        sut:run(RESTART, { timeout = 30 }):assert_ok()
        resolvd_ready()
        network.reg(sut, { "set", network.KEY .. "\\Dns\\Hosts", "pt-provoke.test", "sz:10.77.5." .. math.random(1, 250) }):assert_ok()
        network.reg(sut, { "set", network.KEY .. "\\PtScratch", "PtUnused", "dword:" .. math.random(1, 1000) }):assert_ok()
        sut:run("sleep 2")
    end)
    local out = {}
    for _, e in ipairs(kmes.of_type(events, "lcs.audit.key.opened")) do
        local subject = e.payload and e.payload.subject
        local caller = subject and subject.token
        out[#out + 1] = { sid = caller and caller.sid and token.sid_string(caller.sid) or "?" }
    end
    return out
end

local function by_sid(events)
    local n = {}
    for _, e in ipairs(events) do n[e.sid] = (n[e.sid] or 0) + 1 end
    return n
end

test("resolvd reads Machine\\System\\Network\\Dns and its subkeys, and opens no other key under Machine\\System\\Network: not Profiles, not Rules, not the networks' records",
    { spec = "PSPU *nri-manager.resolver-reads-only-dns-key PSPU *nri-manager.resolver-never-reads-profiles" },
    function(t)
        t:assert(network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 }), "netd bound")
        network.write(sut, "Dns", {})   -- `reg new` makes one level at a time
        network.write(sut, "Dns\\Hosts", { ["pt-static.test"] = "sz:10.77.5.5" })
        network.write(sut, "PtScratch", { PtUnused = "dword:0" })
        resolvd_ready()
        local resolvd_sid, netd_sid = sid_of("resolvd"), sid_of("netd")
        t:log("resolvd runs as " .. resolvd_sid .. ", netd as " .. netd_sid)
        t:assert(resolvd_sid ~= netd_sid, "two identities")

        -- The instrument: Dns and Dns\Hosts audited.
        for _, k in ipairs({ network.KEY .. "\\Dns", network.KEY .. "\\Dns\\Hosts" }) do
            local r = audit(k, true)
            t:assert_eq(r.exit_code, 0, "SACL on " .. k .. ": " .. r.stdout .. r.stderr)
        end
        local seen = by_sid(provoke(t))
        t:log("Dns audited: " .. json.encode(seen))
        t:assert((seen[resolvd_sid] or 0) > 0, "resolvd's opens of Dns are seen")
        for _, k in ipairs({ network.KEY .. "\\Dns", network.KEY .. "\\Dns\\Hosts" }) do audit(k, false) end

        -- Everything else under Machine\System\Network audited.
        local r = network.reg(sut, { "tree", network.KEY, "--json" })
        t:assert_eq(r.exit_code, 0, "reg tree: " .. r.stderr)
        local keys = json.decode(r.stdout).keys
        local audited = {}
        for _, k in ipairs(keys) do
            local rel = k:sub(#network.KEY + 2)
            if rel ~= "Dns" and not rel:match("^Dns\\") then
                local a = audit(k, true)
                t:assert_eq(a.exit_code, 0, "SACL on " .. k .. ": " .. a.stderr)
                audited[#audited + 1] = rel
            end
        end
        t:log("audited: " .. table.concat(audited, ", "))
        t:assert(#audited >= 3, "Profiles, Rules and more are audited")
        seen = by_sid(provoke(t))
        t:log("the rest audited: " .. json.encode(seen))
        t:assert((seen[netd_sid] or 0) > 0, "SYSTEM's opens of those keys are seen: the auditing is live")
        t:assert_eq(seen[resolvd_sid] or 0, 0, "resolvd opened none of them")
        for _, rel in ipairs(audited) do audit(network.KEY .. "\\" .. rel, false) end
        network.delete(sut, "PtScratch")
    end)
