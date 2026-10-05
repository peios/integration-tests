-- netd TRM §5.7 (first half) — how netd names the machine and each
-- interface to a DHCP server: the DUID and the per-interface client
-- identifier, where each comes from, and what netd writes back.
--
-- Every identifier is read off the wire, as option 61 in the DISCOVER or
-- REQUEST the gateway records, and compared byte for byte with what the
-- TRM's rule gives: `ff`, the IAID (the interface id's text folded into
-- four bytes by XOR), then the DUID. The registry and the state file are
-- read back as well, since writing them is half of each claim.
--
-- The DUID is decided once per netd process, so every DUID source needs
-- a fresh netd (`network.restart_netd`), and the interface's `ClientId`
-- must be deleted first: a written ClientId is used as written, and would
-- hide the DUID it was generated from. A ClientId is read when a client
-- starts, so the ClientId tests restart the client with a cable pull.
-- Each restart and each pull comes back through INIT-REBOOT (the lease
-- address is remembered, §5.7 second half), so a new client's first
-- REQUEST is the frame that carries its identifier.
--
-- One pair for the file; the tests run in order, each from the state the
-- one before left. The `RequestedAddress` half of §5.7 is
-- `dhcp4-memory-requested`.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local DUID_FILE = "/var/state/netd/duid"

local function hex(b)
    return (b:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function colon_hex(b)
    local out = {}
    for i = 1, #b do out[#out + 1] = string.format("%02x", b:byte(i)) end
    return table.concat(out, ":")
end

local function bytes(h)
    return (h:gsub("[^%x]", ""):gsub("%x%x", function(x) return string.char(tonumber(x, 16)) end))
end

--- The TRM's IAID: byte i of the interface id's text XORed into i mod 4.
local function iaid(ifid)
    local b = { 0, 0, 0, 0 }
    for i = 1, #ifid do
        local k = (i - 1) % 4 + 1
        b[k] = b[k] ~ ifid:byte(i)
    end
    return string.char(table.unpack(b))
end

local ifid, mac, ifkey

local function client_id_value() return network.get(sut, ifkey, "ClientId") end
local function duid_value() return network.get(sut, network.KEY, "Duid") end
local function del_value(key, name)
    if not key:match("^Machine\\") then key = network.KEY .. "\\" .. key end
    network.reg(sut, { "del", key, name })
end

--- The option 61 of the newest DISCOVER or REQUEST seen.
local function last_client_id()
    local last
    for _, f in ipairs(gw.seen) do
        if f.udp and f.udp.dport == 67 and f.payload then
            local m = gateway.dhcp_decode(f.payload)
            if m and m.op == 1 and (m.type == gateway.DHCP.DISCOVER or m.type == gateway.DHCP.REQUEST) then
                last = m
            end
        end
    end
    return last and last.opt[61], last
end

--- Forget what was seen, do `restart` (a function), and pump until the
--- new client has bound. Returns the option 61 its exchange carried.
local function fresh_client(t, restart, what)
    gw:forget()
    restart()
    local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 40 })
    t:assert(s, what .. ": the new client binds")
    local id, m = last_client_id()
    t:assert(id, what .. ": the new client's messages carry option 61")
    t:log(string.format("%s: option 61 = %s (in a %s)", what, hex(id), gateway.DHCP_NAME[m.type]))
    return id
end

local function restart_netd() network.restart_netd(sut) end

local function pull_cable()
    local nic = lan:nic(sut)
    nic:disconnect()
    assert(network.serve_until(gw, sut, function(x) return x.carrier == false end,
        { iface = "eth0", timeout = 20 }), "carrier goes")
    nic:reconnect()
end

test("a first start with no DUID anywhere makes a DUID-LL from the MAC, writes it to the file and the registry, and builds the client id on it",
    { spec = "netd *dhcp4-memory.duid netd *dhcp4-memory.duid-written-back netd *dhcp4-memory.client-id" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound a lease")
        local i = network.iface(s, "eth0")
        ifid, mac = i.ifid, gateway.mac(i.mac)
        ifkey = "Interfaces\\" .. ifid
        local duid = "\0\3\0\1" .. mac
        local expected_id = "\xff" .. iaid(ifid) .. duid
        t:log("ifid " .. ifid .. ", IAID " .. hex(iaid(ifid)) .. ", expected DUID " .. hex(duid))

        local d = gw:dhcp_messages(gateway.DHCP.DISCOVER)
        t:assert(#d >= 1, "a DISCOVER was seen")
        t:assert_eq(hex(d[1].opt[61] or ""), hex(expected_id), "the DISCOVER's option 61 is ff, the IAID, then the DUID-LL")
        t:assert_eq(hex(sut:read_file(DUID_FILE)), hex(duid), DUID_FILE .. " holds the DUID-LL's bytes")
        t:assert_eq(duid_value(), colon_hex(duid), "the registry's Duid is the DUID, colon-separated lower-case hex")
        t:assert_eq(client_id_value(), colon_hex(expected_id), "the generated ClientId is written back")
    end)

test("an operator's ClientId is sent as written, from the next client start on",
    { spec = "netd *dhcp4-memory.client-id" }, function(t)
        t:assert(ifid, "the first test found the interface")
        local generated = bytes(client_id_value())
        network.write(sut, ifkey, { ClientId = "sz:01 52 54 00 AA BB CC" })

        -- A renewal is the running client: it keeps the identifier it
        -- started with.
        gw:forget()
        local r = network.call(sut, { query = "renew", interface = "eth0" })
        t:assert(r and r.ok, "renew accepted")
        t:assert(gw:serve({ timeout = 10, until_ = function() return last_client_id() ~= nil end }), "a renewal arrives")
        t:assert_eq(hex(last_client_id()), hex(generated), "the running client still sends the identifier it started with")

        local id = fresh_client(t, pull_cable, "after a cable pull")
        t:assert_eq(hex(id), "01525400aabbcc", "the next client sends the operator's identifier, its spaces dropped")
        t:assert_eq(client_id_value(), "01 52 54 00 AA BB CC", "and netd leaves the value as the operator wrote it")
    end)

test("a ClientId that is not hex is logged and replaced by a generated one",
    { spec = "netd *dhcp4-memory.client-id" }, function(t)
        t:assert(ifid, "the first test found the interface")
        network.write(sut, ifkey, { ClientId = "sz:not-hex!" })
        local id = fresh_client(t, pull_cable, "not hex")
        local expected = "\xff" .. iaid(ifid) .. "\0\3\0\1" .. mac
        t:assert(network.logged(sut, 'ClientId "not-hex!" is not hex; regenerating'),
            "netd logged `ClientId \"not-hex!\" is not hex; regenerating`")
        t:assert_eq(hex(id), hex(expected), "the client sends a generated identifier")
        t:assert_eq(client_id_value(), colon_hex(expected), "and the value is overwritten with it")
    end)

test("a Duid in the registry is the DUID, written with dashes or spaces; it is decided once per netd process",
    { spec = "netd *dhcp4-memory.duid" }, function(t)
        t:assert(ifid, "the first test found the interface")
        local file_before = sut:read_file(DUID_FILE)
        network.write(sut, network.KEY, { Duid = "sz:00-02-00-00-AB-11-01-02" })
        del_value(ifkey, "ClientId")
        local id = fresh_client(t, restart_netd, "registry Duid with dashes")
        local duid = bytes("0002 0000 ab11 0102")
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. duid), "the client id is built on the registry's DUID")
        t:assert_eq(duid_value(), "00-02-00-00-AB-11-01-02", "the registry value is left as written")
        t:assert_eq(hex(sut:read_file(DUID_FILE)), hex(file_before), "and the file is neither read nor rewritten")
        t:assert_eq(client_id_value(), colon_hex("\xff" .. iaid(ifid) .. duid), "the new ClientId is written back")

        -- Changed under a running netd, the Duid is not re-read: the next
        -- client of this process still builds on the first.
        network.write(sut, network.KEY, { Duid = "sz:00 02 00 00 ab 11 09 09" })
        del_value(ifkey, "ClientId")
        id = fresh_client(t, pull_cable, "Duid changed, same netd")
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. duid), "the same process keeps the DUID it decided")
        -- A new process takes the new one, spaces and all.
        del_value(ifkey, "ClientId")
        id = fresh_client(t, restart_netd, "Duid with spaces, new netd")
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. bytes("0002 0000 ab11 0909")),
            "a new process reads the registry again")
    end)

test("with no registry Duid the file's DUID is used and written back to the registry",
    { spec = "netd *dhcp4-memory.duid netd *dhcp4-memory.duid-written-back" }, function(t)
        t:assert(ifid, "the first test found the interface")
        local duid = "\0\4\x11\x22\x33\x44\x55\x66"
        del_value(network.KEY, "Duid")
        t:assert_eq(duid_value(), nil, "the registry has no Duid")
        sut:write_file(DUID_FILE, duid)
        del_value(ifkey, "ClientId")
        local id = fresh_client(t, restart_netd, "file DUID")
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. duid), "the client id is built on the file's DUID")
        t:assert_eq(duid_value(), "00:04:11:22:33:44:55:66", "the file's DUID is written to the registry")
    end)

test("a DUID file shorter than 4 bytes is ignored: a new DUID-LL is made and written to both places",
    { spec = "netd *dhcp4-memory.duid netd *dhcp4-memory.duid-written-back" }, function(t)
        t:assert(ifid, "the first test found the interface")
        del_value(network.KEY, "Duid")
        sut:write_file(DUID_FILE, "\0\4\x11")
        del_value(ifkey, "ClientId")
        local id = fresh_client(t, restart_netd, "3-byte file")
        local duid = "\0\3\0\1" .. mac
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. duid), "the client id is built on a DUID-LL")
        t:assert_eq(hex(sut:read_file(DUID_FILE)), hex(duid), "the file now holds the DUID-LL")
        t:assert_eq(duid_value(), colon_hex(duid), "and so does the registry")
    end)

test("a registry Duid that is not hex is passed over for the file, logged, and replaced by the file's DUID",
    { spec = "netd *dhcp4-memory.duid netd *dhcp4-memory.duid-written-back" }, function(t)
        t:assert(ifid, "the first test found the interface")
        local duid = "\0\4\x77\x88\x99\xaa"
        sut:write_file(DUID_FILE, duid)
        network.write(sut, network.KEY, { Duid = "sz:00:02:0g" })
        del_value(ifkey, "ClientId")
        local id = fresh_client(t, restart_netd, "Duid not hex")
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. duid), "the client id is built on the file's DUID")
        t:assert(network.logged(sut, 'Duid "00:02:0g" is not hex; ignoring it'), "netd logged the bad Duid")
        t:log("registry Duid afterwards: " .. tostring(duid_value()))
        t:assert_eq(duid_value(), "00:04:77:88:99:aa", "the value that was not hex is replaced by the file's DUID")
    end)

test("a DUID that cannot be written to the file is logged and used all the same",
    { spec = "netd *dhcp4-memory.duid" }, function(t)
        t:assert(ifid, "the first test found the interface")
        del_value(network.KEY, "Duid")
        sut:run("rm -f " .. DUID_FILE .. " && mkdir " .. DUID_FILE):assert_ok()
        del_value(ifkey, "ClientId")
        local id = fresh_client(t, restart_netd, "unwritable file")
        local duid = "\0\3\0\1" .. mac
        t:assert(network.logged(sut, "could not persist the DUID at " .. DUID_FILE .. ":"),
            "netd logged that it could not persist the DUID")
        t:assert_eq(hex(id), hex("\xff" .. iaid(ifid) .. duid), "the client id is built on the new DUID-LL")
        t:assert_eq(duid_value(), colon_hex(duid), "the registry still gets it")
        sut:run("rmdir " .. DUID_FILE):assert_ok()
    end)
