-- netd TRM §8.1 "The inventory": the Interfaces\<id> record netd keeps
-- for every non-loopback interface it has seen, the values under its
-- Status subkey and when each is present, writing only on change, and
-- the descriptor that keeps Status netd's alone.
--
-- Harness: the scripted gateway (DHCPv4) and one whole Peios machine;
-- eth0 is the joined, networked interface. The other subjects are links
-- made in the guest — dummies (wired, no bus path) over rtnetlink from
-- the agent (local functions below; the image ships no `ip`), and tunl0,
-- which the ipip module makes and no rule speaks for (the backstop).
-- Rules naming the made links by MAC at priority 20+ give them each
-- verdict in turn.
--
-- Registry values are read with LCS directly (helpers.lcs, synchronous
-- against the machine's real loregd), which gives each value's type and
-- its write sequence: a value whose sequence has not moved has not been
-- written. The administrator's refused write is a worker holding a
-- minted token in Administrators (helpers.token), since the agent itself
-- is SYSTEM and Status grants SYSTEM everything.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local lcs = require("helpers.lcs")
local token = require("helpers.token")
local kacs = require("helpers.kacs")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")
local sha1 = require("helpers.sha1")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })
local nic = lan:nic(sut)

-- ---------------------------------------------------------------------------
-- Links
-- ---------------------------------------------------------------------------

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

local function nl_request(msg_type, flags, body)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    local fd = s.ret
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 16 + #body, msg_type, flags | 0x5, 1, 0) .. body)
    local buf = ntfe.recv(sut, fd, 3000, 65536)
    sys.close(sut, fd)
    if not buf or #buf < 20 then return nil, "no ack" end
    local err = string.unpack("<i4", buf, 17)
    if err ~= 0 then return nil, sys.errname(-err) end
    return true
end

local function dummy(name, mac)
    local body = string.pack("<I1I1I2i4I4I4", 0, 0, 0, 0, 0, 0)
        .. nla(3, name .. "\0") .. nla(1, gateway.mac(mac)) .. nla(18, nla(1, "dummy"))
    local ok, err = nl_request(16, 0x600, body) -- RTM_NEWLINK, CREATE | EXCL
    assert(ok, "dummy " .. name .. ": " .. tostring(err))
end

local function link_del(name)
    local index = assert(ntfe.if_index(sut, name))
    local ok, err = nl_request(17, 0, string.pack("<I1I1I2i4I4I4", 0, 0, 0, index, 0, 0))
    assert(ok, "delete " .. name .. ": " .. tostring(err))
end

local function ifid_of_mac(mac) return sha1.uuid5("peios-netd-ifid||" .. gateway.mac(mac)) end

-- ---------------------------------------------------------------------------
-- The registry
-- ---------------------------------------------------------------------------

local IFACES = network.KEY .. "\\Interfaces"
local STATUS_VALUES = { "Name", "Kind", "Mac", "Path", "Driver", "Verdict", "Rule", "Profile",
    "Readiness", "Network", "LastNetwork" }

--- Every Status value of interface `id`: name -> { type, text, sequence }.
--- Absent values are absent. Raises if the key cannot be opened.
local function status(id)
    local key = IFACES .. "\\" .. id .. "\\Status"
    local r = lcs.open_key(nil, sut, -1, key, lcs.RIGHT.KEY_READ)
    if r.ret < 0 and r.errno == sys.E.NOENT then return {} end -- no record (yet)
    assert(r.ret >= 0, "open " .. key .. ": " .. sys.errname(r.errno or 0))
    local out = {}
    for _, name in ipairs(STATUS_VALUES) do
        local v = lcs.query_value(nil, sut, r.ret, name)
        if v.ret == 0 then
            out[name] = { type = v.type, text = (v.data:gsub("%z+$", "")), sequence = v.sequence }
        end
    end
    sys.close(sut, r.ret)
    return out
end

local function key_exists(path)
    local r = lcs.open_key(nil, sut, -1, path, lcs.RIGHT.KEY_READ)
    if r.ret >= 0 then sys.close(sut, r.ret); return true end
    return false
end

local function text(st, name) return st[name] and st[name].text end

--- Write a rule, its conditions and priority before its actions, so that
--- no pass sees an unconditional rule half-written.
local function rule(name, values)
    local key = network.KEY .. "\\Rules\\Interface\\" .. name
    network.reg(sut, { "new", key })
    values.Priority = values.Priority or "dword:20"
    local names = {}
    for k in pairs(values) do if k ~= "Actions" then names[#names + 1] = k end end
    table.sort(names)
    names[#names + 1] = "Actions"
    for _, k in ipairs(names) do
        network.reg(sut, { "set", key, k, values[k] }):assert_ok()
    end
    return key
end

local function iface(name) return network.iface(network.status(sut), name) end

local function wait(pred, desc)
    return wait_until(pred, { timeout = 20, interval = 0.25, desc = desc })
end

local eth = {}

-- ---------------------------------------------------------------------------

test("every non-loopback interface netd sees gets Interfaces\\<id>, created on the first pass that sees it; the key is the operator's apart from ClientId; records are never deleted",
    { spec = "netd *inventory.record" }, function(t)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
    t:assert(s, "eth0 bound")
    local e = network.iface(s, "eth0")
    eth.id, eth.network, eth.mac = e.ifid, e.network, e.mac
    t:assert(key_exists(IFACES .. "\\" .. eth.id), "eth0 has Interfaces\\<its id>")
    t:assert(key_exists(IFACES .. "\\" .. eth.id .. "\\Status"), "with a Status subkey")
    t:assert(not key_exists(IFACES .. "\\" .. sha1.uuid5("peios-netd-ifid||" .. string.rep("\0", 6))),
        "loopback has none")

    -- ClientId: the one value on the record itself, netd's DHCP client id.
    local r = lcs.open_key(nil, sut, -1, IFACES .. "\\" .. eth.id, lcs.RIGHT.KEY_READ)
    local cid = lcs.query_value(nil, sut, r.ret, "ClientId")
    sys.close(sut, r.ret)
    t:assert_eq(cid.ret, 0, "ClientId is on the record")
    t:assert_eq(cid.type, lcs.TYPE.SZ, "ClientId is REG_SZ")
    local cid_text = cid.data:gsub("%z+$", "")
    t:log("ClientId = " .. cid_text)
    t:assert(cid_text:match("^%x%x[%x:]*$") and #cid_text:gsub(":", "") % 2 == 0, "ClientId is hex bytes: " .. cid_text)

    -- A new link: by the time netd's status lists it, its record exists.
    local mac = "02:c0:00:00:04:01"
    rule("ptc-rec", { ["Interface.Mac.Equal"] = "sz:" .. mac, Actions = "multi:IGNORE" })
    local id = ifid_of_mac(mac)
    t:assert(not key_exists(IFACES .. "\\" .. id), "no record before the link exists")
    dummy("ptrec0", mac)
    wait(function() return iface("ptrec0") end, "netd to list ptrec0")
    t:assert_eq(text(status(id), "Name"), "ptrec0", "the record was written by the pass that saw it")

    -- Gone, and netd restarted: the record stays.
    link_del("ptrec0")
    wait(function() return iface("ptrec0") == nil end, "ptrec0 gone")
    network.restart_netd(sut)
    t:assert(key_exists(IFACES .. "\\" .. id), "the record outlives its link and a netd restart")
    t:assert_eq(text(status(id), "Name"), "ptrec0", "with what netd last wrote")
end)

test("Status holds Name, Kind, Mac, Path, Driver, Verdict, Rule, Profile, Readiness, Network and LastNetwork, every one REG_SZ",
    { spec = "netd *inventory.status-values" }, function(t)
    t:assert(eth.id, "the first test found eth0")
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 30 })
    local e = network.iface(s, "eth0")
    local st = status(eth.id)
    local want = {
        Name = "eth0", Kind = "wired", Mac = sut:read_file("/sys/class/net/eth0/address"):match("[%x:]+"),
        Path = "pci-0000:00:02.0", Driver = "virtio_net", Verdict = "JOIN", Rule = "wired",
        Profile = "default", Readiness = e.level, Network = e.network, LastNetwork = e.network,
    }
    for _, name in ipairs(STATUS_VALUES) do
        t:log(string.format("%s = %s (type %s, seq %s)", name, tostring(text(st, name)),
            tostring(st[name] and st[name].type), tostring(st[name] and st[name].sequence)))
        t:assert(st[name] ~= nil, name .. " is present")
        t:assert_eq(st[name].type, lcs.TYPE.SZ, name .. " is REG_SZ")
        t:assert_eq(st[name].text, want[name], name)
    end
    t:assert_eq(e.level, "routed", "eth0 is routed")
    t:assert(st.Mac.text:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") and st.Mac.text == st.Mac.text:lower(),
        "Mac is lower-case and colon-separated")
end)

test("presence: Mac when the link has one, Path and Driver when there are any; Verdict when a rule spoke (gone for the backstop or a tie); Rule when a rule spoke or rules tied; Profile and Readiness for JOIN only; Network while identified, LastNetwork never removed",
    { spec = "netd *inventory.value-presence" }, function(t)
    t:assert(eth.id, "the first test found eth0")
    -- A dummy: a MAC, no bus path, no driver; IGNORE, then JOIN, then DOWN.
    local mac = "02:c0:00:00:04:02"
    local id = ifid_of_mac(mac)
    rule("ptc-pres", { ["Interface.Mac.Equal"] = "sz:" .. mac, Actions = "multi:IGNORE" })
    dummy("ptpres0", mac)
    wait(function() return text(status(id), "Verdict") == "IGNORE" end, "IGNORE recorded")
    local st = status(id)
    t:assert_eq(text(st, "Mac"), mac, "Mac present")
    t:assert_eq(text(st, "Path"), nil, "no Path for a virtual link")
    t:assert_eq(text(st, "Driver"), nil, "no Driver for a virtual link")
    t:assert_eq(text(st, "Rule"), "ptc-pres", "Rule names the rule that spoke")
    t:assert_eq(text(st, "Profile"), nil, "no Profile when ignored")
    t:assert_eq(text(st, "Readiness"), nil, "no Readiness when ignored")
    t:assert_eq(text(st, "Network"), nil, "no Network")
    t:assert_eq(text(st, "LastNetwork"), nil, "no LastNetwork before any identification")

    -- JOIN a profile written in mixed case: Profile is the path as written.
    network.write(sut, "Profiles\\PtPres-Mixed", {})
    rule("ptc-pres", { ["Interface.Mac.Equal"] = "sz:" .. mac, Actions = "multi:JOIN(ptpres-mixed)" })
    wait(function() return text(status(id), "Verdict") == "JOIN" and text(status(id), "Readiness") ~= nil end,
        "JOIN recorded")
    st = status(id)
    t:assert_eq(text(st, "Profile"), "PtPres-Mixed", "Profile is the profile's path as written")
    t:assert_eq(text(st, "Readiness"), iface("ptpres0").level, "Readiness is the interface's level")

    rule("ptc-pres", { ["Interface.Mac.Equal"] = "sz:" .. mac, Actions = "multi:DOWN" })
    wait(function() return text(status(id), "Verdict") == "DOWN" end, "DOWN recorded")
    st = status(id)
    t:assert_eq(text(st, "Profile"), nil, "Profile removed once not joined")
    t:assert_eq(text(st, "Readiness"), nil, "Readiness removed once not joined")
    t:assert_eq(text(st, "Rule"), "ptc-pres", "Rule stays while a rule speaks")

    -- tunl0: no 6-byte MAC, and no rule speaks for an `other` link.
    sut:run("modprobe ipip"):assert_ok()
    local tun = wait(function() return iface("tunl0") end, "netd to list tunl0")
    local tid = tun.ifid
    wait(function() return text(status(tid), "Name") == "tunl0" end, "tunl0's record")
    st = status(tid)
    t:assert_eq(text(st, "Mac"), nil, "no Mac without a 6-byte address")
    t:assert_eq(text(st, "Verdict"), nil, "the backstop: no Verdict")
    t:assert_eq(text(st, "Rule"), nil, "the backstop: no Rule")
    -- A rule speaks, then is removed: both values go again.
    rule("ptc-tun", { ["Interface.Equal"] = "sz:tunl0", Actions = "multi:DOWN" })
    wait(function() return text(status(tid), "Verdict") == "DOWN" end, "tunl0 DOWN recorded")
    t:assert_eq(text(status(tid), "Rule"), "ptc-tun", "Rule written")
    network.delete(sut, "Rules\\Interface\\ptc-tun")
    wait(function() return text(status(tid), "Verdict") == nil end, "the backstop again")
    t:assert_eq(text(status(tid), "Rule"), nil, "Rule removed when the backstop answers")

    -- A tie. Rules that tie on a link netd already has refuse their
    -- generation (§3.2), so the link goes, the tie is written, and the
    -- link comes back: it is judged against the tie with no check.
    local tmac = "02:c0:00:00:04:03"
    local tie_id = ifid_of_mac(tmac)
    rule("ptc-tiew", { ["Interface.Mac.Equal"] = "sz:" .. tmac, Actions = "multi:IGNORE" })
    dummy("pttie0", tmac)
    wait(function() return text(status(tie_id), "Verdict") == "IGNORE" end, "pttie0 IGNORE recorded")
    link_del("pttie0")
    wait(function() return iface("pttie0") == nil end, "pttie0 gone")
    network.delete(sut, "Rules\\Interface\\ptc-tiew")
    network.write(sut, "Profiles\\pttie-p", {})
    network.write(sut, "Profiles\\pttie-q", {})
    rule("ptc-tie-b", { ["Interface.Mac.Equal"] = "sz:" .. tmac, Priority = "dword:50", Actions = "multi:JOIN(pttie-q)" })
    rule("ptc-tie-a", { ["Interface.Mac.Equal"] = "sz:" .. tmac, Priority = "dword:50", Actions = "multi:JOIN(pttie-p)" })
    t:assert_eq(network.status(sut).refusal, nil, "the tying generation was taken (nothing to tie on yet)")
    dummy("pttie0", tmac)
    wait(function() local i = iface("pttie0"); return i and i.warning ~= nil end, "pttie0 judged into the tie")
    st = status(tie_id)
    t:assert_eq(text(st, "Verdict"), nil, "a tie: Verdict removed")
    t:assert_eq(text(st, "Rule"), "ptc-tie-a vs ptc-tie-b", "a tie: Rule names both, sorted")
    t:assert_eq(text(st, "Profile"), nil, "no Profile")
    link_del("pttie0")
    network.delete(sut, "Rules\\Interface\\ptc-tie-a")
    network.delete(sut, "Rules\\Interface\\ptc-tie-b")

    -- Network goes with the carrier; LastNetwork stays.
    t:assert_eq(text(status(eth.id), "Network"), eth.network, "eth0's Network while identified")
    nic:disconnect()
    local off = network.serve_until(gw, sut, function(i) return i.carrier == false and i.network == nil end,
        { iface = "eth0", timeout = 30 })
    t:assert(off, "carrier gone")
    wait(function() return text(status(eth.id), "Network") == nil end, "Network removed")
    t:assert_eq(text(status(eth.id), "LastNetwork"), eth.network, "LastNetwork kept")
    nic:reconnect()
    local back = network.serve_until(gw, sut, function(i) return network.bound(i) and i.network ~= nil end,
        { iface = "eth0", timeout = 60 })
    t:assert(back, "bound and identified again")
    wait(function() return text(status(eth.id), "Network") == eth.network end, "Network back")
end)

test("a value is written only when it differs and a pass that changes nothing writes nothing",
    { spec = "netd *inventory.writes-only-on-change" }, function(t)
    t:assert(eth.id, "the first test found eth0")
    local before = status(eth.id)
    for _ = 1, 3 do
        local r = network.call(sut, { query = "reconcile" })
        t:assert(r and r.ok, "a full pass")
    end
    local after = status(eth.id)
    for _, name in ipairs(STATUS_VALUES) do
        if before[name] then
            t:assert_eq(after[name] and after[name].sequence, before[name].sequence,
                name .. " was not rewritten by three passes")
        end
    end
    -- A pass that does change one value writes that value and no other.
    local mac = "02:c0:00:00:04:04"
    local id = ifid_of_mac(mac)
    rule("ptc-seq", { ["Interface.Mac.Equal"] = "sz:" .. mac, Actions = "multi:IGNORE" })
    dummy("ptseq0", mac)
    wait(function() return text(status(id), "Verdict") == "IGNORE" end, "ptseq0 recorded")
    local s1 = status(id)
    rule("ptc-seq", { ["Interface.Mac.Equal"] = "sz:" .. mac, Actions = "multi:DOWN" })
    wait(function() return text(status(id), "Verdict") == "DOWN" end, "the verdict rewritten")
    local s2 = status(id)
    t:log(string.format("Verdict seq %d -> %d; Name seq %d -> %d", s1.Verdict.sequence, s2.Verdict.sequence,
        s1.Name.sequence, s2.Name.sequence))
    t:assert(s2.Verdict.sequence ~= s1.Verdict.sequence, "the changed value was written (its sequence moved)")
    for _, name in ipairs({ "Name", "Kind", "Mac", "Rule" }) do
        t:assert_eq(s2[name].sequence, s1[name].sequence, name .. " was not rewritten")
    end
end)

test("Status carries O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD): an administrator may read it but its write is refused; the descriptor is set only when netd creates the key",
    { spec = "netd *inventory.status-descriptor" }, function(t)
    t:assert(eth.id, "the first test found eth0")
    local key = IFACES .. "\\" .. eth.id .. "\\Status"
    local sd = network.reg(sut, { "sd", key })
    sd:assert_ok()
    local sddl = sd.stdout:match("[^\n]+")
    t:log("Status: " .. sddl)
    t:assert_eq(sddl, "O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)", "netd's descriptor")

    local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED
    local admin = {
        integrity_level = token.INTEGRITY.HIGH,
        groups = {
            { sid = kacs.SID.EVERYONE, attributes = ENABLED },
            { sid = kacs.SID.AUTHENTICATED_USERS, attributes = ENABLED },
            { sid = kacs.SID.ADMINISTRATORS, attributes = ENABLED },
        },
    }
    local results = {}
    token.as_principal(t, sut, admin, function(w)
        local rd = lcs.open_key(nil, w, -1, key, lcs.RIGHT.KEY_READ)
        results.read = rd.ret >= 0 and "ok" or sys.errname(rd.errno or 0)
        if rd.ret >= 0 then sys.close(w, rd.ret) end
        local wr = lcs.open_key(nil, w, -1, key, lcs.RIGHT.SET_VALUE)
        results.write = wr.ret >= 0 and "ok" or sys.errname(wr.errno or 0)
        if wr.ret >= 0 then sys.close(w, wr.ret) end
        -- The record itself is the operator's: the same principal may write there.
        local parent = lcs.open_key(nil, w, -1, IFACES .. "\\" .. eth.id, lcs.RIGHT.SET_VALUE)
        results.parent = parent.ret >= 0 and "ok" or sys.errname(parent.errno or 0)
        if parent.ret >= 0 then
            local sv = lcs.set_value(nil, w, parent.ret, "PtProbe", lcs.TYPE.SZ, "x\0")
            results.parent_set = sv.ret == 0 and "ok" or sys.errname(sv.errno or 0)
            sys.close(w, parent.ret)
        end
    end)
    t:log(string.format("admin: read Status %s, open Status for write %s, write the record %s/%s",
        tostring(results.read), tostring(results.write), tostring(results.parent), tostring(results.parent_set)))
    t:assert_eq(results.read, "ok", "Everyone may read Status")
    t:assert_eq(results.write, "EACCES (13)", "an administrator's write to Status is refused")
    t:assert_eq(results.parent, "ok", "the administrator can open the record itself for writing")
    t:assert_eq(results.parent_set, "ok", "and write a value there")
    network.reg(sut, { "del", IFACES .. "\\" .. eth.id, "PtProbe" })

    -- Widen it by hand; a fresh netd that finds the key does not put its
    -- own descriptor back.
    local wide = "O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)(A;;KA;;;BA)"
    network.reg(sut, { "sd", key, "--set", wide }):assert_ok()
    network.restart_netd(sut)
    network.serve_until(gw, sut, network.bound, { iface = true, timeout = 30 })
    network.call(sut, { query = "reconcile" })
    local now = network.reg(sut, { "sd", key })
    now:assert_ok()
    t:log("after a netd restart: " .. now.stdout:match("[^\n]+"))
    t:assert_eq(now.stdout:match("[^\n]+"), wide, "the descriptor is not reset on an existing key")
    network.reg(sut, { "sd", key, "--set", "O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)" }):assert_ok()
end)
