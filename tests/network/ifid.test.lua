-- netd TRM §4.1 "Identity and carrier", the identity half: how netd
-- classifies a link, reads its bus path and driver, derives its interface
-- id, what appearing and disappearing do, and that the id survives a
-- rename and a fresh netd. (The carrier half is ifid-carrier.test.lua.)
--
-- Harness: the scripted gateway (helpers.gateway) and one whole Peios
-- machine (helpers.network), the usual pair. Most of the subjects are
-- links the test makes in the guest: the image ships the kernel's
-- dummy, bridge, veth, ipip and mac80211_hwsim modules, so a test can
-- put a wired, a wireless and an `other` link in front of netd without
-- any hardware. They are made over rtnetlink from the agent (the image
-- ships no `ip`), by local functions below, with fixed MACs so their ids
-- can be computed in advance.
--
-- The shipped baseline joins every wired link. So that the made links do
-- not run DHCP clients for nothing, the first test writes an IGNORE rule
-- (priority 30, above the baseline's 10) naming their MACs; an IGNOREd
-- link still gets an id and a record, which is all §4.1 is about.
--
-- The id is checked against sha1.uuid5 over the TRM's exact byte string,
-- never only for shape. The last test renames the real card (eth0) under
-- a DOWN rule, restarts netd, and puts it back, so it runs last.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sha1 = require("helpers.sha1")
local ntfe = require("helpers.ntfe")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

-- ---------------------------------------------------------------------------
-- rtnetlink, from the agent
-- ---------------------------------------------------------------------------

local RTM = { NEWLINK = 16, DELLINK = 17, SETLINK = 19 }
local NLM_F = { REQUEST = 0x1, ACK = 0x4, EXCL = 0x200, CREATE = 0x400 }
local IFLA = { ADDRESS = 1, IFNAME = 3, LINKINFO = 18 }

local function nla(attr, payload)
    local len = 4 + #payload
    return string.pack("<I2I2", len, attr) .. payload .. string.rep("\0", (4 - len % 4) % 4)
end

local function ifinfo(index)
    return string.pack("<I1I1I2i4I4I4", 0, 0, 0, index or 0, 0, 0)
end

--- One acknowledged rtnetlink request. Returns true, or nil and a reason.
local function nl_request(msg_type, flags, body)
    local s = sut:syscall(ntfe.NR.socket, 16, ntfe.SOCK_RAW, 0)
    assert(s.ret >= 0, "netlink socket: " .. sys.errname(s.errno))
    local fd = s.ret
    ntfe.send(sut, fd, string.pack("<I4I2I2I4I4", 16 + #body, msg_type,
        flags | NLM_F.REQUEST | NLM_F.ACK, 1, 0) .. body)
    local buf = ntfe.recv(sut, fd, 3000, 65536)
    sys.close(sut, fd)
    if not buf or #buf < 20 then return nil, "no ack" end
    local _, kind = string.unpack("<I4I2", buf)
    if kind ~= 2 then return nil, "reply type " .. kind end
    local err = string.unpack("<i4", buf, 17)
    if err ~= 0 then return nil, sys.errname(-err) end
    return true
end

--- Make a link of `kind` named `name` with MAC `mac` (text). `o.peer`,
--- `o.peer_mac` for a veth.
local function link_add(name, kind, mac, o)
    o = o or {}
    local data = ""
    if kind == "veth" then
        local peer = ifinfo() .. nla(IFLA.IFNAME, o.peer .. "\0")
            .. nla(IFLA.ADDRESS, gateway.mac(o.peer_mac))
        data = nla(2, nla(1, peer)) -- IFLA_INFO_DATA { VETH_INFO_PEER }
    end
    local body = ifinfo() .. nla(IFLA.IFNAME, name .. "\0") .. nla(IFLA.ADDRESS, gateway.mac(mac))
        .. nla(IFLA.LINKINFO, nla(1, kind) .. data)
    return nl_request(RTM.NEWLINK, NLM_F.CREATE | NLM_F.EXCL, body)
end

--- Raise unless `ok`; `what` names the step.
local function must(what, ok, err)
    if not ok then error(what .. ": " .. tostring(err), 2) end
    return ok
end

local function index_of(name) return ntfe.if_index(sut, name) end

local function link_del(name)
    local index = assert(index_of(name), "no link " .. name)
    return nl_request(RTM.DELLINK, 0, ifinfo(index))
end

--- Rename a (down) link.
local function link_rename(name, new)
    local index = assert(index_of(name), "no link " .. name)
    return nl_request(RTM.SETLINK, 0, ifinfo(index) .. nla(IFLA.IFNAME, new .. "\0"))
end

-- ---------------------------------------------------------------------------
-- What netd published
-- ---------------------------------------------------------------------------

local function status_of(name)
    return network.iface(network.status(sut), name)
end

--- Wait until netd's status lists the link `name`; returns its entry.
local function seen(name)
    return wait_until(function() return status_of(name) end,
        { timeout = 20, interval = 0.25, desc = "netd's status to list " .. name })
end

local function record(id, value)
    return network.get(sut, "Interfaces\\" .. id .. "\\Status", value)
end

local function mac_text(name)
    return (sut:read_file("/sys/class/net/" .. name .. "/address"):match("[%x:]+"))
end

local function ifid(path, mac_or_name)
    return sha1.uuid5("peios-netd-ifid|" .. path .. "|" .. mac_or_name)
end

local function has_file(path)
    return sut:run("test -e '" .. path .. "'").exit_code == 0
end

--- The links the kernel lists now (not lo).
local function link_set()
    local out = {}
    for _, n in ipairs(network.links(sut)) do out[n] = true end
    return out
end

local UUID5 = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-5%x%x%x%-[89ab]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

-- The made links' MACs, all locally administered.
local MAC = {
    dummy = "02:c0:00:00:01:01", bridge = "02:c0:00:00:01:02",
    veth_a = "02:c0:00:00:01:03", veth_b = "02:c0:00:00:01:04",
    appear = "02:c0:00:00:01:05", rename = "02:c0:00:00:01:06",
}
local QUIET = "Rules\\Interface\\ptc-quiet"

-- What the first test learns about eth0 and the made links, for the rest.
local eth0 = {}
local made = {}

-- ---------------------------------------------------------------------------

test("netd classifies a link once per dump: wired for Ethernet (including bridge, veth and dummy), wireless when sysfs has wireless or phy80211, other for any other link type, and loopback (never recorded)",
    { spec = "netd *ifid.kind" }, function(t)
    local s = network.serve_until(gw, sut, network.bound, { iface = true, timeout = 60 })
    t:assert(s, "netd bound a lease on eth0")
    local e = network.iface(s, "eth0")
    eth0.id, eth0.index, eth0.mac = e.ifid, e.index, mac_text("eth0")

    -- Loopback: classified loopback, so never judged and never recorded.
    -- Its id is still derived and logged at first sight (no bus path, its
    -- 6-byte zero MAC).
    local lo_id = ifid("", string.rep("\0", 6))
    t:assert(network.logged(sut, "interface lo () is " .. lo_id, { take = 1000 }),
        "netd logged lo's id " .. lo_id)
    t:assert(status_of("lo") == nil, "lo is not in the status reply")
    t:assert_eq(network.get(sut, "Interfaces\\" .. lo_id .. "\\Status", "Kind"), nil,
        "lo has no record under Interfaces")
    t:assert_eq(network.get(sut, "Interfaces\\" .. eth0.id .. "\\Status", "Kind"), "wired",
        "while eth0, seen in the same dump, has one")

    -- Keep every made link out of the baseline's JOIN.
    network.write(sut, QUIET, {
        ["Interface.Mac.Equal"] = "multi:" .. table.concat({ MAC.dummy, MAC.bridge,
            MAC.veth_a, MAC.veth_b, MAC.rename }, ","),
        Priority = "dword:30", Actions = "multi:IGNORE",
    })

    sut:run("modprobe dummy numdummies=0"):assert_ok()
    sut:run("modprobe bridge"):assert_ok()
    sut:run("modprobe veth"):assert_ok()
    local before = link_set()
    must("link_add('ptdum0', 'dummy', MAC.dummy)", link_add("ptdum0", "dummy", MAC.dummy))
    must("link_add('ptbr0', 'bridge', MAC.bridge)", link_add("ptbr0", "bridge", MAC.bridge))
    must("link_add('ptva0', 'veth', MAC.veth_a, { peer = 'ptvb0', peer_mac = MAC.veth_b })", link_add("ptva0", "veth", MAC.veth_a, { peer = "ptvb0", peer_mac = MAC.veth_b }))
    -- mac80211_hwsim makes a station (wlan*) with phy80211 in sysfs, and
    -- its radiotap medium (hwsim*). ipip makes the fallback tunnel tunl0
    -- (ARPHRD_TUNNEL, a 4-byte hardware address).
    sut:run("modprobe mac80211_hwsim radios=1"):assert_ok()
    sut:run("modprobe ipip"):assert_ok()
    local wlan
    wait_until(function()
        for n in pairs(link_set()) do
            if not before[n] and has_file("/sys/class/net/" .. n .. "/phy80211") then wlan = n end
        end
        return wlan ~= nil and link_set()["tunl0"]
    end, { timeout = 20, interval = 0.5, desc = "a hwsim station and tunl0" })
    made.wlan = wlan
    t:log("hwsim station: " .. wlan)

    local want = {
        eth0 = "wired", ptdum0 = "wired", ptbr0 = "wired", ptva0 = "wired", ptvb0 = "wired",
        [wlan] = "wireless", tunl0 = "other",
    }
    for name, kind in pairs(want) do
        local i = seen(name)
        made[name] = i
        local got = wait_until(function() return record(i.ifid, "Kind") end,
            { timeout = 20, interval = 0.25, desc = name .. "'s Status Kind" })
        t:log(string.format("%s: id %s, Kind %s", name, i.ifid, got))
        t:assert_eq(got, kind, name .. "'s Kind")
    end
    -- The wireless rule is sysfs's, not the link type's: the station is
    -- link type Ethernet (1) like every wired one here.
    t:assert_eq(sut:read_file("/sys/class/net/" .. wlan .. "/type"):match("%d+"), "1",
        wlan .. " is link type Ethernet")
    t:assert(not has_file("/sys/class/net/ptdum0/wireless") and not has_file("/sys/class/net/ptdum0/phy80211"),
        "the dummy has neither wireless nor phy80211")
    t:assert_eq(sut:read_file("/sys/class/net/tunl0/type"):match("%d+"), "768", "tunl0 is ARPHRD_TUNNEL")
end)

test("the bus path is the nearest PCI ancestor of the device, as pci-<address> (a virtio NIC is named by its function); a device with no PCI ancestor by its own name; a virtual link has none; the driver is device/driver's target",
    { spec = "netd *ifid.path-and-driver" }, function(t)
    -- eth0: virtio0 under the PCI function 0000:00:02.0.
    local real = sut:run("realpath /sys/class/net/eth0/device")
    real:assert_ok()
    local dev = real.stdout:match("[^\n]+")
    t:log("eth0's device: " .. dev)
    local leaf = dev:match("([^/]+)$")
    local parent = dev:match("([^/]+)/[^/]+$")
    t:assert(not leaf:match("^%x%x%x%x:%x%x:%x%x%.%x$"), "the device itself is not the PCI function: " .. leaf)
    t:assert_eq(parent, "0000:00:02.0", "the device sits one level below its PCI function")
    local e = status_of("eth0")
    t:assert_eq(e.path, "pci-0000:00:02.0", "eth0's bus path")
    t:assert_eq(e.driver, "virtio_net", "eth0's driver")
    t:assert_eq((sys.readlink(sut, "/sys/class/net/eth0/device/driver") or ""):match("([^/]+)$"),
        "virtio_net", "device/driver points at virtio_net")
    t:assert_eq(record(e.ifid, "Path"), "pci-0000:00:02.0", "Status Path")
    t:assert_eq(record(e.ifid, "Driver"), "virtio_net", "Status Driver")

    -- A virtual link (no `device`): no bus path, no driver.
    t:assert(not has_file("/sys/class/net/ptdum0/device"), "the dummy has no device")
    local d = status_of("ptdum0")
    t:assert_eq(d.path, "", "the dummy's path is empty")
    t:assert_eq(d.driver, "", "the dummy's driver is empty")
    t:assert_eq(record(d.ifid, "Path"), nil, "no Status Path for the dummy")
    t:assert_eq(record(d.ifid, "Driver"), nil, "no Status Driver for the dummy")

    -- The hwsim station: a device with no PCI ancestor is named by the
    -- device's own directory name; its driver is whatever device/driver
    -- names, or nothing.
    local w = made.wlan
    local wreal = sut:run("realpath /sys/class/net/" .. w .. "/device")
    wreal:assert_ok()
    local wdev = wreal.stdout:match("[^\n]+")
    t:log(w .. "'s device: " .. wdev)
    t:assert(not wdev:find("/%x%x%x%x:%x%x:%x%x%.%x/"), "the station's device has no PCI ancestor")
    local wi = status_of(w)
    t:assert_eq(wi.path, wdev:match("([^/]+)$"), w .. "'s path is its device's own name")
    local wdrv = sys.readlink(sut, "/sys/class/net/" .. w .. "/device/driver")
    t:log(w .. "'s device/driver: " .. tostring(wdrv))
    t:assert_eq(wi.driver, wdrv and wdrv:match("([^/]+)$") or "", w .. "'s driver")
end)

test("the interface id is SHA-1 of peios-netd-ifid|<bus path>|<six MAC bytes> (the name for a link without a 6-byte address), stamped v5/RFC 4122 and lower-case; it keys the record and is the Interface.Id fact",
    { spec = "netd *ifid.derivation" }, function(t)
    local e = status_of("eth0")
    local want = ifid("pci-0000:00:02.0", gateway.mac(eth0.mac))
    t:assert_eq(e.ifid, want, "eth0's id over path and MAC")
    t:assert(e.ifid:match(UUID5), "a lower-case v5 UUID: " .. e.ifid)
    t:assert_eq(record(want, "Name"), "eth0", "the record is keyed by the id")

    -- No bus path: the path part is empty, the separator stays.
    local d = status_of("ptdum0")
    t:assert_eq(d.ifid, ifid("", gateway.mac(MAC.dummy)), "the dummy's id over its MAC alone")
    local b = status_of("ptbr0")
    t:assert_eq(b.ifid, ifid("", gateway.mac(MAC.bridge)), "the bridge's id over its MAC alone")

    -- tunl0 has a 4-byte hardware address: its name stands in.
    local tun = status_of("tunl0")
    t:assert_eq(tun.mac, "", "tunl0 has no 6-byte MAC")
    t:assert_eq(tun.ifid, ifid("", "tunl0"), "tunl0's id over its name")
    t:assert(tun.ifid:match(UUID5), "a lower-case v5 UUID: " .. tun.ifid)

    -- The Interface.Id fact: a rule naming the dummy's id speaks for it.
    local key = network.write(sut, "Rules\\Interface\\ptc-byid", {
        ["Interface.Id.Equal"] = "sz:" .. d.ifid, Priority = "dword:40", Actions = "multi:DOWN",
    })
    local ok = wait_until(function()
        local i = status_of("ptdum0")
        return i.rule == "ptc-byid" and i.verdict == "DOWN"
    end, { timeout = 20, interval = 0.25, desc = "the Interface.Id rule to speak" })
    t:assert(ok, "a rule on Interface.Id judged the dummy")
    network.delete(sut, key)
    wait_until(function() return status_of("ptdum0").rule == "ptc-quiet" end,
        { timeout = 20, interval = 0.25, desc = "the quiet rule back" })
end)

test("first sight logs `interface <name> (<path>) is <id>` and writes accept_ra = 0 for the link; a link that disappears is dropped from netd's table and its record stays",
    { spec = "netd *ifid.appear-disappear" }, function(t)
    -- The kernel would give a new link `default`'s accept_ra, which netd
    -- set to 0 at startup; turn the default back on so only netd's own
    -- per-link write can make the new link's 0.
    local DEFAULT = "/proc/sys/net/ipv6/conf/default/accept_ra"
    local saved = sut:read_file(DEFAULT):match("%d+")
    sut:run("echo 1 > " .. DEFAULT):assert_ok()
    t:assert_eq(sut:read_file(DEFAULT):match("%d+"), "1", "default accept_ra turned on")
    local ok, err = pcall(function()
        must("link_add('ptapp0', 'dummy', MAC.appear)", link_add("ptapp0", "dummy", MAC.appear))
        local id = ifid("", gateway.mac(MAC.appear))
        local i = seen("ptapp0")
        t:assert_eq(i.ifid, id, "the new link's id")
        wait_until(function() return network.logged(sut, "interface ptapp0 () is " .. id) end,
            { timeout = 20, interval = 0.5, desc = "the first-sight log line" })
        local ra = sut:read_file("/proc/sys/net/ipv6/conf/ptapp0/accept_ra"):match("%d+")
        t:log("ptapp0 accept_ra = " .. ra .. " (default is 1)")
        t:assert_eq(ra, "0", "netd wrote accept_ra = 0 for the new link")
        -- The record exists (the baseline joined it: a wired link)...
        wait_until(function() return record(id, "Name") == "ptapp0" end,
            { timeout = 20, interval = 0.25, desc = "ptapp0's record" })
        t:assert_eq(record(id, "Verdict"), "JOIN", "the baseline joined the new dummy")

        -- ...and stays after the link goes, with what netd last wrote.
        must("link_del('ptapp0')", link_del("ptapp0"))
        wait_until(function() return status_of("ptapp0") == nil end,
            { timeout = 20, interval = 0.25, desc = "ptapp0 gone from the status reply" })
        t:assert_eq(record(id, "Name"), "ptapp0", "the record keeps its Name")
        t:assert_eq(record(id, "Kind"), "wired", "the record keeps its Kind")
        t:assert_eq(record(id, "Verdict"), "JOIN", "the record keeps its Verdict")
    end)
    sut:run("echo " .. saved .. " > " .. DEFAULT)
    if not ok then error(err, 0) end
end)

test("the id follows the card, not the name: a virtual link remade under another name with the same MAC has the same id, a renamed link keeps it, and a fresh netd derives it again; the real card renamed keeps its id across a netd restart",
    { spec = "netd *ifid.stable-across-renames-and-boots" }, function(t)
    local id = ifid("", gateway.mac(MAC.rename))
    -- Made, removed, made again under another name.
    must("link_add('ptrn0', 'dummy', MAC.rename)", link_add("ptrn0", "dummy", MAC.rename))
    t:assert_eq(seen("ptrn0").ifid, id, "ptrn0's id")
    must("link_del('ptrn0')", link_del("ptrn0"))
    wait_until(function() return status_of("ptrn0") == nil end, { timeout = 20, interval = 0.25 })
    must("link_add('ptrn1', 'dummy', MAC.rename)", link_add("ptrn1", "dummy", MAC.rename))
    local again = seen("ptrn1")
    t:assert_eq(again.ifid, id, "the same MAC under another name has the same id")
    wait_until(function() return record(id, "Name") == "ptrn1" end,
        { timeout = 20, interval = 0.25, desc = "the record renamed to ptrn1" })

    -- Renamed in place (it is IGNOREd, so still down and renameable).
    must("link_rename('ptrn1', 'ptrn2')", link_rename("ptrn1", "ptrn2"))
    local renamed = seen("ptrn2")
    t:assert_eq(renamed.ifid, id, "a renamed link keeps its id")
    t:assert_eq(renamed.index, again.index, "the same kernel link")

    -- The real card. A DOWN rule on its MAC has netd take it down, so it
    -- can be renamed; a fresh netd then derives its id from scratch.
    local before = status_of("eth0")
    t:assert_eq(before.ifid, eth0.id, "eth0's id before")
    local down = network.write(sut, "Rules\\Interface\\ptc-down", {
        ["Interface.Mac.Equal"] = "sz:" .. eth0.mac, Priority = "dword:40", Actions = "multi:DOWN",
    })
    wait_until(function() local i = status_of("eth0"); return i and not i.up end,
        { timeout = 30, interval = 0.25, desc = "netd to take eth0 down" })
    must("link_rename('eth0', 'ptlan0')", link_rename("eth0", "ptlan0"))
    local pid = network.restart_netd(sut)
    t:log("netd restarted as pid " .. tostring(pid))
    local after = seen("ptlan0")
    t:assert_eq(after.ifid, eth0.id, "the renamed card has its id after a netd restart")
    t:assert_eq(after.path, "pci-0000:00:02.0", "same slot")
    t:assert(status_of("eth0") == nil, "no eth0 any more")
    -- And ptrn2, first seen by this netd under its new name.
    t:assert_eq(seen("ptrn2").ifid, id, "the fresh netd derives ptrn2's id from its MAC")
    wait_until(function() return record(eth0.id, "Name") == "ptlan0" end,
        { timeout = 20, interval = 0.25, desc = "the card's record names ptlan0" })

    -- Put the card back in service under its new name.
    network.delete(sut, down)
    local s = network.serve_until(gw, sut, network.bound, { iface = "ptlan0", timeout = 60 })
    t:assert(s, "the renamed card joined and bound a lease again")
    t:assert_eq(network.iface(s, "ptlan0").ifid, eth0.id, "same id, bound")
end)
