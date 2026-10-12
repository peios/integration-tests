-- netd TRM §8.4 — the hostname: which name netd uses (the registry's
-- `Hostname`, else a lease's option 12 where the profile takes it), that
-- it follows the shared one-label rule, when sethostname(2) is called, and
-- that netd never unsets a name.
--
-- The kernel's name is read from /proc/sys/kernel/hostname, netd's from
-- the `hostname` field of its status reply (the name it last set). The
-- image ships no registry `Hostname` and boots with the kernel's
-- `(none)`, so the lease source can be tested first with nothing to
-- clear. The gateway's lease carries option 12 throughout until the last
-- test takes it away; a renewal (`renew` control request) puts a changed
-- lease in place without touching anything else.
--
-- Order matters and the tests share the pair: lease name, registry name
-- (and its precedence), invalid names and DHCP announcements, a change
-- made behind netd's back, then removing every source.
--
-- The first-joined-interface-in-index-order rule needs two leases on two
-- interfaces; that is `hostname-order`.

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
local LEASE_NAME = "lease-name"
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, options = { { 12, LEASE_NAME } } })
local files = {}
files = network.test_binary("netd", files)
local sut = network.boot({ bridges = { lan }, gateway = gw, files = files })

local function kernel_name()
    return (sut:read_file("/proc/sys/kernel/hostname"):gsub("%s+$", ""))
end

local function netd_name() return network.status(sut).hostname end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { take = 400 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local function full_pass(t)
    local r = network.call(sut, { query = "reconcile" })
    t:assert(r and r.ok, "a full pass on request")
    gw:serve({ timeout = 1 })
end

--- Pump until the kernel's hostname is `name`.
local function kernel_becomes(t, name, what)
    local ok = gw:serve({ timeout = 15, until_ = function() return kernel_name() == name end })
    t:assert(ok, what .. " (kernel has `" .. kernel_name() .. "`)")
end

local function renew(t)
    local r = network.call(sut, { query = "renew", interface = "eth0" })
    t:assert(r and r.ok, "renew accepted")
end

test("the name is the registry's Hostname when set, else the option 12 of a lease whose profile has Hostname.Offered",
    { spec = "netd *hostname.source" }, function(t)
        local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
        t:assert(s, "netd bound a lease carrying option 12")
        t:assert_eq(network.get(sut, network.KEY, "Hostname"), nil, "the registry has no Hostname")
        full_pass(t)
        t:assert_eq(netd_name(), "", "without Hostname.Offered the lease's name is not taken: netd has set none")
        t:assert_eq(kernel_name(), "(none)", "and the kernel keeps its own")

        -- The profile takes the network's name (and restarts the client,
        -- which binds the same lease again).
        network.write(sut, [[Profiles\default]], { ["Hostname.Offered"] = "dword:1" })
        kernel_becomes(t, LEASE_NAME, "the lease's name becomes the hostname")
        t:assert_eq(netd_name(), LEASE_NAME, "netd reports the name it set")
        t:assert(network.logged(sut, "hostname is " .. LEASE_NAME), "and logged `hostname is " .. LEASE_NAME .. "`")

        -- The registry outranks the lease.
        network.write(sut, network.KEY, { Hostname = "sz:registry-name" })
        kernel_becomes(t, "registry-name", "the registry's Hostname wins over the lease's")
        t:assert_eq(netd_name(), "registry-name", "netd reports it")
        -- An empty Hostname is as good as none: the lease's name comes back.
        network.write(sut, network.KEY, { Hostname = "sz:" })
        kernel_becomes(t, LEASE_NAME, "an empty Hostname falls through to the lease")
        network.write(sut, network.KEY, { Hostname = "sz:registry-name" })
        kernel_becomes(t, "registry-name", "and a set one wins again")
    end)

test("invalid registry names retain the applied name, warn once, and do not fall through to DHCP",
    { spec = "netd *hostname.passed-as-written", tags = { "pei-1334" } }, function(t)
        local previous = kernel_name()
        for _, name in ipairs({ "Not_One.Label", "LocalHost", string.rep("x", 64), "bad name" }) do
            local before = count_logged(" refused: ")
            network.write(sut, network.KEY, { Hostname = "sz:" .. name })
            wait_until(function() return count_logged(" refused: ") > before end,
                { timeout = 15, interval = 0.1, desc = "invalid registry name refused" })
            t:assert_eq(kernel_name(), previous, "invalid registry name does not change the kernel or select the lease")
            t:assert_eq(netd_name(), previous, "status retains the applied name")
            local count = count_logged(" refused: ")
            full_pass(t)
            full_pass(t)
            t:assert_eq(count_logged(" refused: "), count, "the same invalid candidate is not logged every pass")
        end
        network.write(sut, network.KEY, { Hostname = "sz:  Registry-Trimmed  " })
        kernel_becomes(t, "Registry-Trimmed", "valid registry names use the shared whitespace normalization")
    end)

test("invalid DHCP hostnames are refused and a later valid offered name is adopted",
    { tags = { "pei-1334" } }, function(t)
        network.reg(sut, { "del", network.KEY, "Hostname" }):assert_ok()
        kernel_becomes(t, LEASE_NAME, "return to the valid offered name")
        for i, name in ipairs({ "bad.name", "bad name", "LocalHost", string.rep("x", 64), "bad\nname" }) do
            local lease = 3500 - i * 100
            local before = count_logged(" refused: ")
            gw:dhcp({ pool = { "10.77.0.50" }, lease = lease, options = { { 12, name } } })
            renew(t)
            t:assert(network.serve_until(gw, sut, function(iface)
                return network.bound(iface) and iface.lease.expires_in <= lease
            end, { iface = "eth0", timeout = 15 }), "renewal with invalid name was taken")
            wait_until(function() return count_logged(" refused: ") > before end,
                { timeout = 10, interval = 0.1, desc = "invalid offered name refused" })
            t:assert_eq(kernel_name(), LEASE_NAME, "the prior valid hostname survives the invalid offer")
            t:assert_eq(netd_name(), LEASE_NAME, "invalid offer is not published as the applied hostname")
        end
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 2800, options = { { 12, "  New-Lease  " } } })
        renew(t)
        kernel_becomes(t, "New-Lease", "a subsequent valid lease name is normalized and adopted")
    end)

test("DHCP announcements omit invalid registry names and normalize valid names",
    { tags = { "pei-1334" } }, function(t)
        for _, case in ipairs({ { "bad.announce", false }, { "  Announce-Good  ", "Announce-Good" } }) do
            network.write(sut, network.KEY, { Hostname = "sz:" .. case[1] })
            full_pass(t)
            network.write(sut, [[Profiles\default]], { ["Hostname.Announce"] = "dword:0" })
            full_pass(t)
            gw:forget()
            network.write(sut, [[Profiles\default]], { ["Hostname.Announce"] = "dword:1" })
            local request
            t:assert(gw:serve({ timeout = 20, until_ = function()
                local requests = gw:dhcp_messages(gateway.DHCP.REQUEST)
                request = requests[#requests]
                return request ~= nil
            end }), "a restarted client sent a DHCP request")
            t:assert_eq(request.opt[12], case[2] or nil, "option 12 contains only a validated registry hostname")
            t:assert(network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 20 }), "bound after restart")
        end
        network.write(sut, [[Profiles\default]], { ["Hostname.Announce"] = "dword:0" })
    end)

test("sethostname is called only when netd's own name changes, never to undo another's change",
    { spec = "netd *hostname.applied-after-each-pass" }, function(t)
        network.write(sut, network.KEY, { Hostname = "sz:netd-name" })
        kernel_becomes(t, "netd-name", "netd sets its name")
        local sets = count_logged("hostname is netd-name")
        t:assert_eq(sets, 1, "logged once")

        -- Changed behind netd's back: not reverted, pass after pass.
        sut:run("hostname changed-by-hand"):assert_ok()
        t:assert_eq(kernel_name(), "changed-by-hand", "the kernel took the hand change")
        full_pass(t)
        full_pass(t)
        t:assert_eq(kernel_name(), "changed-by-hand", "netd does not revert it")
        t:assert_eq(netd_name(), "netd-name", "and still reports the name it set")
        t:assert_eq(count_logged("hostname is netd-name"), sets, "no sethostname for an unchanged name")

        -- netd compares with its own last name, not the kernel's: a new
        -- name equal to what the kernel already has is still set and logged.
        network.write(sut, network.KEY, { Hostname = "sz:changed-by-hand" })
        t:assert(wait_until(function()
            gw:serve({ timeout = 0 })
            return count_logged("hostname is changed-by-hand") == 1
        end, { timeout = 15, interval = 0.25, desc = "netd to set its new name" }),
            "netd logs `hostname is changed-by-hand` though the kernel already had it")
        t:assert_eq(netd_name(), "changed-by-hand", "it is now netd's name")
        -- And its next change is applied over whatever is there.
        network.write(sut, network.KEY, { Hostname = "sz:netd-again" })
        kernel_becomes(t, "netd-again", "a change of netd's name is applied")
    end)

test("with no name from any source netd does nothing: the kernel keeps the last name",
    { spec = "netd *hostname.never-unset" }, function(t)
        -- The lease stops offering a name, then the registry value goes.
        -- A shorter lease, so the moment the ACK is taken shows in status.
        gw:dhcp({ pool = { "10.77.0.50" }, lease = 1800 })
        renew(t)
        t:assert(network.serve_until(gw, sut, function(i)
            return network.bound(i) and i.lease.expires_in <= 1800
        end, { iface = "eth0", timeout = 15 }), "the renewal is answered with a lease without option 12, and taken")
        t:assert_eq(kernel_name(), "netd-again", "the registry name still stands")
        network.reg(sut, { "del", network.KEY, "Hostname" }):assert_ok()
        t:assert_eq(network.get(sut, network.KEY, "Hostname"), nil, "Hostname is gone from the registry")
        full_pass(t)
        full_pass(t)
        t:assert_eq(kernel_name(), "netd-again", "the kernel keeps the name it had")
        t:assert_eq(netd_name(), "netd-again", "and netd still reports the name it last set")
        network.reg(sut, { "del", network.KEY .. [[\Profiles\default]], "Hostname.Offered" })
    end)
