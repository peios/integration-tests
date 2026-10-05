-- netd TRM §5.5 — the link-local address is never desired beside a static
-- address of either family.
--
-- A silent gateway (it records DHCP and answers none of it), so every
-- DHCPv4 client netd starts here goes unanswered and makes its "nobody
-- answered" report about 28 s in. The machine first shows the fallback
-- with the shipped baseline untouched, which is the control: the same
-- link, the same profile but for one value, does get the address. Then
-- `Address.Static` is written on `Profiles\default`, once with an IPv4
-- entry and once with an IPv6 entry. Each write changes the profile, so
-- netd restarts the client (§3.3), and the new client reports again; the
-- report is the event to wait for, and it is counted in netd's log
-- because the claim is precisely that the report happens and the address
-- still does not appear.
--
-- Its own pair because the profile edits would disturb `linklocal`'s
-- timings. That a lease also keeps the address away is shown there
-- (`linklocal.test.lua`, the lease test).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local rtnl = require("helpers.rtnl")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600, silent = true })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local PROFILE = [[Profiles\default]]
local REPORT = "interface eth0: no DHCP offer; link-local "

local function link_locals(i)
    local out = {}
    for _, a in ipairs((i and i.addresses) or {}) do
        if a:match("^169%.254%.") then out[#out + 1] = a end
    end
    return out
end

local function count_logged(text)
    local n = 0
    for _, l in ipairs(network.logs(sut, { take = 400 })) do
        if l:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local function iface()
    return network.iface(network.status(sut), "eth0")
end

--- Write `Address.Static` = `value`, then pump until the restarted
--- client has made its report (the report count passes `reports`).
--- Returns the interface status at that moment.
local function static_and_report(t, value, reports)
    network.write(sut, PROFILE, { ["Address.Static"] = value })
    local ok = gw:serve({ timeout = 50, until_ = function() return count_logged(REPORT) > reports end })
    t:assert(ok, "the restarted client reports that nobody answered (" .. value .. ")")
    -- The report and the reconcile it triggers are one loop iteration;
    -- one more status read is after both.
    gw:serve({ timeout = 1 })
    return iface()
end

test("a static address of either family keeps the link-local address away, even after the report",
    { spec = "netd *linklocal.not-beside-a-lease-or-static" }, function(t)
        -- Control: the untouched baseline does fall back.
        local s = network.serve_until(gw, sut, function(x) return #link_locals(x) > 0 end,
            { iface = "eth0", timeout = 50 })
        t:assert(s, "with no static address the link-local address appears")
        local index = network.iface(s, "eth0").index
        t:assert_eq(count_logged(REPORT), 1, "after one report")

        -- An IPv4 static.
        local i = static_and_report(t, "sz:10.77.9.9/24", 1)
        t:log("IPv4 static: " .. table.concat(i.addresses, " "))
        t:assert_eq(count_logged(REPORT), 2, "the new client made its own report")
        t:assert(network.has_address(i, "10.77.9.9"), "the static address is applied")
        t:assert_eq(#link_locals(i), 0, "and no link-local address is desired beside it")
        for _, a in ipairs(rtnl.addresses_of(sut, index, 4)) do
            t:assert(not a.address:match("^169%.254%."), "the kernel holds no 169.254 address: " .. a.address)
        end

        -- An IPv6 static: either family counts.
        i = static_and_report(t, "sz:fd77::99/64", 2)
        t:log("IPv6 static: " .. table.concat(i.addresses, " "))
        t:assert_eq(count_logged(REPORT), 3, "the next client made its report too")
        t:assert(network.has_address(i, "fd77::99"), "the IPv6 static address is applied")
        t:assert(not network.has_address(i, "10.77.9.9"), "the IPv4 static is gone with its value")
        t:assert_eq(#link_locals(i), 0, "and an IPv6 static keeps the IPv4 link-local away as well")
        for _, a in ipairs(rtnl.addresses_of(sut, index, 4)) do
            t:assert(not a.address:match("^169%.254%."), "the kernel holds no 169.254 address: " .. a.address)
        end

        network.reg(sut, { "del", network.KEY .. "\\" .. PROFILE, "Address.Static" }):assert_ok()
    end)
