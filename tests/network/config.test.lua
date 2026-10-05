-- netd §2.3 — Reading the registry: what netd reads from
-- Machine\System\Network, how each value is lowered before anything
-- interprets it, the sixteen-level depth limit, and what a change under
-- the key causes.
--
-- Harness: the scripted gateway (helpers.gateway) and a whole Peios
-- (helpers.network). Values the `reg` command line cannot spell (a
-- two-byte DWORD, an SZ with a NUL inside or bytes that are not UTF-8, a
-- MULTI_SZ with empty or broken items, a key's default value) are
-- written with the registry's own calls from the agent (`set_raw`).
--
-- Whether a reading took a value or refused it is read off the outcome:
-- the profile parser and the rule builder refuse a value of the wrong
-- shape by name, and a generation that builds logs `interface layer: N
-- rule tree(s), M profile(s)`. netd's log is the evidence where a test
-- asserts that a write was NOT configuration (`configuration changed` is
-- logged exactly when a reading differs from the last).
--
-- Own VMs: the tests change the machine's hostname and swap the control
-- object, and leave the hostname set (netd never unsets one).

local peinit = require("helpers.peinit")
local gateway = require("helpers.gateway")
local network = require("helpers.network")
local sys = require("helpers.sys")

peinit.claim(2)

local lan = network.bridge("lan")
local gw = gateway.boot({ bridge = lan })
gw:dhcp({ pool = { "10.77.0.50" }, lease = 3600 })
local sut = network.boot({ bridges = { lan }, gateway = gw })

local KEY = network.KEY

-- ---------------------------------------------------------------------------
-- Local instruments
-- ---------------------------------------------------------------------------

local function guest_ns()
    return assert(tonumber(sut:run("date +%s%N").stdout:match("%d+")), "guest clock")
end

--- netd's log lines newer than `since` (guest ns), oldest first, in the
--- order eventd recorded them.
local function log_since(since)
    local r = sut:run("evctl 'LOGS FROM netd SINCE 1h ago TAKE 5000'")
    assert(r.exit_code == 0, "evctl: " .. r.stderr)
    local newest_first = {}
    for line in r.stdout:gmatch("[^\n]+") do
        local msg = line:match('message="(.-)"  origin=')
        local ts = tonumber(line:match("timestamp=(%d+)"))
        if msg and ts and ts > since then
            newest_first[#newest_first + 1] = { ts = ts, msg = (msg:gsub("\\(.)", "%1")) }
        end
    end
    local out = {}
    for i = #newest_first, 1, -1 do out[#out + 1] = newest_first[i] end
    return out
end

local function find(lines, text, from)
    for i = from or 1, #lines do
        if lines[i].msg:find(text, 1, true) then return i end
    end
end

local function count(lines, text)
    local n = 0
    for _, l in ipairs(lines) do
        if l.msg:find(text, 1, true) then n = n + 1 end
    end
    return n
end

local function dump(t, lines)
    local out = {}
    for _, l in ipairs(lines) do out[#out + 1] = l.msg end
    t:log("netd log:\n" .. table.concat(out, "\n"))
end

local function apply(doc)
    sut:write_file("/tmp/pt-batch.json", json.encode(doc))
    local r = network.reg(sut, { "apply", "/tmp/pt-batch.json" })
    assert(r.exit_code == 0, "reg apply: " .. r.stdout .. r.stderr)
end

local function set(key, name, typed)
    if not key:match("^Machine\\") then key = KEY .. (key ~= "" and "\\" .. key or "") end
    network.reg(sut, { "set", key, name, typed }):assert_ok()
end

local function unset(key, name)
    if not key:match("^Machine\\") then key = KEY .. (key ~= "" and "\\" .. key or "") end
    network.reg(sut, { "del", key, name }):assert_ok()
end

local function del_tree(key)
    network.reg(sut, { "del", "-r", KEY .. "\\" .. key }):assert_ok()
end

--- A full pass that has certainly handled every registry event before
--- it: `net reconcile` is answered after the iteration that read them.
local function barrier()
    sut:run("net reconcile"):assert_ok()
end

--- Wait for the generation the last write caused: returns the log line
--- (`interface layer: …` when taken, `interface layer refused: …`).
local function generation(since)
    local line
    wait_until(function()
        local lines = log_since(since)
        local i = find(lines, "interface layer")
        line = i and lines[i].msg
        return line ~= nil
    end, { timeout = 15, interval = 0.25, desc = "a generation to be built" })
    return line
end

local function rebind(t)
    local s = network.serve_until(gw, sut, network.bound, { iface = "eth0", timeout = 60 })
    t:assert(s, "eth0 holds a bound lease")
    return s
end

-- ---------------------------------------------------------------------------
-- What is read
-- ---------------------------------------------------------------------------

test("netd reads Hostname, ControlSecurity, Duid and the two trees, and nothing else as configuration",
    { spec = "netd *config.what-is-read" }, function(t)
        local s = rebind(t)
        local netid = network.iface(s, "eth0").network
        t:assert(netid, "the network is identified")
        local mark = guest_ns()
        -- Empty values count as unset: the reading does not change.
        set("", "Hostname", "sz:")
        barrier()
        set("", "ControlSecurity", "hex:")
        barrier()
        -- A value no list names, and one under Networks\: not configuration.
        set("", "PtUnrelated", "sz:anything")
        barrier()
        set([[Networks\]] .. netid, "Name", "sz:pt-cfg-net")
        barrier()
        local quiet = log_since(mark)
        dump(t, quiet)
        t:assert_eq(count(quiet, "configuration changed"), 0,
            "an empty Hostname, an empty ControlSecurity and unlisted values change nothing")
        t:assert_eq(find(quiet, "ControlSecurity is not a valid descriptor"), nil,
            "the empty ControlSecurity was never taken as a descriptor")
        t:assert(network.call(sut, { query = "status" }).ok, "the default control object stands")
        -- Networks\ is read when netd needs it, at the pass.
        t:assert_eq(network.iface(network.status(sut), "eth0").network_name, "pt-cfg-net",
            "the network record's Name is read where it is shared")
        unset([[Networks\]] .. netid, "Name")
        unset("", "PtUnrelated")
        unset("", "ControlSecurity")

        -- Hostname, set.
        mark = guest_ns()
        set("", "Hostname", "sz:pt-netd-a")
        wait_until(function() return network.status(sut).hostname == "pt-netd-a" end,
            { timeout = 15, interval = 0.25, desc = "the hostname to be applied" })
        t:assert_eq(sut:read_file("/proc/sys/kernel/hostname"), "pt-netd-a\n", "the kernel's hostname")
        local lines = log_since(mark)
        t:assert_eq(count(lines, "configuration changed"), 1, "a set Hostname is a change of configuration")

        -- Duid that is not hex: ignored with a warning.
        local orig = network.reg(sut, { "get", "--raw", KEY, "Duid" })
        orig:assert_ok()
        local duid = orig.stdout:gsub("%z.*$", "")
        t:log("Duid was " .. duid)
        t:assert(duid:match("^%x%x:"), "netd's Duid is hex")
        mark = guest_ns()
        set("", "Duid", "sz:not-hex!")
        barrier()
        lines = log_since(mark)
        dump(t, lines)
        t:assert(find(lines, 'netd: warn: Duid "not-hex!" is not hex; ignoring it') ~= nil,
            "a Duid that is not hex is ignored with a warning")
        set("", "Duid", "sz:" .. duid)
        barrier()

        -- The two trees (each written in one transaction, so one
        -- generation follows).
        mark = guest_ns()
        apply({ keys = { { path = KEY .. [[\Profiles\pt-cfg]],
            values = { { name = "Address.Offered", type = "dword", data = 1 } } } } })
        t:assert_eq(generation(mark), "netd: info: interface layer: 1 rule tree(s), 2 profile(s)",
            "a profile under Profiles\\ is read")
        mark = guest_ns()
        apply({ keys = { { path = KEY .. [[\Rules\Interface\pt-cfg]],
            values = { { name = "Interface.Kind.Equal", type = "sz", data = "wireless" },
                       { name = "Actions", type = "multi", data = { "JOIN(pt-cfg)" } } } } } })
        t:assert_eq(generation(mark), "netd: info: interface layer: 2 rule tree(s), 2 profile(s)",
            "a rule under Rules\\Interface is read")
        del_tree([[Rules\Interface\pt-cfg]])
        del_tree([[Profiles\pt-cfg]])
        barrier()
        t:assert_eq(network.status(sut).refusal, nil, "the baseline again")
    end)

-- ---------------------------------------------------------------------------
-- Lowering
-- ---------------------------------------------------------------------------

local PROFILE = [[Machine\System\Network\Profiles\pt-low]]
local RULE = [[Machine\System\Network\Rules\Interface\pt-low]]

-- Registry value types (PKM's, Windows' numbering).
local T = { SZ = 1, EXPAND_SZ = 2, BINARY = 3, DWORD = 4, MULTI_SZ = 7, QWORD = 11 }

--- Set a value's raw bytes under any type, through the registry's own
--- calls (reg_open_key, REG_IOC_SET_VALUE): the image's `reg` checks
--- what it writes, and these cases are values it would not write.
local function set_raw(path, name, vtype, data)
    local o = sut:syscall(1100, { -- reg_open_key
        args = { -1, 0, 0x000F003F, 0 }, bufs = { path .. "\0" }, ptrs = { 1 } })
    assert(o.ret >= 0, "reg_open_key " .. path .. ": errno " .. tostring(o.errno))
    local r = sut:syscall(sys.NR.ioctl, {
        args = { o.ret, 0x40405201, 0 }, -- REG_IOC_SET_VALUE
        bufs = {
            string.pack("<I4I4I8I4I4I8I4I4I8i4I4I8", #name, 0, 0, vtype, #data, 0, 0, 0, 0, -1, 0, 0),
            name, data,
        },
        ptrs = { 2 },
        nested = { { parent = 1, child = 2, offset = 8 }, { parent = 1, child = 3, offset = 24 } },
    })
    sys.close(sut, o.ret)
    assert(r.ret == 0, "set " .. path .. " " .. name .. ": errno " .. tostring(r.errno))
end

--- Set one raw value and return the log line of the generation it caused.
local function try(path, name, vtype, data)
    local mark = guest_ns()
    set_raw(path, name, vtype, data)
    return generation(mark)
end

local TAKEN = "netd: info: interface layer: "
local function refused(why)
    return "netd: error: interface layer refused: " .. why .. "; the last good generation stands"
end

test("every value is lowered to an integer, a string, a list or other before it is interpreted",
    { spec = "netd *config.lowering" }, function(t)
        local function taken(line, what)
            t:log(what .. " -> " .. line)
            t:assert(line:find(TAKEN, 1, true) == 1, what .. ": taken")
        end
        local mark = guest_ns()
        network.write(sut, [[Profiles\pt-low]], {})
        taken(generation(mark), "an empty profile")
        -- A QWORD of eight bytes is an integer.
        taken(try(PROFILE, "Address.Offered", T.QWORD, string.pack("<I8", 1)), "QWORD Address.Offered")
        -- A DWORD of the wrong length is other: the wrong shape.
        local l = try(PROFILE, "Address.Offered", T.DWORD, "\1\0")
        t:log("2-byte DWORD -> " .. l)
        t:assert_eq(l, refused("profile pt-low: address.offered has the wrong shape"),
            "a two-byte DWORD is refused as the wrong shape")
        t:assert_eq(network.status(sut).refusal, "profile pt-low: address.offered has the wrong shape",
            "and reported")
        taken(try(PROFILE, "Address.Offered", T.DWORD, string.pack("<I4", 1)), "a four-byte DWORD")
        -- An SZ is cut at its first NUL.
        taken(try(PROFILE, "Address.OnExpiry", T.SZ, "keep\0junk\0"), "SZ keep<NUL>junk")
        -- An SZ that is not UTF-8 is other.
        l = try(PROFILE, "Address.OnExpiry", T.SZ, "\xff\xfe\0")
        t:log("non-UTF-8 SZ -> " .. l)
        t:assert_eq(l, refused("profile pt-low: address.onexpiry has the wrong shape"),
            "an SZ that is not UTF-8 is refused as the wrong shape, not read lossily")
        -- An EXPAND_SZ is a string.
        taken(try(PROFILE, "Address.OnExpiry", T.EXPAND_SZ, "keep\0"), "EXPAND_SZ keep")
        -- A MULTI_SZ drops empty items and items that are not UTF-8.
        taken(try(PROFILE, "Address.Families", T.MULTI_SZ, "ipv4\0\0\xff\xfe\0\0"),
            "MULTI_SZ ipv4, <empty>, <not UTF-8>")
        -- A key's default value is skipped: writing one does not change
        -- the reading at all (read, it would be an unknown value).
        local function skipped(path, what)
            local m = guest_ns()
            set_raw(path, "", T.BINARY, "\0")
            barrier()
            local exported = network.reg(sut, { "export", path }).stdout
            t:assert(exported:find("\n  @ = ", 1, true), what .. ": the default value is in the registry")
            local ls = log_since(m)
            dump(t, ls)
            t:assert_eq(count(ls, "configuration changed"), 0, what .. ": the reading did not change")
            t:assert_eq(count(ls, "interface layer"), 0, what .. ": no generation")
        end
        skipped(PROFILE, "a profile's default value")

        -- The rule builder. An empty Actions item vanishes in lowering.
        mark = guest_ns()
        network.write(sut, [[Rules\Interface\pt-low]], {})
        taken(generation(mark), "an empty rule")
        taken(try(RULE, "Actions", T.MULTI_SZ, "\0JOIN(pt-low)\0\0"), "Actions with an empty item")
        -- Other is refused by name.
        l = try(RULE, "Interface.Kind.Equal", T.BINARY, "wireless")
        t:log("binary rule condition -> " .. l)
        t:assert_eq(l, refused("rule pt-low: value Interface.Kind.Equal has an unsupported type"),
            "the rule builder refuses an unusable value by name")
        taken(try(RULE, "Interface.Kind.Equal", T.SZ, "wireless\0"), "repaired")
        -- A QWORD priority is an integer; the default value is skipped.
        taken(try(RULE, "Priority", T.QWORD, string.pack("<I8", 5)), "QWORD Priority")
        skipped(RULE, "a rule's default value")
        t:assert_eq(network.status(sut).refusal, nil, "the refusal is cleared")
        t:assert_eq(network.iface(network.status(sut), "eth0").rule, "wired", "eth0 untouched throughout")

        -- Values come back sorted, so an unchanged tree reads equal: a
        -- rewrite of the same bytes is not a change.
        mark = guest_ns()
        set_raw(RULE, "Priority", T.QWORD, string.pack("<I8", 5))
        set_raw(RULE, "Interface.Kind.Equal", T.SZ, "wireless\0")
        barrier()
        -- Then a real change, which must be the only one.
        del_tree([[Rules\Interface\pt-low]])
        local line = generation(mark)
        local lines = log_since(mark)
        dump(t, lines)
        t:assert_eq(line, "netd: info: interface layer: 1 rule tree(s), 2 profile(s)",
            "the deletion is the generation that follows")
        t:assert_eq(count(lines, "configuration changed"), 1,
            "the rewrite of unchanged values read equal; only the deletion changed the reading")
        del_tree([[Profiles\pt-low]])
        barrier()
    end)

-- ---------------------------------------------------------------------------
-- Depth
-- ---------------------------------------------------------------------------

test("a tree is read sixteen levels deep and no further",
    { spec = "netd *config.tree-read-sixteen-deep" }, function(t)
        local keys, path, names = {}, [[Machine\System\Network\Profiles]], {}
        for d = 1, 17 do
            path = path .. "\\pt-d" .. d
            names[d] = "pt-d" .. d
            keys[#keys + 1] = { path = path }
        end
        local mark = guest_ns()
        apply({ keys = keys })
        local line = generation(mark)
        local lines = log_since(mark)
        dump(t, lines)
        t:assert(find(lines, "netd: warn: pt-d16: tree deeper than 16; the rest is ignored") ~= nil,
            "the read stops below the sixteenth level, with a warning")
        t:assert_eq(line, "netd: info: interface layer: 1 rule tree(s), 17 profile(s)",
            "default and pt-d1..pt-d16 are profiles; pt-d17 is not configuration")
        local p16 = table.concat(names, "/", 1, 16)
        local p17 = table.concat(names, "/", 1, 17)
        local function rule(values)
            local m = guest_ns()
            apply({ keys = { { path = [[Machine\System\Network\Rules\Interface\pt-deep]], values = values } } })
            return generation(m)
        end
        line = rule({
            { name = "Interface.Kind.Equal", type = "sz", data = "wireless" },
            { name = "Actions", type = "multi", data = { "JOIN(" .. p16 .. ")" } } })
        t:log("JOIN(…pt-d16) -> " .. line)
        t:assert(line:find(TAKEN, 1, true) == 1, "a rule may name the sixteenth level")
        line = rule({ { name = "Actions", type = "multi", data = { "JOIN(" .. p17 .. ")" } } })
        t:log("JOIN(…pt-d17) -> " .. line)
        t:assert_eq(line, refused("JOIN(" .. p17 .. ") names no profile"),
            "but not the seventeenth, which was never read")
        del_tree([[Rules\Interface\pt-deep]])
        del_tree([[Profiles\pt-d1]])
        barrier()
        t:assert_eq(network.status(sut).refusal, nil, "the baseline again")
    end)

-- ---------------------------------------------------------------------------
-- A registry change
-- ---------------------------------------------------------------------------

test("any change under the key is a reload and a full pass; netd's own writes plan nothing",
    { spec = "netd *config.registry-change" }, function(t)
        local s = rebind(t)
        local netid = network.iface(s, "eth0").network
        -- A change that is not configuration still causes a full pass,
        -- which reads the network record afresh.
        local mark = guest_ns()
        set([[Networks\]] .. netid, "Trust", "sz:pt-trusted")
        wait_until(function() return network.iface(network.status(sut), "eth0").network_trust == "pt-trusted" end,
            { timeout = 15, interval = 0.25, desc = "a pass to read the record" })
        t:assert_eq(count(log_since(mark), "configuration changed"), 0, "with no change of configuration")
        unset([[Networks\]] .. netid, "Trust")

        -- A change of configuration rebuilds the control object at once.
        local deny = peinit.system_descriptor_hex(0x2) -- SYSTEM: NETWORK_CONTROL only
        set("", "ControlSecurity", "hex:" .. deny)
        local denied
        wait_until(function()
            denied = network.call(sut, { query = "status" })
            return denied and denied.ok == false
        end, { timeout = 15, interval = 0.25, desc = "the new descriptor to apply" })
        t:log("status under the new descriptor: " .. json.encode(denied))
        t:assert_eq(denied.error, "access denied", "the next connection is judged by the written descriptor")
        unset("", "ControlSecurity")
        wait_until(function()
            local x = network.call(sut, { query = "status" })
            return x and x.ok == true
        end, { timeout = 15, interval = 0.25, desc = "the default descriptor back" })

        -- netd's own writes: a pass in a new second rewrites the network's
        -- LastSeen under the watched key, and that comes back through
        -- the watch as a reload that finds nothing and a pass with
        -- nothing to apply.
        local status_key = [[Networks\]] .. netid .. [[\Status]]
        local seen0 = network.reg(sut, { "get", "--raw", KEY .. "\\" .. status_key, "LastSeen" }).stdout:gsub("%z.*$", "")
        sut:run("sleep 1.2")
        local pid = network.netd_pid(sut)
        local function cpu()
            local f = sut:read_file("/proc/" .. pid .. "/stat"):match("%) (.*)")
            local fields = {}
            for w in f:gmatch("%S+") do fields[#fields + 1] = w end
            return tonumber(fields[12]) + tonumber(fields[13]) -- utime + stime
        end
        mark = guest_ns()
        barrier()
        local seen1 = network.reg(sut, { "get", "--raw", KEY .. "\\" .. status_key, "LastSeen" }).stdout:gsub("%z.*$", "")
        t:log("LastSeen " .. seen0 .. " -> " .. seen1)
        t:assert(tonumber(seen1) > tonumber(seen0), "netd wrote under its own watched key")
        local c0 = cpu()
        sut:run("sleep 3")
        local c1 = cpu()
        local lines = log_since(mark)
        dump(t, lines)
        t:log("netd CPU ticks over 3 s idle: " .. (c1 - c0))
        t:assert_eq(count(lines, "configuration changed"), 0, "its own write is no change of configuration")
        t:assert_eq(count(lines, "applying"), 0, "and the pass it causes plans nothing")
        t:assert(c1 - c0 <= 5, "and it does not feed itself: netd is idle")
    end)
