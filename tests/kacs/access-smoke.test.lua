-- Probe the AccessCheck helper: a grant, a denial, MAXIMUM_ALLOWED, and
-- the result-list variant — establishing the syscall's return contract
-- before the §3.8 suites build on it.
local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

test("AccessCheck grants, denies and reports MAXIMUM_ALLOWED",
    { spec = "PKM *check.accesscheck.returns" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x120089, token.SID.EVERYONE) })
        local r = access.check(vm, { token_fd = fd, sd = sd, desired = 0x1 })
        t:log(string.format("grant: ret=%d errno=%d granted=0x%x ca=%s sm=%s", r.ret, r.errno or 0,
            r.granted or -1, tostring(r.continuous_audit), tostring(r.staging_mismatch)))
        t:assert_eq(r.ret, 0x1, "a granted request returns the granted mask: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, 0x1, "granted mask is the requested bit")
        local d = access.check(vm, { token_fd = fd, sd = sd, desired = 0x2 })
        t:log(string.format("deny: ret=%d errno=%d granted=0x%x", d.ret, d.errno or 0, d.granted or -1))
        t:assert(d.denied, "a denied request is -1/EACCES: ret=" .. d.ret .. " " .. sys.errname(d.errno or 0))
        t:assert_eq(d.granted, 0, "and grants nothing")
        local m = access.check(vm, { token_fd = fd, sd = sd, desired = access.STD.MAXIMUM_ALLOWED })
        t:log(string.format("max: ret=%d granted=0x%x", m.ret, m.granted or -1))
        t:assert_eq(m.ret, 0x120089, "MAXIMUM_ALLOWED succeeds, returning the accumulated mask")
        t:assert_eq(m.granted, 0x120089, "and returns the accumulated mask")
        local l = access.check_list(vm, { token_fd = fd, sd = sd, desired = 0x1,
            tree = { { level = 0, guid = string.rep("\1", 16) } } })
        t:log(string.format("list: ret=%d errno=%d granted=0x%x node0=%s/%s", l.ret, l.errno or 0,
            l.granted or -1, tostring(l.nodes[1] and l.nodes[1].granted), tostring(l.nodes[1] and l.nodes[1].status)))
        t:assert(l.ok, "result-list variant succeeds: ret=" .. l.ret .. " " .. sys.errname(l.errno or 0))
        sys.close(vm, fd)
    end)
