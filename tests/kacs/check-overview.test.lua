-- PKM §3.8.1 — the AccessCheck surface: what the two API variants
-- return, when the CAAP staging mismatch flag is raised, and the rule
-- that the layers after the DACL walk narrow the result rather than
-- re-opening what the walk decided.
--
-- The agent is SYSTEM and would pass almost everything, so every case
-- mints its own subject with helpers/token and passes it as `token_fd`.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E = token.SID.EVERYONE
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits, so a case can tell which category a granted bit came
--- from. The standard rights live in `all` and in none of the three.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE = 0x1, 0x2

local function guid(n) return string.rep(string.char(n), 16) end

--- Publish a CAAP policy whose one rule has an effective DACL and,
--- optionally, a differing staged DACL; returns the policy SID. The
--- caller removes it again with `drop_policy`.
local function publish_policy(rid, effective_mask, staged_mask)
    local sid = token.sid(5, 21, 1000, 2000, 3000, rid)
    local rule = { effective_dacl = access.acl({ access.ace(access.ACE.ALLOWED, effective_mask, E) }) }
    if staged_mask then
        rule.staged_dacl = access.acl({ access.ace(access.ACE.ALLOWED, staged_mask, E) })
    end
    local r = access.set_caap(vm, sid, access.caap_spec({ rule }))
    assert(r.ret == 0, "kacs_set_caap: " .. sys.errname(r.errno or 0))
    return sid
end
local function drop_policy(sid) access.set_caap(vm, sid, nil) end

--- A descriptor granting `mask` to Everyone, referencing `policy_sid`
--- through a SYSTEM_SCOPED_POLICY_ID ACE in its SACL.
local function sd_under_policy(mask, policy_sid)
    return access.simple({ access.ace(access.ACE.ALLOWED, mask, E) },
        { sacl = access.acl({ access.ace(access.ACE.SCOPED_POLICY_ID, 0, policy_sid) }) })
end

test("AccessCheck returns the granted mask, the verdict, the continuous audit mask and the staging flag",
    { spec = "PKM *check.accesscheck.returns" }, function(t)
        local fd = assert(token.mint(vm, {}))
        -- An alarm ACE is what feeds the continuous audit mask.
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x7, E) },
            { sacl = access.acl({ access.ace(access.ACE.ALARM, 0x6, E,
                access.ACE_FLAG.SUCCESSFUL_ACCESS | access.ACE_FLAG.FAILED_ACCESS) }) })
        local r = access.check(vm, { token_fd = fd, sd = sd, desired = READ, mapping = OBJ })
        t:log(string.format("grant: ret=%d granted=0x%x ca=0x%x sm=%d", r.ret, r.granted,
            r.continuous_audit, r.staging_mismatch))
        t:assert(r.ok, "the request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.ret, READ, "and the syscall returns the granted mask")
        t:assert_eq(r.granted, READ, "which is also written to granted_out")
        t:assert_eq(r.continuous_audit, 0x6, "the continuous audit mask comes from the SACL alarm ACE")
        t:assert_eq(r.staging_mismatch, 0, "and no CAAP policy applies, so no staging mismatch")

        -- 0x8 is a right the DACL never mentions; the read bit is granted
        -- alongside it, so the failed request still reports a mask.
        local d = access.check(vm, { token_fd = fd, sd = sd, desired = READ | 0x8, mapping = OBJ })
        t:log(string.format("deny: ret=%d errno=%s granted=0x%x", d.ret, sys.errname(d.errno or 0), d.granted))
        t:assert(d.denied, "a request naming a right the DACL does not carry fails: ret=" .. d.ret
            .. " " .. sys.errname(d.errno or 0))
        t:assert_eq(d.granted, READ, "and the partial granted mask is still reported")
        sys.close(vm, fd)
    end)

test("the staging mismatch flag is set when a staged CAAP result differs from the effective one",
    { spec = "PKM *check.staging-flag.accesscheck" }, function(t)
        local fd = assert(token.mint(vm, {}))
        -- Effective rule grants read+write, staged grants read only.
        local differing = publish_policy(9101, READ | WRITE, READ)
        local r = access.check(vm, { token_fd = fd, sd = sd_under_policy(0x7, differing),
            desired = READ | WRITE, mapping = OBJ })
        t:log(string.format("differing staged DACL: ret=%d granted=0x%x sm=%d", r.ret, r.granted,
            r.staging_mismatch))
        t:assert(r.ok, "the effective result still grants the request: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted, READ | WRITE, "the effective rule is what decides access")
        t:assert_eq(r.staging_mismatch, 1, "and the staged scalar result differing raises the flag")
        drop_policy(differing)

        local matching = publish_policy(9102, READ | WRITE, READ | WRITE)
        local m = access.check(vm, { token_fd = fd, sd = sd_under_policy(0x7, matching),
            desired = READ | WRITE, mapping = OBJ })
        t:log(string.format("identical staged DACL: ret=%d granted=0x%x sm=%d", m.ret, m.granted,
            m.staging_mismatch))
        t:assert_eq(m.staging_mismatch, 0, "an identical staged result leaves the flag clear")
        drop_policy(matching)
        sys.close(vm, fd)
    end)

test("AccessCheckResultList requires an object type list",
    { spec = "PKM *check.result-list.requires-tree" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local sd = access.simple({ access.ace(access.ACE.ALLOWED, 0x7, E) })
        -- helpers/access always supplies a tree to check_list, so this
        -- builds the args block by hand with a null object_type pointer
        -- and a zero count — the shape a caller that omitted the list
        -- entirely produces.
        local args = string.pack("<I4i4I8I4I4I4I4I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I4I4I8I8",
            access.ARGS_SIZE, fd, 0, #sd, READ,
            OBJ.read, OBJ.write, OBJ.execute, OBJ.all,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        local nested = { { parent = 1, child = 2, offset = 8 } }
        local list = vm:syscall(access.SYS.ACCESS_CHECK_LIST, {
            args = { 0, 0, 0 }, bufs = { args, sd }, ptrs = { 0 }, nested = nested,
        })
        t:log(string.format("list with no tree: ret=%d %s", list.ret, sys.errname(list.errno or 0)))
        t:assert(list.ret < 0, "the result-list variant refuses a request with no object type list")
        t:assert(list.errno ~= sys.E.ACCES, "as an invalid request rather than a denial: "
            .. sys.errname(list.errno or 0))

        local scalar = vm:syscall(access.SYS.ACCESS_CHECK, {
            args = { 0 }, bufs = { args, sd }, ptrs = { 0 }, nested = nested,
        })
        t:log(string.format("scalar with no tree: ret=%d %s", scalar.ret, sys.errname(scalar.errno or 0)))
        t:assert_eq(scalar.ret, READ, "while scalar AccessCheck accepts the very same request")
        sys.close(vm, fd)
    end)

test("AccessCheckResultList returns a verdict per node, so one denial fails that node alone",
    { spec = "PKM *check.result-list.returns" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local tree = { { level = 0, guid = guid(1) }, { level = 1, guid = guid(2) },
            { level = 1, guid = guid(3) } }
        -- Everyone is allowed the read bit everywhere, but it is denied on
        -- the second child through an object ACE naming its GUID.
        local sd = access.simple({
            access.ace(access.ACE.DENIED_OBJECT, READ, E, 0, { object_type = guid(3) }),
            access.ace(access.ACE.ALLOWED, READ, E),
        })
        local r = access.check_list(vm, { token_fd = fd, sd = sd, desired = READ,
            mapping = OBJ, tree = tree })
        t:log(string.format("list: ret=%d nodes=%d/%d %d/%d %d/%d", r.ret,
            r.nodes[1].granted, r.nodes[1].status, r.nodes[2].granted, r.nodes[2].status,
            r.nodes[3].granted, r.nodes[3].status))
        t:assert(r.ok, "the call itself succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.nodes[2].granted, READ, "the undenied property keeps the right")
        t:assert_eq(r.nodes[2].status, 0, "and its own verdict is success")
        t:assert_eq(r.nodes[3].granted, 0, "the denied property gets nothing")
        t:assert(r.nodes[3].status ~= 0, "and carries its own denial status: " .. r.nodes[3].status)

        local scalar = access.check(vm, { token_fd = fd, sd = sd, desired = READ,
            mapping = OBJ, tree = tree })
        t:assert(scalar.denied, "while scalar AccessCheck fails the whole request: ret=" .. scalar.ret)
        sys.close(vm, fd)
    end)

test("the staging mismatch flag is set when a node's staged grant differs from its effective grant",
    { spec = "PKM *check.staging-flag.result-list" }, function(t)
        local fd = assert(token.mint(vm, {}))
        local tree = { { level = 0, guid = guid(1) }, { level = 1, guid = guid(2) } }
        local differing = publish_policy(9103, READ | WRITE, READ)
        local r = access.check_list(vm, { token_fd = fd, sd = sd_under_policy(0x7, differing),
            desired = READ | WRITE, mapping = OBJ, tree = tree })
        t:log(string.format("differing staged DACL: node1=0x%x node2=0x%x sm=%d",
            r.nodes[1].granted, r.nodes[2].granted, r.staging_mismatch))
        t:assert(r.ok, "the call succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.nodes[1].granted, READ | WRITE, "every node carries the effective grant")
        t:assert_eq(r.staging_mismatch, 1, "and the per-node staged delta raises the flag")
        drop_policy(differing)

        local matching = publish_policy(9104, READ | WRITE, nil)
        local m = access.check_list(vm, { token_fd = fd, sd = sd_under_policy(0x7, matching),
            desired = READ | WRITE, mapping = OBJ, tree = tree })
        t:log(string.format("no staged DACL: node1=0x%x sm=%d", m.nodes[1].granted, m.staging_mismatch))
        t:assert_eq(m.staging_mismatch, 0,
            "a rule with no staged DACL contributes to both totals, so the flag stays clear")
        drop_policy(matching)
        sys.close(vm, fd)
    end)

test("a layer after the DACL narrows the result and does not re-open a decided bit",
    { spec = "PKM *check.state.narrow-not-reopen" }, function(t)
        -- The DACL denies the read bit through TEST_GROUP_2 before allowing
        -- read+write through Everyone, so the normal pass decides read as
        -- denied. The restricted pass sees only Everyone, never reaches the
        -- deny ACE, and grants read+write. If the intersection re-opened the
        -- decided bit the caller would end up with read; it must not.
        local sd = access.simple({
            access.ace(access.ACE.DENIED, READ, token.SID.TEST_GROUP_2),
            access.ace(access.ACE.ALLOWED, READ | WRITE, E),
        })
        local fd = assert(token.mint(vm, {
            groups = { { sid = E, attributes = ENABLED },
                { sid = token.SID.TEST_GROUP_2, attributes = ENABLED } },
            restricted_sids = { { sid = E, attributes = 0 } },
        }))
        local r = access.check(vm, { token_fd = fd, sd = sd,
            desired = STD.MAXIMUM_ALLOWED, mapping = OBJ })
        t:log(string.format("restricted intersection: ret=%d granted=0x%x", r.ret, r.granted))
        t:assert(r.ok, "a pure MAXIMUM_ALLOWED request succeeds: " .. sys.errname(r.errno or 0))
        t:assert_eq(r.granted & READ, 0,
            "the bit the normal walk decided as denied stays denied through the intersection")
        t:assert_eq(r.granted & WRITE, WRITE, "while the bit both passes granted survives")

        local denial = access.check(vm, { token_fd = fd, sd = sd, desired = READ, mapping = OBJ })
        t:assert(denial.denied, "and asking for it outright fails: ret=" .. denial.ret
            .. " " .. sys.errname(denial.errno or 0))
        sys.close(vm, fd)
    end)
