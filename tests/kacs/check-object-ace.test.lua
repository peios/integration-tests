-- PKM §3.8.5 — object ACEs and property-level access: how a GUID-scoped
-- ACE applies with and without an object type list, the four directions
-- decisions propagate through the tree, PRINCIPAL_SELF, the scalar
-- result, and the parse-time validation of the list itself.

local sys = require("helpers.sys")
local token = require("helpers.token")
local access = require("helpers.access")

local vm = provium:vm("v", "kernel-only"):boot()

local STD = access.STD
local E, USER = token.SID.EVERYONE, token.SID.TEST_USER
local PRINCIPAL_SELF = token.sid(5, 10)
local ENABLED = token.GROUP.MANDATORY | token.GROUP.ENABLED_BY_DEFAULT | token.GROUP.ENABLED

--- A synthetic object type whose read, write and execute rights are three
--- disjoint bits.
local OBJ = { read = 0x1, write = 0x2, execute = 0x4,
    all = 0x7 | STD.DELETE | STD.READ_CONTROL | STD.WRITE_DAC | STD.WRITE_OWNER | STD.SYNCHRONIZE }
local READ, WRITE, EXEC = 0x1, 0x2, 0x4
local ALLOW, DENY = access.ACE.ALLOWED, access.ACE.DENIED
local ALLOW_OBJECT, DENY_OBJECT = access.ACE.ALLOWED_OBJECT, access.ACE.DENIED_OBJECT

local function guid(n) return string.rep(string.char(n), 16) end
local ROOT, A, B, A_CHILD, ABSENT = guid(1), guid(2), guid(3), guid(4), guid(9)

--- root, with two children A and B.
local FLAT = { { level = 0, guid = ROOT }, { level = 1, guid = A }, { level = 1, guid = B } }
--- root, with A carrying a child of its own, and a sibling B.
local DEEP = { { level = 0, guid = ROOT }, { level = 1, guid = A },
    { level = 2, guid = A_CHILD }, { level = 1, guid = B } }

--- An object ACE for Everyone. `object_type` nil means the ACE carries no
--- GUID, so `ACE_OBJECT_TYPE_PRESENT` is unset.
local function obj(ace_type, mask, object_type)
    return access.ace(ace_type, mask, E, 0, { object_type = object_type })
end

--- Mint a fresh subject from `spec` (copied, because `token.mint` stamps
--- the session it creates into it) and run `fn(fd)`.
local function with_subject(spec, fn)
    local fresh = {}
    for k, v in pairs(spec or {}) do fresh[k] = v end
    local fd, e = token.mint(vm, fresh)
    assert(fd, "mint: " .. sys.errname(e or 0))
    local ok, err = pcall(fn, fd)
    sys.close(vm, fd)
    if not ok then error(err, 0) end
    return nil
end

--- Scalar AccessCheck as a fresh default subject.
local function scalar(sd, desired, opts)
    opts = opts or {}
    local out
    with_subject(opts.spec, function(fd)
        out = access.check(vm, { token_fd = fd, sd = sd, desired = desired, mapping = OBJ,
            tree = opts.tree, self_sid = opts.self_sid })
    end)
    return out
end

--- AccessCheckResultList as a fresh default subject.
local function result_list(sd, desired, tree, opts)
    opts = opts or {}
    local out
    with_subject(opts.spec, function(fd)
        out = access.check_list(vm, { token_fd = fd, sd = sd, desired = desired, mapping = OBJ,
            tree = tree, self_sid = opts.self_sid })
    end)
    return out
end

local function nodes_of(r)
    local parts = {}
    for i, n in ipairs(r.nodes) do parts[i] = string.format("%d:0x%x/%d", i, n.granted, n.status) end
    return table.concat(parts, " ")
end

test("an object ACE with no GUID behaves exactly like a basic ACE",
    { spec = "PKM *check.object-ace.no-guid-is-basic" }, function(t)
        local as_object = access.simple({ obj(DENY_OBJECT, READ, nil), obj(ALLOW_OBJECT, READ | WRITE, nil) })
        local as_basic = access.simple({ access.ace(DENY, READ, E), access.ace(ALLOW, READ | WRITE, E) })
        local a = scalar(as_object, STD.MAXIMUM_ALLOWED)
        local b = scalar(as_basic, STD.MAXIMUM_ALLOWED)
        t:log(string.format("object-ace granted=0x%x, basic granted=0x%x", a.granted, b.granted))
        t:assert_eq(a.granted, b.granted,
            "the same masks and order through object ACEs without a GUID give the same result")
        t:assert_eq(a.granted, WRITE, "first-writer-wins and all")
    end)

test("each node of an object type list carries its own decided and granted pair",
    { spec = "PKM *check.object-ace.per-node-state" }, function(t)
        local sd = access.simple({ obj(ALLOW_OBJECT, READ, A), obj(ALLOW_OBJECT, WRITE, B) })
        local r = result_list(sd, STD.MAXIMUM_ALLOWED, FLAT)
        t:log("nodes " .. nodes_of(r))
        t:assert_eq(r.nodes[2].granted, READ, "the node named by the first ACE has that right")
        t:assert_eq(r.nodes[3].granted, WRITE, "the node named by the second has the other")
        t:assert_eq(r.nodes[1].granted, 0, "and the root, which neither named, has neither")
    end)

test("with no object type list supplied, an object ACE's GUID applies globally",
    { spec = "PKM *check.object-ace.no-list-applies-globally" }, function(t)
        local allowed = scalar(access.simple({ obj(ALLOW_OBJECT, READ, ABSENT) }), READ)
        local denied = scalar(access.simple({ obj(DENY_OBJECT, READ, ABSENT),
            access.ace(ALLOW, READ, E) }), READ)
        t:log(string.format("allow ret=%d, deny ret=%d %s", allowed.ret, denied.ret,
            sys.errname(denied.errno or 0)))
        t:assert(allowed.ok, "the GUID-scoped allow ACE grants as if it were basic: "
            .. sys.errname(allowed.errno or 0))
        t:assert(denied.denied, "and the GUID-scoped deny ACE denies the same way: ret="
            .. denied.ret .. " " .. sys.errname(denied.errno or 0))
    end)

test("with a list supplied, every ACE that behaves like a basic ACE applies to every node",
    { spec = "PKM *check.object-ace.basic-applies-to-all-nodes" }, function(t)
        local basic = result_list(access.simple({ access.ace(ALLOW, READ, E) }), READ, FLAT)
        local guidless = result_list(access.simple({ obj(ALLOW_OBJECT, READ, nil) }), READ, FLAT)
        t:log("basic " .. nodes_of(basic) .. " | no-guid object ACE " .. nodes_of(guidless))
        for i = 1, 3 do
            t:assert_eq(basic.nodes[i].granted, READ, "an ordinary basic ACE reaches node " .. i)
            t:assert_eq(guidless.nodes[i].granted, READ,
                "an object ACE without an ObjectType GUID reaches node " .. i)
        end
    end)

test("an object ACE whose GUID is not in the tree is silently skipped",
    { spec = "PKM *check.object-ace.unmatched-guid-skipped" }, function(t)
        local r = result_list(access.simple({ obj(ALLOW_OBJECT, READ, ABSENT) }),
            STD.MAXIMUM_ALLOWED, FLAT)
        t:log(string.format("ret=%d %s nodes %s", r.ret, sys.errname(r.errno or 0), nodes_of(r)))
        t:assert(r.ok, "the unmatched GUID is not an error: " .. sys.errname(r.errno or 0))
        for i = 1, 3 do
            t:assert_eq(r.nodes[i].granted, 0, "and grants nothing on node " .. i)
        end
    end)

test("a grant on a property set flows down to every attribute within it",
    { spec = "PKM *check.object-ace.grant-propagates-down" }, function(t)
        local r = result_list(access.simple({ obj(ALLOW_OBJECT, READ, A) }),
            STD.MAXIMUM_ALLOWED, DEEP)
        t:log("nodes " .. nodes_of(r))
        t:assert_eq(r.nodes[2].granted, READ, "the named set is granted")
        t:assert_eq(r.nodes[3].granted, READ, "and so is the attribute inside it")
        t:assert_eq(r.nodes[4].granted, 0, "while the sibling set is untouched")
    end)

test("a right every attribute in a set holds propagates up to the set",
    { spec = "PKM *check.object-ace.grant-propagates-up" }, function(t)
        local one = result_list(access.simple({ obj(ALLOW_OBJECT, READ, A) }),
            STD.MAXIMUM_ALLOWED, FLAT)
        local both = result_list(access.simple({ obj(ALLOW_OBJECT, READ, A),
            obj(ALLOW_OBJECT, READ, B) }), STD.MAXIMUM_ALLOWED, FLAT)
        t:log("one child " .. nodes_of(one) .. " | both children " .. nodes_of(both))
        t:assert_eq(one.nodes[1].granted, 0,
            "one child holding the right is not enough — the propagation is a per-bit intersection")
        t:assert_eq(both.nodes[1].granted, READ, "with every child holding it, the parent gets it")
    end)

test("a denial on an attribute propagates to every ancestor and leaves siblings alone",
    { spec = "PKM *check.object-ace.denial-propagates-up" }, function(t)
        local r = result_list(access.simple({ obj(DENY_OBJECT, READ, A),
            access.ace(ALLOW, READ, E) }), STD.MAXIMUM_ALLOWED, FLAT)
        t:log("nodes " .. nodes_of(r))
        t:assert_eq(r.nodes[2].granted, 0, "the denied node has nothing")
        t:assert_eq(r.nodes[1].granted, 0, "its ancestor inherits the denial")
        t:assert_eq(r.nodes[3].granted, READ, "and its sibling is unaffected")
    end)

test("ancestors apply first-writer-wins to a propagated denial",
    { spec = "PKM *check.object-ace.denial-up-first-writer-wins" }, function(t)
        -- Ancestor decides first: the later denial on a descendant cannot
        -- take the right back from it.
        local already = result_list(access.simple({ access.ace(ALLOW, READ, E),
            obj(DENY_OBJECT, READ, A) }), STD.MAXIMUM_ALLOWED, FLAT)
        -- Denial first: the propagated bit is decided on the ancestor, so
        -- the allow ACE behind it cannot grant there either.
        local propagated = result_list(access.simple({ obj(DENY_OBJECT, READ, A),
            access.ace(ALLOW, READ, E) }), STD.MAXIMUM_ALLOWED, FLAT)
        t:log("allow first " .. nodes_of(already) .. " | deny first " .. nodes_of(propagated))
        t:assert_eq(already.nodes[1].granted, READ,
            "a denial cannot overturn what the ancestor had already decided")
        t:assert_eq(propagated.nodes[1].granted, 0,
            "and a propagated denial is itself decided, so a later ACE cannot grant over it")
    end)

test("a denial on a property set flows down to every attribute within it",
    { spec = "PKM *check.object-ace.denial-propagates-down" }, function(t)
        local r = result_list(access.simple({ obj(DENY_OBJECT, READ, A),
            access.ace(ALLOW, READ, E) }), STD.MAXIMUM_ALLOWED, DEEP)
        t:log("nodes " .. nodes_of(r))
        t:assert_eq(r.nodes[2].granted, 0, "the named set is denied")
        t:assert_eq(r.nodes[3].granted, 0,
            "and so is the attribute inside it, which the later allow ACE cannot rescue")
        t:assert_eq(r.nodes[4].granted, READ, "while the sibling set still gets the right")
    end)

test("a PRINCIPAL_SELF ACE matches the caller when self_sid names the object's principal",
    { spec = "PKM *check.object-ace.principal-self-matches-self-sid" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, PRINCIPAL_SELF) })
        local r = scalar(sd, READ, { self_sid = USER })
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.ok, "S-1-5-10 resolves through the supplied self_sid: "
            .. sys.errname(r.errno or 0))
        t:assert_eq(r.ret, READ, "granting the right the ACE carries")
    end)

test("with a null self_sid a PRINCIPAL_SELF ACE matches nothing",
    { spec = "PKM *check.object-ace.principal-self-null-matches-nothing" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, PRINCIPAL_SELF) })
        local r = scalar(sd, READ)
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.denied, "the same ACE grants nothing without a self_sid: ret=" .. r.ret
            .. " " .. sys.errname(r.errno or 0))
    end)

test("PRINCIPAL_SELF follows the ordinary deny-only rules",
    { spec = "PKM *check.object-ace.principal-self-deny-only" }, function(t)
        -- self_sid is the token's user SID, and the token is user_deny_only.
        local deny_only = { groups = { { sid = E, attributes = ENABLED } }, user_deny_only = true }
        local allowed = scalar(access.simple({ access.ace(ALLOW, READ, PRINCIPAL_SELF) }), READ,
            { spec = deny_only, self_sid = USER })
        local denied = scalar(access.simple({ access.ace(DENY, READ, PRINCIPAL_SELF),
            access.ace(ALLOW, READ, E) }), READ, { spec = deny_only, self_sid = USER })
        local ordinary = scalar(access.simple({ access.ace(ALLOW, READ, PRINCIPAL_SELF) }), READ,
            { self_sid = USER })
        t:log(string.format("deny-only allow ret=%d, deny-only deny ret=%d, ordinary allow ret=%d",
            allowed.ret, denied.ret, ordinary.ret))
        t:assert(ordinary.ok, "an ordinary token matches the allow ACE: "
            .. sys.errname(ordinary.errno or 0))
        t:assert(allowed.denied, "a deny-only matching SID does not match an allow ACE: ret="
            .. allowed.ret .. " " .. sys.errname(allowed.errno or 0))
        t:assert(denied.denied, "but does match a deny ACE: ret=" .. denied.ret
            .. " " .. sys.errname(denied.errno or 0))
    end)

test("scalar AccessCheck requires every node to pass",
    { spec = "PKM *check.object-ace.scalar-requires-all-nodes" }, function(t)
        local sd = access.simple({ obj(DENY_OBJECT, READ, B), access.ace(ALLOW, READ, E) })
        local r = scalar(sd, READ, { tree = FLAT })
        local list = result_list(sd, READ, FLAT)
        t:log(string.format("scalar ret=%d %s | list %s", r.ret, sys.errname(r.errno or 0),
            nodes_of(list)))
        t:assert(r.denied, "a denial on one property fails the whole request: ret=" .. r.ret
            .. " " .. sys.errname(r.errno or 0))
        t:assert_eq(list.nodes[2].granted, READ,
            "even though another property in the same tree was granted the right")
    end)

test("the scalar result is the root node's granted mask",
    { spec = "PKM *check.object-ace.scalar-is-root-mask" }, function(t)
        -- read reaches only A, write only B, execute every node; the root's
        -- mask is therefore execute alone.
        local sd = access.simple({ obj(ALLOW_OBJECT, READ, A), obj(ALLOW_OBJECT, WRITE, B),
            access.ace(ALLOW, EXEC, E) })
        local r = scalar(sd, STD.MAXIMUM_ALLOWED, { tree = FLAT })
        local list = result_list(sd, STD.MAXIMUM_ALLOWED, FLAT)
        t:log(string.format("scalar granted=0x%x | list %s", r.granted, nodes_of(list)))
        t:assert_eq(r.granted, list.nodes[1].granted,
            "the scalar granted mask is the root node's")
        t:assert_eq(r.granted, EXEC, "which here is the one right every node holds")
    end)

test("a supplied object type list must be non-empty",
    { spec = "PKM *check.object-ace.list-non-empty" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local empty = scalar(sd, READ, { tree = {} })
        local omitted = scalar(sd, READ)
        t:log(string.format("empty list ret=%d %s, no list ret=%d", empty.ret,
            sys.errname(empty.errno or 0), omitted.ret))
        t:assert(empty.ret < 0 and not empty.denied,
            "a list with no entries is rejected: " .. sys.errname(empty.errno or 0))
        t:assert(omitted.ok, "while omitting the list entirely is fine: "
            .. sys.errname(omitted.errno or 0))
    end)

test("the first node of an object type list must be at level 0",
    { spec = "PKM *check.object-ace.list-first-node-level-zero" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local r = scalar(sd, READ, { tree = { { level = 1, guid = ROOT } } })
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.ret < 0 and not r.denied,
            "a list whose first node is at level 1 is rejected: " .. sys.errname(r.errno or 0))
    end)

test("an object type list has exactly one level-0 node",
    { spec = "PKM *check.object-ace.list-one-root" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local r = scalar(sd, READ, { tree = { { level = 0, guid = ROOT }, { level = 0, guid = A } } })
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.ret < 0 and not r.denied,
            "a second level-0 node is rejected: " .. sys.errname(r.errno or 0))
    end)

test("an object type list has no level gaps",
    { spec = "PKM *check.object-ace.list-no-level-gaps" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local r = scalar(sd, READ, { tree = { { level = 0, guid = ROOT }, { level = 2, guid = A } } })
        local ok = scalar(sd, READ, { tree = { { level = 0, guid = ROOT }, { level = 1, guid = A } } })
        t:log(string.format("gap ret=%d %s, no gap ret=%d", r.ret, sys.errname(r.errno or 0), ok.ret))
        t:assert(r.ret < 0 and not r.denied,
            "a node at level 2 following one at level 0 is rejected: " .. sys.errname(r.errno or 0))
        t:assert(ok.ok, "while the same list without the gap is accepted: "
            .. sys.errname(ok.errno or 0))
    end)

test("no GUID appears twice in an object type list",
    { spec = "PKM *check.object-ace.list-no-duplicate-guid" }, function(t)
        local sd = access.simple({ access.ace(ALLOW, READ, E) })
        local r = scalar(sd, READ, { tree = { { level = 0, guid = ROOT }, { level = 1, guid = ROOT } } })
        t:log(string.format("ret=%d %s", r.ret, sys.errname(r.errno or 0)))
        t:assert(r.ret < 0 and not r.denied,
            "a repeated GUID is rejected: " .. sys.errname(r.errno or 0))
    end)
