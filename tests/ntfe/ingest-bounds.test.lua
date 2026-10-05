-- PKM §6.5 — The walk's own bounds (rule depth 12, 4096 rules per
-- layer), and what becomes of a generation once it is replaced: its
-- forests are freed after grace, so publishing many generations does
-- not grow the kernel.
--
-- These walks are long — thousands of round trips through a source
-- served from Lua — which is why they have a file of their own.
--
-- Own VM: the policy is machine-wide state, and the memory test wants a
-- kernel nothing else is allocating in.

local sys = require("helpers.sys")
local ntfe = require("helpers.ntfe")
local ing = require("helpers.ntfe_ingest")

local vm = provium:vm("vntfeibd", "kernel-only"):boot()
assert(ntfe.if_up(vm, "lo"))

local E = ing.engine(vm, ing.policy())

-- A chain of `levels` rules, each the only exception of the one above:
-- the root at depth 0, the last at depth levels - 1. The deepest
-- REJECTs 6801.
local function chain(levels)
    local rule = { ["DstPort.Equal"] = 6801, Actions = { "REJECT" } }
    for i = levels - 1, 1, -1 do
        rule = { ["DstPort.Equal"] = 6801, Actions = { "PASS" }, children = { ["d" .. i] = rule } }
    end
    return ing.policy({ chain = rule })
end

-- The walk counts a root as depth 0 and refuses depth > 12, so a chain
-- of 13 rules (depth 12) is the deepest it reads, and 14 is refused in
-- the walk, before anything is built.
test("a rule deeper than 12 below its root refuses the walk",
    { spec = "PKM *ntfe-ingest.walk-bounded-depth-12-and-4096-rules" }, function(t)
        local s = ing.replace(E, chain(12))
        t:assert_eq(s.last_ingest_error, 0, "a root and eleven nested exceptions are read")
        t:assert_eq(ing.verdict(vm, 6801), "reject", "and the deepest speaks")
        local refused = ing.replace(E, chain(14))
        t:assert_eq(refused.last_ingest_error, ing.E2BIG, "depth 13 refuses the walk (E2BIG)")
        t:assert_eq(refused.generation, s.generation, "and publishes nothing")
    end)

-- One layer's forest of `count` rules: 64 roots with exceptions under
-- them, the first root passing everything.
local function many(count)
    local layer, n = {}, 0
    for r = 0, 63 do
        local root = { Actions = { "PASS" }, children = {} }
        if r > 0 then root["DstPort.Equal"] = 1 end
        layer[string.format("r%02d", r)] = root
        n = n + 1
    end
    local r = 0
    while n < count do
        local root = layer[string.format("r%02d", r % 64)]
        root.children[string.format("c%04d", n)] = { ["DstPort.Equal"] = 2, Actions = { "DROP" } }
        n, r = n + 1, r + 1
    end
    return layer
end

test("a layer holds 4096 rules and no more",
    { spec = "PKM *ntfe-ingest.walk-bounded-depth-12-and-4096-rules" }, function(t)
        -- Packet is walked first; 4096 there and 64 more in Flow is more
        -- than 4096 in the walk, and the bound is per layer.
        local s = ing.replace(E, { RawPacket = ing.PASS_ALL, Packet = many(4096), Flow = many(64) })
        t:assert_eq(s.last_ingest_error, 0, "4096 rules in one layer, and more beside, are read")
        t:assert_eq(ing.verdict(vm, 6802), "pass", "and judge")
        local refused = ing.replace(E, { RawPacket = ing.PASS_ALL, Packet = many(4097), Flow = many(64) })
        t:assert_eq(refused.last_ingest_error, ing.E2BIG, "the 4097th in a layer refuses the walk (E2BIG)")
        t:assert_eq(refused.generation, s.generation, "and publishes nothing")
    end)

-- ---- generations are freed ----------------------------------------------

local function meminfo(field)
    local fd = assert(sys.open(vm, "/proc/meminfo", sys.O.RDONLY))
    local text = assert(sys.read(vm, fd, 8192))
    sys.close(vm, fd)
    return tonumber(text:match(field .. ":%s+(%d+) kB"))
end

-- A Flow rule with one big list of ports; `salt` makes it a different
-- policy without changing its size.
local function big(salt)
    local ports = {}
    for i = 1, 20000 do ports[i] = tostring(10000 + i) end
    ports[1] = tostring(salt)
    return ing.policy({ big = { ["DstPort.Equal"] = ports, Actions = { "REJECT" } } })
end

test("a replaced generation's forests are freed",
    { spec = "PKM *ntfe-ingest.old-policy-freed-after-grace" }, function(t)
        ing.replace(E, ing.policy())
        local base = meminfo("MemAvailable")
        ing.replace(E, big(1))
        local one = base - meminfo("MemAvailable")
        for i = 2, 41 do ing.replace(E, big(i)) end
        -- Grace periods end on their own: poll, bounded, for the frees.
        local forty
        for _ = 1, 40 do
            forty = base - meminfo("MemAvailable")
            if forty < one * 5 then break end
            sys.nanosleep(vm, 0, 50000000)
        end
        t:assert(one > 200, string.format("(one generation holding the list costs %d kB)", one))
        t:assert(forty < one * 5, string.format(
            "forty more generations cost about what one does: %d kB against %d kB", forty, one))
        ing.replace(E, ing.policy())
    end)

-- Last in the file: a regression would panic the kernel.
test("a rule at depth 12 below its root is read, built and enforced",
    { spec = "PKM *ntfe-ingest.walk-bounded-depth-12-and-4096-rules",
      -- Building a 13-rule chain whose rules carry conditions once
      -- overflowed the kernel stack in pnp_core's recursive build_rule,
      -- about a kilobyte a level, and panicked the machine (PEI-1299);
      -- the build and the evaluation walk with a heap stack now.
    }, function(t)
        local s = ing.replace(E, chain(13))
        t:assert_eq(s.last_ingest_error, 0, "a root and twelve nested exceptions are read")
        t:assert_eq(ing.verdict(vm, 6801), "reject", "and the deepest speaks")
    end)
