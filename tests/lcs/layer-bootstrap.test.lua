-- PKM §5.3.3 — the bootstrap refresh isolates a malformed layer: one
-- badly authored metadata key under `Layers\` is skipped, and its
-- well-formed siblings publish as they would have without it.
--
-- Its own file because the malformed layer has to be in storage before
-- the source registers. Every other layer-metadata case seeds a clean
-- table and breaks a layer live, which the live refresh isolates by
-- construction; the bootstrap refresh had to be given the same
-- isolation (PEI-762, red until kernel 0.20.1-rc13-9).

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")

local vm = provium:vm("v", "kernel-only"):boot()

local TEST_PATH = "Machine\\Software\\Test"

local src = lcs.source(vm)
src:key(TEST_PATH)
src:seed_layer("base")
-- An Enabled of 2 is malformed (§5.3.3). Seeded between two good
-- siblings so that, whatever order the source enumerates in, at least
-- one well-formed layer follows the broken one.
src:seed_layer("early")
src:seed_layer("broken", { enabled = 2 })
src:seed_layer("late", { precedence = 0 })
assert(src:register())
src:pump()

local w = vm:spawn_worker()

test("a malformed layer at bootstrap is skipped and its siblings publish",
    { spec = "PKM *layer.metadata.bootstrap-isolates-a-malformed-layer" },
    function(t)
        local root = lcs.open_key(src, w, -1, TEST_PATH, lcs.KEY_ALL_ACCESS)
        t:assert(root.ret >= 0, "open the test key: " .. sys.errname(root.errno or 0))
        local c = lcs.create_key(src, w, { parent_fd = root.ret, path = "Bootstrap" })
        t:assert(c.ret >= 0, "a fresh subkey: " .. sys.errname(c.errno or 0))
        local fd = c.ret

        -- The siblings on either side of the broken layer are in the
        -- table: a write naming each one lands.
        for _, name in ipairs({ "early", "late" }) do
            local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
                { layer = name })
            t:assert_eq(s.ret, 0, name .. " published at bootstrap despite its " ..
                "malformed sibling: " .. sys.errname(s.errno or 0))
        end

        -- The broken one itself is not: it is an unknown layer.
        local s = lcs.set_value(src, w, fd, "V", lcs.TYPE.DWORD, lcs.dword(1),
            { layer = "broken" })
        t:assert(s.ret < 0, "the malformed layer was not published")
        t:assert_eq(s.errno, sys.E.NOENT,
            "and is unknown, not merely disabled: " .. sys.errname(s.errno or 0))

        sys.close(w, fd)
        sys.close(w, root.ret)
    end)
