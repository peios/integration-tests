-- Peinit TRM §2.3 step 3 — the persisted random seed: peinit's fallback
-- restore of the machine-local entropy cache, and the one step of Phase
-- 1 that cannot fail the boot however it fails.
--
-- The image ships no seed (see p1-phase1-steady.test.lua for the silence
-- that produces), so every seed this file reasons about is one it staged
-- itself. Each shape needs its own boot: there is one seed path, the
-- restore happens once, and the console line it writes is the only
-- record of which arm it took.
--
-- Boots are test-scoped rather than file-scoped for that reason, and the
-- file therefore claims one VM rather than one per shape.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SEED_PATH = "var/state/peinit/random-seed"

test("a seed of a usable size is restored into the kernel pool",
    { spec = "peinit *phase1.the-random-seed-is-restored" },
    function(t)
        -- 512 bytes is what peinit itself writes at shutdown, so this is
        -- the shape a machine that has booted before really finds. The
        -- restore happens after /dev is up and before registryd starts,
        -- and the console line is what says it happened.
        local vm = peinit.boot({
            name = "seed-good",
            files = { [SEED_PATH] = string.rep("pt-seed-", 64) },
        })
        local log = vm:console():read_log()
        local restored = log:find("peinit: phase1 restored random seed", 1, true)
        t:assert(restored, "peinit restored the seed it found")
        t:assert(not log:find("random seed restore failed", 1, true),
            "with no complaint, so the entropy was credited rather than only mixed")

        -- Before registryd, which is what makes the seed worth
        -- restoring at all: everything with a key or a timestamp in it
        -- comes after this point.
        local registryd = log:find("peinit: phase1 starting registryd", 1, true)
        t:assert(registryd and restored < registryd,
            "and did it before registryd started")
    end)

test("an empty seed file is an error the boot survives",
    {
        spec = {
            "peinit *phase1.an-empty-or-oversized-seed-is-an-error",
            "peinit *phase1.no-seed-failure-enters-recovery",
        },
    },
    function(t)
        -- Empty is not the same as absent: absent is an ordinary first
        -- boot, empty is a file that should have held entropy and does
        -- not. peinit says so and carries on — a system with no entropy
        -- cache still boots, it just starts with less entropy.
        local vm = peinit.boot({ name = "seed-empty", files = { [SEED_PATH] = "" } })
        local log = vm:console():read_log()
        t:assert(log:find("random seed restore failed", 1, true),
            "peinit reported the seed as an error: " .. log:sub(-600))
        t:assert(log:find("InvalidSeedSize", 1, true),
            "naming the size as the reason")
        t:assert(not log:find("entering recovery", 1, true),
            "and did not enter recovery over it")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "the boot reached Phase 2")
    end)

test("a seed larger than the maximum is an error the boot survives",
    {
        spec = {
            "peinit *phase1.an-empty-or-oversized-seed-is-an-error",
            "peinit *phase1.no-seed-failure-enters-recovery",
        },
    },
    function(t)
        -- 4096 bytes is the ceiling, so 5000 is over it. peinit reads
        -- one byte past the limit precisely so that "too big" is
        -- distinguishable from "exactly the limit" rather than silently
        -- truncated and mixed in.
        local vm = peinit.boot({
            name = "seed-big",
            files = { [SEED_PATH] = string.rep("x", 5000) },
        })
        local log = vm:console():read_log()
        t:assert(log:find("random seed restore failed", 1, true),
            "peinit reported the oversized seed as an error: " .. log:sub(-600))
        t:assert(log:find("InvalidSeedSize", 1, true),
            "naming the size as the reason")
        t:assert(not log:find("peinit: phase1 restored random seed", 1, true),
            "and did not credit it")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "while the boot reached Phase 2 regardless")
    end)
