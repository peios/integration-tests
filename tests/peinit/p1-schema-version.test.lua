-- Peinit TRM §2.3 step 6 — the schema-version guard's failing half: a
-- `SchemaVersion` that is present and is not a REG_DWORD fails the probe,
-- and a failed probe is recovery.
--
-- Reaching it takes a registry that already holds a malformed value when
-- Phase 1 reads it, and no lever this suite has writes the registry that
-- early: a seed in `/lcl/policy/autoapply.d` is applied by an autorun at
-- step 7, which is after the probe, and peinit's own ensure writes a
-- DWORD. So the hive itself is the fixture. The first test below boots a
-- machine, makes the value a REG_SZ through `reg`, and copies loregd's
-- storage out of the guest; the second stages those bytes into a fresh
-- boot, where registryd opens them and peinit reads back what is in
-- them.
--
-- Both of loregd's files are captured, not just the hive: the store
-- keeps its recent writes in the write-ahead log, and a 4 KiB hive
-- without its WAL is an empty registry rather than a modified one.
--
-- Two boots, and provium releases a test's VM at the end of the test —
-- so this is two tests rather than one, and the file claims one VM.

local peinit = require("helpers.peinit")
peinit.claim(1)

local HIVE = "var/state/loregd/Machine.hive"
local WAL = "var/state/loregd/Machine.hive-wal"

local captured

test("a hive whose SchemaVersion is a REG_SZ (the fixture for the test below)",
    function(t)
        local vm = peinit.boot({ name = "schema-capture" })
        -- `reg set` takes the data with a type prefix, so this replaces
        -- the DWORD peinit wrote with a string of the same name.
        vm:run([[reg set 'Machine\System\Services' SchemaVersion 'sz:not-a-dword']])
            :assert_ok()
        local check = vm:run([[reg get 'Machine\System\Services' SchemaVersion --json]])
        check:assert_ok()
        t:assert(check.stdout:find('"sz"', 1, true),
            "the value is now a REG_SZ: " .. check.stdout)

        captured = {
            [HIVE] = vm:read_file("/var/state/loregd/Machine.hive"),
            [WAL] = vm:read_file("/var/state/loregd/Machine.hive-wal"),
        }
        t:assert(#captured[HIVE] > 0 and #captured[WAL] > 0,
            "loregd's storage was captured (" .. #captured[HIVE] .. " + " ..
                #captured[WAL] .. " bytes)")
    end)

test("a SchemaVersion that is not a REG_DWORD fails the probe and sends peinit to recovery",
    {
        spec = {
            "peinit *phase1.a-malformed-schema-version-fails-the-probe",
            "peinit *phase1.the-schema-version-guard",
        },
    },
    function(t)
        t:assert(captured, "the fixture boot produced a hive")
        local log = peinit.boot_to_recovery(t, {
            name = "schema-malformed",
            agent_timeout = 20,
            files = captured,
        })

        -- registryd itself is fine — it opened the staged hives and said
        -- it was serving. What failed is the read peinit does after
        -- readiness, which is the whole point of the probe: readiness is
        -- registryd's word, and the probe is peinit checking it.
        t:assert(log:find("entering request loop", 1, true),
            "registryd opened the staged registry and was serving: " .. log:sub(-1200))
        t:assert(log:find("InvalidServicesSchemaType", 1, true),
            "and peinit rejected the value's type")
        t:assert(log:find("entering recovery: Registryd", 1, true),
            "which took the boot into recovery")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "with no Phase 2")
    end)
