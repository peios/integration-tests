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

-- The guard's passing half for an absent value. peinit ensures the value
-- exists and then reads it back, so an absent value at the read means the
-- ensure's write did not take effect — and the way a real registry produces
-- exactly that is a layer. LCS resolves each value to its highest-precedence
-- entry, a tombstone in a layer above the base masks whatever the base
-- holds, and peinit's ensure writes to the base: it finds the value absent,
-- writes it, and reads it back absent again. The fixture is a hive carrying
-- such a layer, built the same way as the one above.
local masked

test("a hive whose SchemaVersion is masked by a higher-precedence layer (the fixture for the test below)",
    function(t)
        local vm = peinit.boot({ name = "schema-mask-capture" })
        -- The layer table lives in the registry, under this key, which a
        -- fresh image does not have yet.
        vm:run([[reg new 'Machine\System\Registry']]):assert_ok()
        vm:run([[reg new 'Machine\System\Registry\Layers']]):assert_ok()
        -- Precedence 1, above the base layer's 0, so its tombstone wins.
        vm:run("reg layer new pt-schema-mask --precedence 1"):assert_ok()
        vm:run([[reg mask 'Machine\System\Services' SchemaVersion --layer pt-schema-mask]])
            :assert_ok()
        local check = vm:run([[reg get 'Machine\System\Services' SchemaVersion]])
        t:assert(check.exit_code ~= 0,
            "the value now reads as absent: " .. check.stdout .. check.stderr)

        masked = {
            [HIVE] = vm:read_file("/var/state/loregd/Machine.hive"),
            [WAL] = vm:read_file("/var/state/loregd/Machine.hive-wal"),
        }
        t:assert(#masked[HIVE] > 0 and #masked[WAL] > 0,
            "loregd's storage was captured (" .. #masked[HIVE] .. " + " ..
                #masked[WAL] .. " bytes)")
    end)

test("a SchemaVersion that is absent at the probe reads as zero and passes",
    { spec = "peinit *phase1.an-absent-schema-version-passes" },
    function(t)
        t:assert(masked, "the fixture boot produced a hive")
        -- An ordinary boot, not a recovery: the probe found nothing, read
        -- that as schema version 0, and let Phase 1 go on.
        local vm = peinit.boot({ name = "schema-masked", files = masked })
        local log = vm:console():read_log()
        t:assert(log:find("peinit: phase1 registryd started", 1, true),
            "registryd passed readiness and the probe: " .. log:sub(-1200))
        t:assert(not log:find("entering recovery", 1, true),
            "the absent value did not send the boot to recovery")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "and the boot went on through Phase 2")

        -- What the probe read is what the registry still says: the layer
        -- came through with the hive, and SchemaVersion is absent from the
        -- effective view — so the ensure's write did not take effect where
        -- the read looks, which is the case the rule is for.
        local layers = vm:run("reg layer ls")
        layers:assert_ok()
        t:assert(layers.stdout:find("pt-schema-mask", 1, true),
            "the masking layer is loaded in this boot: " .. layers.stdout)
        local read = vm:run([[reg get 'Machine\System\Services' SchemaVersion]])
        t:assert(read.exit_code ~= 0,
            "SchemaVersion is absent: " .. read.stdout .. read.stderr)
    end)
