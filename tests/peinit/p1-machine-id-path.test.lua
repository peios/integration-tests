-- Peinit TRM §2.3 step 4 — the machine ID when its path will not take a
-- write: the boot continues with an identifier valid for this boot only.
--
-- The lever is the path rather than the contents. `/lcl/etc/machine-id`
-- is staged as a DIRECTORY, which is a shape neither the read nor the
-- rename can do anything with: the read cannot say what identifier is on
-- disk, and the rename that publishes the new one cannot land. That is
-- the fail-soft arm exactly — a path peinit cannot persist to — and it
-- is reachable from the harness because the staging hook copies whatever
-- tree a test hands it into the root before peinit runs.
--
-- The identifier peinit uses for the boot instead is in-memory and
-- leaves no artefact, so what a test can check is the warning and the
-- fact that the boot went on.

local peinit = require("helpers.peinit")
peinit.claim(1)

test("a machine ID that cannot be persisted is a warning, and the boot continues",
    { spec = "peinit *phase1.an-unpersistable-machine-id-is-fail-soft" },
    function(t)
        local vm = peinit.boot({
            name = "mid-unwritable",
            files = { ["lcl/etc/machine-id/keep"] = "a directory where the file goes\n" },
        })
        local log = vm:console():read_log()

        -- The message §2.3 specifies, with the reason in it. It matters
        -- that the reason is carried: the identifier is fail-soft
        -- because it is a local opaque install ID rather than an
        -- authorisation input, not because nothing went wrong.
        t:assert(log:find("machine%-id not persisted"),
            "peinit reported the identifier as unpersisted: " .. log:sub(-900))
        t:assert(log:find("using an identifier for this boot only", 1, true),
            "and said what it did instead")

        -- Fail-soft means the boot, not just the step: this is a machine
        -- with no persistent install identity that came all the way up.
        t:assert(not log:find("entering recovery", 1, true),
            "no recovery over an identifier that is not a security principal")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "and Phase 2 ran")

        -- The path is still what it was. peinit did not remove or
        -- replace what it found; it could not write, and said so.
        local listing = vm:run("ls /lcl/etc/machine-id")
        listing:assert_ok()
        t:assert(listing.stdout:find("keep", 1, true),
            "the staged path is untouched: " .. listing.stdout)
    end)
