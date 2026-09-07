-- peinit TRM §2.4 — the fail-closed half of path provisioning: an entry
-- marked `Required=1` that does not apply stops the boot.
--
-- Its own file because its boot has no Phase 2. Every other provisioning
-- case shares one VM and reads its evidence out of a completed boot;
-- this one ends at the recovery console instead, so it cannot share.
--
-- The VM is still usable, which is worth stating because the neighbouring
-- recovery cases in this suite are not. Recovery entered *here* is
-- entered at Phase 1 step 8 — after step 7 has already run the autorun
-- that starts the provium agent — so the agent exists and answers. What
-- it cannot do is drive the recovery shell, so the console is the oracle
-- and `stage = false` is what stops `peinit.boot` waiting for a Phase 2
-- that will never come.

local peinit = require("helpers.peinit")
peinit.claim(1)

test("a Required entry that fails enters recovery before Phase 2 starts",
    { spec = "peinit *provision.a-required-entry-that-fails-is-recovery" },
    function(t)
        -- The same failure the optional cases use — a parent that does
        -- not exist, which peinit will not create — differing only in
        -- carrying Required=1. So what is being tested is the flag
        -- rather than the failure.
        local vm = peinit.boot({
            name = "required",
            stage = false,
            files = peinit.seed("zz-pt-required", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Init]] },
                { path = [[Machine\System\Init\ProvisionedPaths]] },
                { path = [[Machine\System\Init\ProvisionedPaths\pt-required]], values = {
                    { name = "Kind", type = "sz", data = "directory" },
                    { name = "Path", type = "sz", data = "/run/pt-absent/child" },
                    { name = "Required", type = "dword", data = 1 },
                } },
            }),
        })
        vm:console():expect("peinit entering Recovery mode", peinit.STAGE_TIMEOUT)

        local log = vm:console():read_log()
        t:assert(log:find("peinit: required provisioned path pt%-required at /run/pt%-absent/child failed"),
            "peinit named the entry and the path it could not provision: " .. log:sub(-700))
        t:assert(log:find("Provisioning", 1, true),
            "and gave provisioning as the reason for recovery: " .. log:sub(-700))

        -- Before Phase 2 starts, not during it: the fail-closed entry is
        -- there so that nothing runs against a filesystem that is missing
        -- a path some service was promised.
        t:assert(not log:find("peinit: phase2 boot starting", 1, true),
            "Phase 2 was never planned")
        t:assert(not log:find("peinit: phase2 boot complete", 1, true),
            "and never completed")
    end)
