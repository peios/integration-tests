-- PKM §2.5/§2.6 — what still cannot be driven from a live guest even
-- with the Lua-served registry source (helpers/registry): forced
-- allocation failure, planted migration corruption, and the plan
-- machinery's defensive branches. Each defers to a named KUnit case
-- or is flagged open on PEI-604.

test("a failed allocation keeps the old rings live",
    { spec = "PKM *ring.swap.alloc-failure-keeps-old",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "allocation failure cannot be forced from a guest; runs " ..
             "under pkm_kunit_kmes_swap_failed_allocation_keeps_live_ring" },
    function(t)
    end)

test("a failed swap is reported with both capacities",
    { spec = "PKM *config.swap-failed-event",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "the KMES_BUFFER_SWAP_FAILED event only fires on allocation " ..
             "failure, which cannot be forced from a guest; runs under " ..
             "pkm_lcs_kunit_kmes_config_swap_failure_emits_kmes_event" },
    function(t)
    end)

test("a migration abort abandons the swap with no event",
    { spec = "PKM *ring.swap.abort-emits-no-event",
      covered_by = "unreachable",
      skip = "needs corruption planted inside the quiesced migration, " ..
             "which no interface reaches — NOTE: no KUnit case covers " ..
             "it either (PEI-604)" }, function(t)
    end)

test("application is all or nothing, capacity first",
    { spec = "PKM *config.apply-all-or-nothing",
      covered_by = "unreachable",
      skip = "the ordering only shows when the capacity swap FAILS on a " ..
             "valid value (allocation failure), which cannot be forced " ..
             "from a guest; no KUnit case exercises the cross-parameter " ..
             "ordering either (PEI-604)" }, function(t)
    end)

test("plans are validated twice, the second gate failing EINVAL",
    { spec = "PKM *config.validated-twice",
      covered_by = "unreachable",
      skip = "the second gate only matters when the first is bypassed, " ..
             "which needs a kernel-side caller; open, with no KUnit case " ..
             "(PEI-604)" }, function(t)
    end)

test("self-configuration events are best-effort",
    { spec = "PKM *config.self-events-best-effort",
      covered_by = "unreachable",
      skip = "observing the discarded emission result or the 768-byte " ..
             "payload skip needs a kernel-side vantage; open, with no " ..
             "KUnit case (PEI-604)" }, function(t)
    end)

test("at most four invalid-value reports per read",
    { spec = "PKM *config.at-most-four-reports",
      covered_by = "unreachable",
      skip = "only four canonical keys exist and unknown names are " ..
             "ignored rather than reported, so no real source can " ..
             "produce a fifth report — the cap is a defensive bound; " ..
             "no KUnit case counts to it (PEI-604)" }, function(t)
    end)

test("the configuration keys inherit the Machine hive root descriptor",
    { spec = "PKM *config.keys-inherit-machine-root-sd",
      skip = "an image-level property of the composed hive that loregd " ..
             "serves, not of the kernel-only guest, whose hive is test " ..
             "apparatus" }, function(t)
    end)
