-- PKM §2.5/§2.6 — what still cannot be driven from a live guest even
-- with the Lua-served registry source (helpers/registry): planted
-- migration corruption and the plan machinery's defensive branches.
-- Each runs under a KUnit case that reaches the kernel-side vantage
-- (PEI-604).

test("a migration abort abandons the swap with no event",
    { spec = "PKM *ring.swap.abort-emits-no-event",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "needs corruption planted inside the quiesced migration, " ..
             "which no interface reaches; runs under " ..
             "pkm_kunit_kmes_swap_migration_abort_keeps_ring_and_stays_silent" },
    function(t)
    end)

test("plans are validated twice, the second gate failing EINVAL",
    { spec = "PKM *config.validated-twice",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "the second gate only matters when the first is bypassed, " ..
             "which needs a kernel-side caller; runs under " ..
             "pkm_lcs_kunit_kmes_publish_second_gate_rejects_out_of_range " ..
             "(and pkm_kunit_kmes_runtime_config_validates_ranges for the " ..
             "gate itself)" }, function(t)
    end)

test("self-configuration events are best-effort",
    { spec = "PKM *config.self-events-best-effort",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "observing the discarded emission result needs a kernel-side " ..
             "vantage; runs under " ..
             "pkm_lcs_kunit_kmes_publish_self_events_are_best_effort" },
    function(t)
    end)

test("at most four invalid-value reports per read",
    { spec = "PKM *config.at-most-four-reports",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "only four canonical keys exist and unknown names are " ..
             "ignored rather than reported, so no real source can " ..
             "produce a fifth report; runs under " ..
             "pkm_lcs_kunit_kmes_publish_caps_reports_at_four, which hands " ..
             "the publisher a five-audit plan" }, function(t)
    end)
