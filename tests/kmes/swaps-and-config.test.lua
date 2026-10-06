-- PKM §2.5/§2.6 — what still cannot be driven from a live guest even
-- with the Lua-served registry source (helpers/registry): planted
-- migration corruption and the plan machinery's defensive branches.
-- Each runs under a KUnit case that reaches the kernel-side vantage
-- (PEI-604).

test("a migration abort abandons the swap and reports -EIO",
    { spec = "PKM *ring.swap.abort-emits-event",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "needs corruption planted inside the quiesced migration, " ..
             "which no interface reaches; runs under " ..
             "pkm_kunit_kmes_swap_migration_abort_keeps_ring_and_reports" },
    function(t)
    end)

test("every failed swap is reported, whatever the error",
    { spec = "PKM *config.swap-failed-every-errno",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "the only failure a guest can provoke is ENOMEM (the live " ..
             "case is adversarial's config.swap-failed-event); the -EIO " ..
             "of a corrupt migration runs under " ..
             "pkm_kunit_kmes_swap_migration_abort_keeps_ring_and_reports" },
    function(t)
    end)

test("a re-read that fails is recorded and changes nothing",
    { spec = "PKM *config.refresh-failed-event",
      covered_by = "kunit:pkm_lcs_kunit_kmes",
      skip = "a failed re-read needs the source to fail the query the " ..
             "watch makes while answering the write that caused it; runs " ..
             "under pkm_lcs_kunit_kmes_config_refresh_failure_is_recorded " ..
             "(and, for the emission policy, " ..
             "pkm_lcs_kunit_kmes_event_policy_failed_walk_keeps_mask)" },
    function(t)
    end)

-- Ring writers outside task context (PKM §2.3). A guest has no way to
-- run a kernel emitter in softirq or hard interrupt context on demand,
-- so these run under KUnit, from a timer callback and an irq_work.

test("a ring writer holds bottom halves off across its write",
    { spec = "PKM *kernel-emit.bottom-halves-held",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "an interleaving softirq writer cannot be scheduled from a " ..
             "guest; runs under " ..
             "pkm_kunit_kmes_softirq_emit_lands_and_defers_wake and " ..
             "pkm_kunit_kmes_bh_disabled_task_emit_wakes_directly" },
    function(t)
    end)

test("a softirq writer hands the consumer wake to process context",
    { spec = "PKM *kernel-emit.softirq-wake-deferred",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "needs a kernel emitter in softirq context; runs under " ..
             "pkm_kunit_kmes_softirq_emit_lands_and_defers_wake" },
    function(t)
    end)

test("an emit from hard interrupt context is refused",
    { spec = "PKM *kernel-emit.hardirq-refused",
      covered_by = "kunit:pkm_kunit_kmes",
      skip = "needs a kernel emitter in hard interrupt context, which no " ..
             "kernel emitter is; runs under " ..
             "pkm_kunit_kmes_hardirq_emit_is_refused" },
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
