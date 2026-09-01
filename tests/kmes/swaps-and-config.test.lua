-- PKM §2.5 capacity swaps and §2.6 registry-driven configuration.
--
-- Every case here needs a Machine-hive registry source to drive from
-- a live guest, which the kernel-only profile does not have (yet —
-- serving one from the agent is the natural unblocking work, the way
-- the stratafs test hooks unblocked chapter 4's last skips). Until
-- then, each citation with a named KUnit case defers to it; the ones
-- with no coverage anywhere stay honestly open and are listed on the
-- tracking task.

local function kunit_stub(suite)
    return function(name, spec, case, why)
        test(name, { spec = spec, covered_by = "kunit:" .. suite,
                     skip = (why or "needs a registry source to drive " ..
                             "from a guest") .. "; runs under " .. case },
            function(t) end)
    end
end

local kmes_stub = kunit_stub("pkm_kunit_kmes")
local lcs_stub = kunit_stub("pkm_lcs_kunit_kmes")
local watch_stub = kunit_stub("pkm_lcs_kunit_misc")

-- ---- §2.5 capacity swaps --------------------------------------------

kmes_stub("a swap is prepared, then committed under stop_machine",
    "PKM *ring.swap-under-stop-machine",
    "the pkm_kunit_kmes_swap_* family")

kmes_stub("the generation bump signals consumers to re-attach",
    "PKM *ring.swap.generation-bump-signals-reattach",
    "pkm_kunit_kmes_swap_old_fd_freezes_and_new_attach_rebinds")

kmes_stub("old and new generations coexist until the last old fd",
    "PKM *ring.swap.generations-coexist",
    "pkm_kunit_kmes_swap_old_fd_freezes_and_new_attach_rebinds")

kmes_stub("sleepers on a dead generation are woken",
    "PKM *ring.swap.wakes-stale-sleepers",
    "pkm_kunit_kmes_swap_wakes_old_generation_waiter")

kmes_stub("migration re-compacts from zero with counters carried",
    "PKM *ring.swap.migration-recompacts",
    "pkm_kunit_kmes_swap_downsize_preserves_newest_suffix and the " ..
    "rebind case")

kmes_stub("a shrinking swap skips the oldest events",
    "PKM *ring.swap.shrink-skips-oldest",
    "pkm_kunit_kmes_swap_downsize_preserves_newest_suffix")

kmes_stub("a failed allocation keeps the old rings live",
    "PKM *ring.swap.alloc-failure-keeps-old",
    "pkm_kunit_kmes_swap_failed_allocation_keeps_live_ring")

test("a migration abort abandons the swap with no event",
    { spec = "PKM *ring.swap.abort-emits-no-event",
      covered_by = "unreachable",
      skip = "needs corruption planted inside the quiesced migration, " ..
             "which no interface reaches — NOTE: no KUnit case covers " ..
             "it either" }, function(t)
    end)

-- ---- §2.6 configuration through the registry ------------------------

lcs_stub("value names fold; unknown names are counted and ignored",
    "PKM *config.names-case-folded-unknown-ignored",
    "pkm_lcs_kunit_kmes_config_apply_ignores_unknown_and_retains_invalid")

lcs_stub("a right-typed value with a wrong payload length is wrong-typed",
    "PKM *config.wrong-length-is-wrong-type",
    "pkm_lcs_kunit_kmes_config_refresh_malformed_source_retains")

lcs_stub("invalid values are rejected outright, never clamped",
    "PKM *config.invalid-rejected-not-clamped",
    "pkm_lcs_kunit_kmes_config_apply_ignores_unknown_and_retains_invalid " ..
    "and the wrong-type case")

lcs_stub("a valid capacity change swaps the rings",
    "PKM *config.capacity-change-swaps",
    "pkm_lcs_kunit_kmes_config_refresh_from_source_hot_swaps")

lcs_stub("an invalid value is reported through a KMES event",
    "PKM *config.invalid-event-nine-keys",
    "pkm_lcs_kunit_kmes_config_invalid_emits_kmes_event")

lcs_stub("self-configuration reports carry origin class 1",
    "PKM *config.self-events-origin-kmes",
    "pkm_lcs_kunit_kmes_config_invalid_emits_kmes_event")

lcs_stub("a failed swap is reported with both capacities",
    "PKM *config.swap-failed-event",
    "pkm_lcs_kunit_kmes_config_swap_failure_emits_kmes_event")

lcs_stub("an absent Machine hive leaves every default in place",
    "PKM *config.empty-key-emits-four",
    "pkm_lcs_kunit_kmes_config_machine_hive_missing_retains_defaults " ..
    "(retention; the four-events count is the open half)")

watch_stub("the bootstrap arms the targeted watch",
    "PKM *config.bootstrap-sequence",
    "pkm_lcs_kunit_internal_self_watch_arm_targeted_and_fallback")

watch_stub("the watch is filtered to value events on the key itself",
    "PKM *config.watch-filtered-to-key",
    "pkm_lcs_kunit_internal_self_watch_non_value_event_noop and " ..
    "pkm_lcs_kunit_internal_kmes_watch_value_event_refreshes_config")

watch_stub("the fallback watch re-runs the bootstrap on key creation",
    "PKM *config.fallback-watch-on-hive-root",
    "pkm_lcs_kunit_internal_self_watch_fallback_create_rearms_targeted " ..
    "and the non-create no-op case")

test("application is all or nothing, capacity first",
    { spec = "PKM *config.apply-all-or-nothing",
      skip = "needs a registry source to submit a mixed valid/invalid " ..
             "plan from a guest; no KUnit case exercises the ordering — " ..
             "open until the profile can serve a Machine hive" }, function(t)
    end)

test("plans are validated twice, the second gate failing EINVAL",
    { spec = "PKM *config.validated-twice",
      skip = "the second gate only matters when the first is bypassed, " ..
             "which needs a kernel-side caller; open, with no KUnit case" },
    function(t)
    end)

test("self-configuration events are best-effort",
    { spec = "PKM *config.self-events-best-effort",
      skip = "observing the discarded emission result or the 768-byte " ..
             "skip needs a kernel-side vantage; open, with no KUnit case" },
    function(t)
    end)

test("at most four invalid-value reports per read",
    { spec = "PKM *config.at-most-four-reports",
      skip = "needs a registry source serving five bad keys to a live " ..
             "guest; open until the profile can serve a Machine hive" },
    function(t)
    end)

test("the configuration keys inherit the Machine hive root descriptor",
    { spec = "PKM *config.keys-inherit-machine-root-sd",
      skip = "an image-level property of the composed hive, not of the " ..
             "kernel-only guest, which has no hive at all" }, function(t)
    end)
