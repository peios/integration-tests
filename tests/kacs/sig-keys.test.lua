-- PKM §3.6 — the key table, the verification trial against it, the
-- boot-time crypto probe, and revocation.
--
-- Almost nothing here is reachable from a guest, and the reason is the
-- same for every case: the key table lives in a data section of the
-- kernel image, there is no interface that reads it or replaces it, and
-- the kernel holds no private key — so a test can present a signature
-- that fails, and nothing else. What *is* reachable is the shape of the
-- failure, which is enough for two of the claims:
--
--   * a blob the kernel accepts as material and then cannot match
--     reports `no-key-match` rather than a crypto failure, which is only
--     possible if the ML-DSA transform the boot probe allocates is
--     present and the table validated;
--   * the securityfs surface holds nothing that could revoke a key.
--
-- The rest are stubs against the pkm_kunit_signing suite, which builds
-- its own tables and its own signatures from the FIPS 204 test vectors.
--
-- One correction for the record: this profile's kernel is **not** a
-- KUnit build (`CONFIG_SECURITY_PKM_KUNIT` is absent from
-- `/usr/lib/modules/*/config-*`), so the guest carries the production
-- key table, not the test key of §3.6's KUnit paragraph.

local sys = require("helpers.sys")
local hooks = require("helpers.hooks")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

local B = signing.workspace(vm, "keys")

local function stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_signing",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

-- What the guest can see -----------------------------------------------------

test("a well-formed signature that matches no key is a verification miss, not a crypto failure",
    { spec = "PKM *sig.boot-probe" }, function(t)
        -- §3.6's boot probe exists to make an unallocatable ML-DSA
        -- transform visible at boot rather than inferred from every
        -- process running unlabelled. Its condition is observable from
        -- the other side: a blob the lookup accepts reaches a real
        -- per-key trial and comes back `no-key-match`. Had the
        -- transform been unavailable the verifier would be tri-state
        -- negative and the exec would have been refused EACCES instead.
        local path = signing.place(vm, B .. "/nomatch",
            signing.craft({ no_sections = true }),
            { xattr = signing.blob({ fill = "\xBB" }) })
        local events, run = signing.exec_traced(vm,
            { signing.EV_VERIFY, signing.EV_EXEC }, path)
        local verify = signing.first(events, "kacs_signing_verify")
        t:assert(verify, "the verifier ran")
        t:assert_eq(verify.reason, "no-key-match",
            "the signature was tried against the table and did not match")
        t:assert_eq(verify:num("source"), signing.SOURCE.XATTR,
            "against material the lookup did find")
        t:assert_eq(run.exit_code, 0,
            "and the exec proceeded, so nothing was unverifiable")
        for _, e in ipairs(signing.of(events, "kacs_exec")) do
            t:assert_neq(e.reason, "signature-unverifiable",
                "no exec reported the crypto as unavailable")
        end
    end)

test("there is no revocation interface of any kind",
    { spec = "PKM *sig.no-revocation" }, function(t)
        -- §3.6 says flatly that no hash blocklist, per-key revocation or
        -- revocation state exists. KACS's whole securityfs surface is
        -- two files, neither of which is one.
        local path, err = hooks.hook_path(vm, "unused")
        t:assert(path, "securityfs is available: " .. tostring(err))
        local names = {}
        for _, e in ipairs(vm:listdir(hooks.SECURITYFS_AT .. "/kacs")) do
            names[#names + 1] = e.name
        end
        table.sort(names)
        t:assert_eq(table.concat(names, ","), "self,sessions",
            "securityfs/kacs holds only the token and session endpoints")
        -- And a signature that does not verify is simply unsigned; it
        -- leaves nothing behind that a later attempt could consult.
        local p = signing.place(vm, B .. "/norevoke",
            signing.craft({ no_sections = true }),
            { xattr = signing.blob({ fill = "\xCC" }) })
        for i = 1, 2 do
            local events = signing.exec_traced(vm, { signing.EV_VERIFY }, p)
            t:assert_eq(signing.reasons(events, "kacs_signing_verify"),
                "no-key-match",
                "attempt " .. i .. " reaches the same verdict: no state accrues")
        end
    end)

-- The table ------------------------------------------------------------------

stub("the key table is an array of 1960-byte entries with an all-zero terminator",
    "PKM *sig.key-table.entry-layout",
    "pkm_kunit_builtin_signing_key_table_has_one_tcb_key",
    "the table lives in a kernel data section with no interface that " ..
    "reads, counts or replaces it")

stub("a table with no terminator, or an entry off-tier, is rejected with EINVAL",
    "PKM *sig.key-table.validation-einval",
    "pkm_kunit_signing_verify_missing_terminator_fails_closed and " ..
    "pkm_kunit_signing_verify_unsupported_tier_fails_closed",
    "the built-in table cannot be replaced from the guest, so no " ..
    "invalid table can be presented")

stub("an invalid table disables every verification on the system",
    "PKM *sig.key-table.invalid-disables-all",
    "pkm_kunit_signing_verify_missing_terminator_fails_closed",
    "same reason: the only table this kernel has is the valid built-in " ..
    "one")

stub("a verified binary is always Protected with PeiosTcb trust",
    "PKM *sig.verified-always-protected-tcb",
    "pkm_kunit_signing_crypto_verify_sets_tcb_trust and " ..
    "pkm_kunit_signing_verify_first_key_sets_tcb_trust",
    "no signature this guest can author verifies — signing needs the " ..
    "ML-DSA-65 private key, which the kernel does not hold and the " ..
    "guest has no tool for")

stub("the Isolated type is reserved and unreachable",
    "PKM *sig.isolated-type-unreachable",
    "pkm_kunit_signing_verify_unsupported_tier_fails_closed",
    "reaching a non-Protected tier would need a second key in the " ..
    "built-in table")

stub("a KUnit build compiles in a different hard-coded key at the same tier",
    "PKM *sig.kunit-test-key",
    "pkm_kunit_builtin_signing_key_table_has_one_tcb_key",
    "the claim is about a CONFIG_SECURITY_PKM_KUNIT kernel, which is " ..
    "only observable under KUnit — and this profile's kernel is not " ..
    "one, so it carries the production key")

-- The trial ------------------------------------------------------------------

stub("the signature is tried against each key in order, returning on the first success",
    "PKM *sig.verify.exhaustive-trial-in-order",
    "pkm_kunit_signing_verify_later_key_after_miss and " ..
    "pkm_kunit_signing_verify_terminator_stops_iteration",
    "the built-in table holds one key, so iteration order has no " ..
    "observable consequence, and a matching signature cannot be authored")

stub("the tier comes from which key verified, never from the blob",
    "PKM *sig.tier-from-key-not-blob",
    "pkm_kunit_signing_verify_first_key_sets_tcb_trust",
    "distinguishing the two sources needs a signature that verifies")

stub("the empty FIPS 204 context is structural, so a non-empty one simply fails",
    "PKM *sig.empty-fips204-context",
    "pkm_kunit_mldsa65_crypto_fips204_vectors",
    "the guest cannot produce a signature under any context, empty or " ..
    "not")

stub("the per-key verifier is tri-state: verified, did not verify, or could not check",
    "PKM *sig.verifier.tri-state",
    "pkm_kunit_signing_unverifiable_is_not_unsigned",
    "the negative arm needs an unavailable ML-DSA transform or a key " ..
    "the transform rejects, neither of which a guest can arrange")

stub("an unverifiable signature refuses the exec with EACCES",
    "PKM *sig.unverifiable.exec-eacces",
    "pkm_kunit_signing_unverifiable_is_not_unsigned",
    "same: provoking it needs the crypto machinery to fail, and the " ..
    "boot probe exists precisely because it does not")

stub("the same condition denies the mapping under LSV",
    "PKM *sig.unverifiable.lsv-denies",
    "pkm_kunit_lsv_unsigned_and_bad_signature_deny",
    "the lsv mitigation cannot be committed on any process here — " ..
    "enabling it re-validates existing executable mappings and every " ..
    "process's own text is unsigned (§3.3.2)")
