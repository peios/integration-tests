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
--
-- The table as securityfs shows it, /sys/kernel/security/kacs/signing_keys,
-- is the other thing a guest can read: one `key_sha256=<hex>
-- pip_type=<u32> pip_trust=<u32>` line per entry, not access-checked.
-- What a guest cannot check is that the hash names the right key — the
-- file does not bind itself to whichever keyring built the image;
-- pkm_kunit_signing_key_listing_names_each_key does that binding.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local hooks = require("helpers.hooks")
local signing = require("helpers.signing")
local token = require("helpers.token")

local vm = provium:vm("v", "kernel-only"):boot()

local B = signing.workspace(vm, "keys")

local function stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_signing",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

local FILE = "/kacs/signing_keys"

--- Read a whole file as `who`. Returns text, or nil, errno and which of
--- open and read refused.
local function read_all(who, path)
    local fd, e = sys.open(who, path, sys.O.RDONLY)
    if not fd then return nil, e, "open" end
    local out = {}
    while true do
        local chunk, re = sys.read(who, fd, 4096)
        if not chunk then
            sys.close(who, fd)
            return nil, re, "read"
        end
        if #chunk == 0 then break end
        out[#out + 1] = chunk
    end
    sys.close(who, fd)
    return table.concat(out)
end

-- Before anything else touches securityfs ----------------------------------
--
-- securityfs has one superblock, and a mount's FACS class belongs to the
-- superblock, so this case, which needs it still deny-missing, must be
-- the first in the file: every later hooks.hook_path() mounts it with a
-- synthesising policy for good.

test("on a securityfs mount with no synthesising policy the listing cannot be opened",
    { spec = "PKM *sig.key-table.securityfs-unchecked" }, function(t)
        local at = "/sfs-plain"
        local ok, stage, errno = kacs.new_mount(vm, "securityfs", at, nil, nil)
        t:assert(ok, "securityfs mounts: " .. tostring(stage) .. " " .. sys.errname(errno or 0))
        local fd = sys.open(vm, at, sys.O.PATH)
        t:assert_eq(kacs.get_mount_policy(vm, fd), kacs.MOUNT_POLICY.DENY_MISSING,
            "the superblock is deny-missing")
        sys.close(vm, fd)
        local text, e, which = read_all(vm, at .. FILE)
        t:assert(not text, "even SYSTEM cannot read the listing there")
        t:assert_eq(e, sys.E.ACCES, "EACCES: " .. sys.errname(e or 0))
        t:assert_eq(which, "open", "refused at open, before the file's own read handler")
        sys.umount(vm, at, 0)
    end)

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
        -- three files, none of which is one: the token and session
        -- endpoints, and signing_keys, which only lists the compiled-in
        -- keys (PEI-1314).
        local path, err = hooks.hook_path(vm, "unused")
        t:assert(path, "securityfs is available: " .. tostring(err))
        local names = {}
        for _, e in ipairs(vm:listdir(hooks.SECURITYFS_AT .. "/kacs")) do
            names[#names + 1] = e.name
        end
        table.sort(names)
        t:assert_eq(table.concat(names, ","), "self,sessions,signing_keys",
            "securityfs/kacs holds only the token and session endpoints and the key listing")
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
--
-- Table order, and the listing of an entry the validator would refuse,
-- need a table of more than the one valid key this kernel carries.

test("signing_keys lists each key as key_sha256, pip_type and pip_trust",
    { spec = "PKM *sig.key-table.securityfs-listing" }, function(t)
        t:assert(hooks.hook_path(vm, "unused"), "securityfs mounts with a synthesising policy")
        local text, e, which = read_all(vm, hooks.SECURITYFS_AT .. FILE)
        t:assert(text, "the listing reads: " .. sys.errname(e or 0) .. " on " .. tostring(which))
        -- The kernel this profile boots is the one the peinit profile
        -- runs TCB-signed binaries under, so its table holds a key.
        t:assert(#text > 0, "and is not empty")
        t:assert_eq(text:sub(-1), "\n", "every line is newline-terminated")
        local n = 0
        for line in text:gmatch("([^\n]*)\n") do
            n = n + 1
            local hex, ptype, ptrust =
                line:match("^key_sha256=(%x+) pip_type=(%d+) pip_trust=(%d+)$")
            t:assert(hex, "line " .. n .. " has exactly the three fields: " .. line)
            if hex then
                t:assert_eq(#hex, 64, "the key is named by a SHA-256: 64 hex digits")
                t:assert_eq(hex, hex:lower(), "in lowercase")
                -- The validator accepts no other tier, and a table it
                -- refused would disable every verification — the
                -- existing sig-keys case shows a real per-key trial.
                t:assert_eq(tonumber(ptype), 512, "pip_type in decimal: Protected")
                t:assert_eq(tonumber(ptrust), 8192, "pip_trust in decimal: PeiosTcb")
            end
        end
        t:assert(n >= 1, "one line per key, at least one key: " .. n)
        local again = read_all(vm, hooks.SECURITYFS_AT .. FILE)
        t:assert_eq(again, text, "and it reads the same each time")
    end)

test("reading signing_keys is not access-checked",
    { spec = "PKM *sig.key-table.securityfs-unchecked" }, function(t)
        t:assert(hooks.hook_path(vm, "unused"), "securityfs mounts with a synthesising policy")
        local path = hooks.SECURITYFS_AT .. FILE
        local as_system = assert(read_all(vm, path))
        -- An ordinary signed-in principal: no administrators, no
        -- privilege but traverse.
        local CHANGE_NOTIFY = token.bit(token.PRIV.CHANGE_NOTIFY)
        token.as_principal(t, vm, { privs_present = CHANGE_NOTIFY, privs_enabled = CHANGE_NOTIFY },
            function(w)
                local text, e, which = read_all(w, path)
                t:assert(text, "an ordinary principal reads the listing: "
                    .. sys.errname(e or 0) .. " on " .. tostring(which))
                t:assert_eq(text, as_system, "and reads exactly what SYSTEM reads")
                -- The control: the sessions file beside it on the same
                -- mount does check on read, and refuses this caller.
                local s, se, swhich = read_all(w, hooks.SECURITYFS_AT .. "/kacs/sessions")
                t:assert(not s, "the sessions listing, which is checked, refuses the same caller")
                t:assert_eq(se, sys.E.ACCES, "EACCES: " .. sys.errname(se or 0))
                t:assert_eq(swhich, "read", "at its own read check")
            end)
    end)

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
