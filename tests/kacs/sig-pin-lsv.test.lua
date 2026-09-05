-- PKM §3.6 — content pinning and Library Signature Verification.
--
-- Both hang off a signature that *verifies*, and nothing in this guest
-- can produce one: the kernel holds no ML-DSA-65 private key and the
-- image ships no signing tool, so every exec here lands on None/0 and
-- no inode is ever pinned. LSV is doubly out of reach — §3.3.2 makes
-- enabling the `lsv` mitigation re-validate the process's existing
-- executable mappings first, and every process's own text is the
-- unsigned agent, so `kacs_set_psb(lsv)` is refused EACCES on every
-- process in the VM (see tests/kacs/psb-mitigations.test.lua).
--
-- One half of the pin rules is reachable and is tested live: the
-- negative. Unsigned, invalid, bad-signature and no-match execs never
-- pin, and the proof is that the inode stays fully mutable afterwards.
-- Everything else is a stub against the pkm_kunit_signing and
-- pkm_kunit_process suites, which build verified material out of the
-- FIPS 204 test vectors.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local facs = require("helpers.facs")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

local B = signing.workspace(vm, "pin")

local function stub(name, spec, suite, case, why)
    test(name, { spec = spec, covered_by = "kunit:" .. suite,
                 skip = why .. "; runs under " .. case }, function(t) end)
end

-- The reachable half ---------------------------------------------------------

test("an exec that does not verify never pins its backing inode",
    { spec = "PKM *sig.pin.only-on-verified" }, function(t)
        local shapes = {
            { "unsigned", { no_sections = true }, nil },
            { "a signature no key matches", { no_sections = true },
              signing.blob({ fill = "\xBB" }) },
            { "an invalid ELF section", { sec_size = 7 },
              signing.blob({ fill = "\xBB" }) },
            { "a bad blob version", { blob_version = 9 }, nil },
        }
        for i, s in ipairs(shapes) do
            local path = signing.place(vm, B .. "/unpinned" .. i,
                signing.craft(s[2]), { xattr = s[3] })
            t:assert_eq(vm:run(path, {}).exit_code, 0, s[1] .. " execs")

            -- Every operation a pin would reject (§3.6): a positioned
            -- write that preserves size, ftruncate, fallocate, and
            -- mutation of the signature xattr itself.
            local fd = assert(sys.open(vm, path, sys.O.RDWR))
            local w = vm:syscall(facs.NR.pwrite64, {
                args = { fd, 0, 1, 0 }, bufs = { "\0" }, ptrs = { 1 },
            })
            t:assert_eq(w.ret, 1, s[1] .. ": an in-place write is accepted")
            t:assert_eq(sys.ftruncate(vm, fd, 129).ret, 0,
                s[1] .. ": ftruncate is accepted")
            t:assert_eq(sys.fallocate(vm, fd, 0, 0, 4096).ret, 0,
                s[1] .. ": fallocate is accepted")
            sys.close(vm, fd)
            t:assert_eq(sys.setxattr(vm, path, signing.XATTR,
                signing.blob({ fill = "\xDD" }), 0).ret, 0,
                s[1] .. ": the signature xattr may still be replaced")
            t:assert_eq(sys.removexattr(vm, path, signing.XATTR).ret, 0,
                s[1] .. ": and removed")
        end
    end)

-- Pinning --------------------------------------------------------------------

local PIN_WHY = "pinning happens only for a binary that verifies to a " ..
    "nonzero tier, and no signature this guest can author verifies"

stub("a verified exec pins the backing inode before the result is committed, and so does LSV",
    "PKM *sig.pin.on-verified-exec-and-lsv", "pkm_kunit_signing",
    "pkm_kunit_signed_exec_pin_tracks_verified_material", PIN_WHY)

stub("a pin failure at exec downgrades the tier to None/0 rather than failing the exec",
    "PKM *sig.pin.failure-downgrades-to-none", "pkm_kunit_process",
    "pkm_kunit_exec_pip_signed_material_sets_tcb_trust and the pin-failure " ..
    "arm of pkm_kunit_signed_exec_pin_tracks_verified_material",
    PIN_WHY .. ", and the allocation failure that makes pinning fail cannot " ..
    "be provoked from the guest either")

stub("a pin failure under LSV denies the mapping instead",
    "PKM *sig.pin.failure-denies-lsv-mapping", "pkm_kunit_process",
    "pkm_kunit_lsv_signed_tcb_allows_none_and_tcb_pip",
    "the lsv mitigation cannot be committed on any process here (§3.3.2)")

stub("a pinned inode rejects writes, truncation and every fallocate mode",
    "PKM *sig.pin.rejects-content-mutation", "pkm_kunit_signing",
    "pkm_kunit_signed_exec_pin_blocks_content_mutation", PIN_WHY)

stub("an ioctl the kernel cannot classify fails closed on a pinned inode",
    "PKM *sig.pin.unknown-ioctl-fails-closed", "pkm_kunit_signing",
    "pkm_kunit_signed_exec_pin_blocks_unmanaged_mutation", PIN_WHY)

stub("mutation or removal of security.peios.sig is rejected on a pinned inode",
    "PKM *sig.pin.rejects-sig-xattr-mutation", "pkm_kunit_signing",
    "pkm_kunit_signed_exec_pin_blocks_path_and_sig_xattr", PIN_WHY)

stub("the pin is set once and cleared only when the inode is allocated or freed",
    "PKM *sig.pin.cleared-only-at-inode-lifecycle", "pkm_kunit_signing",
    "pkm_kunit_signed_exec_pin_preserves_unpinned_facs",
    PIN_WHY .. ", so there is no pinned inode whose lifecycle could be watched")

-- Library Signature Verification ----------------------------------------------

local LSV_WHY = "the lsv mitigation cannot be committed on any process in " ..
    "this guest: §3.3.2 re-validates the process's existing executable " ..
    "mappings before the bit goes in, and every process's own text is the " ..
    "unsigned agent"

stub("an unsigned or unmatched library is denied the executable mapping with EACCES",
    "PKM *sig.lsv.denies-unsigned-eacces", "pkm_kunit_process",
    "pkm_kunit_lsv_unsigned_and_bad_signature_deny", LSV_WHY)

stub("the image's tier has to dominate the loading process's",
    "PKM *sig.lsv.image-must-dominate-process", "pkm_kunit_process",
    "pkm_kunit_lsv_insufficient_trust_denies and " ..
    "pkm_kunit_lsv_signed_tcb_allows_none_and_tcb_pip", LSV_WHY)

stub("LSV hashes the entire file, not the mapped region",
    "PKM *sig.lsv.hashes-whole-file", "pkm_kunit_process",
    "pkm_kunit_lsv_signed_tcb_allows_none_and_tcb_pip", LSV_WHY)

stub("mprotect adding PROT_EXEC runs WXP, then TLP, then LSV",
    "PKM *sig.lsv.mprotect-check-order", "pkm_kunit_process",
    "pkm_kunit_tlp_mprotect_checks_new_exec_only with " ..
    "pkm_kunit_wxp_rejects_wx_map_and_transition",
    LSV_WHY .. ", and tlp cannot be committed either — no approved prefix " ..
    "covers the agent's own text")

stub("anonymous mappings skip TLP and LSV, leaving only WXP",
    "PKM *sig.lsv.anonymous-skips-tlp-lsv", "pkm_kunit_process",
    "pkm_kunit_lsv_bypasses_non_exec_and_anonymous",
    "showing that lsv skips an anonymous mapping needs lsv committed, " ..
    "and it cannot be (§3.3.2)")
