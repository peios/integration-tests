-- PKM §3.6 — finding a signature: which of the two sources the kernel
-- consults, what commits it to one of them, and what each malformed
-- shape yields.
--
-- The lookup runs at `execve()`, in `bprm_creds_from_file` — which the
-- ELF loader calls only after it has accepted the image, so a case
-- needs a *loadable* binary. helpers/signing emits one: a 129-byte
-- static ELF whose only instruction is `exit(0)`, with a section header
-- table appended after the loaded segment. The loader reads program
-- headers only, so the section table can be arbitrarily malformed and
-- the file still runs — which is what makes the "commits the ELF path"
-- cases observable at all.
--
-- What the verdict is read from is the `kacs:kacs_signing_probe`
-- tracepoint: no syscall reports a file's signing state, and the
-- tracepoint names exactly which branch of the lookup fired
-- (`found`, `elf-bad-ident`, `xattr-bad-blob`, …) plus the `source`
-- it settled on — 1 for the ELF section, 2 for the xattr, 0 for none.
--
-- Nothing here produces a signature that verifies: the kernel holds no
-- private key and the guest has no signing tool. Every case is about
-- the path taken on the way to "unsigned", which is what §3.6's lookup
-- rules are.

local sys = require("helpers.sys")
local kacs = require("helpers.kacs")
local signing = require("helpers.signing")

local vm = provium:vm("v", "kernel-only"):boot()

local B = signing.workspace(vm, "probe")
local XATTR = signing.blob({ fill = "\xBB" })

--- Place a crafted binary and exec it, returning the probe events.
local function probe(name, bytes, opts)
    local path = signing.place(vm, B .. "/" .. name, bytes, opts)
    local events, result = signing.exec_traced(vm, { signing.EV_PROBE }, path)
    return events, result, path
end

--- The single probe event a case expects, or nil.
local function one(t, events, what)
    local all = signing.of(events, "kacs_signing_probe")
    t:assert_eq(#all, 1, what .. ": exactly one probe outcome (saw " ..
        signing.reasons(events, "kacs_signing_probe") .. ")")
    return all[1]
end

-- Which path the magic selects -----------------------------------------------

test("a file whose first four bytes are \\x7fELF is taken down the ELF path",
    { spec = "PKM *sig.magic-selects-path" }, function(t)
        -- The same signature material in both places. If the ELF path
        -- were not taken the xattr would answer (source 2); it is, so
        -- the section answers (source 1).
        local events = probe("magic-elf",
            signing.craft({}), { xattr = XATTR })
        local e = one(t, events, "an ELF file")
        t:assert_eq(e.reason, "found", "the lookup finds signing material")
        t:assert_eq(e:num("source"), signing.SOURCE.ELF,
            "and it came from the .peios.sig section, not the xattr")
    end)

test("a file with different magic goes straight to the xattr",
    { spec = "PKM *sig.magic-selects-path",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "a non-ELF file cannot be exec'd, and exec is the only " ..
             "reachable entry to the lookup in this guest (LSV cannot be " ..
             "enabled on a process whose own text is unsigned, and no " ..
             "driver here requests firmware); runs under " ..
             "pkm_kunit_signing_xattr_hashes_non_elf and " ..
             "pkm_kunit_signing_short_file_uses_xattr" },
    function(t) end)

-- The ELF section ------------------------------------------------------------

test("the section name matches over all eleven bytes, so a longer name misses",
    { spec = "PKM *sig.elf.section-name-exact-match" }, function(t)
        local events = probe("name-longer",
            signing.craft({ sec_name = ".peios.sigx" }), { xattr = XATTR })
        local e = one(t, events, "a section named .peios.sigx")
        t:assert_eq(e:num("source"), signing.SOURCE.XATTR,
            "a name with the prefix but a twelfth byte does not match, " ..
            "so the lookup falls through to the xattr")
        -- And the exact name does match, on an otherwise identical file.
        local exact = probe("name-exact", signing.craft({}), { xattr = XATTR })
        t:assert_eq(one(t, exact, "a section named .peios.sig"):num("source"),
            signing.SOURCE.ELF, "the exact name matches")
    end)

test("finding the section commits the ELF path — the xattr is not consulted after",
    { spec = "PKM *sig.elf.section-commits-path" }, function(t)
        -- A perfectly valid xattr signature sits beside a section that
        -- is found and then rejected. If the path were not committed
        -- the xattr would answer.
        local events = probe("commits",
            signing.craft({ sec_size = signing.BLOB_LEN + 1 }),
            { xattr = XATTR })
        local e = one(t, events, "a bad section beside a good xattr")
        t:assert_eq(e.reason, "elf-bad-sig-section",
            "the section decides the outcome")
        t:assert_eq(e:num("source"), signing.SOURCE.NONE,
            "and the file is unsigned rather than xattr-signed")
    end)

test("every failure after the section is found yields unsigned, not a refusal",
    { spec = "PKM *sig.elf.section-failures-yield-unsigned" }, function(t)
        local cases = {
            { "wrong section type", { sec_type = signing.SHT_NOBITS },
              "elf-bad-sig-section" },
            { "a size other than 3310", { sec_size = signing.BLOB_LEN - 1 },
              "elf-bad-sig-section" },
            { "a range outside the file", { sec_offset = 1 << 30 },
              "elf-bad-sig-section" },
            { "a bad version byte", { blob_version = 2 }, "elf-bad-blob" },
        }
        for i, c in ipairs(cases) do
            local events, result = probe("fail" .. i, signing.craft(c[2]),
                { xattr = XATTR })
            local e = one(t, events, c[1])
            t:assert_eq(e.reason, c[3], c[1] .. " is reported as " .. c[3])
            t:assert_eq(e:num("source"), signing.SOURCE.NONE,
                c[1] .. " leaves the file unsigned")
            t:assert_eq(result.exit_code, 0,
                c[1] .. " does not refuse the exec")
        end
    end)

test("the structural ELF failures commit the path before any section is seen",
    { spec = "PKM *sig.elf.structural-failures-commit" }, function(t)
        -- Each of these is rejected before the section scan, and each
        -- carries a valid xattr signature that is never read: a 32-bit
        -- or big-endian ELF cannot carry an xattr signature at all.
        local cases = {
            { "a class other than ELFCLASS64",
              { class = signing.ELFCLASS32 }, "elf-bad-ident" },
            { "a byte order other than little-endian",
              { data = signing.ELFDATA2MSB }, "elf-bad-ident" },
            { "an unexpected ELF version",
              { ei_version = 0 }, "elf-bad-ident" },
            { "a section header entry size other than 64",
              { shentsize = 63 }, "elf-bad-shtable" },
            { "an absent section-name string table index",
              { shstrndx = 0 }, "elf-bad-shtable" },
            { "an out-of-range string table index",
              { shstrndx = 3 }, "elf-bad-shtable" },
            { "a section header table outside the recorded size",
              { shoff = 1 << 30 }, "elf-shdrs-range" },
            { "a string table outside the recorded size",
              { strtab_offset = 1 << 30 }, "elf-strtab-range" },
        }
        for i, c in ipairs(cases) do
            local events = probe("struct" .. i, signing.craft(c[2]),
                { xattr = XATTR })
            local e = one(t, events, c[1])
            t:assert_eq(e.reason, c[3], c[1] .. " is reported as " .. c[3])
            t:assert_eq(e:num("source"), signing.SOURCE.NONE,
                c[1] .. " commits the ELF path, so the xattr is not read")
        end
    end)

test("an ELF with no section headers falls through to the xattr",
    { spec = "PKM *sig.elf.no-section-headers-falls-through" }, function(t)
        local events = probe("shnum0", signing.craft({ no_sections = true }),
            { xattr = XATTR })
        local e = one(t, events, "e_shnum == 0")
        t:assert_eq(e.reason, "found", "the lookup still finds material")
        t:assert_eq(e:num("source"), signing.SOURCE.XATTR,
            "from the xattr: e_shnum == 0 is the structural case that " ..
            "does not commit")
    end)

-- The xattr ------------------------------------------------------------------

test("the xattr has to be exactly 3310 bytes; any other size is unsigned",
    { spec = "PKM *sig.xattr.exact-size" }, function(t)
        for _, len in ipairs({ signing.BLOB_LEN - 1, signing.BLOB_LEN + 1 }) do
            local events = probe("xlen" .. len,
                signing.craft({ no_sections = true }),
                { xattr = signing.blob({ len = len }) })
            local e = one(t, events, "a " .. len .. "-byte xattr")
            t:assert_eq(e.reason, "xattr-bad-blob",
                len .. " bytes is rejected as a malformed blob")
            t:assert_eq(e:num("source"), signing.SOURCE.NONE,
                "and the file is treated as unsigned")
        end
        local ok = probe("xlen-exact", signing.craft({ no_sections = true }),
            { xattr = XATTR })
        t:assert_eq(one(t, ok, "a 3310-byte xattr"):num("source"),
            signing.SOURCE.XATTR, "exactly 3310 bytes is accepted as material")
    end)

test("the verifier's own read of the signature is not mediated by the LSM xattr hooks",
    { spec = "PKM *sig.xattr.read-bypasses-lsm-hooks" }, function(t)
        -- A descriptor that grants execute but not FILE_READ_EA. A
        -- caller judged on it cannot read the xattr; the verifier,
        -- running on that caller's exec, reads it anyway.
        local path = signing.place(vm, B .. "/no-read-ea",
            signing.craft({ no_sections = true }),
            { xattr = XATTR,
              rights = kacs.RIGHT.EXECUTE | kacs.RIGHT.READ_DATA
                  | kacs.RIGHT.READ_ATTRIBUTES | kacs.RIGHT.SYNCHRONIZE })
        local events = signing.trace(vm, { signing.EV_PROBE }, function()
            kacs.as_dacl_bound(t, vm, function(w)
                local value, errno = sys.getxattr(w, path, signing.XATTR)
                t:assert(not value,
                    "the caller cannot read security.peios.sig itself")
                t:assert_eq(errno, sys.E.ACCES, "the read is refused with EACCES")
                local run = w:run(path, {})
                t:assert_eq(run.exit_code, 0, "but it may execute the file")
            end)
        end)
        local e = one(t, events, "an exec by a caller denied FILE_READ_EA")
        t:assert_eq(e.reason, "found",
            "the verifier still found the signature material")
        t:assert_eq(e:num("source"), signing.SOURCE.XATTR,
            "reading it straight out of the xattr")
    end)

-- Bounds and hashing ---------------------------------------------------------

test("a file that changes size mid-verification invalidates the whole result",
    { spec = "PKM *sig.size-snapshot-revalidated",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "the size is re-read inside one bprm_creds_from_file call, " ..
             "and nothing in the guest can be scheduled between the two " ..
             "reads of an exec that is already past the point of no " ..
             "return; runs under pkm_kunit_signing_reader_size_change_invalidates" },
    function(t) end)

test("an ELF-section signature is hashed with the section's contents zeroed",
    { spec = "PKM *sig.hash.elf-section-zeroed",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "the content hash is never surfaced and no signature this " ..
             "guest can author verifies, so the two hashing rules are " ..
             "indistinguishable from the verdict; runs under " ..
             "pkm_kunit_signing_elf_section_zeroes_signature_bytes" },
    function(t) end)

test("an xattr signature is hashed over the entire file, ELF or not",
    { spec = "PKM *sig.hash.xattr-covers-whole-file",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "same reason as the ELF-section hash: no authored signature " ..
             "verifies, so the hash input cannot be inferred from the " ..
             "verdict; runs under pkm_kunit_signing_xattr_hashes_non_elf " ..
             "and pkm_kunit_signing_reader_xattr_hashes_non_elf" },
    function(t) end)
