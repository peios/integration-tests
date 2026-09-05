-- PKM §3.6 — firmware verification.
--
-- The hooks are `kernel_read_file` / `kernel_post_read_file` for
-- `READING_FIRMWARE`, and reaching them needs a driver that calls
-- `request_firmware()`. This guest has none: the composed root carries
-- the kernel image and nothing else — no `/lib/firmware`, no modules
-- directory (so `CONFIG_TEST_FIRMWARE=m`'s `trigger_request`, which
-- §3.6 names as the way the `test.fwsig` stage exercises both modes, is
-- not present), `CONFIG_FW_LOADER_USER_HELPER` is off so there is no
-- sysfs fallback, and `/sys/class/firmware` stays empty for the life of
-- the VM. Nothing in the guest can provoke a firmware load, so the
-- verdict rules are stubs against the pkm_kunit_signing suite.
--
-- The one reachable claim is the command-line override, which is parsed
-- by an `__setup` handler at boot: `kacs_fwsig=enforce` and
-- `kacs_fwsig=log` are consumed, and anything else is refused with a
-- named warning and left to userspace. A second VM boots with all three
-- spellings so one boot shows both halves.

local sys = require("helpers.sys")

local vm = provium:vm("v", "kernel-only"):boot()

-- A second guest whose command line offers the parser one bad value and
-- both good ones. The bad one is first so the effective policy at the
-- end of the line is `log`, which is what 2026.8 ships.
local fw = provium:vm("fw", "kernel-only"):boot({
    kernel_cmdline_append = "kacs_fwsig=bogus kacs_fwsig=enforce kacs_fwsig=log",
})

--- The kernel ring buffer, as one string. `/dev/kmsg` opened O_NONBLOCK
--- reads records until it runs out, which is the whole buffer since
--- boot — the console is at `quiet`, so a pr_warn only exists here.
local function kmsg(who)
    local fd, errno = sys.open(who, "/dev/kmsg", sys.O.RDONLY | 0x800)
    assert(fd, "/dev/kmsg: " .. sys.errname(errno or 0))
    local chunks = {}
    for _ = 1, 4000 do
        local data = sys.read(who, fd, 4096)
        if not data or #data == 0 then break end
        chunks[#chunks + 1] = data
    end
    sys.close(who, fd)
    return table.concat(chunks)
end

local function stub(name, spec, case, why)
    test(name, { spec = spec, covered_by = "kunit:pkm_kunit_signing",
                 skip = why .. "; runs under " .. case }, function(t) end)
end

local NO_LOADER = "no driver in a kernel-only guest calls " ..
    "request_firmware(): the root carries no /lib/firmware and no " ..
    "modules, CONFIG_FW_LOADER_USER_HELPER is off, and /sys/class/firmware " ..
    "stays empty, so neither firmware hook can be reached"

-- The command line -------------------------------------------------------------

test("kacs_fwsig accepts enforce and log on the command line and refuses anything else",
    { spec = "PKM *sig.firmware.cmdline-override" }, function(t)
        local line = fw:read_file("/proc/cmdline")
        for _, value in ipairs({ "bogus", "enforce", "log" }) do
            t:assert_contains(line, "kacs_fwsig=" .. value,
                "the guest booted with kacs_fwsig=" .. value)
        end
        local log = kmsg(fw)
        t:assert_contains(log,
            "pkm: kacs_fwsig=bogus ignored (expected enforce or log)",
            "an unrecognised value is refused by name")
        for _, value in ipairs({ "enforce", "log" }) do
            t:assert(not log:find("kacs_fwsig=" .. value ..
                " ignored", 1, true),
                "kacs_fwsig=" .. value .. " is accepted, not ignored")
        end
        -- The setup handler claims the parameter it accepts, so only
        -- the refused spelling is handed on to userspace.
        local unknown = log:match("Unknown kernel command line parameters \"([^\"]*)\"")
        t:assert(unknown, "the kernel reported its unclaimed parameters")
        t:assert_contains(unknown, "kacs_fwsig=bogus",
            "the refused value was not consumed")
        t:assert(not unknown:find("kacs_fwsig=enforce", 1, true),
            "kacs_fwsig=enforce was consumed by the handler")
        t:assert(not unknown:find("kacs_fwsig=log", 1, true),
            "kacs_fwsig=log was consumed by the handler")
    end)

test("a firmware load never happens in this guest, so nothing is verified here",
    { spec = "PKM *sig.firmware.default-is-log",
      skip = "no coverage anywhere: the Kconfig default " ..
             "(CONFIG_SECURITY_PKM_FIRMWARE_SIG_ENFORCE unset, which is " ..
             "what makes 2026.8 log-mode) is not exposed by any kernel " ..
             "interface — no securityfs file, no sysctl, and the " ..
             "kacs_firmware_load tracepoint's enforce= field only appears " ..
             "on a load, which " .. NO_LOADER .. "; pkm_kunit_signing has " ..
             "no case asserting the build-time default either" },
    function(t) end)

-- The verdict --------------------------------------------------------------------

stub("firmware has to clear the PeiosTcb tier; any other verified tier counts as unsigned",
    "PKM *sig.firmware.peiostcb-floor",
    "pkm_kunit_firmware_verdict_requires_tcb", NO_LOADER)

stub("under enforce an unsigned, tampered or under-tier blob is refused with -EPERM",
    "PKM *sig.firmware.enforce-eperm",
    "pkm_kunit_firmware_verdict_requires_tcb, whose every non-allowed " ..
    "case asserts -EPERM with enforce true", NO_LOADER)

stub("under log the verdict is recorded and the load proceeds",
    "PKM *sig.firmware.log-mode",
    "pkm_kunit_firmware_verdict_requires_tcb, whose every case asserts 0 " ..
    "with enforce false", NO_LOADER)

stub("a whole-file read is verified against the exact bytes the loader will use",
    "PKM *sig.firmware.post-read-hashes-loaded-bytes",
    "pkm_kunit_signing_reader_matches_buffer_for_elf and " ..
    "pkm_kunit_signing_xattr_hashes_non_elf, which pin the buffer probe " ..
    "to the same answer as the reader probe", NO_LOADER)

test("a partial firmware read is verified through the reader probe instead",
    { spec = "PKM *sig.firmware.partial-read-uses-probe",
      skip = "no coverage anywhere: " .. NO_LOADER .. ", and the " ..
             "pkm_kunit_signing suite has no case that drives " ..
             "pkm_kacs_kernel_read_file with contents=false — the branch " ..
             "that sends a partial read down the reader probe" },
    function(t) end)

test("the hash covers the compressed bytes as they sit on disk",
    { spec = "PKM *sig.firmware.hashes-compressed-bytes",
      skip = "no coverage anywhere: " .. NO_LOADER .. "; verification " ..
             "preceding decompression is a property of where the hooks sit " ..
             "in the loader, and no pkm_kunit_signing case exercises a " ..
             "compressed blob" },
    function(t) end)
