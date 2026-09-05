-- PKM §3.6 — firmware verification.
--
-- The hooks are `kernel_read_file` / `kernel_post_read_file` for
-- `READING_FIRMWARE`, and reaching them needs a driver that calls
-- `request_firmware()`. The kernel-only guest has no such driver of its
-- own, so the profile's fixture initramfs carries the loader's self-test
-- device, `test_firmware` (/fixtures/modules), whose sysfs knobs issue
-- whole-file, partial and into-buffer requests on demand; and it carries
-- firmware blobs signed at build time with the TCB key the kernel
-- embeds, plus unsigned and tampered ones, each signature beside its
-- blob as the `.peios.sig` sidecar a package would ship
-- (/fixtures/firmware, see profiles/kernel-only/build.sh). A test stands
-- the blobs up on a tmpfs, stamps each sidecar into `security.peios.sig`
-- the way peipkg does at install, and points the loader's search path
-- at it — helpers.fixtures does the standing up.
--
-- Three guests: one at the build default (log mode), one booted with
-- `kacs_fwsig=enforce`, and one whose command line offers the parser a
-- bad value and both good ones so one boot shows the parser's both
-- halves. The verdict is read three ways: the loader's own result (the
-- write to `trigger_request` fails with request_firmware()'s errno), the
-- rate-limited warning in the kernel log, and the kacs_firmware_load
-- tracepoint.

local sys = require("helpers.sys")
local fx = require("helpers.fixtures")
local hooks = require("helpers.hooks")

local vm = provium:vm("v", "kernel-only"):boot()
local enf = provium:vm("enf", "kernel-only"):boot({
    kernel_cmdline_append = "kacs_fwsig=enforce",
})

-- A guest whose command line offers the parser one bad value and both
-- good ones. The bad one is first so the effective policy at the end of
-- the line is `log`, which is what 2026.8 ships.
local fw = provium:vm("fw", "kernel-only"):boot({
    kernel_cmdline_append = "kacs_fwsig=bogus kacs_fwsig=enforce kacs_fwsig=log",
})

local UNAVAILABLE = fx.firmware_unavailable(vm)
local FW = "/fw"
local FIX = fx.FIRMWARE

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

--- The warning KACS logged for a blob called `name`, or nil.
local function warned(who, name)
    return kmsg(who):match("pkm: firmware " .. name:gsub("%p", "%%%0") .. ": ([^\n]*)")
end

--- The error the loader logged against our copy of `name`, or nil.
--- The loader tries each search path in turn and a refused read at one
--- only moves it on to the next, so what request_firmware() finally
--- hands the driver is the last path's miss (ENOENT); the hook's own
--- answer is what the loader wrote against the path it was refused at.
local function loader_error(who, name)
    local path = (FW .. "/" .. name):gsub("%p", "%%%0")
    return tonumber(kmsg(who):match("loading " .. path .. "[%w%.]* failed with error (%-?%d+)"))
end

-- Each guest gets the loader's test device and a firmware directory
-- once; a test that needs them asks for `ready(who)`.
local prepared = {}
local function ready(t, who)
    if UNAVAILABLE then t:skip(UNAVAILABLE) end
    if prepared[who] then return end
    local ok, e = fx.load_module(who, "test_firmware")
    assert(ok, "loading test_firmware: " .. sys.errname(e or 0))
    local ok2, msg = fx.firmware_dir(who, FW)
    assert(ok2, msg)
    prepared[who] = true
end

--- Put fixture `fixture` into the firmware directory under its own name
--- or `as`, carrying the signature of `signed_as` (default: its own
--- sidecar, when it has one). A distinct name per case keeps the kernel
--- log unambiguous when several cases load the same bytes.
local function blob(who, fixture, as, signed_as)
    local name = as or fixture
    who:write_file(FW .. "/" .. name, who:read_file(FIX .. "/" .. fixture))
    local sidecar = FIX .. "/" .. (signed_as or fixture) .. ".peios.sig"
    if fx.present(who, sidecar) then
        local r = fx.stamp_signature(who, FW .. "/" .. name, sidecar)
        assert(r.ret == 0, "stamping " .. name .. ": " .. sys.errname(r.errno))
    end
    return name
end

--- Ask the loader for `name` and return ok, errno.
local function load(who, name)
    return fx.request_firmware(who, name)
end

--- A partial read of `name`: `size` bytes at `offset`, into the
--- caller's buffer — the shape a driver pulling a window out of a large
--- blob uses. Returns the loader's result for the request (0 or -errno).
---
--- test_firmware's buffer is a fixed 1 KiB (TEST_FIRMWARE_BUF_SIZE) and
--- `config_buf_size` is not checked against it: a larger window is a
--- heap overflow in the guest that surfaces as an Oops somewhere else
--- later. Never ask for more.
local TEST_FW_BUF = 1024
local function load_partial(who, name, offset, size)
    assert(size <= TEST_FW_BUF, "a window larger than test_firmware's buffer")
    assert(fx.test_fw_config(who, "reset", "1"))
    assert(fx.test_fw_config(who, "config_name", name))
    assert(fx.test_fw_config(who, "config_num_requests", "1"))
    assert(fx.test_fw_config(who, "config_into_buf", "1"))
    assert(fx.test_fw_config(who, "config_partial", "1"))
    assert(fx.test_fw_config(who, "config_buf_size", tostring(size)))
    assert(fx.test_fw_config(who, "config_file_offset", tostring(offset)))
    assert(fx.test_fw_config(who, "trigger_batched_requests", "1"))
    local result = assert(fx.test_fw_read(who, "test_result"))
    fx.test_fw_config(who, "release_all_firmware", "1")
    fx.test_fw_config(who, "reset", "1")
    return tonumber(result:match("-?%d+"))
end

--- Run `fn` with the kacs_firmware_load tracepoint enabled on `who`;
--- returns the traced lines.
local function traced(t, who, fn)
    local ok, err = hooks.trace_start(who, "kacs/kacs_firmware_load")
    t:assert(ok, "tracing starts: " .. tostring(err))
    local ran, raised = pcall(fn)
    local lines = hooks.trace_stop(who, "kacs/kacs_firmware_load")
    if not ran then error(raised, 0) end
    t:assert(lines, "the buffer reads back")
    return lines
end

local function field(line, name) return line:match(name .. "=([%w%-]+)") end

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

        -- And the last value on the line is the one that governs: this
        -- guest ends on `log`, so an unsigned blob loads.
        ready(t, fw)
        local name = blob(fw, "unsigned.bin", "cmdline-last-wins.bin")
        t:assert(load(fw, name), "the last spelling, log, is in force")
        t:assert_contains(warned(fw, name) or "", "loaded (kacs_fwsig=log)",
            "and the verdict says so")
    end)

test("with no override the build's policy is log mode",
    { spec = "PKM *sig.firmware.default-is-log" }, function(t)
        -- This guest's command line says nothing about kacs_fwsig, so
        -- what governs is CONFIG_SECURITY_PKM_FIRMWARE_SIG_ENFORCE: an
        -- unsigned blob loading, and the verdict saying log, is the
        -- build default made visible.
        ready(t, vm)
        t:assert(not vm:read_file("/proc/cmdline"):find("kacs_fwsig", 1, true),
            "nothing on the command line overrides the build")
        local name = blob(vm, "unsigned.bin", "default-unsigned.bin")
        local lines = traced(t, vm, function()
            t:assert(load(vm, name), "an unsigned blob loads at the default")
        end)
        t:assert_contains(warned(vm, name) or "", "loaded (kacs_fwsig=log)",
            "the recorded verdict names log mode")
        t:assert_eq(#lines, 1, "one verdict traced")
        t:assert_eq(field(lines[1], "enforce"), "0", "enforce=0 at the build default")
    end)

-- The verdict --------------------------------------------------------------------

test("firmware has to clear the PeiosTcb tier; any other verified tier counts as unsigned",
    { spec = "PKM *sig.firmware.peiostcb-floor",
      covered_by = "kunit:pkm_kunit_signing",
      skip = "the kernel's built-in table holds one key, mapped to PeiosTcb, so " ..
             "a signature that verifies at a lower tier cannot be produced for " ..
             "this guest (a TCB-signed blob loading is witnessed by the enforce " ..
             "case beside this); the tier floor runs under " ..
             "pkm_kunit_firmware_verdict_requires_tcb" },
    function(t) end)

test("under enforce an unsigned, tampered or under-tier blob is refused with -EPERM",
    { spec = "PKM *sig.firmware.enforce-eperm" }, function(t)
        ready(t, enf)
        local signed = blob(enf, "signed.bin", "enforce-signed.bin")
        t:assert(load(enf, signed), "a TCB-signed blob loads under enforce")
        t:assert(not warned(enf, signed), "with nothing to warn about")

        local unsigned = blob(enf, "unsigned.bin", "enforce-unsigned.bin")
        local tampered = blob(enf, "tampered.bin", "enforce-tampered.bin")
        local lines = traced(t, enf, function()
            t:assert(not load(enf, unsigned), "an unsigned blob does not load")
            t:assert(not load(enf, tampered), "nor does a tampered one")
        end)
        -- The hook's answer is -EPERM: the tracepoint records it, and
        -- the loader logs it against the path it was refused at before
        -- trying its remaining search paths and reporting the driver an
        -- ordinary load failure.
        t:assert_eq(#lines, 2, "two verdicts traced")
        for i, name in ipairs({ unsigned, tampered }) do
            t:assert_eq(field(lines[i], "enforce"), "1", name .. ": under enforce")
            t:assert_eq(field(lines[i], "ret"), "-1", name .. ": refused -EPERM")
            t:assert_eq(loader_error(enf, name), -sys.E.PERM,
                name .. ": the loader saw -EPERM for the path")
        end
        t:assert_eq(field(lines[1], "reason"), "unsigned", "the unsigned one as unsigned")
        t:assert_contains(warned(enf, unsigned) or "", "no signature; refused",
            "and the refusal is recorded")
        t:assert_eq(field(lines[2], "reason"), "no-key-match", "the tampered one as not verifying")
        t:assert_contains(warned(enf, tampered) or "",
            "signature does not verify against any built-in key; refused",
            "as a signature that does not verify")
    end)

test("under log the verdict is recorded and the load proceeds",
    { spec = "PKM *sig.firmware.log-mode" }, function(t)
        ready(t, vm)
        local unsigned = blob(vm, "unsigned.bin", "log-unsigned.bin")
        local tampered = blob(vm, "tampered.bin", "log-tampered.bin")
        local signed = blob(vm, "signed.bin", "log-signed.bin")
        local lines = traced(t, vm, function()
            t:assert(load(vm, unsigned), "the unsigned blob loads")
            t:assert(load(vm, tampered), "the tampered blob loads")
            t:assert(load(vm, signed), "the signed blob loads")
        end)
        t:assert_contains(warned(vm, unsigned) or "", "no signature; loaded (kacs_fwsig=log)",
            "the unsigned load is warned about, naming the mode")
        t:assert_contains(warned(vm, tampered) or "",
            "signature does not verify against any built-in key; loaded (kacs_fwsig=log)",
            "so is the tampered one")
        t:assert(not warned(vm, signed), "a verified load is silent")
        -- The tracepoint carries the same three verdicts, in order.
        t:assert_eq(#lines, 3, "three verdicts traced")
        t:assert_eq(field(lines[1], "reason"), "unsigned", "unsigned")
        t:assert_eq(field(lines[2], "reason"), "no-key-match", "no key match")
        t:assert_eq(field(lines[3], "reason"), "allowed", "allowed")
        for i = 1, 3 do
            t:assert_eq(field(lines[i], "enforce"), "0", "each under log")
            t:assert_eq(field(lines[i], "ret"), "0", "each let through")
        end
        t:assert_eq(field(lines[3], "pip_trust"), "8192", "the verified one at the PeiosTcb tier")
    end)

test("a whole-file read is verified against the exact bytes the loader will use",
    { spec = "PKM *sig.firmware.post-read-hashes-loaded-bytes" }, function(t)
        -- tampered.bin is signed.bin with one byte changed and carries
        -- signed.bin's signature — a valid signature, of the wrong
        -- bytes. Refusing it means the hash is of what was read, not of
        -- anything the file claims about itself.
        ready(t, enf)
        local tampered = blob(enf, "tampered.bin", "postread-tampered.bin", "signed.bin")
        t:assert(not load(enf, tampered), "the bytes read do not match the signature")
        t:assert_eq(loader_error(enf, tampered), -sys.E.PERM, "and the read was refused -EPERM")
        t:assert_contains(warned(enf, tampered) or "",
            "signature does not verify against any built-in key", "as not verifying")
        -- The same signature over the bytes it was made for.
        local signed = blob(enf, "signed.bin", "postread-signed.bin")
        t:assert(load(enf, signed), "and does match the bytes it signs")
    end)

test("a partial firmware read is verified through the reader probe instead",
    { spec = "PKM *sig.firmware.partial-read-uses-probe" }, function(t)
        -- A window out of a blob never reaches the post-read hook, so
        -- if it were not verified on the way in nothing would verify
        -- it at all. Under enforce an unsigned window is refused and a
        -- signed one served; the whole file is what the probe hashes,
        -- so the signature over all of large.bin covers a read of its
        -- second page.
        ready(t, enf)
        local signed = blob(enf, "large.bin", "partial-signed.bin")
        t:assert_eq(load_partial(enf, signed, 4096, 1024), 0,
            "a window of a signed blob is served")
        local unsigned = blob(enf, "unsigned.bin", "partial-unsigned.bin")
        t:assert_neq(load_partial(enf, unsigned, 1024, 1024), 0,
            "a window of an unsigned blob is not served")
        t:assert_eq(loader_error(enf, unsigned), -sys.E.PERM, "the read was refused -EPERM")
        t:assert_contains(warned(enf, unsigned) or "", "no signature; refused",
            "with the verdict recorded like any other")

        -- And under log the same window is verified and let through,
        -- so the pre-read path traces a verdict of its own.
        ready(t, vm)
        local logged = blob(vm, "unsigned.bin", "partial-log-unsigned.bin")
        local lines = traced(t, vm, function()
            t:assert_eq(load_partial(vm, logged, 1024, 1024), 0, "served under log")
        end)
        t:assert_eq(#lines, 1, "one verdict for the partial read")
        t:assert_eq(field(lines[1], "reason"), "unsigned", "unsigned, seen on the way in")
    end)

test("the hash covers the compressed bytes as they sit on disk",
    { spec = "PKM *sig.firmware.hashes-compressed-bytes" }, function(t)
        -- compressed.bin.zst is what the loader finds for a request of
        -- compressed.bin. Its sidecar signs the compressed bytes; a
        -- second sidecar signs the bytes it decompresses to. Only the
        -- first verifies: verification precedes decompression.
        if not fx.present(vm, FIX .. "/compressed.bin.zst") then
            t:skip("the profile was built without zstd, so there is no compressed fixture")
        end
        ready(t, enf)
        local name = "compressed-case.bin"
        local on_disk = blob(enf, "compressed.bin.zst", name .. ".zst")
        t:assert(load(enf, name), "signed over the on-disk bytes, the blob loads")
        t:assert(not warned(enf, on_disk), "silently")

        local r = fx.stamp_signature(enf, FW .. "/" .. name .. ".zst",
            FIX .. "/compressed.bin.zst.decompressed.peios.sig")
        assert(r.ret == 0, "restamping: " .. sys.errname(r.errno))
        t:assert(not load(enf, name), "signed over the decompressed bytes, it does not load")
        t:assert_eq(loader_error(enf, on_disk), -sys.E.PERM, "the read was refused -EPERM")
        t:assert_contains(warned(enf, on_disk) or "",
            "signature does not verify against any built-in key; refused",
            "because the hash is of what is on disk")
    end)
