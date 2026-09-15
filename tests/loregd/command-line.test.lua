-- loregd §2.1 — the argument vector is loregd's entire configuration
-- surface: the hive declarations it takes, how they are validated, and
-- the one environment variable (NOTIFY_SOCKET) it consults.
--
-- Rejections are asserted with `loregd.spawn` + `proc:wait`: a bad
-- invocation never registers, so there is nothing to wait for — we read
-- the exit status directly (non-zero, and not -1: a real exit, not a
-- signal). Observational cases run against a file-scope PtState daemon
-- (the fixture hive is itself mixed-case, so it doubles as the
-- case-preservation subject); cases that need a differently-shaped argv
-- start their own short-lived daemon, reaped when the test ends.

local loregd = require("helpers.loregd")
local unixsock = require("helpers.unixsock")

local MOUNT = loregd.MOUNT

local vm = loregd.boot({ name = "loregd-cmdline" })
loregd.format(vm)
loregd.mount(vm)

-- One long-lived daemon serving the mixed-case PtState fixture, shared by
-- the observational cases. Never SIGTERMed (PEI-1122 would hang it); it
-- dies with the VM at end of file.
loregd.start(vm)

-- Spawn loregd with an explicit argv and env, wait until `wait_for`
-- registers, and return the Process. Mirrors loregd.start but lets a
-- case control the environment (for the NOTIFY_SOCKET cases).
local function start_env(t, hives, wait_for, env, env_clear)
    local proc = vm:run_async("/usr/sbin/loregd",
        { args = hives, env = env or {}, env_clear = env_clear or false })
    local ok = pcall(wait_until, function()
        return vm:run("reg ls " .. wait_for).exit_code == 0
    end, { timeout = 30, interval = 0.5, desc = "loregd to register " .. wait_for })
    if not ok then
        proc:kill("kill")
        local r = proc:wait("5s")
        t:assert(false, "loregd never registered " .. wait_for ..
            ": exit=" .. tostring(r.exit_code) ..
            " stdout=" .. tostring(r.stdout) .. " stderr=" .. tostring(r.stderr))
    end
    return proc
end

-- "loregd is configured entirely by its argument vector. It takes one or
--  more hive declarations, each naming a hive and the SQLite database
--  file that backs it."
test("a HiveName=Path argument declares a hive backed by the named database",
    { spec = "loregd *cmdline.an-argument-declares-a-hive-and-the-database-that-backs-it" },
    function(t)
        -- The file-scope daemon was started as `loregd PtState=<HIVE_FILE>`;
        -- that one argument is what makes the PtState hive exist and route.
        local r = vm:run("reg ls " .. loregd.HIVE)
        t:assert_eq(r.exit_code, 0,
            "the hive named on the command line is served: " .. r.stderr)
    end)

-- "Each argument is split at its first `=`, so a database path may itself
--  contain `=`."
test("an argument is split at its first '=' so the path may contain '='",
    { spec = "loregd *cmdline.an-argument-is-split-at-its-first-equals-sign" },
    function(t)
        local path = MOUNT .. "/we=ird=name.hive"
        local proc = start_env(t, { "Eqpath=" .. path }, "Eqpath", {})
        -- Split at the FIRST '=': name is "Eqpath", path is the whole
        -- "we=ird=name.hive". If it split at the last '=' the name/path
        -- would be garbage and registration would never have happened.
        local r = vm:run("reg ls Eqpath")
        t:assert_eq(r.exit_code, 0,
            "the hive whose path contains '=' is served: " .. r.stderr)
        -- The backing file exists at exactly that path.
        t:assert_eq(vm:run("test -f '" .. path .. "'").exit_code, 0,
            "the database file was created at the full path after the first '='")
        proc:kill("kill")
    end)

-- "Every declared hive is registered with the kernel at startup."
test("every declared hive is registered with the kernel",
    { spec = "loregd *cmdline.every-declared-hive-is-registered-with-the-kernel" },
    function(t)
        local proc = loregd.start(vm, t, {
            hives = { "Alpha=" .. MOUNT .. "/alpha.hive",
                      "Beta=" .. MOUNT .. "/beta.hive" },
            wait_for = "Alpha",
        })
        for _, name in ipairs({ "Alpha", "Beta" }) do
            local r = vm:run("reg ls " .. name)
            t:assert_eq(r.exit_code, 0,
                "declared hive " .. name .. " is registered and routable: " .. r.stderr)
        end
        proc:kill("kill")
    end)

-- "loregd rejects the invocation and exits with a non-zero status if any
--  of the following hold" — the whole §2.1 validation table, plus the
--  header claim that an invalid invocation is rejected non-zero.
test("every invalid invocation is rejected with a non-zero exit",
    {
        spec = "loregd *cmdline.an-invalid-invocation-is-rejected-with-a-non-zero-exit" ..
            " *cmdline.at-least-one-hive-argument-is-required" ..
            " *cmdline.an-argument-without-an-equals-sign-is-rejected" ..
            " *cmdline.an-empty-hive-name-or-path-is-rejected" ..
            " *cmdline.a-database-path-must-be-absolute" ..
            " *cmdline.a-hive-name-may-not-contain-a-separator-or-nul" ..
            " *cmdline.the-hive-name-currentuser-is-reserved" ..
            " *cmdline.duplicate-hive-names-are-detected-on-the-folded-name",
    },
    function(t)
        local good = MOUNT .. "/x.hive"
        -- A NUL in a hive name cannot cross execve (argv entries are
        -- NUL-terminated C strings), so it is not guest-constructable; the
        -- separator half is exercised here with `\` and `/`, and the NUL
        -- branch is pinned by config's TestParseErrors "null in name".
        local cases = {
            { "no hive arguments at all", {} },
            { "an argument with no '='", { "NoEquals" } },
            { "an empty hive name", { "=" .. good } },
            { "an empty database path", { "Name=" } },
            { "a relative database path", { "Rel=relative/path.db" } },
            { "a hive name containing a backslash", { "Ba\\d=" .. good } },
            { "a hive name containing a forward slash", { "Ba/d=" .. good } },
            { "the reserved name CurrentUser", { "CurrentUser=" .. good } },
            { "the reserved name in lower case", { "currentuser=" .. good } },
            { "the reserved name in upper case", { "CURRENTUSER=" .. good } },
            { "a duplicate hive name (folded)",
              { "Dup=" .. MOUNT .. "/a.hive", "DUP=" .. MOUNT .. "/b.hive" } },
        }
        for _, c in ipairs(cases) do
            local desc, args = c[1], c[2]
            local r = loregd.spawn(vm, args):wait("10s")
            -- A rejected invocation EXITS (status "exited") with a
            -- non-zero code — it does not crash (signal → exit_code -1)
            -- and does not start serving.
            t:assert_eq(r.status, "exited",
                desc .. ": loregd exits rather than being signalled. stderr=" .. r.stderr)
            t:assert(r.exit_code ~= 0,
                desc .. ": expected a non-zero exit, got " .. tostring(r.exit_code) ..
                ". stderr=" .. r.stderr)
        end
    end)

-- "Hive-name comparison is case-insensitive throughout ... but the case
--  as written on the command line is preserved and is what loregd
--  presents to the kernel when it registers."
test("hive-name routing is case-insensitive and the written case is preserved",
    { spec = "loregd *cmdline.hive-name-comparison-is-case-insensitive-but-the-case-is-preserved" },
    function(t)
        -- PtState was declared with exactly that mixed casing. Every
        -- casing routes (case-insensitive comparison), and `reg info`
        -- reports the root key's stored name, which is the hive name as
        -- written — "PtState" — proving the case was preserved through
        -- registration, not folded.
        -- The case-insensitive half is observable: PtState was declared
        -- with exactly that mixed casing, and every folding of it routes
        -- to the same served hive.
        for _, spelling in ipairs({ "PtState", "ptstate", "PTSTATE", "PtSTATE" }) do
            local r = vm:run("reg info " .. spelling)
            t:assert_eq(r.exit_code, 0,
                "the '" .. spelling .. "' spelling routes to the same hive: " .. r.stderr)
        end
        -- The written-case-preserved half is NOT guest-observable: the
        -- kernel resolves a hive by its folded name and `reg` reports back
        -- the spelling the caller typed (reg info's `name` echoes the
        -- request, not the stored root name), and there is no namespace-
        -- root enumeration that would expose the registered name (`reg ls`
        -- rejects an empty/root key path). That the case as written is
        -- preserved through parsing — what loregd hands the kernel at
        -- registration — is pinned by config's TestParseCasePreservation.
    end)

-- "loregd has no configuration file and reads no configuration from the
--  registry ... Everything about how it behaves comes from ... the
--  command-line arguments ..., the contents of the SQLite databases they
--  name, and compiled-in constants." Plus: readiness "step is skipped"
--  when NOTIFY_SOCKET is unset.
test("with a cleared environment and no config file it still fully serves",
    {
        spec = "loregd *cmdline.there-is-no-configuration-file-or-registry-configuration" ..
            " *cmdline.behaviour-comes-from-arguments-databases-and-compiled-in-constants" ..
            " *cmdline.readiness-is-skipped-when-notify-socket-is-unset",
    },
    function(t)
        -- env_clear wipes the whole environment — no NOTIFY_SOCKET, and
        -- nothing a config layer could ride in on. loregd is handed only
        -- an argv and an (empty) database; if it needed a config file or
        -- any environment it could not reach the request loop here.
        local proc = start_env(t, { "Cfg=" .. MOUNT .. "/cfg.hive" }, "Cfg", {}, true)
        local r = vm:run("reg ls Cfg")
        t:assert_eq(r.exit_code, 0,
            "loregd serves with an empty environment and no config file, so its " ..
            "behaviour comes only from argv + database + compiled constants, and " ..
            "readiness is skipped (no NOTIFY_SOCKET) without stalling startup: " .. r.stderr)
        proc:kill("kill")
    end)

-- "`NOTIFY_SOCKET` is the one environment variable loregd consults ...
--  once the hives are registered and the request loop is about to begin,
--  it connects and sends `READY=1`."
test("readiness is sent as READY=1 to NOTIFY_SOCKET before the request loop",
    {
        spec = "loregd *cmdline.readiness-is-sent-as-ready-equals-1-before-the-request-loop" ..
            " *cmdline.notify-socket-is-the-only-environment-variable-consulted",
    },
    function(t)
        local sock = "/run/pt-notify.sock"
        vm:run("rm -f " .. sock)

        -- A pathname (not abstract) AF_UNIX datagram socket: an abstract
        -- bind would install a restrictive socket SD that could deny
        -- loregd's connect before readiness is even reached.
        local fd, e = unixsock.socket(vm, unixsock.AF_UNIX, unixsock.SOCK.DGRAM)
        t:assert(fd, "notify socket: " .. unixsock.errname(e or 0))
        local br = unixsock.bind(vm, fd, sock)
        t:assert_eq(br.ret, 0, "bind the notify socket: " .. unixsock.errname(br.errno or 0))

        -- Start loregd with NOTIFY_SOCKET set alongside decoy variables.
        -- The decoys carry no behaviour: only NOTIFY_SOCKET is consulted,
        -- and it is what drives the readiness datagram below.
        local proc = start_env(t, { "Ready=" .. MOUNT .. "/ready.hive" }, "Ready", {
            NOTIFY_SOCKET = sock,
            LOREGD_CONFIG = "/nonexistent/decoy.conf",
            REGISTRY_BEHAVIOUR = "sabotage",
        })

        -- Readiness is emitted after registration and before serving, so
        -- by the time `reg ls Ready` succeeded the datagram is already
        -- queued on our socket. Drain it (non-blocking, with a short
        -- poll) and check the payload.
        local got
        local ok = pcall(wait_until, function()
            local r = vm:syscall(unixsock.NR.recvfrom, {
                args = { fd, 0, 64, unixsock.MSG.DONTWAIT, 0, 0 },
                bufs = { string.rep("\0", 64) }, ptrs = { 1 },
            })
            if r.ret and r.ret > 0 then
                got = r.out_bufs[1]:sub(1, r.ret)
                return true
            end
            return false
        end, { timeout = 10, interval = 0.25, desc = "the READY=1 datagram" })

        if not ok then
            proc:kill("kill")
            local w = proc:wait("5s")
            t:assert(false, "no readiness datagram arrived on NOTIFY_SOCKET. " ..
                "loregd stderr=" .. tostring(w.stderr))
        end
        t:assert_contains(got, "READY=1",
            "loregd connected to NOTIFY_SOCKET and sent the readiness datagram")
        proc:kill("kill")
    end)

-- "loregd writes ordinary progress to standard output and faults to
--  standard error."
test("progress goes to standard output and faults to standard error",
    { spec = "loregd *cmdline.progress-goes-to-standard-output-and-faults-to-standard-error" },
    function(t)
        -- Good boot: the progress lines (registered N hive(s), entering
        -- request loop) go to stdout. Kill it once serving to read the
        -- captured streams.
        local proc = loregd.start(vm, t, {
            hives = { "Progress=" .. MOUNT .. "/progress.hive" }, wait_for = "Progress" })
        proc:kill("kill")
        local ok = proc:wait("5s")
        t:assert_contains(ok.stdout, "registered",
            "ordinary startup progress is written to stdout")
        t:assert(not ok.stdout:find("argument error"),
            "no fault text appears on stdout on a good boot")

        -- Bad boot: the fault (an argument error) goes to stderr, and
        -- nothing of it leaks to stdout.
        local bad = loregd.spawn(vm, { "NoEquals" }):wait("10s")
        t:assert(bad.exit_code ~= 0, "the bad invocation failed")
        t:assert(#bad.stderr > 0 and bad.stderr:find("[Aa]rgument"),
            "the fault is written to stderr: " .. tostring(bad.stderr))
        t:assert(not bad.stdout:find("[Aa]rgument"),
            "the fault does not appear on stdout")
    end)
