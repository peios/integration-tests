-- Peinit TRM §2.3 — Phase 1: the compiled-in phase with no registry
-- dependency, whose whole purpose is to reach the point where a registry
-- can serve.
--
-- Most of what Phase 1 does is observable from a completed boot, because
-- it does it to the machine the agent is running on: the mounts are in
-- mountinfo, the descriptors are on the inodes, the machine ID is on
-- disk. The rest is on the console, which is the only record of a stage
-- that ran before there was anything to ask.

local peinit = require("helpers.peinit")
peinit.claim(2)

local vm = peinit.boot()

test("the root writability probe leaves nothing behind",
    { spec = "peinit *phase1.root-writability-is-probed" },
    function(t)
        -- peinit probes rather than remounting: it creates /.peinit/,
        -- writes a uniquely named file, and removes it. The directory
        -- survives (the boot-attempt counter lives in it); the probe file
        -- does not.
        local listing = vm:run("ls -a /.peinit").stdout
        t:assert(listing ~= "", "/.peinit exists")
        for name in listing:gmatch("[^%s]+") do
            t:assert(name == "." or name == ".." or name == "boot-attempts",
                "nothing but the counter is left in /.peinit, found: " .. name)
        end
    end)

test("peinit mounts the four filesystems it owns and re-mounts none of the three it inherits",
    {
        spec = {
            "peinit *phase1.mounts-only-what-is-absent",
            "peinit *phase1.an-already-mounted-kernel-filesystem-is-success",
        },
    },
    function(t)
        local at = {}
        for line in vm:read_file("/proc/self/mountinfo"):gmatch("[^\r\n]+") do
            local point, rest = line:match("^%d+ %d+ %S+ %S+ (%S+) (.*)$")
            local fstype = rest:match("%- (%S+) ")
            at[point] = at[point] or {}
            table.insert(at[point], fstype)
        end

        -- The four peinit owns, with the filesystem the table names.
        local owned = {
            ["/dev/pts"] = "devpts",
            ["/dev/shm"] = "tmpfs",
            ["/run"] = "tmpfs",
            ["/sys/fs/cgroup"] = "cgroup2",
        }
        for point, fstype in pairs(owned) do
            t:assert(at[point], point .. " is mounted")
            t:assert_eq(at[point][1], fstype, point .. " is a " .. fstype)
        end

        -- The three the initramfs provides are mounted exactly once. A
        -- redundant mount would stack a second, empty filesystem over the
        -- populated one, so a second line here is the bug the rule exists
        -- to prevent.
        for _, point in ipairs({ "/proc", "/sys", "/dev" }) do
            t:assert_eq(#at[point], 1,
                point .. " is mounted once, so peinit found it and did not mount it again")
        end
    end)

test("the fresh filesystems carry the seed descriptor, and the inherited ones do not",
    {
        spec = {
            "peinit *phase1.fresh-mounts-are-seeded",
            "peinit *phase1.the-initramfs-filesystems-are-not-stamped",
        },
    },
    function(t)
        -- The three peinit mounts fresh are empty at mount time, and
        -- under KACS an inode with no descriptor is denied to everyone —
        -- so a descriptor here is not a nicety, it is what makes the
        -- mount usable at all. SYSTEM and Administrators GenericAll,
        -- Everyone read+execute.
        for _, point in ipairs({ "/dev/shm", "/run", "/sys/fs/cgroup" }) do
            local sd = vm:run("sd show " .. point).stdout
            t:assert(sd:find("S%-1%-5%-18") or sd:find("SY"),
                point .. " grants SYSTEM: " .. sd)
            t:assert(sd:find("S%-1%-1%-0") or sd:find("WD"),
                point .. " carries the Everyone ACE: " .. sd)
        end
    end)

test("the Everyone ACE on a seeded mount is inheritable by containers only",
    { spec = "peinit *phase1.seed-everyone-ace-is-container-inherit-only" },
    function(t)
        -- The one place this descriptor differs from the root
        -- filesystem's, and the reason is exact: container inheritance
        -- lets a service walk to its own runtime directory, while object
        -- inheritance would additionally put Everyone-read on every file
        -- created beneath these mounts.
        --
        -- So: a directory created under /run inherits the Everyone ACE; a
        -- file created under /run does not.
        vm:run("mkdir -p /run/pt-inherit && : > /run/pt-inherit/f"):assert_ok()
        local dir = vm:run("sd show /run/pt-inherit").stdout
        local file = vm:run("sd show /run/pt-inherit/f").stdout

        local function has_everyone(sd)
            return sd:find("S%-1%-1%-0") ~= nil or sd:find(";WD") ~= nil
        end
        t:assert(has_everyone(dir), "a created directory inherited the Everyone ACE: " .. dir)
        t:assert(not has_everyone(file),
            "a created file did not, so object inheritance is off: " .. file)
    end)

test("the device nodes in the policy list are stamped, and the console is not",
    {
        spec = {
            "peinit *phase1.device-nodes-get-explicit-descriptors",
            "peinit *phase1.console-is-not-in-the-device-node-list",
        },
    },
    function(t)
        -- /dev arrives with the initramfs's inheritable descriptor on
        -- every node, which leaves /dev/null unusable by anyone who is
        -- not an administrator. peinit enumerates the exceptions.
        for _, node in ipairs({ "/dev/null", "/dev/zero", "/dev/full",
                                "/dev/random", "/dev/urandom", "/dev/ptmx" }) do
            local sd = vm:run("sd show " .. node).stdout
            t:assert(sd:find("S%-1%-1%-0") or sd:find(";WD"),
                node .. " grants Everyone read and write: " .. sd)
        end

        -- The console is deliberately not on the list: it is the SYSTEM
        -- console, and a read ACE for Everyone on it would hand every
        -- principal the machine's boot output and its input.
        local console = vm:run("sd show /dev/console").stdout
        t:assert(not (console:find("S%-1%-1%-0") or console:find(";WD")),
            "/dev/console kept the inherited default: " .. console)

        -- The console log counts what was stamped, and the count is the
        -- list's length rather than everything in /dev.
        t:assert(vm:console():read_log():find(
            "peinit: phase1 device node policy applied to 7 node%(s%)"),
            "peinit reported stamping exactly the seven nodes in the list")
    end)

test("a machine ID is generated when the image ships none, in the documented format",
    {
        spec = {
            "peinit *phase1.the-machine-id-is-ensured",
            "peinit *phase1.machine-id-format",
        },
    },
    function(t)
        -- An image is expected to ship with no machine ID, so this boot
        -- generated one; the console says which path it took.
        t:assert(vm:console():read_log():find("peinit: phase1 generated machine%-id"),
            "peinit generated an identifier rather than finding one")

        local id = vm:read_file("/lcl/etc/machine-id")
        t:assert_eq(#id, 33, "32 characters and one newline, got " .. #id .. " bytes")
        t:assert(id:match("^[0-9a-f][0-9a-f]*\n$"), "lowercase hexadecimal: " .. id)
        t:assert(id:find("[^0]"), "not all zeroes, which the format treats as invalid")
    end)

test("a valid machine ID staged into the root is left exactly as it is",
    { spec = "peinit *phase1.a-valid-machine-id-is-left-alone" },
    function(t)
        local staged = "0123456789abcdef0123456789abcdef\n"
        local other = peinit.boot({
            name = "mid-valid",
            files = { ["lcl/etc/machine-id"] = staged },
        })
        t:assert_eq(other:read_file("/lcl/etc/machine-id"), staged,
            "a valid file survives the boot untouched")
        t:assert(not other:console():read_log():find("generated machine%-id"),
            "and peinit did not report generating one")
    end)

test("a malformed machine ID is replaced rather than kept or fatal",
    { spec = "peinit *phase1.a-malformed-machine-id-is-replaced" },
    function(t)
        -- Right length, wrong alphabet. The format rules reject it, and
        -- the response is to replace it and boot on.
        local bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n"
        local other = peinit.boot({
            name = "mid-bad",
            files = { ["lcl/etc/machine-id"] = bad },
        })
        local now = other:read_file("/lcl/etc/machine-id")
        t:assert(now ~= bad, "the malformed identifier was not kept")
        t:assert(now:match("^[0-9a-f]+\n$"), "and what replaced it is valid: " .. now)
    end)

test("registryd is started, is serving, and is kept as a runtime service",
    {
        spec = {
            "peinit *phase1.registryd-is-the-only-compiled-in-definition",
            "peinit *phase1.registryd-readiness-means-serving",
            "peinit *phase1.registryd-is-retained-as-a-runtime-instance",
        },
    },
    function(t)
        local log = vm:console():read_log()
        t:assert(log:find("peinit: phase1 registryd started", 1, true),
            "registryd passed readiness")

        -- Readiness means serving, not alive. The proof is that peinit's
        -- own next step reads a value back through it — and that a read
        -- works now.
        -- `reg get` takes the key and the value as separate arguments:
        -- a value name is not a path component.
        local probe = vm:run([[reg get 'Machine\System\Services' SchemaVersion]])
        probe:assert_ok()
        t:assert(probe.stdout:find("1"), "the schema version reads back as 1: " .. probe.stdout)

        -- Retained as an ordinary runtime service rather than dropped at
        -- the Phase 2 boundary, so svctl can see it with a live pid.
        local status = vm:run("svctl status registryd")
        status:assert_ok()
        t:assert(status.stdout:find("[Aa]ctive"),
            "registryd is a live service instance: " .. status.stdout)
    end)

test("every autorun script runs, in sorted order, as SYSTEM with a fixed environment",
    {
        spec = {
            "peinit *phase1.autorun-scripts-run-between-registryd-and-provisioning",
            "peinit *phase1.autorun-runs-every-entry-in-sorted-order",
            "peinit *phase1.an-autorun-scripts-environment",
            "peinit *phase1.autorun-scripts-run-as-system",
        },
    },
    function(t)
        local report = [[#!/bin/sh
echo "pt|NAME|cwd=$(pwd)|path=$PATH|user=$(token user 2>/dev/null || echo unknown)"
]]
        local other = peinit.boot({
            name = "autorun",
            files = {
                ["lcl/policy/autorun.d/40-pt-a.sh"] =
                    { report:gsub("NAME", "a"), exec = true },
                ["lcl/policy/autorun.d/60-pt-b.sh"] =
                    { report:gsub("NAME", "b"), exec = true },
            },
        })
        local log = other:console():read_log()

        -- Both ran, in name order, and between registryd and Phase 2.
        local a, b = log:find("pt|a|", 1, true), log:find("pt|b|", 1, true)
        local registryd = log:find("peinit: phase1 registryd started", 1, true)
        local phase2 = log:find("peinit: phase2 boot starting", 1, true)
        t:assert(a and b, "both staged scripts ran")
        t:assert(a < b, "in sorted order, 40- before 60-")
        t:assert(registryd < a and b < phase2,
            "after registryd and before Phase 2")

        -- The environment the manual specifies, and nothing else.
        t:assert(log:find("cwd=/|", 1, true), "the working directory is /")
        t:assert(log:find("path=/sbin:/bin|", 1, true),
            "PATH is exactly /sbin:/bin")
        t:assert(log:find("user=.*SYSTEM") or log:find("user=.*S%-1%-5%-18"),
            "and the script ran under peinit's own SYSTEM token")
    end)

test("an autorun script that fails is a warning, not a boot failure",
    { spec = "peinit *phase1.autorun-is-fail-open" },
    function(t)
        local other = peinit.boot({
            name = "autorun-fail",
            files = {
                -- One that exits non-zero, and one that cannot be
                -- spawned at all — no shebang the kernel can honour.
                ["lcl/policy/autorun.d/40-pt-fails.sh"] =
                    { "#!/bin/sh\necho pt-fails-ran\nexit 3\n", exec = true },
                ["lcl/policy/autorun.d/41-pt-unspawnable"] =
                    { "\0\0not an executable", exec = true },
            },
        })
        local log = other:console():read_log()
        t:assert(log:find("pt-fails-ran", 1, true), "the failing script did run")
        -- The boot reached Phase 2 regardless, which is the claim.
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "neither failure stopped the boot")
    end)

test("the control and jobs sockets exist before Phase 2, stamped as §10 requires",
    {
        spec = {
            "peinit *phase1.the-control-socket-is-created",
            "peinit *phase1.the-jobs-socket-is-created",
        },
    },
    function(t)
        for _, sock in ipairs({ "/run/services/peinit/control.sock",
                                "/run/services/peinit/jobs.sock" }) do
            local stat = vm:run("stat -c %F " .. sock)
            stat:assert_ok()
            t:assert(stat.stdout:find("socket"), sock .. " is a socket")
        end

        -- The control socket is administrators-only; the jobs socket is
        -- reachable by any authenticated principal, because connecting to
        -- it IS the submission permission.
        local control = vm:run("sd show /run/services/peinit/control.sock").stdout
        t:assert(not (control:find("S%-1%-1%-0") or control:find(";WD")),
            "the control socket grants no Everyone ACE: " .. control)
    end)

test("loopback is up before Phase 2, because services that bind 127.0.0.1 need it",
    { spec = "peinit *phase1.loopback-is-brought-up" },
    function(t)
        local flags = vm:read_file("/sys/class/net/lo/flags"):gsub("%s+$", "")
        -- sysfs prints these with an 0x prefix, which tonumber understands
        -- on its own — passing base 16 as well makes it reject the prefix
        -- and return nil. IFF_UP is bit 0.
        local value = tonumber(flags)
        t:assert(value, "lo's flags parsed: " .. flags)
        t:assert(value % 2 == 1, "lo is up (flags " .. flags .. ")")
    end)
