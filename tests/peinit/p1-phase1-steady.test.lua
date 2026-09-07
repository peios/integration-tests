-- Peinit TRM §2.3 — Phase 1, the parts of it a completed boot still
-- carries: the descriptors it stamped, the clock it set, the identifier
-- it wrote, the registry structure it ensured.
--
-- phase1.test.lua covers the other half of the chapter's steady state.
-- This file is the claims that need either a second reading to compare
-- against (a device node against the /dev it was carved out of, a
-- devpts inode against the tmpfs beside it) or something outside the
-- guest to check against (the host's clock).
--
-- Nothing is staged. That matters twice over: the image ships no random
-- seed and no machine ID, so this is the boot in which peinit takes the
-- absent-seed and generate-an-identifier paths, and a staged file would
-- put a `pt-stage` line in the console every assertion below would then
-- have to reason around.

local peinit = require("helpers.peinit")
peinit.claim(1)

local vm = peinit.boot({ name = "p1-steady" })

--- `sd show` output, as owner, group and the DACL's ACE lines.
local function descriptor(path)
    local shown = vm:run("sd show " .. path)
    shown:assert_ok()
    local out = { aces = {}, raw = shown.stdout }
    for _, line in ipairs(peinit.lines(shown.stdout)) do
        out.owner = line:match("^%s*Owner:%s+(.-)%s*$") or out.owner
        out.group = line:match("^%s*Group:%s+(.-)%s*$") or out.group
        local ace = line:match("^%s*%[%d+%]%s+(.-)%s*$")
        if ace then out.aces[#out.aces + 1] = ace end
    end
    return out
end

local function ace_for(sd, sid)
    for _, ace in ipairs(sd.aces) do
        if ace:find(sid, 1, true) then return ace end
    end
end

local function pid_of(service)
    for _ = 1, 40 do
        local pid = vm:run("svctl status " .. service).stdout:match("pid: (%d+)")
        if pid then return pid end
        vm:run("sleep 1")
    end
    error(service .. " never reported a pid")
end

test("devpts carries a synthesised descriptor, and a slave the kernel materialises gets it too",
    { spec = "peinit *phase1.devpts-gets-a-synthesise-ephemeral-policy" },
    function(t)
        -- devpts cannot store a descriptor, and its slaves appear
        -- without passing through any create path — so under the default
        -- DENY_MISSING every pseudo-terminal on the machine would be
        -- unopenable. The mount policy is what stands in: SYSTEM and
        -- Administrators full control, Authenticated Users read, write
        -- and traverse.
        local mount = descriptor("/dev/pts")
        t:assert(ace_for(mount, "S-1-5-18"), "SYSTEM: " .. mount.raw)
        t:assert(ace_for(mount, "S-1-5-32-544"), "Administrators: " .. mount.raw)
        local authenticated = ace_for(mount, "S-1-5-11")
        t:assert(authenticated,
            "Authenticated Users, which no other Phase 1 descriptor names: " .. mount.raw)
        t:assert(authenticated:find("r", 1, true),
            "with read among their rights: " .. authenticated)

        -- The ephemeral half. Opening /dev/ptmx makes the kernel
        -- materialise a slave inode that has never been through a
        -- create path and can hold no descriptor of its own; the shell
        -- holds the master open for the length of the command, so the
        -- slave exists to be read. What comes back is the template.
        local slave = vm:run(
            "sh -c 'exec 3<>/dev/ptmx; ls /dev/pts; sd show /dev/pts/0'")
        slave:assert_ok()
        t:assert(slave.stdout:find("S%-1%-5%-11"),
            "a freshly materialised slave carries the same synthesised template: "
                .. slave.stdout)
        t:assert(slave.stdout:find("S%-1%-5%-18") and slave.stdout:find("S%-1%-5%-32%-544"),
            "including SYSTEM and Administrators")

        -- And the template is devpts's own rather than Phase 1's
        -- general seed: the tmpfs mounted in the same step grants
        -- Everyone, not Authenticated Users.
        local shm = descriptor("/dev/shm")
        t:assert(not ace_for(shm, "S-1-5-11"),
            "/dev/shm names no Authenticated Users ACE: " .. shm.raw)
    end)

test("a stamped device node keeps the owner and group the seed gave it",
    { spec = "peinit *phase1.device-node-stamping-replaces-only-the-dacl" },
    function(t)
        -- The descriptor peinit applies to a node names a DACL and
        -- nothing else, and it is applied as a DACL-only replacement —
        -- so what the initramfs's seed put on the node's owner and group
        -- is still there afterwards, and only the ACEs moved.
        local dev, null = descriptor("/dev"), descriptor("/dev/null")
        t:assert(null.owner and null.owner ~= "",
            "/dev/null still has an owner: " .. null.raw)
        t:assert_eq(null.owner, dev.owner,
            "and it is the one the seed left on /dev")
        t:assert_eq(null.group, dev.group, "as is the group")

        -- The DACL, meanwhile, is not the inherited one: it grants
        -- Everyone read and write, which /dev deliberately does not, and
        -- it carries no inheritance flags because a device node has no
        -- children.
        local everyone = ace_for(null, "S-1-1-0")
        t:assert(everyone, "/dev/null grants Everyone: " .. null.raw)
        t:assert(not everyone:find("CI", 1, true) and not everyone:find("OI", 1, true),
            "with no inheritance flags: " .. everyone)
        t:assert(not ace_for(dev, "S-1-1-0"),
            "while /dev itself grants Everyone nothing: " .. dev.raw)
    end)

test("an image that ships no random seed boots with nothing said about it",
    { spec = "peinit *phase1.an-absent-random-seed-is-silent" },
    function(t)
        -- A live image ships no entropy cache on purpose — one baked
        -- into an image would hand every instance of it the same
        -- starting entropy — so this boot is the ordinary first-boot
        -- case, and the documented response to it is silence.
        local seed = vm:run("stat -c %F /var/state/peinit/random-seed")
        t:assert(not seed:ok(), "the image ships no seed: " .. seed.stdout)

        local log = vm:console():read_log()
        t:assert(not log:find("restored random seed", 1, true),
            "peinit did not claim to restore one")
        t:assert(not log:find("random seed restore failed", 1, true),
            "and did not warn about one either")
        t:assert(log:find("peinit: phase2 boot complete", 1, true),
            "while the boot went on regardless")
    end)

test("the generated machine ID arrives whole, with no temporary file left beside it",
    { spec = "peinit *phase1.a-new-machine-id-is-written-atomically" },
    function(t)
        -- Written through a temporary file and a rename: what a reader
        -- can see afterwards is that the rename happened — the
        -- identifier is complete and valid, and the temporary it was
        -- written through is gone. A half-written machine-id is what the
        -- rename exists to make unobservable, so its absence is the
        -- claim's whole visible surface.
        local id = vm:read_file("/lcl/etc/machine-id")
        t:assert_eq(#id, 33, "the file is complete: " .. #id .. " bytes")
        t:assert(id:match("^[0-9a-f]+\n$"), "and valid: " .. id)

        for _, name in ipairs(peinit.lines(vm:run("ls -a /lcl/etc").stdout)) do
            t:assert(name == "." or name == ".." or name == "machine-id",
                "nothing but the identifier is in /lcl/etc, found: " .. name)
        end
    end)

test("the clock is set from the hardware RTC, read as UTC, through the fallback device",
    {
        spec = {
            "peinit *phase1.the-clock-is-set-from-the-rtc",
            "peinit *phase1.rtc-falls-back-to-rtc0",
            "peinit *phase1.the-rtc-is-read-as-utc",
        },
    },
    function(t)
        -- This guest has no /dev/rtc — devtmpfs creates rtc0 and nothing
        -- makes the alias — so every boot of this profile takes the
        -- fallback, and a clock that is right is the proof that it
        -- worked. A peinit that opened only /dev/rtc would be in
        -- recovery instead (see p1-recovery.test.lua, which removes rtc0
        -- as well and gets exactly that).
        local primary = vm:run("stat -c %F /dev/rtc")
        t:assert(not primary:ok(), "/dev/rtc is absent: " .. primary.stdout)
        local fallback = vm:run("stat -c %F /dev/rtc0")
        fallback:assert_ok()
        t:assert(fallback.stdout:find("character"), "/dev/rtc0 is the device: " .. fallback.stdout)

        -- The RTC holds UTC and peinit converts it as UTC, so the
        -- guest's CLOCK_REALTIME is the host's. Read the host's clock on
        -- both sides of the guest's to bound the comparison by the round
        -- trip rather than by a guess.
        local before = os.time()
        local guest = tonumber(vm:run("date '+%s'").stdout:match("%d+"))
        local after = os.time()
        t:assert(guest, "the guest reported a clock")
        -- 5 seconds of slack for the round trip. Anything larger is not
        -- drift: an RTC read as anything but UTC lands a whole timezone
        -- offset away, and an unset clock lands in 1970.
        t:assert(guest > before - 5 and guest < after + 5,
            "the guest's clock is the host's UTC clock: guest " .. guest ..
                " against " .. before .. ".." .. after)
    end)

test("registryd is started the way any service is, and kept as one",
    { spec = "peinit *phase1.registryd-is-started-like-any-service" },
    function(t)
        -- The compiled-in definition is the only thing about registryd's
        -- start that is special. Everything the start does is the
        -- ordinary machinery: a minted SYSTEM token carrying the
        -- service's own SID, a cgroup in the same tree under the same
        -- naming, and a service instance svctl can see.
        local registryd, eventd = pid_of("registryd"), pid_of("eventd")
        t:assert_eq(vm:read_file("/proc/" .. registryd .. "/cgroup"):gsub("%s+$", ""),
            "0::/peinit/registryd/main",
            "registryd sits in the service cgroup tree")
        t:assert_eq(vm:read_file("/proc/" .. eventd .. "/cgroup"):gsub("%s+$", ""),
            "0::/peinit/eventd/main",
            "under the same naming as a Phase 2 service")

        local shown = vm:run("token show --pid " .. registryd .. " --raw --all")
        shown:assert_ok()
        t:assert(shown.stdout:find("user%s+S%-1%-5%-18"), "on a SYSTEM token: " .. shown.stdout)
        -- registryd's per-service SID, derived from its name by §4.4's
        -- rule exactly as it is for every other service, and the Service
        -- group every service token carries.
        t:assert(shown.stdout:find(
            "S%-1%-5%-80%-3593071732%-1666014828%-967506459%-673618303%-1085857884"),
            "carrying its own per-service SID: " .. shown.stdout)
        t:assert(shown.stdout:find("S%-1%-5%-6"), "and the Service group")

        local status = vm:run("svctl status registryd")
        status:assert_ok()
        t:assert(status.stdout:find("identity: SYSTEM", 1, true),
            "and svctl reports it as an ordinary SYSTEM service: " .. status.stdout)
    end)

test("the base registry structure is created before the schema version is read back",
    {
        spec = {
            "peinit *phase1.the-schema-version-guard",
            "peinit *phase1.the-base-registry-structure-is-ensured-then-probed",
        },
    },
    function(t)
        -- The hives on this machine were created by registryd minutes
        -- ago and held nothing but their root key, so every key below is
        -- one peinit ensured. Machine\System\Init is the clearest of the
        -- three: nothing else on the system writes it, and the image's
        -- seeds do not name it.
        local keys = vm:run([[reg ls 'Machine\System' --keys-only]])
        keys:assert_ok()
        local present = {}
        for _, line in ipairs(peinit.lines(keys.stdout)) do
            present[(line:gsub("/%s*$", ""):gsub("%s+", ""))] = true
        end
        t:assert(present.Services, "Machine\\System\\Services exists: " .. keys.stdout)
        t:assert(present.Init, "and so does Machine\\System\\Init")

        -- Then the read that verifies registryd is genuinely serving.
        -- Ensuring came first, which is why there is a value here to
        -- read at all; a DWORD of the current schema version is what
        -- passes the probe.
        local probe = vm:run([[reg get 'Machine\System\Services' SchemaVersion --json]])
        probe:assert_ok()
        t:assert(probe.stdout:find('"type":"dword"', 1, true)
            or probe.stdout:find('"type": "dword"', 1, true),
            "SchemaVersion is a REG_DWORD: " .. probe.stdout)
        t:assert(probe.stdout:find("1", 1, true),
            "of the current schema version: " .. probe.stdout)

        -- And the probe passing is what let the boot continue past it.
        local log = vm:console():read_log()
        t:assert(log:find("peinit: phase1 registryd started", 1, true)
            and log:find("peinit: phase2 boot starting", 1, true),
            "the boot went on to Phase 2")
    end)
