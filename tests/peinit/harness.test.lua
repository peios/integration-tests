-- The staging lever itself, asserted directly so that a failure in it is
-- diagnosed here rather than as a puzzling failure somewhere downstream.
--
-- Every test in this testset that varies what peinit is handed goes
-- through `pt-stage.sh`: files injected into the initramfs, copied into
-- the mounted root before prelude chroots. That hook is the suite's own
-- machinery rather than the system under test, and it has already been
-- wrong once in a way that took three agents to find — it reduced the
-- root's descriptor and killed every non-SYSTEM service on any boot that
-- staged anything (PEI-800). These tests are what would have caught it.

local peinit = require("helpers.peinit")

test("staging a file does not disturb the root's own descriptor", {}, function(t)
    -- The trap: `cp -a src/. dst/` copies the SOURCE DIRECTORY's
    -- attributes onto the destination, and a security descriptor is an
    -- extended attribute. Staging must merge into `/` without touching
    -- what live-boot stamped on it.
    local stock = peinit.boot({ name = "sd-stock" })
    local staged = peinit.boot({
        name = "sd-staged",
        files = { ["lcl/pt-harness-marker"] = "present\n" },
    })

    t:assert_eq(staged:read_file("/lcl/pt-harness-marker"), "present\n",
        "the staged file arrived")

    local a = stock:run("sd show --sddl /").stdout
    local b = staged:run("sd show --sddl /").stdout
    t:assert_eq(b, a,
        "a boot that staged a file has the same root descriptor as one that did not")

    -- And the consequence that made the old bug visible: the Everyone
    -- read+execute ACE survives, so a non-SYSTEM principal can still
    -- traverse into `/`. Execute IS traverse on Peios, and an explicit
    -- chdir gets no SeChangeNotifyPrivilege bypass.
    t:assert(b:find("WD", 1, true), "the Everyone ACE is still on /: " .. b)
end)

test("the image's own non-SYSTEM services still start on a boot that staged files", {},
    function(t)
        -- The observable form of the same claim, and the one that
        -- actually bit: with the root's Everyone ACE gone, every service
        -- whose identity is not SYSTEM died in pre-exec with EACCES on
        -- chdir("/"). resolvd and trustd are two the image ships.
        local staged = peinit.boot({
            name = "sd-services",
            files = { ["lcl/pt-harness-marker"] = "present\n" },
        })
        -- Services start after Phase 2 completes, which is what
        -- peinit.boot waits for — so wait for the service itself rather
        -- than reading the log at the moment the boot returned.
        staged:console():expect("peinit: service resolvd started", peinit.STAGE_TIMEOUT)

        local log = staged:console():read_log()
        t:assert(not log:find("set%-working%-directory failed"),
            "no service failed its pre-exec chdir")

        local started = {}
        for _, name in ipairs(peinit.started_services(log)) do started[name] = true end
        t:assert(started["resolvd"], "resolvd, which runs as LocalService, started")
    end)

test("a staged directory merges into an existing one rather than replacing it", {},
    function(t)
        -- /lcl/policy/autorun.d already exists and holds the image's own
        -- two scripts. Staging a third has to leave those alone — the
        -- whole autorun chapter depends on it, since the agent this test
        -- is talking to is started by one of them.
        local staged = peinit.boot({
            name = "sd-merge",
            files = {
                ["lcl/policy/autorun.d/90-pt-merge.sh"] =
                    { "#!/bin/sh\necho pt-merge-ran\n", exec = true },
            },
        })
        local log = staged:console():read_log()
        t:assert(log:find("pt-merge-ran", 1, true), "the staged script ran")
        t:assert(log:find("10%-apply%-seeds%.sh"),
            "and the image's own seed-apply script survived the merge")
        t:assert(log:find("peinit: ran 3 autorun script%(s%)"),
            "three scripts, not one: the directory merged rather than being replaced")
    end)

test("a staged file arrives executable when the test asks for it", {}, function(t)
    -- Under KACS the execute bit is the intrinsic "this is executable"
    -- flag rather than an advisory permission, so it has to survive the
    -- cpio, the kernel's unpack, and the hook's copy. peinit spawns an
    -- autorun by direct exec, so a script that lost it is one peinit
    -- refuses to run — silently, as far as a test can see.
    local staged = peinit.boot({
        name = "sd-exec",
        files = {
            ["lcl/pt-exec-yes"] = { "#!/bin/sh\n", exec = true },
            ["lcl/pt-exec-no"] = "data\n",
        },
    })
    -- `stat` rather than `test -x`: the mode is the thing being
    -- asserted, and a printed mode says what went wrong when it fails.
    local modes = staged:run("stat -c '%a %n' /lcl/pt-exec-yes /lcl/pt-exec-no")
    modes:assert_ok()
    local yes = modes.stdout:match("(%d+) /lcl/pt%-exec%-yes")
    local no = modes.stdout:match("(%d+) /lcl/pt%-exec%-no")
    t:assert(tonumber(yes, 8) % 2 == 1,
        "exec = true arrived executable, mode " .. tostring(yes))
    t:assert(tonumber(no, 8) % 2 == 0,
        "and a plain file did not, mode " .. tostring(no))
end)
