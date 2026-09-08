-- peinit TRM §3.2–§3.6 — every rule about what a service definition may
-- say, asked of a running peinit one definition at a time.
--
-- The chapter states dozens of rules of the same shape: this value is a
-- decode error, that one is not. They are all decided in one place --
-- `build_service_definition_from_registry_values` -- which both the
-- Phase 2 read and reload-config go through, so one probe answers for
-- both readers.
--
-- The probe is reload-config rather than a boot, for two reasons. The
-- cheap one is that a boot per rule would be a hundred and fifty boots.
-- The load-bearing one is that the boot reader is currently broken for
-- exactly this input: an undecodable key takes the whole machine to the
-- recovery console instead of failing that one service (PEI-812, and
-- `phase2.test.lua` records it), so a boot cannot be used to ask what a
-- *particular* definition does. reload-config is the reader that works,
-- and it is also sharper: it distinguishes the two ways a definition can
-- be refused.
--
--   accepted    the read succeeded and the service is in the model
--   decode      the read was refused with INTERNAL_ERROR -- the key
--               would not decode, so the whole transaction aborted
--   validation  the read was refused with INVALID_STATE and a finding --
--               the definition decoded, and the *graph* rejected it
--
-- That third outcome is what makes `Requires = ["pt bad"]` (a decode
-- error, §3.3) distinguishable from `Requires = ["pt-nonexistent"]` (a
-- legal name caught later at graph validation), which is the exact
-- distinction §3.3 draws and which a bare pass/fail could not see.
--
-- One key, `pt-probe`, is rewritten for every probe: deleted, written in
-- a single `reg apply` transaction, and re-read. Nothing else in the
-- registry changes between probes, so the outcome is attributable to the
-- values under test and to nothing else.

local peinit = require("helpers.peinit")
peinit.claim(2) -- the probe machine, plus one boot of its own at the end

local PROBE = [[Machine\System\Services\pt-probe]]

local vm = peinit.boot({
    name = "decode",
    files = peinit.seed("pt-decode", {
        { path = [[Machine\System]] },
        { path = [[Machine\System\Services]] },
        -- A running service, so that "a refused reload changes nothing"
        -- has something to be true of.
        { path = [[Machine\System\Services\pt-resident]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/sleep" },
            { name = "Arguments", type = "multi", data = { "100000" } },
            { name = "Identity", type = "sz", data = "SYSTEM" },
            { name = "Readiness", type = "dword", data = 1 },
            { name = "RestartPolicy", type = "dword", data = 0 },
            { name = "Triggers", type = "multi", data = { "boot" } },
        } },
        -- A demand-only service that exists purely to be named: a legal
        -- dependency target, and a key a `registry:` check can find.
        { path = [[Machine\System\Services\pt-ok]], values = {
            { name = "ImagePath", type = "sz", data = "/bin/true" },
            { name = "Type", type = "dword", data = 1 },
        } },
    }),
})

--- Rewrite `pt-probe` with `values` and make peinit re-read the whole
--- registry. Returns "accepted", "decode" or "validation", and the raw
--- reload result for a failure message.
---
--- The key is deleted first, so what peinit reads is exactly `values`
--- and never a merge with the previous probe. The write is one
--- transaction: built up value by value it would pass through
--- intermediate shapes, and peinit reloads on any watch event, so a
--- half-written definition would get a read of its own.
local function probe(values)
    local batch = peinit.encode_json({ keys = { { path = PROBE, values = values } } })
    vm:run("reg del '" .. PROBE .. "' --recursive >/dev/null 2>&1; " ..
        "cat > /tmp/pt-probe.json <<'PT_JSON_EOF'\n" .. batch .. "\nPT_JSON_EOF\n" ..
        "reg apply /tmp/pt-probe.json"):assert_ok()

    local reload = vm:run("svctl --json reload-config")
    if reload.exit_code == 0 then return "accepted", reload end
    local code = reload.stdout:match('"code":"([^"]+)"')
    if code == "INVALID_STATE" then return "validation", reload end
    return "decode", reload
end

--- The same, for a probe about the service *name* rather than about a
--- value. The key is cleaned up afterwards rather than by the next
--- probe, since every probe here uses a different name and a key left
--- undecodable would refuse every later reload in the file.
---
--- Returns nil when the registry itself would not take the name, which
--- is a different answer from peinit refusing it.
local function probe_named(name, values)
    local path = [[Machine\System\Services\]] .. name
    local batch = peinit.encode_json({ keys = { { path = path, values = values } } })
    local applied = vm:run("cat > /tmp/pt-named.json <<'PT_JSON_EOF'\n" .. batch ..
        "\nPT_JSON_EOF\nreg apply /tmp/pt-named.json")
    if applied.exit_code ~= 0 then return nil, applied end

    local reload = vm:run("svctl --json reload-config")
    local outcome = "decode"
    if reload.exit_code == 0 then
        outcome = "accepted"
    elseif reload.stdout:match('"code":"([^"]+)"') == "INVALID_STATE" then
        outcome = "validation"
    end
    return outcome, reload, path
end

--- Remove a key `probe_named` created and return the model to a clean
--- generation.
local function forget(path)
    vm:run("reg del '" .. path .. "' --recursive >/dev/null 2>&1; " ..
        "svctl --json reload-config")
end

--- `values` with an ImagePath in front, since every definition needs one
--- and almost no probe is about ImagePath.
local function with_image(values)
    local out = { { name = "ImagePath", type = "sz", data = "/bin/true" } }
    for _, value in ipairs(values) do out[#out + 1] = value end
    return out
end

--- One value, on an otherwise valid definition.
local function one(name, kind, data)
    return with_image({ { name = name, type = kind, data = data } })
end

--- Assert a set of probes, each `{label, values}`, all reach `expected`.
--- Reported together, so a run says which of thirty rules moved rather
--- than only the first.
local function expect_all(t, expected, cases)
    local wrong = {}
    for _, case in ipairs(cases) do
        local got, reload = probe(case[2])
        if got ~= expected then
            wrong[#wrong + 1] = case[1] .. " -> " .. got ..
                " (" .. (reload.stdout:gsub("%s+$", "")) .. ")"
        end
    end
    t:assert_eq(#wrong, 0,
        "expected `" .. expected .. "` from every case; these did not: " ..
        table.concat(wrong, " | "))
end

--- A definition that decodes is also one peinit has an entry for.
local function assert_in_model(t, why)
    local status = vm:run("svctl --json status pt-probe")
    t:assert(status.stdout:find('"state"', 1, true),
        why .. ": pt-probe is in the service table: " .. status.stdout)
end

-- The schema table of §3.2 and the registry type each row gives. The
-- wrong type to hand a field follows from it: a dword for anything that
-- is not a dword, and an sz for anything that is.
local SCHEMA = {
    { "ImagePath", "sz" }, { "Arguments", "multi" }, { "Type", "dword" },
    { "Triggers", "multi" }, { "Disabled", "dword" }, { "SafeMode", "dword" },
    { "Identity", "sz" }, { "RequiredPrivileges", "multi" }, { "Requires", "multi" },
    { "Wants", "multi" }, { "BindsTo", "multi" }, { "Conflicts", "multi" },
    { "Provides", "multi" }, { "OnFailure", "sz" }, { "ErrorControl", "dword" },
    { "RemainAfterExit", "dword" }, { "SuccessExitCodes", "multi" },
    { "ExecStartPre", "multi" }, { "ExecStartPost", "multi" },
    { "HookIdentity", "sz" }, { "ExecReload", "sz" },
    { "PreStartCheckTimeout", "dword" }, { "StartTimeout", "dword" },
    { "StopTimeout", "dword" }, { "WatchdogTimeout", "dword" },
    { "HealthCheck", "sz" }, { "HealthCheckInterval", "dword" },
    { "HealthCheckTimeout", "dword" }, { "HealthCheckRetries", "dword" },
    { "RestartPolicy", "dword" }, { "RestartMaxRetries", "dword" },
    { "RestartWindow", "dword" }, { "RestartDelay", "dword" },
    { "Readiness", "dword" }, { "NotifyAccess", "dword" }, { "FdStoreMax", "dword" },
    { "TimerPersistent", "dword" }, { "TimerJitter", "dword" },
    { "Environment", "multi" }, { "WorkingDirectory", "sz" }, { "TTYPath", "sz" },
    { "TTYPrecedence", "dword" }, { "RuntimeDirectories", "multi" },
    { "LimitNOFILE", "dword" }, { "LimitCORE", "dword" }, { "Conditions", "multi" },
    { "Asserts", "multi" }, { "DisplayName", "sz" }, { "Description", "sz" },
    { "ServiceSecurity", "binary" },
}

test("the key name is the service name",
    { spec = "peinit *svc.the-key-name-is-the-service-name" },
    function(t)
        -- Nothing in the definition says what the service is called. The
        -- name comes from the key it was found under, and it is the name
        -- every other interface then uses for it.
        local outcome, reload, path = probe_named("pt-named.by_key-1",
            { { name = "ImagePath", type = "sz", data = "/bin/true" } })
        t:assert_eq(outcome, "accepted", "the definition was read: " .. tostring(
            reload and reload.stdout))

        local status = vm:run("svctl --json status pt-named.by_key-1")
        status:assert_ok()
        t:assert(status.stdout:find('"service":"pt-named.by_key-1"', 1, true),
            "and peinit knows it by the key's own name: " .. status.stdout)
        forget(path)
    end)

test("a service name is 1 to 128 bytes of [A-Za-z0-9._-]",
    { spec = "peinit *svc.a-name-is-1-to-128-bytes-of-the-name-alphabet" },
    function(t)
        local image = { { name = "ImagePath", type = "sz", data = "/bin/true" } }

        -- Every byte of the alphabet, at both ends of the length range.
        local longest = string.rep("a", 128)
        for _, name in ipairs({ "x", "pt-Name_9.z", longest }) do
            local outcome, reload, path = probe_named(name, image)
            t:assert_eq(outcome, "accepted",
                "`" .. (#name > 32 and (#name .. " bytes of the alphabet") or name) ..
                "` is a legal name: " .. tostring(reload and reload.stdout))
            if path then forget(path) end
        end

        -- Any other byte makes it invalid. `/` and `:` are the two
        -- exclusions §3.1 calls deliberate; a space and a bang stand for
        -- everything else outside the set.
        local refused = {}
        for _, name in ipairs({ "pt bad", "pt!bad", "pt:bad", "pt/bad", "pt+bad" }) do
            local outcome, _, path = probe_named(name, image)
            -- A name the registry itself will not store says nothing
            -- about peinit, so it is reported rather than counted.
            if outcome ~= nil and outcome ~= "decode" then
                refused[#refused + 1] = name .. " -> " .. outcome
            end
            if path then forget(path) end
        end
        t:assert_eq(#refused, 0,
            "a byte outside [A-Za-z0-9._-] makes the name invalid; these were " ..
            "read anyway: " .. table.concat(refused, ", "))

        -- And 129 bytes is one too many.
        local outcome, _, path = probe_named(string.rep("a", 129), image)
        if outcome == nil then
            t:assert(false, "the registry would not store a 129-byte key name, so " ..
                "the length bound cannot be asked of peinit from here")
        else
            t:assert_eq(outcome, "decode", "129 bytes is past the bound")
        end
        if path then forget(path) end
    end)

test("every value name in the schema table is a field peinit knows, typed as the table says",
    {
        spec = {
            "peinit *schema.the-field-table",
            "peinit *schema.a-type-mismatch-is-a-decode-error",
        },
    },
    function(t)
        -- Written backwards on purpose. Handing a field the wrong
        -- registry type is a decode error only if peinit knows the
        -- field; an unknown value name is ignored, so the definition
        -- would decode and the probe would be accepted. So "accepted"
        -- here means a name the schema table claims and peinit has never
        -- heard of, and a positive test using valid values could not
        -- have told the two apart.
        local cases = {}
        for _, entry in ipairs(SCHEMA) do
            local field, kind = entry[1], entry[2]
            local wrong = (kind == "dword")
                and { name = field, type = "sz", data = "not-a-dword" }
                or { name = field, type = "dword", data = 1 }
            -- ImagePath is the one field that cannot also be supplied
            -- correctly alongside its own mistyped self.
            cases[#cases + 1] = {
                field .. " as " .. wrong.type .. " rather than " .. kind,
                field == "ImagePath" and { wrong } or with_image({ wrong }),
            }
        end
        expect_all(t, "decode", cases)

        -- And the control: the identical shape with a value name peinit
        -- does not know is accepted, so it really is the field lookup
        -- that rejects the fifty above and not the mistyping in itself.
        local got = probe(one("PtNotAField", "dword", 1))
        t:assert_eq(got, "accepted",
            "a value name outside the schema is ignored rather than type-checked")
    end)

test("a dword outside an enumerated field's range is a decode error",
    { spec = "peinit *schema.a-dword-outside-an-enumerated-range-is-a-decode-error" },
    function(t)
        -- Each of these is a well-formed dword of the right registry
        -- type. What is wrong is the value: it names no member of the
        -- enumeration the field is.
        expect_all(t, "decode", {
            { "Type=7", one("Type", "dword", 7) },
            { "RestartPolicy=9", one("RestartPolicy", "dword", 9) },
            { "Readiness=2", one("Readiness", "dword", 2) },
            { "NotifyAccess=1", one("NotifyAccess", "dword", 1) },
            { "ErrorControl=2", one("ErrorControl", "dword", 2) },
            { "Disabled=2", one("Disabled", "dword", 2) },
            { "SafeMode=2", one("SafeMode", "dword", 2) },
            { "RemainAfterExit=2", one("RemainAfterExit", "dword", 2) },
            { "TimerPersistent=2", one("TimerPersistent", "dword", 2) },
        })

        -- Every member the schema table does list is accepted, so it is
        -- the range and not the field that refused them.
        expect_all(t, "accepted", {
            { "Type=0", one("Type", "dword", 0) },
            { "Type=1", one("Type", "dword", 1) },
            { "RestartPolicy=0", one("RestartPolicy", "dword", 0) },
            { "RestartPolicy=2", one("RestartPolicy", "dword", 2) },
            { "Readiness=1", one("Readiness", "dword", 1) },
            { "NotifyAccess=0", one("NotifyAccess", "dword", 0) },
            { "ErrorControl=1", one("ErrorControl", "dword", 1) },
        })
    end)

test("value names are matched case-insensitively",
    { spec = "peinit *schema.value-names-are-matched-case-insensitively" },
    function(t)
        -- Two probes make the claim in both directions. A definition
        -- whose only value is `imagepath` is accepted, so the name was
        -- matched -- had it not been, the definition would have carried
        -- no ImagePath at all and could not decode.
        local got = probe({ { name = "imagepath", type = "sz", data = "/bin/true" } })
        t:assert_eq(got, "accepted", "`imagepath` is ImagePath")
        assert_in_model(t, "a definition written entirely in lower case decodes")

        -- And `starttimeout` carrying an sz is a decode error, so it was
        -- matched as StartTimeout and type-checked rather than being
        -- ignored as an unknown name.
        t:assert_eq(probe(one("starttimeout", "sz", "x")), "decode",
            "`starttimeout` is StartTimeout, and is checked as one")
        t:assert_eq(probe(one("STARTTIMEOUT", "sz", "x")), "decode",
            "and so is `STARTTIMEOUT`")
    end)

test("an unknown value on a service key is ignored",
    { spec = "peinit *schema.an-unknown-value-on-a-service-key-is-ignored" },
    function(t)
        -- The forward-compatibility rule: a definition written for a
        -- newer peinit still loads on an older one, minus the fields it
        -- does not understand.
        local got = probe(with_image({
            { name = "PtFutureField", type = "sz", data = "whatever" },
            { name = "PtFutureCount", type = "dword", data = 9 },
            { name = "PtFutureList", type = "multi", data = { "a", "b" } },
            { name = "PtFutureBlob", type = "binary", data = "00ff" },
        }))
        t:assert_eq(got, "accepted", "three invented values of four types are ignored")
        assert_in_model(t, "and the definition around them loaded")
    end)

test("a present string field is non-empty",
    { spec = "peinit *fmt.a-present-string-field-is-non-empty" },
    function(t)
        -- The general rule. Each of these fields is a string that means
        -- something only when it has content, and an empty one is a
        -- decode error rather than a quiet absence.
        expect_all(t, "decode", {
            { "ImagePath=''", { { name = "ImagePath", type = "sz", data = "" } } },
            { "WorkingDirectory=''", one("WorkingDirectory", "sz", "") },
            { "OnFailure=''", one("OnFailure", "sz", "") },
            { "ExecReload=''", one("ExecReload", "sz", "") },
            { "HealthCheck=''", one("HealthCheck", "sz", "") },
        })
    end)

test("the three fields that read an empty string as absence",
    { spec = "peinit *fmt.three-fields-treat-the-empty-string-as-absence" },
    function(t)
        -- The exceptions to the rule above. An empty `Identity`,
        -- `HookIdentity`, `DisplayName` or `Description` is the same as
        -- writing nothing, so the definition decodes.
        expect_all(t, "accepted", {
            { "Identity=''", one("Identity", "sz", "") },
            { "HookIdentity=''", one("HookIdentity", "sz", "") },
            { "DisplayName=''", one("DisplayName", "sz", "") },
            { "Description=''", one("Description", "sz", "") },
        })

        -- And "absence" is what it means, not "the empty string": the
        -- last probe left an empty Description on pt-probe, and status
        -- reports no description rather than one that is empty.
        probe(with_image({
            { name = "DisplayName", type = "sz", data = "" },
            { name = "Description", type = "sz", data = "" },
        }))
        local status = vm:run("svctl --json status pt-probe")
        status:assert_ok()
        t:assert(status.stdout:find('"display_name":null', 1, true),
            "an empty DisplayName is absent, not empty: " .. status.stdout)
        t:assert(status.stdout:find('"description":null', 1, true),
            "and so is an empty Description: " .. status.stdout)
    end)

test("WorkingDirectory is a non-empty absolute path, and its existence is not checked when the definition is read",
    {
        spec = {
            "peinit *fmt.workingdirectory-is-a-non-empty-absolute-path",
            "peinit *fmt.workingdirectory-existence-is-checked-at-start-not-at-read",
        },
    },
    function(t)
        expect_all(t, "decode", {
            { "empty", one("WorkingDirectory", "sz", "") },
            { "relative", one("WorkingDirectory", "sz", "tmp/x") },
            { "bare name", one("WorkingDirectory", "sz", "tmp") },
        })

        -- Absolute is the whole of the read-time rule: a path that does
        -- not exist, is not a directory, and could not be reached if it
        -- did is accepted, because none of that is a question about the
        -- definition.
        t:assert_eq(probe(one("WorkingDirectory", "sz", "/pt-no-such-directory")),
            "accepted", "a non-existent absolute path decodes")
        assert_in_model(t, "and the service is in the model")
        t:assert_eq(probe(one("WorkingDirectory", "sz", "/etc/hostname")),
            "accepted", "so does one naming a regular file rather than a directory")
    end)

test("an empty TTYPath means no terminal, and a relative one is rejected",
    { spec = "peinit *fmt.an-empty-ttypath-means-no-terminal-and-a-relative-one-is-rejected" },
    function(t)
        -- The order of the two checks is the whole claim. Emptiness is
        -- asked first, so an empty value is "no terminal" rather than a
        -- malformed path; everything non-empty then has to be absolute.
        t:assert_eq(probe(one("TTYPath", "sz", "")), "accepted",
            "an empty TTYPath is no terminal")
        t:assert_eq(probe(one("TTYPath", "sz", "/dev/tty9")), "accepted",
            "an absolute one is a terminal")
        expect_all(t, "decode", {
            { "relative", one("TTYPath", "sz", "dev/tty9") },
            { "bare name", one("TTYPath", "sz", "console") },
        })
    end)

test("a RuntimeDirectories entry is one non-empty relative name",
    { spec = "peinit *fmt.a-runtime-directory-entry-is-one-relative-name" },
    function(t)
        expect_all(t, "decode", {
            { "empty", one("RuntimeDirectories", "multi", { "" }) },
            { "dot", one("RuntimeDirectories", "multi", { "." }) },
            { "dotdot", one("RuntimeDirectories", "multi", { ".." }) },
            { "absolute", one("RuntimeDirectories", "multi", { "/app" }) },
            { "with a slash", one("RuntimeDirectories", "multi", { "app/cache" }) },
            { "with a backslash", one("RuntimeDirectories", "multi", { "app\\cache" }) },
            { "one bad entry among good ones",
                one("RuntimeDirectories", "multi", { "app", "..", "cache" }) },
        })

        -- A dot inside a name is fine, which is the case the rule is
        -- most easily got wrong on.
        expect_all(t, "accepted", {
            { "a plain name", one("RuntimeDirectories", "multi", { "app" }) },
            { "dots inside", one("RuntimeDirectories", "multi", { "app.sock.d" }) },
            { "several", one("RuntimeDirectories", "multi", { "app", "app-cache_1" }) },
        })
    end)

test("an Environment entry is KEY=VALUE",
    { spec = "peinit *fmt.an-environment-entry-is-key-equals-value" },
    function(t)
        expect_all(t, "decode", {
            { "no equals", one("Environment", "multi", { "NOEQUALS" }) },
            { "empty key", one("Environment", "multi", { "=value" }) },
            { "empty entry", one("Environment", "multi", { "" }) },
            { "one bad entry among good ones",
                one("Environment", "multi", { "A=1", "BROKEN", "B=2" }) },
        })
        expect_all(t, "accepted", {
            { "a pair", one("Environment", "multi", { "A=1" }) },
            { "an empty value", one("Environment", "multi", { "A=" }) },
            { "an equals in the value", one("Environment", "multi", { "A=b=c" }) },
        })
    end)

test("a SuccessExitCodes entry is a decimal integer from 0 to 255",
    { spec = "peinit *fmt.a-success-exit-code-is-a-decimal-integer-0-to-255" },
    function(t)
        -- Signal names and ranges are not accepted -- an exit code is a
        -- number, and the field takes nothing else.
        expect_all(t, "decode", {
            { "256", one("SuccessExitCodes", "multi", { "256" }) },
            { "-1", one("SuccessExitCodes", "multi", { "-1" }) },
            { "a signal name", one("SuccessExitCodes", "multi", { "SIGTERM" }) },
            { "a range", one("SuccessExitCodes", "multi", { "1-3" }) },
            { "a list in one entry", one("SuccessExitCodes", "multi", { "1,2" }) },
            { "hex", one("SuccessExitCodes", "multi", { "0x10" }) },
            { "empty", one("SuccessExitCodes", "multi", { "" }) },
            { "surrounded by space", one("SuccessExitCodes", "multi", { " 3" }) },
        })
        expect_all(t, "accepted", {
            { "0", one("SuccessExitCodes", "multi", { "0" }) },
            { "255", one("SuccessExitCodes", "multi", { "255" }) },
            { "several", one("SuccessExitCodes", "multi", { "1", "3", "42" }) },
            { "duplicates", one("SuccessExitCodes", "multi", { "3", "3" }) },
        })
    end)

test("an illegal dependency name is a decode error, and a merely absent one is not",
    { spec = "peinit *fmt.an-illegal-dependency-name-is-a-decode-error" },
    function(t)
        -- The distinction §3.3 draws, and the reason the rule exists: a
        -- typo containing an illegal character is caught immediately,
        -- while a typo that is still a legal name gets as far as graph
        -- validation and is reported there as a missing target.
        expect_all(t, "decode", {
            { "Requires with a space", one("Requires", "multi", { "pt bad" }) },
            { "Requires with a bang", one("Requires", "multi", { "pt!bad" }) },
            { "Requires with a slash", one("Requires", "multi", { "pt/bad" }) },
            { "Requires empty", one("Requires", "multi", { "" }) },
            { "Wants with a space", one("Wants", "multi", { "pt bad" }) },
            { "BindsTo with a space", one("BindsTo", "multi", { "pt bad" }) },
            { "Conflicts with a space", one("Conflicts", "multi", { "pt bad" }) },
            { "OnFailure with a space", one("OnFailure", "sz", "pt bad") },
        })

        -- A legal name that names nothing decodes and is caught later.
        local got, reload = probe(one("Requires", "multi", { "pt-nothing-defines-this" }))
        t:assert_eq(got, "validation",
            "a legal but absent name reaches graph validation: " .. reload.stdout)
        t:assert(reload.stdout:find("pt%-nothing%-defines%-this"),
            "and is reported as a missing target: " .. reload.stdout)

        -- And a name that resolves is simply accepted.
        t:assert_eq(probe(one("Requires", "multi", { "pt-ok" })), "accepted",
            "a dependency on a service that exists is accepted")
    end)

test("a trigger is one of the listed forms, and the arity of each is enforced",
    {
        spec = {
            "peinit *trig.a-trigger-entry-is-a-type-or-a-type-and-argument",
            "peinit *trig.boot-accepts-only-the-listed-sub-triggers",
            "peinit *trig.a-bare-tty-is-malformed-and-tty-accepts-only-released",
            "peinit *trig.a-timer-with-no-schedule-is-malformed",
        },
    },
    function(t)
        -- The four forms in §3.4's table, each of which must decode.
        -- `tty:released` needs a TTYPath, which §3.4 says in its own
        -- right and which is tested separately below.
        expect_all(t, "accepted", {
            { "boot", one("Triggers", "multi", { "boot" }) },
            { "boot:settled", one("Triggers", "multi", { "boot:settled" }) },
            { "tty:released", with_image({
                { name = "TTYPath", type = "sz", data = "/dev/tty9" },
                { name = "Triggers", type = "multi", data = { "tty:released" } },
            }) },
            { "timer", one("Triggers", "multi", { "timer:*-*-* 02:00:00" }) },
        })

        -- Arity. A known trigger type with the wrong argument is
        -- malformed rather than an unknown trigger to be ignored --
        -- which is the whole point, since a silently ignored
        -- `boot:setled` is a service that never starts and never says
        -- why.
        expect_all(t, "decode", {
            { "boot:setled", one("Triggers", "multi", { "boot:setled" }) },
            { "boot with an argument", one("Triggers", "multi", { "boot:now" }) },
            { "boot with an empty argument", one("Triggers", "multi", { "boot:" }) },
            { "bare tty", one("Triggers", "multi", { "tty" }) },
            { "tty with an empty argument", one("Triggers", "multi", { "tty:" }) },
            { "tty:grabbed", one("Triggers", "multi", { "tty:grabbed" }) },
            { "bare timer", one("Triggers", "multi", { "timer" }) },
            { "timer with an empty schedule", one("Triggers", "multi", { "timer:" }) },
            { "an empty entry", one("Triggers", "multi", { "" }) },
            { "one bad entry among good ones",
                one("Triggers", "multi", { "boot", "boot:setled" }) },
        })
    end)

test("multiple triggers of one type decode, and a trigger type peinit does not know needs no schema change",
    {
        spec = {
            "peinit *trig.multiple-triggers-of-one-type-are-allowed",
            "peinit *trig.a-new-trigger-type-needs-no-schema-change",
        },
    },
    function(t)
        expect_all(t, "accepted", {
            { "two boots", one("Triggers", "multi", { "boot", "boot" }) },
            { "two timers", one("Triggers", "multi",
                { "timer:*-*-* 02:00:00", "timer:*-*-* 14:00:00" }) },
            { "boot and a timer", one("Triggers", "multi",
                { "boot", "timer:*-*-* 02:00:00" }) },
        })

        -- The extensibility claim, which is what keeps the arity rule
        -- above from being a forward-compatibility problem: a trigger is
        -- a string in a list, so a type this build has never heard of
        -- goes into the same array and the definition still loads. The
        -- strictness is per known type, not across the namespace.
        t:assert_eq(probe(one("Triggers", "multi", { "pt-future:argument" })),
            "accepted", "an unrecognised trigger type is carried rather than refused")
        assert_in_model(t, "and the service around it loaded")
    end)

test("the terminal fields need a TTYPath, and emptying it takes both down",
    {
        spec = {
            "peinit *trig.tty-released-without-a-ttypath-is-refused",
            "peinit *trig.ttyprecedence-without-a-ttypath-is-refused",
            "peinit *trig.emptying-ttypath-takes-both-down-with-it",
        },
    },
    function(t)
        -- Both fields are about a terminal the service names, and
        -- neither means anything without one. Refusing beats ignoring:
        -- a `tty:released` with no TTYPath describes a service that
        -- would silently never start.
        expect_all(t, "decode", {
            { "tty:released with no TTYPath",
                one("Triggers", "multi", { "tty:released" }) },
            { "TTYPrecedence with no TTYPath", one("TTYPrecedence", "dword", 5) },
        })

        -- And the interaction with §3.3: an empty TTYPath is an absent
        -- one, so emptying it refuses both in turn rather than leaving
        -- them attached to a terminal that is no longer named.
        expect_all(t, "decode", {
            { "tty:released with an emptied TTYPath", with_image({
                { name = "TTYPath", type = "sz", data = "" },
                { name = "Triggers", type = "multi", data = { "tty:released" } },
            }) },
            { "TTYPrecedence with an emptied TTYPath", with_image({
                { name = "TTYPath", type = "sz", data = "" },
                { name = "TTYPrecedence", type = "dword", data = 5 },
            }) },
        })

        -- With a terminal named, both are accepted -- so it is the
        -- missing TTYPath that refused them above.
        expect_all(t, "accepted", {
            { "tty:released with a TTYPath", with_image({
                { name = "TTYPath", type = "sz", data = "/dev/tty9" },
                { name = "Triggers", type = "multi", data = { "tty:released" } },
            }) },
            { "TTYPrecedence with a TTYPath", with_image({
                { name = "TTYPath", type = "sz", data = "/dev/tty9" },
                { name = "TTYPrecedence", type = "dword", data = 5 },
            }) },
            -- Zero is the default, so a definition that never mentions
            -- precedence is not one that "carries" it.
            { "TTYPrecedence=0 with no TTYPath", one("TTYPrecedence", "dword", 0) },
        })
    end)

test("a check is one of the four types with a non-empty argument",
    {
        spec = {
            "peinit *check.the-four-check-types",
            "peinit *check.an-empty-argument-or-unknown-type-is-a-decode-error",
        },
    },
    function(t)
        for _, field in ipairs({ "Conditions", "Asserts" }) do
            expect_all(t, "accepted", {
                { field .. " path", one(field, "multi", { "path:/run" }) },
                { field .. " file", one(field, "multi", { "file:/etc/hostname" }) },
                { field .. " directory", one(field, "multi", { "directory:/run" }) },
                { field .. " registry", one(field, "multi",
                    { [[registry:Machine\System\Services\pt-ok]] }) },
            })
            expect_all(t, "decode", {
                { field .. " empty argument", one(field, "multi", { "path:" }) },
                { field .. " no colon", one(field, "multi", { "path" }) },
                { field .. " unknown type", one(field, "multi", { "pt-unknown:/run" }) },
                { field .. " bare colon", one(field, "multi", { ":" }) },
                { field .. " empty entry", one(field, "multi", { "" }) },
                { field .. " one bad among good",
                    one(field, "multi", { "path:/run", "path:" }) },
            })
        end
    end)

test("a registry check may only name a key peinit caches",
    { spec = "peinit *check.a-registry-check-must-name-a-cached-key" },
    function(t)
        -- A `registry:` check is answered from the in-memory model
        -- rather than by a live read, so it can only name a key the
        -- model holds. Anything else is caught at load rather than
        -- silently answering false at every start.
        expect_all(t, "accepted", {
            { "the services key itself",
                one("Conditions", "multi", { [[registry:Machine\System\Services]] }) },
            { "a service under it", one("Conditions", "multi",
                { [[registry:Machine\System\Services\pt-ok]] }) },
            { "the init key", one("Conditions", "multi",
                { [[registry:Machine\System\Init]] }) },
            { "a key under init", one("Conditions", "multi",
                { [[registry:Machine\System\Init\Anything]] }) },
        })
        expect_all(t, "decode", {
            { "a key peinit does not cache", one("Conditions", "multi",
                { [[registry:Machine\Software\Vendor]] }) },
            { "the parent of both cached roots",
                one("Conditions", "multi", { [[registry:Machine\System]] }) },
            { "a lookalike prefix", one("Conditions", "multi",
                { [[registry:Machine\System\ServicesOther]] }) },
            { "a user hive", one("Conditions", "multi", { [[registry:User\Default]] }) },
        })
    end)

test("all four command fields are parsed the same way",
    {
        spec = {
            "peinit *cmdstr.the-four-command-fields-are-parsed-alike",
            "peinit *cmdstr.an-empty-or-whitespace-only-command-is-invalid",
            "peinit *cmdstr.an-unclosed-double-quote-is-invalid",
            "peinit *cmdstr.argv0-must-be-an-absolute-path",
            "peinit *cmdstr.arguments-after-argv0-are-not-validated",
        },
    },
    function(t)
        -- The same string, in each of the four fields that hold a
        -- command, has to reach the same answer -- that is what "parsed
        -- the same way" means, and it is the only claim in §3.6 that
        -- cannot be made about any one field.
        local function in_each_field(command)
            return {
                { name = "ExecStartPre", type = "multi", data = { command } },
                { name = "ExecStartPost", type = "multi", data = { command } },
                { name = "ExecReload", type = "sz", data = command },
                { name = "HealthCheck", type = "sz", data = command },
            }
        end

        local bad = {
            ["an empty command"] = "",
            ["a whitespace-only command"] = "   ",
            ["an unclosed double quote"] = '/bin/true "unclosed',
            ["a relative argv[0]"] = "true --flag",
            ["a PATH-searched argv[0]"] = "sleep 1",
            ["a dot-relative argv[0]"] = "./bin/true",
            ["an empty quoted argv[0]"] = '"" /bin/true',
        }
        for label, command in pairs(bad) do
            local cases = {}
            for _, value in ipairs(in_each_field(command)) do
                cases[#cases + 1] = { label .. " in " .. value.name, with_image({ value }) }
            end
            expect_all(t, "decode", cases)
        end

        -- And the accepted shape, in all four: an absolute argv[0], with
        -- everything after it left alone. `not/a/path` is not validated
        -- because it is an argument, not an executable.
        local good = {
            ["a bare absolute path"] = "/bin/true",
            ["arguments that look like paths"] = "/bin/true not/a/path ../x",
            ["an argument that is a flag"] = "/bin/true --name=value",
        }
        for label, command in pairs(good) do
            local cases = {}
            for _, value in ipairs(in_each_field(command)) do
                cases[#cases + 1] = { label .. " in " .. value.name, with_image({ value }) }
            end
            expect_all(t, "accepted", cases)
        end
    end)

test("a reload signal is an exact canonical name, and the accepted set is the non-realtime signals bar SIGKILL and SIGSTOP",
    {
        spec = {
            "peinit *cmdstr.a-reload-signal-is-an-exact-canonical-name",
            "peinit *cmdstr.sigkill-and-sigstop-are-not-reload-signals",
            "peinit *cmdstr.the-accepted-reload-signal-set",
        },
    },
    function(t)
        local ACCEPTED = {
            "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT",
            "SIGBUS", "SIGFPE", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE",
            "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGTSTP",
            "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM",
            "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
        }
        local cases = {}
        for _, name in ipairs(ACCEPTED) do
            cases[#cases + 1] = { name, one("ExecReload", "sz", "signal:" .. name) }
        end
        expect_all(t, "accepted", cases)

        -- The two the set excludes, and why: a service cannot handle
        -- either as a request to re-read its configuration.
        expect_all(t, "decode", {
            { "SIGKILL", one("ExecReload", "sz", "signal:SIGKILL") },
            { "SIGSTOP", one("ExecReload", "sz", "signal:SIGSTOP") },
        })

        -- Exact and canonical: everything that is a way of naming a
        -- signal without being its canonical name is refused.
        expect_all(t, "decode", {
            { "a number", one("ExecReload", "sz", "signal:10") },
            { "a bare number with no SIG", one("ExecReload", "sz", "signal:HUP") },
            { "a realtime expression", one("ExecReload", "sz", "signal:SIGRTMIN+1") },
            { "a realtime name", one("ExecReload", "sz", "signal:SIGRTMIN") },
            { "an alias", one("ExecReload", "sz", "signal:SIGIOT") },
            { "another alias", one("ExecReload", "sz", "signal:SIGCLD") },
            { "lower case", one("ExecReload", "sz", "signal:sighup") },
            { "mixed case", one("ExecReload", "sz", "signal:SigHup") },
            { "trailing space", one("ExecReload", "sz", "signal:SIGHUP ") },
            { "leading space", one("ExecReload", "sz", "signal: SIGHUP") },
            { "no name at all", one("ExecReload", "sz", "signal:") },
            { "an invented name", one("ExecReload", "sz", "signal:SIGNOTREAL") },
        })
    end)

test("a decode failure arriving on reload-config rejects the whole read and changes nothing",
    { spec = "peinit *schema.a-decode-failure-rejects-a-whole-reload" },
    function(t)
        -- Boot marks the one key Failed and carries on because it has to
        -- produce a running system. A reload has one already, so it
        -- refuses the whole transaction: that is the asymmetry §3.2
        -- names, and every probe in this file has been leaning on the
        -- reload half of it. This test is the half itself.
        local before = vm:run("svctl --json status pt-resident")
        before:assert_ok()
        local before_pid = before.stdout:match('"pid":(%d+)')
        t:assert(before_pid, "the resident service is running: " .. before.stdout)

        -- Start from a generation that has no pt-probe in it, so that
        -- "was not admitted" below is about this read rather than about
        -- an entry an earlier probe left behind. A refused reload leaves
        -- the previous generation in place, which is the point of the
        -- test -- and would also have left a stale pt-probe standing.
        vm:run("reg del '" .. PROBE .. "' --recursive >/dev/null 2>&1; " ..
            "svctl --json reload-config"):assert_ok()
        t:assert(vm:run("svctl --json status pt-probe").stdout
            :find("UNKNOWN_SERVICE", 1, true),
            "the generation about to be replaced has no pt-probe in it")

        -- A definition that will not decode, alongside one that would.
        local batch = peinit.encode_json({ keys = {
            { path = [[Machine\System\Services\pt-alongside]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/true" },
                { name = "Type", type = "dword", data = 1 },
            } },
            { path = PROBE, values = with_image({
                { name = "StartTimeout", type = "sz", data = "not-a-dword" },
            }) },
        } })
        vm:run("cat > /tmp/pt-reject.json <<'PT_JSON_EOF'\n" .. batch ..
            "\nPT_JSON_EOF\nreg apply /tmp/pt-reject.json"):assert_ok()

        local reload = vm:run("svctl --json reload-config")
        t:assert(reload.exit_code ~= 0,
            "the reload was refused: " .. reload.stdout)

        -- Rejected entire. The service that would have decoded perfectly
        -- well was not admitted either -- a reload is one transaction,
        -- not a per-key best effort.
        t:assert(vm:run("svctl --json status pt-alongside").stdout
            :find("UNKNOWN_SERVICE", 1, true),
            "a valid definition in the same read was not admitted")
        t:assert(vm:run("svctl --json status pt-probe").stdout
            :find("UNKNOWN_SERVICE", 1, true),
            "and neither was the one that would not decode")

        -- And the generation that was already running is untouched.
        local after = vm:run("svctl --json status pt-resident")
        after:assert_ok()
        t:assert_eq(after.stdout:match('"pid":(%d+)'), before_pid,
            "the running service kept its process: " .. after.stdout)
        t:assert_eq(after.stdout:match('"state":"([^"]+)"'), "active",
            "and its state")

        -- Cleaning up after this one matters: the probe key is left
        -- undecodable, and every later reload in the file would fail on
        -- it.
        vm:run("reg del '" .. PROBE .. "' --recursive"):assert_ok()
        vm:run([[reg del 'Machine\System\Services\pt-alongside' --recursive]]):assert_ok()
        vm:run("svctl --json reload-config"):assert_ok()
    end)

test("the schema version of the services key is 1",
    { spec = "peinit *schema.the-services-schema-version-is-one" },
    function(t)
        local value = vm:run([[reg get 'Machine\System\Services' SchemaVersion]])
        value:assert_ok()
        t:assert_eq((value.stdout:gsub("%s+$", "")), "1",
            "SchemaVersion reads 1: " .. value.stdout)

        -- And it is a dword rather than a string that happens to say 1.
        -- `reg ls` quotes an REG_SZ and prints a dword bare, which is
        -- the only handle the guest's tools give on a value's type.
        local listing = vm:run([[reg ls 'Machine\System\Services']])
        listing:assert_ok()
        t:assert(listing.stdout:find("SchemaVersion = 1", 1, true),
            "and is stored as a dword rather than a string: " .. listing.stdout)
    end)

test("a newer schema version does not prevent boot",
    { spec = "peinit *schema.a-newer-schema-version-does-not-prevent-boot" },
    function(t)
        -- A machine whose services key claims a schema this peinit does
        -- not implement. The seed lands in Phase 1 step 7, after peinit
        -- has stamped the key it creates on a fresh system, so what
        -- Phase 2 reads is the 2 written over the top of it.
        --
        -- The claim is about the boot rather than about any one service,
        -- so most of it is proved by the boot returning at all:
        -- `peinit.boot` waits for `phase2 boot complete`, and a refusal
        -- would have gone to the recovery console and never printed it.
        local newer = peinit.boot({
            name = "decode-v2",
            files = peinit.seed("pt-schema-v2", {
                { path = [[Machine\System]] },
                { path = [[Machine\System\Services]], values = {
                    { name = "SchemaVersion", type = "dword", data = 2 },
                } },
                { path = [[Machine\System\Services\pt-v2]], values = {
                    { name = "ImagePath", type = "sz", data = "/bin/sleep" },
                    { name = "Arguments", type = "multi", data = { "100000" } },
                    { name = "Identity", type = "sz", data = "SYSTEM" },
                    { name = "Readiness", type = "dword", data = 1 },
                    { name = "Triggers", type = "multi", data = { "boot" } },
                } },
            }),
        })

        local seeded = newer:run([[reg get 'Machine\System\Services' SchemaVersion]])
        seeded:assert_ok()
        t:assert(seeded.stdout:find("2"),
            "the premise: the machine really claims schema version 2: " .. seeded.stdout)

        -- And the definitions under that key were read and started, so
        -- the newer version did not cost the boot its services either.
        newer:console():expect("peinit: service pt-v2 started", peinit.STAGE_TIMEOUT)
        local status = newer:run("svctl --json status pt-v2")
        status:assert_ok()
        t:assert_eq(status.stdout:match('"state":"([^"]+)"'), "active",
            "a service read from a newer-versioned key started: " .. status.stdout)
    end)
