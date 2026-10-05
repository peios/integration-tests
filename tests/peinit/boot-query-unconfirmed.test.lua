-- peinit TRM §10.8 — the fourth confirmation row: a grace that ends with
-- the counter reset failing is not a confirmed boot, and `boot` is where
-- an administrator finds out.
--
-- Its own file because the machine is spent afterwards: the tracker tries
-- the reset once, so a boot whose reset has failed can show nothing else.
--
-- The lever is the counter's own path. peinit resets the counter by
-- opening /.peinit/boot-attempts for writing; replace the file with a
-- directory of the same name and that open fails, as it would on a full
-- disk, with nothing else about the machine disturbed. The replacement
-- has to land before the grace runs out, so a Critical Oneshot holds the
-- boot open on a gate file the test creates afterwards, exactly as in
-- boot-query.test.lua. Phase 1 has long since read and advanced the
-- counter by then, so nothing else reads the path again this boot.

local peinit = require("helpers.peinit")
peinit.claim(1)

local SERVICES = [[Machine\System\Services]]
local GATE = "/pt-bqu-go"
local COUNTER = "/.peinit/boot-attempts"

local vm = peinit.boot({
    name = "boot-query-unconfirmed",
    files = peinit.merge(
        { [".peinit/boot-attempts"] = "1\n" },
        peinit.seed("zz-pt-bqu", {
            { path = [[Machine\System]] },
            { path = [[Machine\System\Boot]], values = {
                { name = "BootSuccessGrace", type = "dword", data = 3 },
            } },
            { path = SERVICES },
            { path = SERVICES .. [[\pt-bqu-gate]], values = {
                { name = "ImagePath", type = "sz", data = "/bin/sh" },
                { name = "Arguments", type = "multi",
                  data = { "-c", "while [ ! -e " .. GATE .. " ]; do sleep 1; done" } },
                { name = "Type", type = "dword", data = 1 },
                { name = "RemainAfterExit", type = "dword", data = 1 },
                { name = "StartTimeout", type = "dword", data = 600 },
                { name = "Identity", type = "sz", data = "SYSTEM" },
                { name = "ErrorControl", type = "dword", data = 1 },
                { name = "Triggers", type = "multi", data = { "boot" } },
            } },
        })
    ),
})

--- `svctl --json boot`, decoded (a null field decodes to nil), and the
--- raw answer.
local function ask()
    local r = vm:run("svctl --json boot")
    r:assert_ok()
    local ok, decoded = pcall(json.decode, r.stdout)
    assert(ok and type(decoded) == "table" and type(decoded.boot) == "table",
        "svctl --json boot did not answer with a boot object: " .. r.stdout .. r.stderr)
    return decoded.boot, r.stdout
end

test("a grace that ends with the reset failing is not a confirmed boot, and boot says why",
    {
        spec = {
            "peinit *control.boot.confirmed-means-the-counter-was-reset",
            "peinit *control.boot.confirmation-states",
        },
    },
    function(t)
        local boot, raw = ask()
        t:assert(not boot.confirmed and #boot.waiting_on >= 1,
            "the boot is held open by the gate: " .. raw)

        -- The counter becomes something the reset cannot write.
        vm:run("rm " .. COUNTER .. " && mkdir " .. COUNTER):assert_ok()
        t:assert(vm:run("test -d " .. COUNTER).exit_code == 0,
            "the counter's path is now a directory")

        -- Release the gate; after the grace the tracker tries the reset.
        vm:run("touch " .. GATE):assert_ok()
        local got = wait_until(function()
            local b, text = ask()
            if b.confirm_error ~= nil then return { b, text } end
            return nil
        end, { timeout = 90, interval = 0.5, desc = "boot to report a failed reset" })
        boot, raw = got[1], got[2]

        t:assert_eq(boot.confirmed, false,
            "the grace ran out, but the reset was not written, so the boot is not confirmed: " .. raw)
        t:assert_eq(#boot.waiting_on, 0, "it waits on nothing: " .. raw)
        t:assert(boot.confirms_at == nil, "and has no time still to come: " .. raw)
        t:assert(type(boot.confirm_error) == "string" and #boot.confirm_error > 0,
            "confirm_error says why: " .. raw)

        -- And it stays that way: the tracker does not try again, and an
        -- unwritten reset never turns into a confirmed boot.
        vm:clock():sleep("5s")
        local later
        later, raw = ask()
        t:assert(not later.confirmed and later.confirm_error ~= nil,
            "the boot is still unconfirmed, with the error: " .. raw)
    end)
