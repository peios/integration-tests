-- PEI-1230: service reload must use trustd's control operation and keep its PID.
local peinit = require("helpers.peinit")
peinit.claim(1)
local files = {}
-- Validate a signed candidate before package publication, or use the image's
-- shipped binary for normal release regression runs.
local binary = os.getenv("TRUSTD_TEST_BINARY")
if binary then
    local f = assert(io.open(binary, "rb"))
    files["usr/sbin/trustd"] = { f:read("*a"), exec = true }
    f:close()
end
local vm = peinit.boot({ files = files })

test("service reload recomposes trust without replacing the daemon", function(t)
    local function status()
        local r = vm:run("svctl --json status trustd")
        r:assert_ok()
        return json.decode(r.stdout)
    end
    local pid = wait_until(function()
        local s = status()
        if s.state == "active" and s.current_job and s.current_job.pid
            and vm:run("trust status").exit_code == 0 then
            return s.current_job.pid
        end
    end, { timeout = 30, interval = 0.2, desc = "trustd answering before reload" })
    for _ = 1, 2 do
        local reload = vm:run("svctl --json --wait reload trustd")
        t:log(reload.stdout or "")
        t:log(reload.stderr or "")
        t:assert_eq(reload.exit_code, 0, "service reload succeeds")
        local reply = json.decode(reload.stdout)
        t:assert(reply.mode ~= "failed", "reload operation must not report failure")
        local after = status()
        t:assert_eq(after.state, "active", "reload leaves the service active")
        t:assert_eq(after.current_job.pid, pid, "reload retains the same main process")
        vm:run("trust status"):assert_ok()
    end
end)

test("SIGHUP recomposes unchanged-stamp input and retains the last good store on failure", function(t)
    local before = vm:run("trust status")
    before:assert_ok()
    t:assert(before.stdout:match("health%s+ok"), "initial store is healthy")
    local roots = before.stdout:match("roots%s+(%d+)")
    -- Keep the bundle's length and mtime unchanged so its periodic stamp check
    -- cannot cause the refresh. This makes SIGHUP's effect observable.
    vm:run([[set -eu
bundle=/usr/share/ca-certificates/mozilla.crt
cp -p "$bundle" /tmp/pei1230-bundle
cp /etc/ssl/cert.pem /tmp/pei1230-rendered
size=$(stat -c %s "$bundle")
dd if=/dev/zero of="$bundle" bs="$size" count=1
touch -r /tmp/pei1230-bundle "$bundle"
test "$(stat -c '%s:%Y' "$bundle")" = "$(stat -c '%s:%Y' /tmp/pei1230-bundle)"
]]):assert_ok()
    local reload = vm:run("svctl --json --wait reload trustd")
    reload:assert_ok()
    t:assert(json.decode(reload.stdout).mode ~= "failed")
    local degraded = vm:run("trust status")
    degraded:assert_ok()
    t:assert(degraded.stdout:match("health%s+degraded"), "SIGHUP attempted recomposition of the broken bundle")
    t:assert_eq(degraded.stdout:match("roots%s+(%d+)"), roots, "last good root set remains")
    vm:run("cmp /etc/ssl/cert.pem /tmp/pei1230-rendered"):assert_ok()
    vm:run("cp -p /tmp/pei1230-bundle /usr/share/ca-certificates/mozilla.crt"):assert_ok()
    vm:run("svctl --wait reload trustd"):assert_ok()
    local recovered = vm:run("trust status")
    recovered:assert_ok()
    t:assert(recovered.stdout:match("health%s+ok"), "a later SIGHUP recovers healthy composition")
    t:assert_eq(recovered.stdout:match("roots%s+(%d+)"), roots)
end)
