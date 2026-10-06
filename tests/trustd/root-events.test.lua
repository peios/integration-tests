-- trustd.evman — trustd.root.added, .removed and .distrusted: one record per
-- root that enters or leaves the set in force, carrying the certificate's
-- SHA-256 digest (binary), its subject name and its purposes, and no
-- subject.
--
-- trustd has no TRM yet; the events' definitions in trustd.evman, and the
-- user guide's "Adding and distrusting" (Trust topic), are what this
-- checks. It is also the proof that trustd's service SID holds
-- SeAuditPrivilege (trustd-service.reg), which no unit test can show.
--
-- The machine is the whole Peios of the peinit profile, which runs trustd.
-- The root under test is made in the guest with openssl, so it is in no
-- shipped bundle: adding it is a change. The records are read off the
-- KMES ring (helpers.kmes): one vCPU, so CPU 0's ring sees everything.
--
-- The tests share the root and run in order: added, distrusted, added
-- again when the distrust is lifted, removed.

local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local sys = require("helpers.sys")

peinit.claim(1)

local vm = peinit.boot({})
-- peinit reports phase 2 complete before the boot's own service starts
-- have run. trustd's first composition is its baseline and records
-- nothing, so a root added before trustd is up is in that baseline and
-- is never recorded as added: the test must wait for it.
peinit.settle(vm)

local NAME = "pei617-test-root"
local CN = "PEI-617 Test Root"
local PEM = "/tmp/pei617-root.pem"

local function run(cmd, what)
    local r = vm:run(cmd)
    assert(r.exit_code == 0, (what or cmd) .. " failed (" .. tostring(r.exit_code) .. "): "
        .. tostring(r.stdout) .. tostring(r.stderr))
    return r
end

-- A self-signed CA of our own. The extensions come from a config of our
-- own, so the result does not depend on whatever openssl.cnf the image has.
vm:write_file("/tmp/pei617-root.cnf", table.concat({
    "[req]",
    "distinguished_name = dn",
    "prompt = no",
    "[dn]",
    "CN = " .. CN,
    "[v3]",
    "basicConstraints = critical,CA:TRUE",
    "keyUsage = critical,keyCertSign,cRLSign",
    "subjectKeyIdentifier = hash",
    "",
}, "\n"))
run("openssl req -x509 -config /tmp/pei617-root.cnf -extensions v3"
    .. " -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
    .. " -keyout /tmp/pei617-root.key -out " .. PEM .. " -days 30",
    "making a test CA")
run("openssl x509 -in " .. PEM .. " -outform DER -out /tmp/pei617-root.der", "the CA's DER")
local FP = run("openssl dgst -sha256 -r /tmp/pei617-root.der").stdout:match("^(%x+)")
assert(FP and #FP == 64, "the CA's SHA-256 fingerprint")
local DIGEST = (FP:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))

--- Run `cmd` with a ring attached, and return the trustd.root.* records
--- for the test root that follow, waiting for `want` of them.
local function records(t, cmd, want)
    local ring, errno = kmes.attach(vm, 0)
    t:assert(ring, "a KMES ring attaches: " .. sys.errname(errno or 0))
    local ok, err = pcall(run, cmd)
    local seen = {}
    if ok then
        pcall(wait_until, function()
            for _, e in ipairs(kmes.drain(ring)) do
                local c = e.payload and e.payload.object and e.payload.object.certificate
                if e.type:match("^trustd%.root%.") and c and c.digest == DIGEST then
                    seen[#seen + 1] = e
                end
            end
            return #seen >= want
        end, { timeout = 15, interval = 0.25, desc = "trustd.root records" })
    end
    kmes.detach(ring)
    if not ok then error(err, 0) end
    return seen
end

local function check_one(t, seen, event_type, purposes)
    t:assert_eq(#seen, 1, "one record for the one root (trustd needs SeAuditPrivilege to write it)")
    local e = seen[1]
    if not e then return end
    t:assert_eq(e.type, event_type, "the record is " .. event_type)
    t:assert_eq(e.origin, kmes.ORIGIN.USERSPACE, "written by a userspace emitter")
    local c = e.payload.object.certificate
    t:assert_eq(#c.digest, 32, "object.certificate.digest is the 32-byte SHA-256, binary")
    t:assert(type(c.name) == "string" and c.name:find(CN, 1, true),
        "object.certificate.name is the subject name: " .. tostring(c.name))
    t:assert_eq(table.concat(c.purposes or {}, ","), purposes, "object.certificate.purposes, kebab-case")
    t:assert_eq(e.payload.subject, nil, "no subject: the registry write is LCS's to record")
end

test("adding a root records trustd.root.added, with its digest, name and purposes",
    { spec = "trustd.evman trustd.root.added" }, function(t)
        local seen = records(t, "trust add " .. NAME .. " " .. PEM .. " --purposes ServerAuth,CodeSigning", 1)
        check_one(t, seen, "trustd.root.added", "server-auth,code-signing")
    end)

test("distrusting it records trustd.root.distrusted, not removed",
    { spec = "trustd.evman trustd.root.distrusted" }, function(t)
        local seen = records(t, "trust distrust " .. FP .. " --reason 'PEI-617 test'", 1)
        check_one(t, seen, "trustd.root.distrusted", "server-auth,code-signing")
    end)

test("lifting the distrust records trustd.root.added again",
    { spec = "trustd.evman trustd.root.added" }, function(t)
        local seen = records(t, "trust restore " .. FP, 1)
        check_one(t, seen, "trustd.root.added", "server-auth,code-signing")
    end)

test("withdrawing the addition records trustd.root.removed",
    { spec = "trustd.evman trustd.root.removed" }, function(t)
        local seen = records(t, "trust remove " .. NAME, 1)
        check_one(t, seen, "trustd.root.removed", "server-auth,code-signing")
    end)
