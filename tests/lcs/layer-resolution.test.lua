-- PKM §5.3.6 — Resolution: turning several per-layer entries into one
-- effective answer. The same algorithm runs over path entries and over
-- values; `REG_IOC_QUERY_VALUE` names the winning layer, so the whole
-- rule is observable from the guest, and so are the two validations
-- that stop a source manipulating the outcome.

local sys = require("helpers.sys")
local lcs = require("helpers.lcs")
local kmes = require("helpers.kmes")

local vm = provium:vm("v", "kernel-only"):boot()

local SZ = lcs.TYPE.SZ

--- Name a key as a child of `parent` in one layer, without walking the
--- path from the hive root the way `Source:key` does (which would
--- fabricate a parallel tree for every intermediate component in that
--- layer). `o.guid` names an existing key instead of making a new one.
local function name_child(src, parent, name, layer, o)
    o = o or {}
    local per = src.store.entries[parent]
    if not per then per = {}; src.store.entries[parent] = per end
    local slot = per[lcs.fold(name)]
    if not slot then slot = { name = name, by_layer = {} }; per[lcs.fold(name)] = slot end
    local guid = o.guid or lcs.guid()
    if not src.store.keys[guid] then
        src.store.keys[guid] = {
            name = name, parent = parent, sd = o.sd or lcs.permissive_sd(),
            volatile = false, symlink = false, lwt = 0,
        }
    end
    slot.by_layer[lcs.fold(layer)] = {
        layer = layer, hidden = false, guid = guid, seq = o.seq or src:next_seq(),
    }
    return guid
end

-- One source, seeded before registration: entries that a normal
-- operation cannot create (hidden path entries, tombstones, entries in
-- a layer that does not exist) have to come from storage.
local src = lcs.source(vm)
local ROOT = src:key("Machine\\Software\\Test")
src:seed_layer("base")
src:seed_layer("low")                        -- precedence 0, like base
src:seed_layer("high", { precedence = 5 })
src:seed_layer("off", { precedence = 7, enabled = false })

local K = {}
K.winner = src:key("Machine\\Software\\Test\\Winner")
src:value(K.winner, "Tie", SZ, lcs.sz("base"))
src:value(K.winner, "Tie", SZ, lcs.sz("low"), { layer = "low" })      -- later, so higher sequence
src:value(K.winner, "Tier", SZ, lcs.sz("high"), { layer = "high" })
local TIER_HIGH_SEQ = src.seq
src:value(K.winner, "Tier", SZ, lcs.sz("base"))                      -- higher sequence, lower tier
local TIER_BASE_SEQ = src.seq

K.paths = src:key("Machine\\Software\\Test\\Paths")
local low_child = name_child(src, K.paths, "Which", "low")
local high_child = name_child(src, K.paths, "Which", "high")
src:value(low_child, "Marker", SZ, lcs.sz("low-key"))
src:value(high_child, "Marker", SZ, lcs.sz("high-key"))

K.latent = src:key("Machine\\Software\\Test\\Latent")
src:value(K.latent, "Both", SZ, lcs.sz("base"))
src:value(K.latent, "Both", SZ, lcs.sz("ghost"), { layer = "ghost" })  -- higher sequence
src:value(K.latent, "OnlyGhost", SZ, lcs.sz("ghost"), { layer = "ghost" })

K.inactive = src:key("Machine\\Software\\Test\\Inactive")
src:value(K.inactive, "V", SZ, lcs.sz("base"))
src:value(K.inactive, "V", SZ, lcs.sz("off"), { layer = "off" })

K.blanket = src:key("Machine\\Software\\Test\\Blanket")
src:value(K.blanket, "Masked", SZ, lcs.sz("base"))
src:value(K.blanket, "Later", SZ, lcs.sz("base"))
src:blanket(K.blanket, "high")
src:value(K.blanket, "Later", SZ, lcs.sz("high"), { layer = "high" })  -- after the blanket

K.masked = src:key("Machine\\Software\\Test\\Masked")
src:value(K.masked, "Tombstoned", SZ, lcs.sz("base"))
src:tombstone(K.masked, "Tombstoned", "high")
name_child(src, K.masked, "HiddenChild", "low")
src:hide(K.masked, "HiddenChild", "high")
name_child(src, K.masked, "PlainChild", "low")

K.enum = src:key("Machine\\Software\\Test\\Enum")
src:value(K.enum, "Visible", SZ, lcs.sz("v"))
src:value(K.enum, "Gone", SZ, lcs.sz("secret"))
src:tombstone(K.enum, "Gone", "high")
src:value(K.enum, "Alpha", SZ, lcs.sz("from-low"), { layer = "low" })
src:value(K.enum, "ALPHA", SZ, lcs.sz("from-high"), { layer = "high" })
name_child(src, K.enum, "Kid", "low")
name_child(src, K.enum, "KID", "high")

-- Two entries sharing one sequence number. Both numbers are ones this
-- source has legitimately persisted (below the maximum it reports), so
-- the only thing under test is the duplicate.
K.dup_same = src:key("Machine\\Software\\Test\\DupSame")
local DUP_SAME_SEQ = src:next_seq()
src:value(K.dup_same, "D", SZ, lcs.sz("base"), { seq = DUP_SAME_SEQ })
src:value(K.dup_same, "D", SZ, lcs.sz("low"), { layer = "low", seq = DUP_SAME_SEQ })

K.dup_tier = src:key("Machine\\Software\\Test\\DupTier")
local DUP_TIER_SEQ = src:next_seq()
src:value(K.dup_tier, "D", SZ, lcs.sz("base"), { seq = DUP_TIER_SEQ })
src:value(K.dup_tier, "D", SZ, lcs.sz("high"), { layer = "high", seq = DUP_TIER_SEQ })

K.future = src:key("Machine\\Software\\Test\\Future")
K.badname = src:key("Machine\\Software\\Test\\BadName")
src:value(K.badname, "Ok", SZ, lcs.sz("fine"))
src:value(K.badname, "Bad", SZ, lcs.sz("v"), { layer = "not\\a\\name" })

assert(src:register())
src:pump()
local NEXT_SEQUENCE = src.seq + 1   -- what LCS will allocate next
-- Entries LCS must reject as from the future: numbers it has not issued.
src:value(K.future, "Ahead", SZ, lcs.sz("v"), { seq = NEXT_SEQUENCE + 1000 })
src:value(K.future, "AheadInGhost", SZ, lcs.sz("v"),
    { layer = "ghost", seq = NEXT_SEQUENCE + 1001 })

local w = vm:spawn_worker()

local function open(t, path, access)
    local r = lcs.open_key(src, w, -1, path, access or lcs.KEY_ALL_ACCESS)
    t:assert(r.ret >= 0, "open " .. path .. ": " .. sys.errname(r.errno or 0))
    return r.ret
end

test("the winner is the maximum of (precedence, sequence), precedence first",
    { spec = "PKM *layer.resolution.winner-is-highest-precedence-then-highest-sequence" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Winner")
        local tie = lcs.query_value(src, w, fd, "Tie")
        t:assert_eq(tie.ret, 0, "query Tie: " .. sys.errname(tie.errno or 0))
        t:assert_eq(tie.layer, "low",
            "within one precedence tier the highest sequence number wins")
        local tier = lcs.query_value(src, w, fd, "Tier")
        t:assert_eq(tier.ret, 0, "query Tier: " .. sys.errname(tier.errno or 0))
        t:assert_eq(tier.layer, "high",
            "and precedence is compared first, so a higher tier wins over a higher sequence")
        t:assert_eq(tier.sequence, TIER_HIGH_SEQ,
            "the number returned is the winning precedence-5 entry's")
        t:assert(TIER_HIGH_SEQ < TIER_BASE_SEQ,
            "even though the losing base entry was written later and holds the higher number")
        sys.close(w, fd)
    end)

test("path entries and values resolve by the same algorithm",
    { spec = "PKM *layer.resolution.same-algorithm-for-path-entries-and-values" },
    function(t)
        -- Two layers name *different keys* at one path. The winner is
        -- the higher-precedence entry, exactly as for a value.
        local fd = open(t, "Machine\\Software\\Test\\Paths\\Which")
        local m = lcs.query_value(src, w, fd, "Marker")
        t:assert_eq(m.ret, 0, "query: " .. sys.errname(m.errno or 0))
        t:assert_eq(m.data, lcs.sz("high-key"),
            "the path resolved to the key the higher-precedence layer names")
        sys.close(w, fd)
    end)

test("an entry naming a layer that is not in the table is skipped, not rejected",
    { spec = "PKM *layer.resolution.entry-for-an-unknown-layer-is-skipped" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Latent")
        local q = lcs.query_value(src, w, fd, "Both")
        t:assert_eq(q.ret, 0, "the query still succeeds: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "base",
            "the entry in the absent layer is skipped even though it holds the " ..
            "higher sequence number")
        sys.close(w, fd)
    end)

test("entries from layers that are not active for this thread are discarded",
    { spec = "PKM *layer.resolution.inactive-layers-are-discarded" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Inactive")
        local q = lcs.query_value(src, w, fd, "V")
        t:assert_eq(q.ret, 0, "query: " .. sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "base",
            "a disabled layer is not active for a thread that does not name it, " ..
            "so its precedence-7 entry is discarded")
        sys.close(w, fd)
    end)

test("a blanket tombstone joins the candidate list at its own precedence and sequence",
    { spec = "PKM *layer.resolution.blanket-tombstones-join-the-candidate-list" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Blanket")
        local masked = lcs.query_value(src, w, fd, "Masked")
        t:assert_eq(masked.errno, sys.E.NOENT,
            "the blanket is a tombstone candidate for every name on the key")
        local later = lcs.query_value(src, w, fd, "Later")
        t:assert_eq(later.ret, 0, "but it is only a candidate: " .. sys.errname(later.errno or 0))
        t:assert_eq(later.layer, "high",
            "an entry at the same precedence with a higher sequence beats it")
        sys.close(w, fd)
    end)

test("no candidates is not-found",
    { spec = "PKM *layer.resolution.no-candidates-is-not-found" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Winner")
        local q = lcs.query_value(src, w, fd, "NobodyWroteThis")
        t:assert_eq(q.ret, -1, "a name no layer holds does not resolve")
        t:assert_eq(q.errno, sys.E.NOENT, "and the answer is not-found")
        sys.close(w, fd)
    end)

test("a winning HIDDEN entry, REG_TOMBSTONE value or blanket all mean not-found",
    { spec = "PKM *layer.resolution.winning-hidden-tombstone-or-blanket-is-not-found" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Masked")
        local tomb = lcs.query_value(src, w, fd, "Tombstoned")
        t:assert_eq(tomb.errno, sys.E.NOENT,
            "a winning REG_TOMBSTONE value entry means not-found")
        local hidden = lcs.open_key(src, w, -1,
            "Machine\\Software\\Test\\Masked\\HiddenChild", lcs.RIGHT.KEY_READ)
        t:assert_eq(hidden.errno, sys.E.NOENT,
            "a winning HIDDEN path entry means not-found")
        local blanketed = open(t, "Machine\\Software\\Test\\Blanket")
        local b = lcs.query_value(src, w, blanketed, "Masked")
        t:assert_eq(b.errno, sys.E.NOENT, "and a winning blanket means not-found")
        sys.close(w, blanketed)
        sys.close(w, fd)
    end)

test("an entry in a well-formed layer name that is absent is a valid latent entry",
    { spec = "PKM *layer.resolution.latent-entry-is-valid" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Latent")
        local q = lcs.query_value(src, w, fd, "OnlyGhost")
        t:assert_eq(q.errno, sys.E.NOENT,
            "it is ignored while its layer is absent — not-found, not an error")
        local ok = lcs.query_value(src, w, fd, "Both")
        t:assert_eq(ok.ret, 0,
            "and the response carrying it is not malformed: other names still resolve")
        sys.close(w, fd)
    end)

test("a layer-targeting ioctl naming an absent layer is ENOENT, so normal operations create no latent entries",
    { spec = "PKM *layer.resolution.normal-operations-do-not-create-latent-entries" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Winner")
        local mark = src:mark()
        local s = lcs.set_value(src, w, fd, "Nope", SZ, lcs.sz("v"), { layer = "absent-layer" })
        t:assert_eq(s.errno, sys.E.NOENT, "the write is refused rather than stored latently")
        t:assert_eq(#src:served(lcs.OP.SET_VALUE, mark), 0,
            "and the source is never asked to store it")
        sys.close(w, fd)
    end)

test("a latent entry becomes eligible when a layer of the same folded identity appears",
    { spec = "PKM *layer.resolution.latent-entry-becomes-eligible-when-the-layer-appears" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Latent")
        local before = lcs.query_value(src, w, fd, "OnlyGhost")
        t:assert_eq(before.errno, sys.E.NOENT, "absent to begin with")
        local lfd, e = lcs.create_layer(src, w, "GHOST", { precedence = 9 })
        t:assert(lfd, "creating the layer: " .. sys.errname(e or 0))
        local after = lcs.query_value(src, w, fd, "OnlyGhost")
        t:assert_eq(after.ret, 0, "the stored entry now resolves: " .. sys.errname(after.errno or 0))
        t:assert_eq(after.layer, "GHOST",
            "under the new metadata, matched by folded identity and spelled as created")
        local both = lcs.query_value(src, w, fd, "Both")
        t:assert_eq(both.layer, "GHOST", "and it now outranks the base entry it lost to")
        sys.close(w, lfd)
        sys.close(w, fd)
    end)

test("an entry whose layer name is malformed is rejected as malformed source data",
    { spec = "PKM *layer.resolution.malformed-layer-name-is-rejected" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\BadName")
        local bad = lcs.query_value(src, w, fd, "Bad")
        t:assert_eq(bad.errno, sys.E.IO,
            "a layer name that is not a well-formed name is not latent, it is malformed")
        sys.close(w, fd)
    end)

test("enumerating values returns only the names that resolve",
    { spec = "PKM *layer.resolution.enum-values-returns-only-resolved-names" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Enum")
        local names = {}
        for i = 0, 15 do
            local e = lcs.enum_values(src, w, fd, i)
            if e.ret ~= 0 then break end
            names[lcs.fold(e.name)] = e.name
        end
        t:assert(names["visible"], "a resolved name is enumerated")
        t:assert(not names["gone"],
            "a name whose winning entry is a tombstone is not, because it does not resolve")
        sys.close(w, fd)
    end)

test("enumerating subkeys returns the children that map to a GUID rather than HIDDEN",
    { spec = "PKM *layer.resolution.enum-subkeys-skips-hidden-children" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Masked")
        local names = {}
        for i = 0, 15 do
            local e = lcs.enum_subkeys(src, w, fd, i)
            if e.ret ~= 0 then break end
            names[lcs.fold(e.name)] = true
        end
        t:assert(names["plainchild"], "a child that resolves to a GUID is enumerated")
        t:assert(not names["hiddenchild"],
            "one whose winning entry is HIDDEN is not")
        sys.close(w, fd)
    end)

test("enumeration uniqueness is folded: names differing only in case are one name",
    { spec = "PKM *layer.resolution.enumeration-uniqueness-is-folded" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Enum")
        local alphas, kids = 0, 0
        for i = 0, 15 do
            local e = lcs.enum_values(src, w, fd, i)
            if e.ret ~= 0 then break end
            if lcs.fold(e.name) == "alpha" then alphas = alphas + 1 end
        end
        for i = 0, 15 do
            local e = lcs.enum_subkeys(src, w, fd, i)
            if e.ret ~= 0 then break end
            if lcs.fold(e.name) == "kid" then kids = kids + 1 end
        end
        t:assert_eq(alphas, 1, "`Alpha` and `ALPHA` are one value name")
        t:assert_eq(kids, 1, "`Kid` and `KID` are one child name")
        local b = lcs.query_values_batch(src, w, fd)
        t:assert_eq(b.ret, 0, "batch: " .. sys.errname(b.errno or 0))
        local seen = 0
        for _, v in ipairs(b.values) do
            if lcs.fold(v.name) == "alpha" then seen = seen + 1 end
        end
        t:assert_eq(seen, 1, "and the batch call agrees")
        sys.close(w, fd)
    end)

test("a caller sees effective state only",
    { spec = "PKM *layer.resolution.callers-see-effective-state-only" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Enum")
        local gone = lcs.query_value(src, w, fd, "Gone")
        t:assert_eq(gone.errno, sys.E.NOENT,
            "the base-layer data under a tombstone is simply absent")
        local b = lcs.query_values_batch(src, w, fd)
        t:assert_eq(b.ret, 0, "batch: " .. sys.errname(b.errno or 0))
        for _, v in ipairs(b.values) do
            t:assert(lcs.fold(v.name) ~= "gone", "and no normal operation exposes it")
            if lcs.fold(v.name) == "alpha" then
                t:assert_eq(v.data, lcs.sz("from-high"),
                    "only the winning entry's data is returned, never the per-layer set")
            end
        end
        sys.close(w, fd)
    end)

test("index-based enumeration re-resolves the whole set at every index",
    { spec = "PKM *layer.resolution.enumeration-re-resolves-at-every-index" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Enum")
        local mark = src:mark()
        local n = 0
        for i = 0, 15 do
            local e = lcs.enum_values(src, w, fd, i)
            if e.ret ~= 0 then break end
            n = n + 1
        end
        local rounds = #src:served(lcs.OP.QUERY_VALUES, mark, K.enum)
        t:assert(n >= 2, "the key has several effective values")
        t:assert(rounds >= n,
            "walking 0..N-1 performs N full resolutions, not one — " ..
            n .. " indices cost " .. rounds .. " resolutions")
        sys.close(w, fd)
    end)

test("REG_IOC_QUERY_VALUES_BATCH returns the whole effective set in one resolution",
    { spec = "PKM *layer.resolution.batch-query-resolves-the-whole-set-once" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Enum")
        local mark = src:mark()
        local b = lcs.query_values_batch(src, w, fd)
        t:assert_eq(b.ret, 0, "batch: " .. sys.errname(b.errno or 0))
        t:assert(b.count >= 2, "the whole effective value set comes back at once")
        t:assert_eq(#src:served(lcs.OP.QUERY_VALUES, mark, K.enum), 1,
            "in one resolution")
        sys.close(w, fd)
    end)

test("enumeration order is undefined and indices must not be cached across mutations",
    { spec = "PKM *layer.resolution.enumeration-order-is-undefined" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Enum")
        local first = lcs.enum_values(src, w, fd, 0)
        t:assert_eq(first.ret, 0, "index 0: " .. sys.errname(first.errno or 0))
        local s = lcs.set_value(src, w, fd, "AAAFirst", SZ, lcs.sz("v"))
        t:assert_eq(s.ret, 0, "a value is added: " .. sys.errname(s.errno or 0))
        local again = lcs.enum_values(src, w, fd, 0)
        t:assert_eq(again.ret, 0, "index 0 again: " .. sys.errname(again.errno or 0))
        t:assert(again.name ~= first.name,
            "the index-to-entry mapping changed when the effective set did")
        sys.close(w, fd)
    end)

test("a source-returned sequence at or above the next one LCS would allocate is malformed",
    { spec = "PKM *layer.resolution.future-sequence-number-is-malformed" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Future")
        local q = lcs.query_value(src, w, fd, "Ahead")
        t:assert_eq(q.errno, sys.E.IO,
            "a source cannot legitimately hold a number LCS has not issued")
        sys.close(w, fd)
    end)

test("every entry in a response is sequence-checked, whatever layer it names",
    { spec = "PKM *layer.resolution.every-entry-in-a-response-is-sequence-checked" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Future")
        local q = lcs.query_value(src, w, fd, "AheadInGhost")
        t:assert_eq(q.errno, sys.E.IO,
            "an entry naming a layer that is not even in the table is checked too")
        sys.close(w, fd)
    end)

test("a sequence validation failure is EIO and an LCS_SOURCE_VALIDATION_FAILURE audit event",
    { spec = "PKM *layer.resolution.sequence-validation-failure-is-eio" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\Future")
        local q
        local events = kmes.recording(t, vm, function()
            q = lcs.query_value(src, w, fd, "Ahead")
        end)
        t:assert_eq(q.errno, sys.E.IO, "the caller sees EIO")
        t:assert(#kmes.of_type(events, "LCS_SOURCE_VALIDATION_FAILURE") >= 1,
            "and LCS emits an LCS_SOURCE_VALIDATION_FAILURE audit event")
        sys.close(w, fd)
    end)

test("duplicate sequence numbers that would have to be compared are malformed",
    { spec = "PKM *layer.resolution.compared-duplicate-sequences-are-malformed" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\DupSame")
        local q = lcs.query_value(src, w, fd, "D")
        t:assert_eq(q.errno, sys.E.IO,
            "two entries at the same precedence with one sequence number leave no " ..
            "defensible winner, so LCS rejects the response rather than choosing")
        sys.close(w, fd)
    end)

test("duplicate sequence numbers that never get compared are not an error",
    { spec = "PKM *layer.resolution.uncompared-duplicate-sequences-are-not-an-error" },
    function(t)
        local fd = open(t, "Machine\\Software\\Test\\DupTier")
        local q = lcs.query_value(src, w, fd, "D")
        t:assert_eq(q.ret, 0, "precedence decides before sequence is looked at: " ..
            sys.errname(q.errno or 0))
        t:assert_eq(q.layer, "high", "and the higher tier wins")
        sys.close(w, fd)
    end)
