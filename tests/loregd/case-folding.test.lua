-- loregd §3.4 — names are case-insensitive but case-preserving, implemented
-- by storing a folded form beside the written one and comparing the folded
-- forms as bytes.
--
-- The observable half is reachable end to end through `reg`/LCS: create a key
-- with one case, look it up with another, and see the stored case come back.
-- The mechanism (a `_folded` column, no SQLite collation, the exact
-- CaseFolding.txt table and the fold-vs-lowercase divergence) is internal and
-- homed on internal/fold and internal/handler unit tests, each read and run
-- (all PASS; TestMatchesCaseFoldingTxt run with CASEFOLDING_TXT set) before
-- citing. One file-scope loregd serves PtState for the reachable cases.

local loregd = require("helpers.loregd")

local vm = loregd.boot({ name = "loregd-fold" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm)

-- §3.4: "Key names and value names are case-insensitive but case-preserving."
-- / "The canonical name is what comes back in responses, so callers see the
-- case they originally supplied while storage compares the folded form."
-- Create with one case; a different-case lookup resolves it, and enumeration
-- returns the stored (canonical) case.
test("names are case-insensitive but case-preserving", {
    spec = "loregd *fold.key-and-value-names-are-case-insensitive-but-case-preserving " ..
        "*fold.responses-return-the-case-the-caller-supplied",
}, function(t)
    loregd.new_key(vm, [[PtState\FoldA\MixedName]]):assert_ok()

    -- Case-insensitive: a differently-cased spelling finds the same key.
    local hit = vm:run("reg ls 'PtState\\FoldA\\MIXEDNAME'")
    t:assert_eq(hit.exit_code, 0,
        "a different-case spelling resolves the key (folded comparison): " .. hit.stderr)

    -- Case-preserving: RSI_ENUM_CHILDREN returns the stored child_name, which
    -- is the canonical case the creator supplied — not the case just queried.
    local ls = vm:run("reg ls 'PtState\\FoldA' --keys-only")
    ls:assert_ok()
    t:assert(ls.stdout:match("MixedName/"),
        "the response carries the case the caller originally supplied at " ..
        "creation, 'MixedName': " .. ls.stdout)
end)

-- §3.4: "The folded form is Unicode Simple Case Folding: each codepoint is
-- replaced by its status C or S mapping from CaseFolding.txt" / "loregd must
-- produce byte-identical results [to the kernel], because a name the two fold
-- differently is a key that exists for one side and not the other."
--
-- Greek Σ (U+03A3) and final sigma ς (U+03C2) both fold to σ (U+03C3), so a
-- key created as Σ is found by a lookup for ς. This is the spec's own worked
-- example of why folding is not lowercasing: Go's ToLower leaves ς unchanged,
-- so "a key stored as Σ is not found by a lookup for ς" under lowercasing.
-- The lookup travels Caller -> kernel -> loregd, so its success also shows the
-- two sides fold these codepoints identically — otherwise the key would exist
-- for one and not the other.
test("folding is Unicode Simple Case Folding, byte-identical to the kernel", {
    spec = "loregd *fold.folding-is-unicode-simple-case-folding-status-c-and-s " ..
        "*fold.loregd-must-fold-byte-identically-to-the-kernel",
}, function(t)
    loregd.new_key(vm, "PtState\\Greek\\Σ"):assert_ok()

    -- Look the key up by the final-sigma spelling; both fold to σ.
    local hit = vm:run("reg info 'PtState\\Greek\\ς'")
    t:assert_eq(hit.exit_code, 0,
        "the key created as Σ is found by a lookup for ς — both fold to σ under " ..
        "Unicode Simple Case Folding, whereas lowercasing would leave ς distinct " ..
        "and the lookup would miss: " .. hit.stderr)

    -- And enumeration returns the stored capital-sigma spelling.
    local ls = vm:run("reg ls 'PtState\\Greek' --keys-only")
    ls:assert_ok()
    t:assert(ls.stdout:match("Σ/"),
        "the canonical Σ spelling is preserved in the response: " .. ls.stdout)
end)

-- §3.4: "Hive names are folded too, though not stored: routing a request to a
-- hive and rejecting duplicate hive declarations (§2.1) both compare folded
-- names."
test("hive names are folded for routing and duplicate rejection", {
    spec = "loregd *fold.hive-names-are-folded-but-never-stored " ..
        "*fold.hive-routing-and-duplicate-rejection-compare-folded-names",
}, function(t)
    -- Routing folds the hive name: a differently-cased hive name reaches the
    -- same served hive.
    local route = vm:run("reg ls PTSTATE")
    t:assert_eq(route.exit_code, 0,
        "the request for PTSTATE routed to the PtState hive (folded routing): " ..
        route.stderr)

    -- Duplicate rejection folds too: two hive declarations whose names fold
    -- together are refused at startup (§2.1). loregd.spawn does not wait — the
    -- process is expected to fail before it ever registers.
    local proc = loregd.spawn(vm, {
        "Dup=/mnt/pt-hive/dup1.hive", "DUP=/mnt/pt-hive/dup2.hive",
    })
    local r = proc:wait("10s")
    t:assert(r.exit_code ~= 0,
        "loregd refused two hive names that fold to the same thing (Dup vs DUP) " ..
        "rather than serving both. stderr=" .. tostring(r.stderr))
    t:assert(tostring(r.stderr):match("[Dd]uplicate"),
        "and it said so: " .. tostring(r.stderr))
end)

-- ---- unit-cited: internal fold mechanism, no guest route -------------

test("both the written and folded forms are stored", {
    spec = "loregd *fold.both-the-written-and-folded-forms-are-stored",
    skip = true,
    -- name and name_folded are internal columns. TestRootKeyProperties reads
    -- both back from a real row (name="Machine", name_folded="machine").
    covered_by = "go:loregd internal/hivedb::TestRootKeyProperties",
}, function() end)

test("the folded form is computed once and is what every comparison uses", {
    spec = "loregd *fold.the-folded-form-is-computed-once-and-is-what-every-comparison-uses",
    skip = true,
    -- fold.String is applied at write time to produce the _folded columns, and
    -- every lookup compares those columns. TestLookupCaseInsensitive stores a
    -- key and finds it by a different case, exercising the folded-column
    -- comparison; the write-time folding is fold.String (internal).
    covered_by = "go:loregd internal/handler::TestLookupCaseInsensitive",
}, function() end)

test("lookups are plain binary comparisons", {
    spec = "loregd *fold.lookups-are-plain-binary-comparisons",
    skip = true,
    -- WHERE child_name_folded = ? is a byte comparison of pre-folded values.
    -- TestLookupCaseInsensitive proves the folded-column lookup resolves a
    -- differently-cased query without any collation involved.
    covered_by = "go:loregd internal/handler::TestLookupCaseInsensitive",
}, function() end)

test("no custom SQLite collation is registered", {
    spec = "loregd *fold.no-custom-sqlite-collation-is-registered",
    skip = true,
    -- A negative that is not guest-observable: loregd registers no collation
    -- (hivedb.openConn installs none) because case-insensitivity is already
    -- done in the folded columns. TestLookupCaseInsensitive shows the
    -- case-insensitive match happening purely through the pre-folded column
    -- comparison, which is what makes a collation unnecessary.
    covered_by = "go:loregd internal/handler::TestLookupCaseInsensitive",
}, function() end)

test("layer names are not folded", {
    spec = "loregd *fold.layer-names-are-not-folded",
    skip = true,
    -- Unlike key/value names, layer names keep their case. A guest sees only
    -- the kernel's resolved value. TestBlanketTombstonesAreReturnedInACanonical
    -- Order stores layer "MIDDLE" and returns it verbatim ("MIDDLE/20"), which
    -- folding would collapse to "middle"; the folded form is used only for
    -- ordering.
    covered_by = "go:loregd internal/handler::TestBlanketTombstonesAreReturnedInACanonicalOrder",
}, function() end)

test("the fold is not derived from the Go standard library", {
    spec = "loregd *fold.the-fold-is-not-derived-from-the-go-standard-library",
    skip = true,
    -- The 222-codepoint divergence between Simple Case Folding and Go's
    -- unicode.ToLower is exhaustively pinned by TestLowercasingIsNotFolding
    -- (Cherokee folding towards uppercase, Greek final sigma and symbol
    -- variants, Cyrillic historic letters, Garay, etc.). A guest sees only one
    -- representative (Σ/ς, above); the full divergence is unit territory.
    covered_by = "go:loregd internal/fold::TestLowercasingIsNotFolding",
}, function() end)

test("the table is generated by the kernel's own generator", {
    spec = "loregd *fold.the-table-is-generated-by-the-kernels-own-generator",
    skip = true,
    -- Build provenance is not guest-observable. casefold_table.go records the
    -- generator (pkm/tools/lcs/generate_casefold_table.py), the source (Unicode
    -- 16.0.0 CaseFolding.txt) and its SHA-256. TestTableIsComplete checks the
    -- table against the count the generator recorded; TestMatchesCaseFoldingTxt
    -- checks every scalar against CaseFolding.txt itself (run here with
    -- CASEFOLDING_TXT set — PASS).
    covered_by = "go:loregd internal/fold::TestTableIsComplete",
}, function() end)

test("columns written before September 2026 used lowercasing", {
    spec = "loregd *fold.columns-written-before-september-2026-used-lowercasing",
    skip = true,
    -- Historical: data written by the retired lowercasing-plus-three-fixes
    -- implementation cannot be produced by current loregd, so there is no
    -- guest route. TestLowercasingIsNotFolding pins exactly the 222 codepoints
    -- on which those old folded columns differ from the current rule.
    covered_by = "go:loregd internal/fold::TestLowercasingIsNotFolding",
}, function() end)
