-- loregd §5.2 (Response Ordering) — the canonical wire order loregd imposes
-- on every enumeration array so the kernel's dense-index walk is stable.
--
-- What a guest can see, and what it cannot:
--
--   * The kernel walks RSI_ENUM_CHILDREN results by dense index across
--     repeated, independent calls, and it surfaces the child *set* to a
--     caller. So the child order and the reported display-name case ARE
--     observable end to end: `reg ls <parent>` repeated returns the children
--     in loregd's canonical folded-name order, the same order and the same
--     names every time. That is the one VM case below.
--
--   * Everything else in this chapter is loregd's raw *wire* order that the
--     kernel resolves away before any caller sees it: the per-entry
--     (layer, sequence) order inside a LOOKUP or a child block, the
--     (folded-name, layer, sequence) order of QUERY_VALUES entries, the
--     (folded-layer, sequence) order of the blanket-tombstone array, the
--     bytewise order of a DELETE_LAYER orphan array, and the ascending-GUID
--     order of a key-metadata block. Layer resolution selects a maximum, not
--     a first match (§5.2: "wire-stability guarantee only ... the kernel
--     selects a maximum"), so a guest observes resolved values, never the
--     ordered array. Those anchors are homed on the internal determinism
--     suite (internal/handler/determinism_test.go and the enum-order
--     regression in handler_test.go), each read and run — all PASS — before
--     citing. The (layer,sequence) / (folded,layer,sequence) / metadata-GUID
--     sorts are produced by the same canonicalisation pass those tests drive
--     (handler.go sortPathEntries / sortedGUIDs, values.go queryValueEntries),
--     though loregd carries no dedicated multi-row assertion for each — see
--     the ledger note to the coordinator.

local loregd = require("helpers.loregd")

local vm = loregd.boot({ name = "loregd-ordering" })
loregd.format(vm)
loregd.mount(vm)
loregd.start(vm) -- one daemon for the whole file; no restart needed here

-- Child names in enumeration order out of `reg ls <parent> --keys-only`,
-- which prints one "Name/" per child in the order loregd returned them.
local function ls_names(parent)
    local r = vm:run("reg ls '" .. parent .. "' --keys-only")
    local names = {}
    for n in r.stdout:gmatch("([%w]+)/") do names[#names + 1] = n end
    return names, r
end

local function same(a, b)
    if #a ~= #b then return false end
    for i = 1, #a do if a[i] ~= b[i] then return false end end
    return true
end

local function show(t) return "[" .. table.concat(t, ", ") .. "]" end

-- ==== reachable: enumeration order and reported case are stable =========

-- §5.2: "RSI_ENUM_CHILDREN children [are sorted by] folded child name." And:
-- "Both the order of children and the case of the name reported for each are
-- therefore stable across calls." Children are created out of order and in
-- mixed case; every `reg ls` returns them in the same folded-name order with
-- the same reported case.
test("reg ls returns children in a stable, folded-name order", {
    spec = "loregd *order.enum-children-sorts-children-by-folded-name " ..
        "*order.child-order-and-reported-case-are-both-stable-across-calls",
}, function(t)
    local parent = [[PtState\Enum]]
    -- Deliberately created out of alphabetical order and in mixed case.
    for _, name in ipairs({ "Zulu", "alpha", "Mike", "bravo" }) do
        loregd.new_key(vm, parent .. "\\" .. name):assert_ok()
    end

    -- Folded order: alpha < bravo < mike < zulu; the display name keeps the
    -- case each was created with.
    local want = { "alpha", "bravo", "Mike", "Zulu" }

    local first, r = ls_names(parent)
    r:assert_ok()
    t:assert(same(first, want),
        "children enumerate in canonical folded-name order: got " ..
        show(first) .. ", want " .. show(want) .. "\n" .. r.stdout)

    -- Repeated calls must be byte-identical: same order, same reported case.
    -- An unstable UNION ALL would make the kernel's dense-index walk drop or
    -- duplicate entries.
    for call = 2, 4 do
        local again = ls_names(parent)
        t:assert(same(again, first),
            "call " .. call .. " order/case differs from the first: got " ..
            show(again) .. ", first " .. show(first))
    end
end)

-- ==== unit-cited: raw wire order the kernel resolves away ===============

-- §5.2: "The queries backing enumerations and lookups carry no ORDER BY ...
-- That order is not stable across calls." / "loregd therefore sorts every
-- affected array into a canonical order before encoding a response." /
-- "RSI_ENUM_CHILDREN groups rows by child_name_folded and emits one child
-- block per folded name." The premise (unordered UNION ALL) and the response
-- (a stable, deduplicated, folded-name-ordered child list) are exactly what
-- TestEnumChildrenDeterministicOrder asserts: children inserted out of order,
-- one of them present in two layers, enumerate as one block each in a fixed
-- order that is byte-identical across 50 calls. Not separately guest-visible
-- beyond the reachable case above (the kernel surfaces the resolved set).
test("enumeration imposes a canonical order over an unordered union", {
    spec = "loregd *order.the-underlying-query-order-is-not-stable-across-calls" ..
        " *order.every-affected-array-is-sorted-into-a-canonical-order" ..
        " *order.enum-children-emits-one-child-block-per-folded-name",
    skip = true,
    covered_by = "go:loregd internal/handler::TestEnumChildrenDeterministicOrder",
}, function() end)

-- §5.2: "Where two rows share a folded name but differ in stored case — Foo
-- in one store and FOO in the other — the display name emitted is the lower
-- of the two bytewise." Constructing two stored cases for one folded name
-- needs the same child in two stores/layers, which a guest cannot arrange
-- (the entry cross-schema guard rejects the same triple in both stores, and
-- non-base layers are not guest-reachable). TestEnumChildrenReportsAStableNameCase
-- seeds FOO (base) and Foo (vendor) and asserts the emitted name is "FOO"
-- (bytewise lower), stable across 50 calls.
test("the display name is the bytewise lower of the stored cases", {
    spec = "loregd *order.the-display-name-is-the-bytewise-lower-of-the-stored-cases",
    skip = true,
    covered_by = "go:loregd internal/handler::TestEnumChildrenReportsAStableNameCase",
}, function() end)

-- §5.2 (per-entry order, LOOKUP): "RSI_LOOKUP path entries [sorted by] layer,
-- then sequence." Implemented by handler.go sortPathEntries (handler.go:320),
-- the identical function TestEnumChildrenDeterministicOrder drives through
-- enum's per-child block (handler.go:595). The kernel resolves a lookup to
-- the winning target, so the multi-entry wire order is never guest-visible.
test("lookup path entries sort by layer then sequence", {
    spec = "loregd *order.lookup-path-entries-sort-by-layer-then-sequence",
    skip = true,
    covered_by = "go:loregd internal/handler::TestEnumChildrenDeterministicOrder",
}, function() end)

-- §5.2 (per-entry order, ENUM_CHILDREN): "RSI_ENUM_CHILDREN per-child entries
-- [sorted by] layer, then sequence." Same sortPathEntries call, applied per
-- child block (handler.go:595) by the handler TestEnumChildrenDeterministicOrder
-- exercises. Resolved away before a caller sees a child's entries.
test("enum-children per-child entries sort by layer then sequence", {
    spec = "loregd *order.enum-children-per-child-entries-sort-by-layer-then-sequence",
    skip = true,
    covered_by = "go:loregd internal/handler::TestEnumChildrenDeterministicOrder",
}, function() end)

-- §5.2 (per-entry order, QUERY_VALUES): "RSI_QUERY_VALUES value entries
-- [sorted by] folded value name, then layer, then sequence." Implemented by
-- values.go queryValueEntries (values.go:97). TestBlanketTombstonesAreReturnedInACanonicalOrder
-- drives handleQueryValues and its comment states the blanket list "uses the
-- same key the value entries beside them use" — i.e. the value entries are
-- already canonicalised by that sort. LCS returns resolved values
-- (REG_IOC_QUERY_VALUES batch carries no layer/sequence), so the wire order
-- is not guest-observable.
test("query-values entries sort by folded name then layer then sequence", {
    spec = "loregd *order.query-values-entries-sort-by-folded-name-then-layer-then-sequence",
    skip = true,
    covered_by = "go:loregd internal/handler::TestBlanketTombstonesAreReturnedInACanonicalOrder",
}, function() end)

-- §5.2: "RSI_QUERY_VALUES blanket tombstones [sorted by] folded layer name,
-- then sequence" and "The blanket-tombstone array ... comes from its own
-- UNION ALL ... and takes the same order they do." /
-- "Two of those arrays are ... assembled first and sorted afterwards."
-- TestBlanketTombstonesAreReturnedInACanonicalOrder inserts blankets out of
-- order, split across both stores, and asserts (folded-layer, sequence)
-- order — the same key the value entries use — byte-stable across 50 calls.
test("the blanket-tombstone array is assembled then sorted by folded layer, sequence", {
    spec = "loregd *order.query-values-blanket-tombstones-sort-by-folded-layer-name-then-sequence" ..
        " *order.the-blanket-tombstone-array-takes-the-same-order-as-the-value-entries" ..
        " *order.two-arrays-are-assembled-first-and-sorted-afterwards",
    skip = true,
    covered_by = "go:loregd internal/handler::TestBlanketTombstonesAreReturnedInACanonicalOrder",
}, function() end)

-- §5.2: "RSI_DELETE_LAYER orphan GUIDs [sorted by] ascending GUID, compared
-- bytewise" and "The orphan-GUID array ... is the concatenation of every
-- registered hive's orphan set. That walk ranges a Go map, whose iteration
-- order is randomised, so the array is sorted bytewise before it is encoded."
-- TestDeleteLayerOrphansAreReturnedInByteOrder seeds one orphan per hive so
-- hive order and byte order disagree, and asserts ascending byte order. There
-- is no REG_IOC_DELETE_LAYER in the uapi, so this is not guest-drivable.
test("the orphan-GUID array is sorted bytewise before it is encoded", {
    spec = "loregd *order.delete-layer-orphan-guids-sort-by-ascending-guid" ..
        " *order.the-orphan-guid-array-is-sorted-bytewise-before-it-is-encoded",
    skip = true,
    covered_by = "go:loregd internal/handler::TestDeleteLayerOrphansAreReturnedInByteOrder",
}, function() end)

-- §5.2: "Key-metadata blocks, in any response [sorted by] ascending GUID,
-- compared bytewise." Implemented by handler.go sortedGUIDs (handler.go:33),
-- called when a LOOKUP/ENUM_CHILDREN response builds its metadata block
-- (handler.go:332, :618) — the pass TestEnumChildrenDeterministicOrder runs.
-- The kernel consumes the metadata block internally; a caller never sees it.
test("key-metadata blocks sort by ascending GUID", {
    spec = "loregd *order.key-metadata-blocks-sort-by-ascending-guid",
    skip = true,
    covered_by = "go:loregd internal/handler::TestEnumChildrenDeterministicOrder",
}, function() end)

-- §5.2: "This ordering is a wire-stability guarantee only. It has no bearing
-- on layer resolution, which is order-independent — the kernel selects a
-- maximum, not a first match." The determinism suite exists precisely because
-- the order matters only for the dense-index walk, not for resolution
-- (handler.go:23-30, :46). Not a guest-observable behaviour: the guarantee is
-- about wire reproducibility, which the kernel consumes, not the caller.
test("the ordering is a wire-stability guarantee only", {
    spec = "loregd *order.the-ordering-is-a-wire-stability-guarantee-only",
    skip = true,
    covered_by = "go:loregd internal/handler::TestEnumChildrenDeterministicOrder",
}, function() end)
