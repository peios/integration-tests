-- PEI-540: exercise the live image's StrataFS destination with real tools.
-- The unsupported install applet is deliberately outside this matrix.
local peinit = require('helpers.peinit')
peinit.claim(1)
local vm = peinit.boot()
test('copy into the live lcl view', function(t)
    local r = vm:run([[set -eu
mkdir -p /lcl/pei540 /tmp/pei540
# 139177 bytes, matching the reported firmware file's length.
head -c 139177 /bin/peiosutils > /tmp/pei540/source
for source in /bin/peiosutils /usr/bin/peiosutils /tmp/pei540/source; do
  if test -f "$source"; then
    cp "$source" /lcl/pei540/copied
    cmp "$source" /lcl/pei540/copied
    cp --reflink=never "$source" /lcl/pei540/no-reflink
    cmp "$source" /lcl/pei540/no-reflink
    cp --sparse=never "$source" /lcl/pei540/no-sparse
    cmp "$source" /lcl/pei540/no-sparse
    dd if="$source" of=/lcl/pei540/dd-copy bs=65536
    cmp "$source" /lcl/pei540/dd-copy
  fi
done
cp /tmp/pei540/source /tmp/pei540/move
mv /tmp/pei540/move /lcl/pei540/moved
cmp /tmp/pei540/source /lcl/pei540/moved
]])
    t:log(r.stdout or '')
    t:log(r.stderr or '')
    t:assert_eq(r.exit_code, 0, 'copy variants preserve contents')
end)
