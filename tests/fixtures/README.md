# Test fixtures

## `ext2-nofiletype.img`

A 1 MiB ext2 filesystem **without the `filetype` feature**, so its
directory entries carry no type and `readdir` reports `DT_UNKNOWN`. No
filesystem the kernel-only VM can create itself does that — tmpfs,
ramfs and the rest all fill `d_type` in from the inode mode — and
PKM §4.3.4 requires stratafs to propagate `DT_UNKNOWN` unchanged.

It doubles as a provider whose objects carry **no Peios security
descriptors**, since it was built outside Peios entirely. Nothing the
VM can build has that property either: a filesystem mounted at runtime
cannot be populated under the deny-missing class, and one populated
under a synthesising class keeps a readable descriptor afterwards.

Rebuild it with:

```sh
mkdir -p src/stratum/sub
printf 'from the image\n' > src/stratum/from_image
printf 'nested\n'         > src/stratum/sub/nested
printf 'x\n'              > src/stratum/another
mke2fs -q -F -t ext2 -O ^filetype -b 1024 -N 64 -d src ext2-nofiletype.img 1024
```

Check the feature is absent with `dumpe2fs -h ext2-nofiletype.img`:
`filetype` must not appear in `Filesystem features`.

The VM has no virtio-blk, so `helpers/image.lua` pushes the image into
the guest and attaches it to a loop device rather than using
`vm:attach_disk`.
