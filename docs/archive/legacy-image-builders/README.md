# Historical image recipes

These files preserve the image builders and signing recipes imported from
integration-tests commit `a9aeaa2d6255bf59034ac5d90bee871a0d4829be`.
They depend on retired Pekit and `.peipkg` composition. They are not runnable
entry points for the maintained qualification workflow.

Use these recipes to identify guest fixtures, service configuration, boot
arguments, and trust-policy requirements when supplying test images. The
maintained runner consumes supplied artifacts and never invokes these files.
`original-readme.md` preserves the source repository's original instructions.

Component fixture sources live with their owning suites. Connecting a PPK
image composer is separate work; these recipes do not implement one.
