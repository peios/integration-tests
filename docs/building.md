# Building and Checking the Integration Tests

Use pekit to run the qualification runner's own tests. The supported
development host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first run: the Bootlin C toolchain's sysroot, Python 3.14, busybox,
and Git 2.56.0, which pekit builds from its pinned source. The first run
needs network access; later runs find what they need in pekit's store, and
the test runs without network access in a sandbox that holds only its
declared inputs.

The build files use the gcslib libraries named in `workspace.gcsl` and the
build files. `pekit lock` pins their commits in `pekit.lock`.

## Test

```sh
pekit test
```

| Test | Check |
|---|---|
| `runner` | The runner's unit tests in `checks/`: source pinning, artifact staging, deadlines, and result completeness |

The tests make their own Git repositories and stand-in runners in a
temporary directory. A test whose inputs did not change is found in the
store and not run again. These checks do not run a suite against a Peios
image; see the run guide for native runs.

## Style

Install the pinned PSC tools into a directory outside the repository, then
run the shared entry point:

```sh
python3 tools/prepare-style-tools.py "$HOME/.cache/integration-tests-style"
export PEIOS_STYLE_BIN="$HOME/.cache/integration-tests-style/bin"
tools/check
```

`tools/check` checks owned source formatting and lint with Ruff,
ShellCheck, shfmt, and Prettier, then runs `pekit test`. Ruff reads
`pyproject.toml` and Prettier reads `.prettierrc.json`. The tool versions
and hashes are recorded in `tools/style-tools.lock.json`. GitHub's
workflow runs the style checks alone; tests run with pekit on the build
server.
