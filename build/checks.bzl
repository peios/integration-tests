"""Python host checks with explicit source inputs; VM runs use supplied artifacts."""

def _host_test_impl(ctx):
    launcher = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(launcher, """#!/bin/sh
set -eu
cd "${RUNFILES_DIR:-$0.runfiles}/%s"
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -m unittest discover -s checks -v
""" % ctx.workspace_name, is_executable = True)
    return [DefaultInfo(executable = launcher, runfiles = ctx.runfiles(files = ctx.files.srcs))]

host_test = rule(
    implementation = _host_test_impl,
    attrs = {"srcs": attr.label_list(allow_files = True)},
    test = True,
)
