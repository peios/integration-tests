# pt-hook.sh — the scripted-hook library, staged at /fixtures/pt-hook.sh.
#
# Sourced by every hook this profile stages, and available to any hook a
# test injects with `files`. It does two things.
#
# **It reports.** Everything a test needs to know about a hook run goes to
# stderr as one line, which prelude's console carries and provium captures
# even when the boot goes on to halt:
#
#   pt|<hook>|pass=2|pid=57|cwd=/|argc=0|arg0=/usr/libexec/…|env=PATH=…,TERM=linux,|spec=defer:2
#   pt|<hook>|outcome=deferred
#
# The console is the oracle rather than a file on the real root because a
# hook runs before there is a real root to write to, and because half the
# behaviour worth testing ends with prelude halting, at which point no
# file anywhere is reachable.
#
# **It obeys the kernel command line.** A hook's behaviour comes from
# `pt.<hook>=<spec>`, so one initramfs covers every scenario and a test
# chooses between them with `kernel_cmdline_append` instead of a rebuild:
#
#   ok            exit 0 — satisfied (the default when no spec is given)
#   decline       exit 69
#   defer         exit 75, every time: the hook that never becomes ready
#   defer:<n>     exit 75 until the n-th run, then act and exit 0
#   fail          exit 1
#   fail:<code>   exit <code> — for the codes prelude must treat as failure
#   signal        SIGTERM itself: killed by a signal, never an exit code
#   sleep:<secs>  sleep, then exit 0
#
# Sourced, not executed: `$#` and `$0` are the hook's own, which is how
# the argv prelude passes gets reported.
PT_ARGC=$#
PT_ARG0=$0

# The last occurrence of `<key>=` on the kernel command line, empty when
# absent. Last wins, matching the kernel's own handling of a repeated
# parameter, so a test can append a spec that overrides the profile's.
pt_cmdline_value() {
    pt_key=$1
    pt_val=
    for pt_tok in $(cat /proc/cmdline); do
        case "$pt_tok" in
            "$pt_key"=*) pt_val="${pt_tok#*=}" ;;
        esac
    done
    printf '%s' "$pt_val"
}

# One report line. Fields are `key=value`, pipe-separated, hook name first.
pt_mark() {
    pt_name=$1
    shift
    pt_line="pt|$pt_name"
    for pt_f in "$@"; do
        pt_line="$pt_line|$pt_f"
    done
    echo "$pt_line" >&2
}

# How many times this hook has run, this boot. Kept in the initramfs
# rather than in the hook, because a deferred hook is a fresh process
# each time it is retried and the count is exactly what a test asserting
# on the re-queue loop needs.
pt_pass() {
    mkdir -p /run/pt
    pt_n=$(cat "/run/pt/$1.n" 2>/dev/null || echo 0)
    pt_n=$((pt_n + 1))
    echo "$pt_n" > "/run/pt/$1.n"
    printf '%s' "$pt_n"
}

# Report this run and act on its spec. Returns only when the hook should
# go on to do its work; every other spec exits from here.
pt_gate() {
    pt_hook=$1
    pt_this=$(pt_pass "$pt_hook")
    pt_spec=$(pt_cmdline_value "pt.$pt_hook")
    [ -n "$pt_spec" ] || pt_spec=ok
    pt_mark "$pt_hook" "pass=$pt_this" "pid=$$" "cwd=$(pwd)" \
        "argc=$PT_ARGC" "arg0=$PT_ARG0" "env=$(env | tr '\n' ',')" \
        "spec=$pt_spec"
    case "$pt_spec" in
        ok) ;;
        decline)
            pt_mark "$pt_hook" outcome=declined
            exit 69
            ;;
        defer)
            pt_mark "$pt_hook" outcome=deferred
            exit 75
            ;;
        defer:*)
            if [ "$pt_this" -lt "${pt_spec#defer:}" ]; then
                pt_mark "$pt_hook" outcome=deferred
                exit 75
            fi
            ;;
        fail)
            pt_mark "$pt_hook" outcome=failed code=1
            exit 1
            ;;
        fail:*)
            pt_mark "$pt_hook" outcome=failed "code=${pt_spec#fail:}"
            exit "${pt_spec#fail:}"
            ;;
        signal)
            pt_mark "$pt_hook" outcome=signalled
            kill -TERM $$
            sleep 5
            ;;
        sleep:*)
            sleep "${pt_spec#sleep:}"
            ;;
        *)
            pt_mark "$pt_hook" outcome=failed "code=1" "reason=unknown spec"
            exit 1
            ;;
    esac
}

# A hook that exists only to be scheduled: report, obey the spec, done.
pt_scripted() {
    pt_gate "$1"
    pt_mark "$1" outcome=satisfied
    exit 0
}
