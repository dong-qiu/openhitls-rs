#!/usr/bin/env bash
#
# Phase T89 — Wrapper that runs a tlsfuzzer script with our XFAIL list
# attached. Exits 0 iff the script's own exit logic agrees, i.e.:
#   - all FAIL conversations are listed in the xfail file (becomes XFAIL),
#   - and no XFAIL conversations now PASS (XPASS).
#
# tlsfuzzer's own main() exits 1 when (FAIL > 0 OR XPASS > 0), so we
# just propagate the exit code.
#
# XFAIL file format: tests/tlsfuzzer/xfail/<script-stem>.txt
#
#     # comments start with '#'
#     # blank lines ok
#     <conversation name> :: <reason>
#     <conversation name>             # reason optional
#
# `<conversation name>` must be the literal name from the script's
# `conversations[...]` dict (same string the script prints under
# `FAILED:`). Reason is free-form text — when present, tlsfuzzer also
# checks that the runtime exception text contains the reason substring,
# which is a nice signal but easy to over-tighten. Keep reasons short
# or omit them.
#
# Usage:
#     tests/tlsfuzzer/run.sh <script-name.py> [-h <host>] [-p <port>] \
#                            [extra args passed through]
#
# Env vars:
#     TLSFUZZER_DIR    path to the tlsfuzzer repo (default: $RUNNER_TEMP/tlsfuzzer)
#     TLSFUZZER_PY     python interpreter with tlslite-ng installed
#                      (default: $RUNNER_TEMP/tlsfuzzer-venv/bin/python)
#     XFAIL_DIR        directory holding xfail lists (default: alongside this script)

set -u

script_name="${1:?usage: run.sh <script-name.py> [args...]}"
shift

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
xfail_dir="${XFAIL_DIR:-${here}/xfail}"
tlsfuzzer_dir="${TLSFUZZER_DIR:-${RUNNER_TEMP:-/tmp}/tlsfuzzer}"
tlsfuzzer_py="${TLSFUZZER_PY:-${RUNNER_TEMP:-/tmp}/tlsfuzzer-venv/bin/python}"

if [ ! -d "${tlsfuzzer_dir}" ]; then
    echo "tlsfuzzer not found at ${tlsfuzzer_dir} — set TLSFUZZER_DIR" >&2
    exit 2
fi
if [ ! -x "${tlsfuzzer_py}" ]; then
    echo "tlsfuzzer python not found at ${tlsfuzzer_py} — set TLSFUZZER_PY" >&2
    exit 2
fi

xfail_args=()
xfail_file="${xfail_dir}/${script_name%.py}.txt"
xfail_count=0
if [ -f "${xfail_file}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
        # Strip comments and trailing whitespace, skip blanks.
        line="${line%%#*}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "${line}" ] && continue
        # Split on ` :: ` (literal). Bash parameter expansion: if no ::
        # marker, name is the whole line and reason is empty.
        if [[ "${line}" == *' :: '* ]]; then
            name="${line%% :: *}"
            reason="${line#* :: }"
        else
            name="${line}"
            reason=""
        fi
        xfail_args+=("-x" "${name}")
        if [ -n "${reason}" ]; then
            xfail_args+=("-X" "${reason}")
        fi
        xfail_count=$((xfail_count + 1))
    done < "${xfail_file}"
fi

echo "[run.sh] script=${script_name} xfail_entries=${xfail_count}" >&2

# Optional per-script "extra args" file (Phase T90). Useful when a
# script needs a fixed extra flag every run (e.g. TLS 1.2 scripts
# need `-C 49199` to negotiate our ECDHE-AES-128-GCM cipher). One
# arg per line; blank lines and `#` comments stripped.
args_dir="${ARGS_DIR:-${here}/args}"
args_file="${args_dir}/${script_name%.py}.txt"
extra_script_args=()
if [ -f "${args_file}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
        line="${line%%#*}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "${line}" ] && continue
        extra_script_args+=("${line}")
    done < "${args_file}"
fi

cd "${tlsfuzzer_dir}"
# Bash <4.4 chokes on `${arr[@]}` when arr is empty under `set -u`;
# expand with the +-substitution form to side-step that.
PYTHONPATH=. exec "${tlsfuzzer_py}" "scripts/${script_name}" \
    ${extra_script_args[@]+"${extra_script_args[@]}"} \
    ${xfail_args[@]+"${xfail_args[@]}"} \
    "$@"
