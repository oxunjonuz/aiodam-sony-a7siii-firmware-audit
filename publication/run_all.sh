#!/bin/sh
# run_all.sh — the whole paper in one command: audit instruments -> numbers -> PDF -> number
# binding -> layout -> the cited names -> self-tests -> manifest. Every stage that can go red
# is checked for its exit code, and a red stage stops the run (steps 4 to 8: no pipe swallows it).
#
# The order is not arbitrary: the paper's numbers come from the instruments' output, so the
# instruments run first and numbers.json is rebuilt AFTER them, so that no number can drift
# away from the run that produced it.
set -e
cd "$(dirname "$0")"
ROOT=/work/SONY_A7SIII_UPDATE
PY="$ROOT/env/venv/bin/python3"
RUNS=verification_runs
mkdir -p "$RUNS"

echo "=== 1/8 audit instruments afresh (their output is kept as the paper's artifacts) ==="
for step in "checks:audit/checks.py:$PY" \
            "report_check:audit/report_check.py:$PY" \
            "round277:audit/round277_check.py:$PY" \
            "round278:audit/round278_check.py:$PY" \
            "round279:audit/round279_check.py:python3" \
            "verify_findings:audit/verify_findings.py:$PY"; do
  name=${step%%:*}; rest=${step#*:}; script=${rest%%:*}; interp=${rest#*:}
  ( cd "$ROOT" && $interp "$script" ) > "$RUNS/$name.txt" 2>&1 || rc=$?
  rc=${rc:-0}
  printf '  %-16s exit=%s  %s\n' "$name" "$rc" "$(tail -1 "$RUNS/$name.txt" | cut -c1-72)"
  rc=0
done

echo "=== 2/8 the paper's numbers, from the artifact bytes ==="
$PY make_numbers.py

echo "=== 3/8 building main.pdf ==="
( cd paper && xelatex -interaction=nonstopmode -halt-on-error main.tex >/tmp/pub_tex1.log 2>&1 \
  && xelatex -interaction=nonstopmode -halt-on-error main.tex >/tmp/pub_tex2.log 2>&1 ) \
  || { echo "BUILD_FAIL: main.tex"; tail -20 /tmp/pub_tex1.log /tmp/pub_tex2.log; exit 1; }
[ -s paper/main.pdf ] || { echo "BUILD_FAIL: no main.pdf"; exit 1; }
echo "  paper/main.pdf: $(pdfinfo paper/main.pdf | awk '/^Pages/{print $2}') pages, $(wc -c < paper/main.pdf) bytes"

echo "=== 4/8 binding every number to its artifact (re-derivation + text + PDF) ==="
$PY paper_check.py > /tmp/pub_number_check.log 2>&1 || { tail -12 /tmp/pub_number_check.log; echo "RED STEP: paper_check.py"; exit 1; }
tail -9 /tmp/pub_number_check.log

echo "=== 5/8 layout: letters on top of letters and overflow past the margin (two routes) ==="
python3 layout_check.py > /tmp/pub_layout.log 2>&1 || { tail -12 /tmp/pub_layout.log; echo "RED STEP: layout_check.py"; exit 1; }
tail -7 /tmp/pub_layout.log

echo "=== 5b/8 the names the paper cites (they must survive into print; F167) ==="
python3 string_check.py > /tmp/pub_strings.log 2>&1 || { tail -12 /tmp/pub_strings.log; echo "RED STEP: string_check.py"; exit 1; }
tail -4 /tmp/pub_strings.log

echo "=== 5c/8 self-test of the name check: removing a cited name must turn it red ==="
python3 selftest_string.py > /tmp/pub_selftest_string.log 2>&1 || { tail -12 /tmp/pub_selftest_string.log; echo "RED STEP: selftest_string.py"; exit 1; }
tail -6 /tmp/pub_selftest_string.log

echo "=== 5d/8 the printed appendix must still be a table (F169) ==="
python3 appendix_density.py > /tmp/pub_appendix.log 2>&1 || { tail -12 /tmp/pub_appendix.log; echo "RED STEP: appendix_density.py"; exit 1; }
tail -6 /tmp/pub_appendix.log

echo "=== 6/8 number self-test: the injected faults must turn it red ==="
python3 selftest_paper.py > /tmp/pub_selftest_number.log 2>&1 || { tail -12 /tmp/pub_selftest_number.log; echo "RED STEP: selftest_paper.py"; exit 1; }
tail -7 /tmp/pub_selftest_number.log

echo "=== 7/8 layout self-test: the instrument must go red on a real defect ==="
python3 selftest_layout.py > /tmp/pub_selftest_layout.log 2>&1 || { tail -12 /tmp/pub_selftest_layout.log; echo "RED STEP: selftest_layout.py"; exit 1; }
tail -5 /tmp/pub_selftest_layout.log

echo "=== 8/8 package manifest ==="
python3 make_manifest.py > /tmp/pub_manifest.log 2>&1 || { tail -12 /tmp/pub_manifest.log; echo "RED STEP: make_manifest.py"; exit 1; }
cat /tmp/pub_manifest.log

echo "RUN_ALL_PUBLICATION_OK"
