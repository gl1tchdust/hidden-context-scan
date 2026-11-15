#!/usr/bin/env bash
# Fetch the public system-prompt corpus, pinned to one commit.
#
# This script is the only thing in the repository that touches the network,
# and it is a shell script rather than a Python module on purpose: the `hcx`
# package cannot import it, so the scanner has no network path at all.
#
# The corpus is CC0-1.0, so it is read, never vendored. It is also updated
# daily, which is why the commit is pinned: a census whose corpus moves under
# it is not reproducible.
set -euo pipefail

REPO="https://github.com/asgeirtj/system_prompts_leaks"
# Pinned 2026-11-15. Bump deliberately and re-run `python -m hcx.measure`,
# because new files can invalidate the labels.
PIN="bb4c9c5a8bcbe281e2fbe3fd1fa961e514c0a93f"
DEST="${1:-.corpus/spl}"

if [ -d "$DEST/.git" ]; then
  echo "corpus already present at $DEST"
  current="$(git -C "$DEST" rev-parse HEAD)"
  if [ "$current" != "$PIN" ]; then
    echo "WARNING: on $current, expected the pin $PIN" >&2
    echo "Run: git -C $DEST fetch --depth 1 origin $PIN && git -C $DEST checkout $PIN" >&2
    exit 1
  fi
  exit 0
fi

mkdir -p "$(dirname "$DEST")"
git init -q "$DEST"
git -C "$DEST" remote add origin "$REPO"
git -C "$DEST" fetch -q --depth 1 origin "$PIN"
git -C "$DEST" checkout -q FETCH_HEAD

n="$(find "$DEST" -name '*.md' -not -path '*/.git/*' | wc -l)"
echo "fetched $n markdown files to $DEST at $PIN"

# Check the count, do not just print it. A pinned commit should produce the
# same tree everywhere, and when it does not, every rate computed from it is
# quietly wrong. That is not hypothetical here: one markdown symlink in this
# corpus made the census 1,699 files on Windows and 1,700 on Linux, and it
# took a CI run on a different operating system to notice. See RESEARCH.md,
# "Every published rate was a Windows number".
EXPECTED_MD=1710
if [ "$n" -ne "$EXPECTED_MD" ]; then
  echo "WARNING: expected $EXPECTED_MD markdown files at this pin, found $n." >&2
  echo "The checkout differs from the one every published number was" >&2
  echo "computed on. Do not trust a census from this tree until you know why." >&2
  exit 1
fi

# The corpus is third-party text. It is read and parsed, never executed, and
# nothing here imports from it.
