#!/usr/bin/env bash
# Fetch the comparison corpora, pinned.
#
# The primary corpus (corpus/fetch.sh) is one collection by one curator. Every
# rate measured on it describes that collection. These three exist to test
# whether any of it transfers, and the answer in RESEARCH.md section 5.8 is
# mostly no.
#
# Statistics only. Nothing from these is redistributed, and the two copyleft
# licences below are respected by not vendoring a single line of their text.
set -euo pipefail

DEST="${1:-.corpus}"

fetch() {
  local name="$1" repo="$2" pin="$3" lic="$4"
  local dir="$DEST/$name"
  if [ -d "$dir/.git" ]; then
    local cur; cur="$(git -C "$dir" rev-parse HEAD)"
    if [ "$cur" != "$pin" ]; then
      echo "WARNING: $name is on $cur, expected the pin $pin" >&2
      exit 1
    fi
    echo "$name already present ($lic)"
    return
  fi
  mkdir -p "$(dirname "$dir")"
  git init -q "$dir"
  git -C "$dir" remote add origin "$repo"
  git -C "$dir" fetch -q --depth 1 origin "$pin"
  git -C "$dir" checkout -q FETCH_HEAD
  echo "fetched $name at $pin ($lic)"
}

# B. Third-party custom GPT instructions plus a second vendor-prompt set.
#    Different curator, different authors, MIT.
fetch bigprompt "https://github.com/0xeb/TheBigPromptLibrary" \
      "5f5f69fa863f0cfaa5927729be7a5fc12f8ac3f6" "MIT"

# C. Coding-agent prompts. Different population again. GPL-3.0: read and
#    measured, never redistributed.
fetch aitools "https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools" \
      "162db92f54d717d8ebd12292e155aeef32bb4b3c" "GPL-3.0"

# Check the trees, do not assume them. On the author's machine Windows
# Defender quarantines three Hack The Box cheat sheets in bigprompt and
# re-deletes them after a restore, which moved every B1 rate and took a CI
# run on Linux to notice. See RESEARCH.md, "And then the antivirus ate the
# corpus". `git status` is the honest check: it compares the working tree to
# the pinned commit rather than counting whatever happens to be present.
for name in bigprompt aitools; do
  dir="$DEST/$name"
  [ -d "$dir/.git" ] || continue
  if [ -n "$(git -C "$dir" status --porcelain)" ]; then
    echo "WARNING: $dir differs from the pinned commit:" >&2
    git -C "$dir" status --short >&2
    echo "Files are missing or modified, so any rate computed from this tree" >&2
    echo "is not the rate this corpus describes. Restore them with:" >&2
    echo "  git -C $dir checkout -- ." >&2
    echo "If they vanish again, something on this machine is deleting them." >&2
    exit 1
  fi
done

cat <<'NOTE'

The four populations, and why they are kept apart:

  A  .corpus/spl                             frontier vendor prompts and skills
  B1 .corpus/bigprompt/CustomInstructions    third-party custom GPT authors
  B2 .corpus/bigprompt/SystemPrompts         vendor prompts, a second curator
  C  .corpus/aitools                         coding agents (scan *.txt, not *.md)

B2 is the control: same population as A, assembled independently. B1 and C are
different populations. Blending them would produce a number describing none of
them.
NOTE
