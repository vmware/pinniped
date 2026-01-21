#!/bin/bash

# Copyright 2021-2026 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

files=$(git diff --cached --name-only)
year=$(date +"%Y")

missing_copyright_files=()

for f in $files; do
    head -10 "$f" | grep -i 'Copyright.*the Pinniped contributors' 2>&1 1>/dev/null || continue

    if ! head -10 "$f" | grep -i -e "Copyright.*$year.*the Pinniped contributors" 2>&1 1>/dev/null; then
        missing_copyright_files+=("$f")
    fi
done

if [[ "${#missing_copyright_files[@]}" -gt "0" ]]; then
    echo "Fixing copyright notice in the following files:"

    for f in "${missing_copyright_files[@]}"; do
        echo "    $f"
        # The rule when updating copyrights is to always keep the starting year,
        # and to replace the ending year with the current year.
        if [[ "$(uname -s)" == "Linux" ]]; then
          # sed on Linux uses -i'' (no space in between).
          # Replace "XXXX-YYYY" with "XXXX-year" in the copyright notice.
          sed -E -e 's/Copyright ([0-9]{4})-([0-9]{4}) the Pinniped contributors/Copyright \1-'"$year"' the Pinniped contributors/' -i'' "$f"
          # Replace "XXXX" with "XXXX-year" in the copyright notice.
          sed -E -e 's/Copyright ([0-9]{4}) the Pinniped contributors/Copyright \1-'"$year"' the Pinniped contributors/' -i'' "$f"
        else
          # sed on MacOS uses -i '' (with space in between).
          # Replace "XXXX-YYYY" with "XXXX-year" in the copyright notice.
          sed -E -e 's/Copyright ([0-9]{4})-([0-9]{4}) the Pinniped contributors/Copyright \1-'"$year"' the Pinniped contributors/' -i '' "$f"
          # Replace "XXXX" with "XXXX-year" in the copyright notice.
          sed -E -e 's/Copyright ([0-9]{4}) the Pinniped contributors/Copyright \1-'"$year"' the Pinniped contributors/' -i '' "$f"
        fi
    done

    echo "Done!"
fi
