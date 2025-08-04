#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${BRANCH:-}" || -z "${COMMIT_MESSAGE:-}" || -z "${PR_TITLE:-}" || -z "${PR_BODY:-}" ]]; then
  echo "BRANCH, COMMIT_MESSAGE, PR_TITLE, and PR_BODY env vars are all required"
  exit 1
fi

cd pinniped

# Print the current status to the log.
git status

# Prepare to be able to do commits and pushes.
git config user.email "pinniped-ci-bot@users.noreply.github.com"
git config user.name "Pinny"
git remote add https_origin "https://${GH_TOKEN}@github.com/vmware/pinniped.git"

# Add all the changed files.
git add .

# Print the current status to the log.
git status

# Did we just stage any changes?
staged=$(git --no-pager diff --staged)
if [[ "$staged" == "" ]]; then
  # Nothing to commit. We are done.
  echo "No changes to any files detected. Done."
  exit 0
fi

# Check if the branch already exists on the remote.
new_branch="no"
if [[ -z "$(git ls-remote https_origin "$BRANCH")" ]]; then
  echo "The branch does not already exist, so create it."
  git checkout -b "$BRANCH"
  git status
  new_branch="yes"
else
  echo "The branch already exists, so pull it."
  # Stash our changes before using git checkout and git reset, which both can throw away local changes.
  git status
  git stash
  # Fetch all the remote branches so we can use one of them.
  git fetch https_origin
  # The branch already exists, so reuse it.
  git checkout "$BRANCH"
  # Pull to sync up commits with the remote branch.
  git pull --rebase --autostash
  # Throw away all previous commits on the branch and set it up to look like main again.
  git reset --hard main
  # Bring back our changes and stage them again.
  git stash pop
  git add .
  git status
fi

# Show diff for the log.
echo "Found changes to commit:"
echo
git --no-pager diff --staged
echo

# Commit.
echo "Committing changes to branch $BRANCH. New branch? $new_branch."
git commit -m "$COMMIT_MESSAGE"

# Push.
if [[ "$new_branch" == "yes" ]]; then
  # Push the new branch to the remote.
  echo "Pushing the new branch."
  git push --set-upstream https_origin "$BRANCH"
else
  # Force push the existing branch to the remote.
  echo "Force pushing the existing branch."
  git push --force-with-lease
fi

# Now check if there is already a PR open for our branch.
# If there is already an open PR, then we just updated it by force pushing the branch.
# Note that using the gh CLI without login depends on setting the GH_TOKEN env var.
open_pr=$(gh pr list --head "$BRANCH" --json title --jq '. | length')
if [[ "$open_pr" == "0" ]]; then
  # There is no currently open PR for this branch, so open a new PR for this branch
  # against main, and set the title and body.
  echo "Creating PR."
  gh pr create --head "$BRANCH" --base main --title "$PR_TITLE" --body "$PR_BODY"
fi
