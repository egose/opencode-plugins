#!/bin/bash

editmsg="$(git rev-parse --git-path COMMIT_EDITMSG)"

# shellcheck disable=SC2086
./node_modules/.bin/commitlint --config commitlint.config.mjs --edit "$editmsg" --verbose
