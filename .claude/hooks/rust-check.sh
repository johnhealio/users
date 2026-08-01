#!/bin/bash
# Runs after any file edit/write. Only acts on Rust files; exits quietly otherwise.
if [[ "$CLAUDE_TOOL_INPUT_FILE_PATH" == *.rs ]]; then
  cargo check --quiet 2>&1
fi
