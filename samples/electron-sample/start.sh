#!/bin/bash
# Start script — unsets ELECTRON_RUN_AS_NODE which may be set in the
# parent environment (e.g. by Devin CLI), then launches the Electron app.
unset ELECTRON_RUN_AS_NODE
cd "$(dirname "$0")"
exec npx electron .
