#!/bin/bash
set -e
npm run build
npm version patch -m "chore(release): bump version to %s"
git push origin main --tags
npm publish --access public
echo "=== Release Complete! ==="
