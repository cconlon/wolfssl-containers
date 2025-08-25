#!/bin/sh
set -e
trap 'echo wolfSSL startup test failed' ERR
/test-fips
python -c "import ssl; context = ssl.create_default_context()"
trap - ERR
"$@"
