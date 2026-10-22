#!/usr/bin/env bash
set -euo pipefail
umask 0027
ulimit -c 0

cp -R /opt/lab/. /work/
{
  /src/sapi/cli/php -v
  /src/sapi/cgi/php-cgi -v
  sha256sum /src/sapi/cli/php /src/sapi/cgi/php-cgi \
    /work/run-tests.php \
    /work/ext/session/tests/rfc1867_no_user_code.phpt \
    /work/ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt \
    /work/ext/session/tests/rfc1867_sid_invalid.phpt \
    /work/ext/session/tests/skipif.inc \
    /work/LICENSE
} > /results/identity.txt

export TEST_PHP_EXECUTABLE=/src/sapi/cli/php
export TEST_PHP_CGI_EXECUTABLE=/src/sapi/cgi/php-cgi
export TEST_PHP_SRCDIR=/work
export TEST_PHP_JUNIT=/results/junit.xml
export REPORT_EXIT_STATUS=1

exec timeout --signal=TERM --kill-after=5s 120s \
  /src/sapi/cli/php -n -d memory_limit=64M /work/run-tests.php \
  -n -q --offline --set-timeout 20 -p /src/sapi/cli/php -d memory_limit=64M \
  /work/ext/session/tests/rfc1867_no_user_code.phpt \
  /work/ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt \
  /work/ext/session/tests/rfc1867_sid_invalid.phpt
