: '
 * Copyright (c) 2018 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'

#!/bin/sh

set -xe

rm -f user_ca user_ca.pub
rm -f user-key user-key.pub
rm -f *.cert

ssh-keygen -q -f user_ca -t rsa -b 4096 -C "user_ca" -N ''
ssh-keygen -q -f user-key -t rsa -b 4096 -C "user@libssh" -N ''

sign() {
  output=$1
  principals=$2
  serial=$3
  shift 3
  set -xe
  ssh-keygen -q -s user_ca -I test@libssh.com "$principals" \
      -V 19990101:19991231 "$serial" "$@" user-key.pub
  mv user-key-cert.pub "$output"
}

# Only default extensions - 1 principal (default)
sign default_exts.cert -nuser1 -z0 ``
# All extensions - 1 principals (default)
sign all_exts.cert -nuser1 -z1 -Opermit-agent-forwarding -Opermit-port-forwarding \
    -Opermit-pty -Opermit-user-rc -Opermit-X11-forwarding -Ono-touch-required
# No extensions - 6 principals
sign no_exts.cert -nuser1,user2,user3,user4,user5,user6 -z2 -Oclear

# Only force-command (critical) - default extensions - 1 principal (default)
sign force_command.cert -nuser1 -z3 -Oforce-command="/path/to/run.sh"
# Only source-address (critical) - default extensions - 4 principal (default)
sign source_address.cert -nuser1,user2,user3,user4 -z4 -Osource-address="127.0.0.1/32,::1/128"
# Only verify-required (critical) - default extensions - 9 principals
sign verify_required.cert -nuser1,user2,user3,user4,user5,user6,user7,user8,user9 \
    -z5 -Overify-required

# All critical options - all extensions - 1 principal (default)
sign all_options.cert -nuser1 -z6 -Oforce-command="/path/to/run.sh" -Osource-address="127.0.0.1/32,::1/128" \
    -Overify-required -Ono-touch-required

# Host certificate - no extensions/critical options - 1 principal (default)
sign host.cert -nhostname -z8 -h

# No principals - no dates - no extensions - no critical options
ssh-keygen -q -s user_ca -I test@libssh.com -z7 -Oclear user-key.pub
mv user-key-cert.pub no_all.cert
