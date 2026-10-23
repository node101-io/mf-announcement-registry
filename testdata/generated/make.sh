#!/usr/bin/env bash
# Test vectors: two throwaway Ed25519 keys (keys/, private keys discarded) signing
# ../mf-6/announcement.txt at a faked time of 1790000000.
#   sha/       test-a with SHA-512, test-b with SHA-256
#   expiring/  test-a with SHA-512, expiring after 10 years; test-b with SHA-256
#   same-key/  two signatures by test-a
#   sha384/    test-a with SHA-384 (not counted); test-b with SHA-256
# Running this regenerates them with new keys; the tests rely only on the properties above.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf keys sha expiring same-key sha384 && mkdir -p keys sha expiring same-key sha384
export GNUPGHOME=$(mktemp -d)
T=1790000000
G() { gpg --batch --quiet --pinentry-mode loopback --passphrase '' --faked-system-time "$T!" "$@" 2>/dev/null; }
G --quick-gen-key test-a ed25519 sign 0
G --quick-gen-key test-b ed25519 sign 0
G --armor --export test-a > keys/test-a.pub.asc
G --armor --export test-b > keys/test-b.pub.asc
TXT=../mf-6/announcement.txt
S=$(mktemp -d)
G -u test-a --digest-algo SHA512 --detach-sign -o $S/a512 $TXT
G -u test-a --digest-algo SHA384 --detach-sign -o $S/a384 $TXT
G -u test-a --digest-algo SHA512 --default-sig-expire 10y --detach-sign -o $S/aexp $TXT
G -u test-b --digest-algo SHA256 --detach-sign -o $S/b256 $TXT
for d in sha expiring same-key sha384; do cp $TXT $d/announcement.txt; done
cat $S/a512 $S/b256 | gpg --enarmor > sha/announcement.sig
cat $S/aexp $S/b256 | gpg --enarmor > expiring/announcement.sig
cat $S/aexp $S/a512 | gpg --enarmor > same-key/announcement.sig
cat $S/a384 $S/b256 | gpg --enarmor > sha384/announcement.sig
