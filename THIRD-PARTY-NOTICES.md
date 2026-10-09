# Third-party notices

GitCoffer is MIT-licensed (see [LICENSE](LICENSE)). It depends on and
redistributes nothing at runtime except the Go runtime itself; this file
carries the license notices that accompany the dependencies of the
source and the release binaries.

## Go

The Go toolchain and its standard library (BSD 3-Clause):
https://golang.org/LICENSE — Copyright (c) The Go Authors.

## golang.org/x/crypto

Used for Argon2id key derivation and XChaCha20-Poly1305
(https://pkg.go.dev/golang.org/x/crypto), BSD 3-Clause:

```
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## golang.org/x/term and golang.org/x/sys

Used for hidden terminal passphrase input (and its syscall base),
same BSD 3-Clause notice as above (Copyright (c) The Go Authors).

## Design acknowledgment

GitCoffer's design follows the path proven by git-remote-gcrypt
(GPL-2+); no code from it is used — the acknowledgment in
[README.md](README.md) credits the idea, which is all it shares.
