# Security

## Status: OpenSSL 1.0.1u is past its end of life

Layer A uses **OpenSSL 1.0.1u**. The OpenSSL project ended support for 1.0.1 on 2016-12-31 and publishes no fixes
for it. This project backports fixes from later OpenSSL branches (1.0.2, 1.1.0, 1.1.1, 3.x) to 1.0.1u, one advisory
at a time. It is much better than the OpenSSL 1.0.1e that Android 4.4 ships, but it is **not** a supported OpenSSL:

- Fixes come from this project, not from the OpenSSL project. Advisories published after the last review are not
  covered until someone triages them.
- Six advisories are deliberately not fixed (below). Some others are safe only under the conditions listed below; a
  build or a caller that breaks a condition can be vulnerable.
- Android 4.4 itself gets no security updates. A current TLS library does not fix the platform.

Use it to keep old devices talking to current servers. Do not use it where a supported platform is an option.

Layer D (Conscrypt 2.6-alpha2 with BoringSSL) is a separate upstream binary; see condition 8.

## CVE status

The table covers the OpenSSL advisories published after the 1.0.1u release (2016-09) up to the last review (2026-10),
triaged for
**any** Android 4.4 device. That threat model is wider than one app: third-party and vendor native code may call any
exported `libcrypto`/`libssl` function, apps may run TLS servers, untrusted apps share the CPU, and the ARM, x86 and
MIPS builds use their own assembler code.

Of the 66 advisories: **25 fixed** (2020-1971 and its template completion counted once), 3 need no patch, 32 are not
reachable or not affected under the conditions below, **6 are not fixed** (2023-0464, 2023-5678, 2022-4304,
2018-5407, 2026-54872, 2024-13176). The ids below are CVE ids (`CVE-YYYY-NNNN`).

| CVE | Status on Android 4.4 |
|---|---|
| 2022-0778, 2023-2650, 2026-35189, 2018-0739, 2018-0732, 2024-5535 | fixed (2024-5535 includes the NPN client follow-up) |
| 2020-1971, 2021-4160 (MIPS asm), 2021-23841, 2023-0286, 2026-45447, 2026-22796 | fixed |
| 2018-0737, 2019-1559, 2019-1563, 2023-0215, 2023-0465, 2023-3446, 2024-0727, 2025-69421, 2026-28388 | fixed |
| 2017-3737 | fixed; the 2019-1559 fix is complete only with it |
| 2017-3731 | fixed (carried in the OpenSSL recipe as `rc4_md5_harden.patch`) |
| 2017-3735 | fixed in the source; the code is not built (`no-rfc3779`) |
| 2018-0734, 2023-3817, 2026-42768 | no patch needed: already mitigated in 1.0.1u, or 1.0.1u has no matching code |
| 2025-9230, 2026-28389, 2026-28390, 2026-9076, 2026-42766 | not reachable under condition 1 (`no-cms`) |
| 2025-69420 | not reachable under condition 1 (TS is not built) |
| 2026-54874, 2026-84782 | not reachable under condition 1 (no DTLS method) |
| 2021-23839 | not reachable under condition 1 (`OPENSSL_NO_SSL2`) |
| 2026-34180, 2026-7383, 2026-31789, 2021-23840 | not reachable under condition 2 (32-bit user space) |
| 2016-7055, 2017-3732, 2017-3736, 2017-3738, 2019-1551 | not reachable under condition 2 (x86_64 assembler, not built on 4.4) |
| 2016-7052, 2025-69419, 2026-22795, 2026-75806, 2026-84783 | not affected: the code is absent from 1.0.1u, or the advisory excludes 1.0.2 and older |
| 2022-1292, 2022-2068, 2019-1552 | not affected: `c_rehash` is not installed on Android 4.4; Windows-only build paths |
| 2023-0466 | documentation only; see condition 4 |
| 2021-3712, 2020-1968, 2025-68160, 2024-9143, 2019-1547 | not reachable from peer input: needs an app's own malformed objects, or a server that reuses DH keys (it never does) |
| 2023-0464 | **not fixed** (policy tree complexity; large change); see condition 4 |
| 2023-5678 | **not fixed**: 1.0.1u does no DH q exponentiation (`DH_generate_key` callers never set q) |
| 2022-4304 | **not fixed** (RSA decryption timing; large bignum change); see condition 5 |
| 2018-5407, 2026-54872, 2024-13176 | **not fixed**: side channels; see condition 6 (2026-54872 matters only together with the 2018-5407 ladder) |
| 2016-8610 | fixed; the warning-alert counter is shared after `SSL_copy_session_id`, see condition 7 |
| 2020-1971 template completion | fixed (with a known-answer test) |
| 2026-72896 | not applicable: named in one upstream commit, but there is no advisory for it |

**Tests.** `tools/openssl-cve-test.sh` runs reproducers for 2018-0732, 2018-0739, 2020-1971 (template completion),
2021-4160, 2022-0778, 2023-2650, 2023-3446, 2024-5535 and 2026-35189 against unpatched 1.0.1u (they must show the
bug) and the patched build (they must pass), for host, x86, ARM and MIPS, with and without assembler, wherever the bug
applies. Side channels
and padding oracles (2018-0737, 2019-1559, 2019-1563) have no reproducer by design. The other fixes, including the
ones whose reproducer would need a crafted malicious file, were verified by comparing the diff with the upstream fix
and by OpenSSL's own `make test`.

**ABI.** The release build compares our libraries with the stock OpenSSL 1.0.1e of the same AOSP tag: no public
symbol is removed. 32 internal `libssl` symbols (`ssl2_*`, `dtls1_clear_record_buffer`, ...) are gone; nothing in
AOSP 4.4 imports them. The recovery zip checks on the device that every symbol the device's library exports is
exported by ours, apart from those 32. A matching symbol list does not prove that a vendor's own
native code was compiled against the same structs and `#define` values; that is why the installer accepts only
AOSP-like builds.

**Android 4.1 to 4.3.** The Jelly Bean openssl zips carry the same OpenSSL 1.0.1u with the same backports, the same
configuration and the same conditions; the table applies to them as to 4.4 (the platform itself is older and equally
unpatched). Each is built from the AOSP tree of its version (`android-4.3_r3`, `android-4.2.2_r1`, `android-4.1.2_r2`)
and compared there with the stock library (1.0.1e on 4.3, 1.0.1c on 4.1/4.2): no public symbol removed; the internal
ones listed in `patches/jb/<ver>/allow-missing-*.txt` are gone, nothing in AOSP of that version imports them. Left out
compared with 4.4: ALPN (all three) and Channel ID (4.1/4.2), which are features, not fixes; their struct members
would move fields that stock callers use. 4.1's stock `libcrypto` offered zlib TLS compression (CRIME); this build
does not, as stock 4.2. The CVE reproducers run on each Jelly Bean recipe too (`openssl-cve-test.sh --jb-base`).
The 4.3, 4.2 and 4.1 java zips give the Java layer of 4.3, 4.2 and 4.1.2 the defaults of 4.4 layer A (the same
lists, so condition 5 applies to them too). On 4.1.1, which the 4.1 java zip refuses, Java apps keep the stock
defaults: SSLv3 and RC4 enabled, and an `HttpsURLConnection` retry over SSLv3 without SNI after a failed handshake;
there only the CA store and the native libraries change.

## Conditions

The verdicts above hold only when all of these are true. If you build or use the libraries differently, triage the
affected rows again.

1. **Configuration unchanged:** `no-rfc3779`, `no-cms`, TS not built (only `ts_err.c`), `OPENSSL_NO_SSL2`, no
   DTLS method (`d1_meth.c`, `d1_clnt.c`, `d1_srvr.c` not built, no `DTLS*_method` exported). The rows marked
   "condition 1" depend on it. Adding `d1_meth.c` would expose 2026-84782 (High); enabling RFC 3779 or CMS needs a new
   triage.
2. **32-bit user space** (ARM, x86, MIPS). AOSP 4.4 never builds the x86_64 assembler lists in `openssl.config`.
   2026-34180 affects 64-bit builds only, and the size-based rows need inputs that a 32-bit process cannot hold.
   Reusing the patches on a 64-bit (Android 5.0+) build needs a new triage.
3. **MIPS:** the shipped `bn-mips.S` must be generated from the patched `mips.pl` (the 2021-4160 fix, covered by a
   known-answer test for MIPS with assembler). A MIPS build without that fix must use `no-asm`.
4. **Certificate policy checking is not hardened:** native callers must not enable `X509_V_FLAG_POLICY_CHECK`,
   explicit policies or `set1_policies` on untrusted chains (2023-0464). `X509_VERIFY_PARAM_add0_policy` alone does
   not enable the policy check (2023-0466).
5. **TLS servers:** the timing side channel in RSA key exchange (2022-4304) is not fixed. Apps that run a TLS server
   should enable ECDHE suites only. The default list of the Java layer (`NativeCrypto`) still includes `TLS_RSA_*`
   suites.
6. **Private-key operations are not constant-time** against an attacker on the same CPU: EC scalar multiplication
   (wNAF), the nonce inverse, and DSA. 2018-5407 and 2026-54872 are not fixed. This matters most on x86 Atom CPUs
   with Hyper-Threading.
7. **2016-8610 counter scope:** the warning-alert counter lives in the `CERT` structure, as in upstream 1.0.2. Two
   `SSL` objects linked by `SSL_copy_session_id` (or `SSL_dup` with a session) share it, which can abort a connection
   early or reset the count. Native callers that use those functions get the 1.0.2 behaviour; nothing in AOSP 4.4
   calls them. The 2020-1971 template completion now rejects implicit tags on multi-string and CHOICE items: a native
   caller with its own ASN.1 template that tags such an item implicitly gets `ASN1_R_BAD_TEMPLATE`. AOSP 4.4 has no
   such template.
8. **Layer D is separate.** The standalone Conscrypt 2.6-alpha2 (`kktls-conscrypt.jar`, `libkktls_conscrypt_jni.so`,
   BoringSSL inside) is not part of the OpenSSL patches. It is installed only by its own zip and can be turned off with
   `persist.kktls.conscrypt=0`. Its security status is that of upstream Conscrypt 2.6-alpha2 and the BoringSSL commit
   it was built from, not this table. 2.6-alpha2 is a pre-release; check upstream for its status.

## Reporting a vulnerability

Report security problems in this project's patches, installer or build scripts privately through GitHub: the
repository's **Security** tab, **Report a vulnerability**. Please do not open a public issue for them. This is a
spare-time project, so a reply may take a while.

- A new OpenSSL advisory that may affect 1.0.1u: a public issue is fine once the advisory is public.
- Problems in Conscrypt or BoringSSL themselves: report them upstream
  ([Conscrypt](https://github.com/google/conscrypt), [BoringSSL](https://boringssl.googlesource.com/boringssl)).
- Problems in Android 4.4 outside the files this project replaces cannot be fixed here.
