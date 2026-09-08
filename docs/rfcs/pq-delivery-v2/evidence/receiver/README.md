# Review-only strict-v2 receiver tests

These tests do not change a wallet, node, wire format, or transaction builder.
The prototype includes the inspected scanner implementation in one translation
unit and reuses its private authenticated-decryption and ownership predicates.
Only the choice to omit historical context fallback is different.

Source baseline: Core `05cb1424ba9cea19bf3fa0630b647b9d6d9162cf`.
Use a clean checkout of that revision and its matching Release static libraries.
On Windows with Visual Studio 2022 C++ Build Tools, CMake and Ninja:

```powershell
.\run_review_tests.ps1 -CoreSource <core-checkout> -CoreBuild <matching-release-build>
```

The Core build must provide CryptoPq, CryptoNoteCommon, Crypto,
chacha20poly1305 and oqs Release libraries at their standard CMake locations.
Google Test is built from the supplied Core source. The script creates only its
own `build` directory. CTest runs four executables and writes Google Test XML.
Use the XML test-case count, not CTest's executable count: the recorded run has
13 scanner + 7 builder + 16 derivation + 10 strict-receiver cases = 46 passes.

`maxT=1` still accepts the local historical-T0 compatibility vector; the strict
prototype rejects it. The current-output route tests preserve exact recognized
records at T0, 1, 44, 259, 4095 and 0xffffffff. The latter is a cryptographic
payload test, not a claim that every UI accepts that address index.

This is not a production patch. No transaction serialization, daemon submission,
activation rule, restart persistence, or network/GUI behavior is tested here.
The version-binding test exercises the digest only, not a newly admitted version.
