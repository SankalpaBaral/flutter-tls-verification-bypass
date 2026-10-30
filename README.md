# Flutter TLS Verification – Updated x86_64 Pattern

## Overview

I was using the [NVISO Flutter TLS Verification script](https://github.com/NVISOsecurity/disable-flutter-tls-verification) while testing Flutter applications. The script uses byte patterns to find the certificate verification function inside `libflutter.so`.

However, when I tested some applications on an Android x86_64 emulator, the existing signatures failed to find the function.

So I decided to investigate it myself using **Ghidra**.

## What I Found

The original script already had signatures for multiple architectures, including x86_64. But none of the existing x86_64 patterns matched the `libflutter.so` binary I was analyzing.

This made me look into how Flutter's bundled BoringSSL implementation was compiled in that particular build.

## Analysis with Ghidra

I loaded `libflutter.so` into Ghidra and started looking through the functions.

During the analysis, I found a potential certificate-verification-related function at:

```text
Ghidra Address: 0x957F55
Image Base:     0x100000
```

To get its RVA, I subtracted the image base:

```text
0x957F55 - 0x100000 = 0x857F55
```

The function also contained references to Flutter's bundled BoringSSL source:

```text
flutter/third_party/boringssl/src/ssl/ssl_x509.cc
```

I also noticed references to `ssl_server` and `ssl_client`, along with certificate-verification-related operations. These were useful clues that the function was part of the BoringSSL verification path.

## New x86_64 Signature

After examining the function's disassembly, I extracted this byte pattern:

```text
55 41 57 41 56 41 55 41 54 53
48 83 EC 38
80 BF B0 01 00 00 00
74 13
```

I added it as an additional x86_64 candidate to the existing pattern collection, keeping the original NVISO signatures unchanged.

The pattern is based on the function found in the binary I analyzed, so it may not match every Flutter build.

## Changes Made

The updated version includes:

- The original architecture signatures are preserved.
- A new x86_64 signature extracted using Ghidra.
- Runtime module and address information for debugging.
- Match-count reporting to identify multiple matches.
- Runtime RVA reporting to make comparison with Ghidra easier.

## How to Use

### Requirements

- An Android device or emulator.
- [Frida](https://frida.re/) installed on your computer.
- Frida server running on the Android device.
- The target application's package name.

### Run the Script

Connect your Android device or emulator and launch the application with Frida:

```bash
frida -U -f <package.name> -l flutter-tls-bypass.js
```

Replace `<package.name>` with the package name of the application you're testing.

Use the script only on applications you own or have permission to test.

## Notes

This signature was extracted from one particular `libflutter.so` build. It is not guaranteed to work with every Flutter version.

Flutter updates, compiler changes and different architectures can all affect the generated machine code. If the pattern doesn't match, the function may need to be analyzed again in Ghidra.

This is an additional investigation based on the original work by NVISO Security.

## Credits

- [NVISO Security – Disable Flutter TLS Verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [BoringSSL](https://github.com/google/boringssl)

---

Research and additional signature analysis by **Sankalpa Baral**.

For educational purposes and authorized application security testing only.
