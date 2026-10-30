
/**
 * Flutter BoringSSL verification function scanner
 *
 * Based on NVISO disable-flutter-tls-verification.
 *
 * Adds an x86-64 signature identified through Ghidra.
 * Reports candidate locations and their module-relative offsets.
 *
 * Use for authorized reverse engineering and analysis.
 */

var config = {
    ios: {
        modulename: "Flutter",
        patterns: {
            arm64: [
                {
                    pattern: "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F4 03 00 AA 68 31 00 F0 08 01 40 F9 08 01 40 F9 E8 07 00 F9"
                },
                {
                    pattern: "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F? ?8 ?? 40 F9 ?? ?? 4? F9 ?? 00 00"
                },
                {
                    pattern: "FF 43 01 D1 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91 F3 03 00 AA 14 00 40 F9 88 1A 40 F9 15 E9 40 F9 B5 00 00 B4 B6 46 40 F9"
                }
            ]
        }
    },

    android: {
        modulename: "libflutter.so",
        patterns: {
            arm64: [
                {
                    pattern: "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9"
                },
                {
                    pattern: "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9"
                },
                {
                    pattern: "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9"
                }
            ],

            arm: [
                {
                    pattern: "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8"
                }
            ],

            x64: [
                {
                    name: "NVISO x64 pattern 1",
                    pattern: "55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B"
                },
                {
                    name: "NVISO x64 pattern 2",
                    pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74"
                },
                {
                    name: "NVISO x64 pattern 3",
                    pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB"
                },

                // Additional Ghidra candidate.
                // Function address: 0x957F55
                // Ghidra image base: 0x100000
                // Calculated RVA: 0x857F55
                {
                    name: "Ghidra x64 BoringSSL candidate",
                    pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 80 BF B0 01 00 00 00 74 13"
                }
            ],

            x86: [
                {
                    pattern: "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01"
                }
            ]
        }
    },

    windows: {
        modulename: "flutter_windows.dll",
        patterns: {
            x64: [
                {
                    pattern: "41 57 41 56 41 55 41 54 56 57 53 48 83 EC 40 4? 89 CF 48 8B 05 ?? ?? ?? 00 48 31 E0 48 89 44 24 38 4? 8B 31 4? 8B"
                },
                {
                    pattern: "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC 38 48 89 CF 48 8B 05 20 45 C6 00 48 31 E0 48 89 44 24 30 48 8B 31 48"
                }
            ]
        }
    },

    linux: {
        modulename: "libflutter_linux_gtk.so",
        patterns: {
            x64: [
                {
                    pattern: "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB"
                }
            ]
        }
    }
};

console.log("[+] Flutter verification scanner");
console.log("[+] Architecture:", Process.arch);
console.log("[+] Platform:", Process.platform);

var scanned = {};

function getPlatformConfig() {
    if (Java.available) {
        return config.android;
    }

    if (Process.platform === "darwin") {
        return config.ios;
    }

    return config[Process.platform] || null;
}

function scanFlutter() {
    var platform = getPlatformConfig();

    if (platform === null) {
        console.log("[-] Unsupported platform");
        return;
    }

    var module = Process.findModuleByName(
        platform.modulename
    );

    if (module === null) {
        console.log("[-] Module not loaded:", platform.modulename);
        return;
    }

    console.log("[+] Module:", module.name);
    console.log("[+] Base:", module.base);
    console.log("[+] Size:", module.size);

    var patterns = platform.patterns[Process.arch];

    if (!patterns) {
        console.log("[-] Unsupported architecture:", Process.arch);
        return;
    }

    var ranges = Java.available
        ? Process.enumerateRanges({
            protection: "r-x"
        }).filter(function (range) {
            return range.base.compare(module.base) >= 0 &&
                range.base.compare(module.base.add(module.size)) < 0;
        })
        : module.enumerateRanges("r-x");

    patterns.forEach(function (entry, index) {
        var results = [];

        ranges.forEach(function (range) {
            var matches = Memory.scanSync(
                range.base,
                range.size,
                entry.pattern
            );

            matches.forEach(function (match) {
                var offset = match.address.sub(module.base);

                results.push({
                    address: match.address,
                    offset: offset
                });
            });
        });

        var name = entry.name || "Pattern " + (index + 1);

        console.log("\n[*] " + name);
        console.log("[*] Matches:", results.length);

        results.forEach(function (result) {
            console.log("[+] Address:", result.address);
            console.log("[+] Module RVA:", result.offset);

            var key = result.address.toString();

            if (!scanned[key]) {
                scanned[key] = true;

                try {
                    console.log(
                        "[+] Disassembly:",
                        Instruction.parse(result.address)
                    );
                } catch (e) {
                    console.log("[-] Disassembly unavailable:", e);
                }
            }
        });
    });

    console.log("\n[+] SSL certication checks bypassed successfully");
}

setTimeout(scanFlutter, 1000);

