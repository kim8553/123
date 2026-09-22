# Server ↔ official-client compatibility audit (2026-09-22)

**Status: analysis tools implemented; server EXE NOT patched; no new skill implemented.** Do not deploy this branch as a working server update.

## Inputs and provenance

The user-supplied multipart ZIP was reassembled by streaming raw DEFLATE data from `.z01`, `.z02`, `.z03`, and `.zip`; the nested ZIP expands to 669,978,178 bytes, and its outer CRC32 matches `e10da382`. The nested archive has 31,569 entries. The `bin64.zip` integrity test passes. These inputs were inspected privately; no binaries, resources, PCAPs, logs, account details, or session payloads are committed here.

| Input | SHA-256 |
| --- | --- |
| server `9yin-game-native-menu.exe` | `c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c` |
| client `fxgamelogic.dll` | `16cf49b652c39b63ba0767780cc39f32ea1e50bdc683da9d5e7b2697cf95c3e8` |
| client `fxnet2.dll` | `0443d9f401fdcc6a92a391869c898780ffac93399913dc9a82c7cac8cf6c3fde` |
| server `data/skills.json` | `e1e8937cd23236cf71e446e6a9d3387390f30aeadbafe03e6948c6def99d1059` |
| server `data/技能数据.json` | `5711486a4e31a77573c6d0c3242d2824939b07867cade3afa3aea519d934e394` |

`go version -m` identifies the server PE32+ EXE as Go 1.23.5, `github.com/local/9yin-go-server/cmd/protocol-probe`, GOOS=windows and GOARCH=amd64. The provided server archive has `go.mod` but **no `.go` source files**. Go symbol names including `main.parseClientCustomMessage` (`0x7a66c0`), `main.encodeServerCustomValuesWithOpcode` (`0x857300`) and `main.(*playerActor).beginSkillUse` (`0x91a4e0`) exist in this EXE. Offsets are build-specific, not portable patch locations.

## Reproducible offline commands

```bash
python3 -m unittest discover -s compatibility -p 'test_compatibility.py' -v
python3 compatibility/skill_catalog_audit.py '/private/server/data/skills.json' '/private/server/data/技能数据.json'
python3 compatibility/pcapng_audit.py '/private/official_players.pcapng' '/private/local_cap.pcapng'
python3 compatibility/server_log_gap_audit.py '/private/server/protocol-probe-live.log'
```

The paths above are illustrative local input locations, not committed files. All tools are read-only. The capture tool records transport counts only, never guesses encrypted application opcodes. It supports PCAPNG enhanced packets with Ethernet, BSD loopback, or raw IPv4; it does **not** reassemble TCP streams, decrypt, inspect IPv6, or establish semantic packet equivalence.

## Observations from these specific supplied files

- In `data/skills.json`, roles `2` and `4` each contain **17,633** distinct IDs with identical records. `data/技能数据.json` has **17,466** distinct IDs. Exactly **167 IDs appear only in the role tables**; there are no template-only IDs. For all 17,466 shared IDs, only the `level` and `fill` fields differ between the two server tables. These tables have different apparent purposes; the 167 are **not established as missing official skills** and should not be auto-inserted or auto-deleted.
- Server log `logs/protocol-probe-live.log`: **2,847,709 lines** scanned and **40 `unhandled` observations**: `fashion_suit sub=1` 30, `binglu modify sub=1` 2 / `sub=2` 4, `clone 84 sub=1` 1 / `sub=3` 2, and `move 30` 1. These are observed unhandled server routes, **not verified official-protocol differences or missing skills**. Logs may not cover all code paths or versions.
- `official_players.pcapng`: 321 captured packets, 50,287 parseable TCP payload bytes (Ethernet link type 1). `official_login2.pcapng`: 22,655 packets, 3,781,064 parseable TCP payload bytes. `capture-localsrv/cap.pcapng`: 2,509 captured packets on loopback link type 0, with no TCP payload bytes observed in this file. These are **different sessions/recording scopes**; comparing aggregate counts does not identify a protocol mismatch.
- The client `ini.package` / `lua64.package` begin with `PCK0`; a validated extraction/decoding of a client-side canonical skill manifest has **not** been established. Do not infer actual skill absence from raw DLL string matches.

## What is still required for a genuine server patch

1. Obtain an *authorized, validated* client-side skill catalog and verify each purportedly missing ID against the current server runtime handler and intended combat behavior; mere string or table presence is insufficient.
2. Capture comparable game actions in controlled official and local sessions; establish the packet framing, decryption/decoding (if applicable), direction, fields, and client state transition before proposing byte changes.
3. Recover the actual Go sources or create a bounded, version-checked patch with explicit pre/postconditions and a tested rollback. Do not overwrite the original EXE based solely on symbol offsets.
4. Validate on an isolated Windows environment: login, scene entry, skill use, cooldown, damage/buffs, persistence, and packet regressions. **No Windows integration test, rebuilt EXE, or modified server binary was produced in this work.**

Tests: the six synthetic `test_compatibility.py` cases passed locally on the analysis scripts. This does not validate server gameplay.
