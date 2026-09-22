# Server compatibility and skill implementation audit

This document records only observations verified from the user-provided files on 2026-09-22. **No server executable has been patched and no live-server protocol equivalence is established.**

## Input inventory

- Server: split ZIP volumes `새 압축.z01`, `.z02`, `.z03`, `.zip`; the outer ZIP contains `九阴服务端-2026年9月21日更新.zip` (669,978,178 uncompressed bytes). The inner ZIP lists 31,569 entries.
- Server executable: `9yin-game-native-menu.exe` in the inner ZIP.
- Server skill data: `data/skills.json`; JSON root keys `version` and `roles`; roles `2` and `4` each contain 17,633 records (35,266 role-skill records, 17,633 distinct `config_id` values across both roles). Presence in a data table **does not establish that the server implements a skill**.
- Client: supplied `bin64.zip` contains `fxgame.exe`, `fxgamelogic.dll`, `fxnet2.dll`.
- Google Drive client `res`: `lua64.package` and `ini.package` were fetched. Their first four bytes are `PCK0`; their inner entries and skill definitions have **not** been decoded or verified.
- No `.go` file was found among the inner server archive entries. Source restoration is not presumed.

## Open technical questions (unverified)

1. Extract authoritative client opcode/field definitions from `fxnet2.dll` / `fxgamelogic.dll`, including direction, framing, byte order and any relevant cryptographic/session context. Do not infer a protocol from strings alone.
2. Establish a reproducible baseline with legal test accounts in an isolated Windows environment: login, scene entry, skill cast, cooldown and server state synchronization. Record captures for client-to-server and server-to-client messages.
3. Compare expected response sequences against the supplied server binary and logs; classify each candidate mismatch with a concrete capture, parser location and regression case. Avoid claiming a mismatch solely because a handler name or string is absent.
4. Decode the client resource package format or obtain a documented manifest; compare normalized skill identifiers and parameters against `data/skills.json`. Independently verify runtime handlers, damage logic, costs, cooldowns, range and animations for each proposed skill.
5. For each confirmed gap, implement a minimal change in a reproducible source project if source can be recovered; otherwise investigate a narrowly scoped binary patch with rollback and executable integrity checks. Build and exercise end-to-end tests before claiming compatibility.

## Publication and safety

The repository was public at the time of this audit. **Do not commit proprietary game binaries, client resources, private packets, credentials or bulk extracted assets to this repository.** Store source inputs in access-controlled storage and publish only reviewed, minimally necessary analysis/scripts. Existing `main` was the Luna Chat Coder template, not a server codebase.
