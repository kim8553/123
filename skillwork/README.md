# Skill-only audit: `StaticData=5675` — PATCH BLOCKED

Date: 2026-09-22. **Do not install the previously supplied `skill_id_5675_data_only_patch.zip`.** The earlier candidate JSON-only repair has been **withdrawn** after checking another skill resource. This branch contains no server EXE modification, no implemented combat skill, no save migration, and no Windows gameplay verification.

## Newly verified conflict in the provided SERVER archive

All evidence below is from the same uploaded server archive, **not** a decoded official-client manifest:

| Source | Observed entry for `StaticData=5675` |
| --- | --- |
| `data/skills.json` | `config_id = ȭ` (one row each in roles 2 and 4) |
| `data/技能数据.json` | `config_id = ȭ` (one template row) |
| `resources/modern/share/skill/skill_new.ini` | GB18030 section `[裂天拳]` |
| `resources/modern/share/skill/skill_init.ini` | GB18030 section `[    拳]`, with **four literal ASCII spaces**, not an encoding display artifact |
| `resources/modern/share/skill/skill_static.ini` | Numeric section `[5675]`, `TaoLu=clone011` |

The first two JSON rows declare `max_level=12`, whereas the `skill_init.ini` entry declares `maxlevel=1`; their different purposes and the executable's interpretation have **not** been established, so this alone is not called a bug. The two resource files' conflicting section names prevent selecting a safe replacement ID. `skill_static_to_id.ini` does not provide a section `[5675]` in this archive; the scope and completeness of that mapping are unknown.

Bytes for the two conflicting resource headers were directly checked: `skill_new.ini` contains `[\xc1\xd1\xcc\xec\xc8\xad]` (GB18030 `裂天拳`), and `skill_init.ini` contains `[    \xc8\xad]` (four spaces then `拳`). Both archive backups of these files contain the same respective names. The exact official-client ID and correct migration strategy remain **unknown**.

## Binary investigation, limited to skills

The supplied Windows Go server binary exposes `main.loadCombatSkillCatalog` (`skill_catalog.go`, which calls `main.loadSkillResourceTables`), `main.loadSkillInitViews` (`skill_view.go`, which calls `main.loadINISections`), `main.(*playerActor).restoreSkillLevelsFromSave`, and `main.skillSaveApplyLevels`. These are real Go symbol/disassembly observations, **not** proof of a successful cast, a particular name lookup for 5675, or a safe binary patch.

## Safety fix applied to the analysis tool

`skill_id_repair.py` now cross-checks BOTH `skill_new.ini` and `skill_init.ini` by `StaticData=5675`. If either has zero/multiple sections, or their names differ, audit mode reports `BLOCKED_RESOURCE_CONFLICT`, returns nonzero exit code 2, and **refuses to create any output patch**. Patch mode also fails closed. `patch_one` remains a pure function used for synthetic tests only; it is not an authorization to deploy data changes. Missing `skill_init.ini` is rejected.

```bash
python skillwork/skill_id_repair.py /path/to/nested_server.zip
python skillwork/skill_id_repair.py /path/to/nested_server.zip --output /path/to/patch.zip  # BLOCKED for provided archive
python -m unittest discover -s skillwork -p 'test_*.py' -v
```

The provided server archive returned `skill_new_ids=["裂天拳"]`, `skill_init_ids=["    拳"]`, status `BLOCKED_RESOURCE_CONFLICT`; no new ZIP was written. Nine synthetic unit tests passed in the sandbox. The originally uploaded archives, server EXE, character saves, and GitHub `main` were not edited. The previously generated ZIP remains an **unsafe candidate and must not be deployed**.

## Original skill-data inventory (still valid)

The server's role lists contain 17,633 distinct skill IDs each and its template has 17,466. `skill_new.ini` has 17,855 unique sections; 389 `wuji_` entries absent from the general role JSON must **not** be designated missing skills without checking the dedicated `main.loadWuJiCatalog` / WuJi execution path. No official-client skill inventory or controlled Windows cast comparison was available.

## Next skill-specific gate

Obtain a verifiably decoded matching-version **client** skill identity for 5675 or controlled cast behavior, determine the server's 5675 lookup and persisted ID semantics, then design a coordinated multi-source + save-migration change. Do not normalize names, install the retired patch, inject server instructions, or bulk-import `wuji_` IDs on these observations alone.
