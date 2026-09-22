# Skill 5675: compiled-server cast path (2026-09-22)

**Status: static catalog-key mismatch identified; no verified game failure; NO PATCH.** Only the user-supplied server's skill resources and exact Go EXE were inspected. No official-client skill identity or controlled Windows casting observation is available. Do not use the earlier withdrawn `skill_id_5675_data_only_patch.zip`.

## Reproducible evidence

Run `python skillwork/skill_cast_path_audit.py /path/to/nested_server.zip /path/to/9yin-game-native-menu.exe` with Go 1.23 tooling available; `--output /path/to/report.json` writes a redacted report. A different EXE SHA-256 is rejected before drawing version-dependent control-flow conclusions. The tool does not write to the server archive, EXE, player saves, or any game resources. The report from the supplied inputs is `skillwork/skill_cast_5675_path_audit.json`.

- The executable SHA-256 is `c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c`.
- `skill_new.ini` section with `StaticData=5675`: **raw section ID `c1d1ccecc8ad`** (GB18030 display `裂天拳`); `script=SkillNormal`, `ItemType=1000`.
- `skill_init.ini` section with the same numeric ID: four ASCII spaces followed by `c8ad`; trimming the spaces yields `c8ad` (`ȭ` in UTF-8).
- Both JSON skill tables use `config_id=ȭ`, UTF-8 `c8ad`. There are **zero** normalized `c8ad` section IDs in the supplied `skill_new.ini`.

### EXE disassembly anchors (addresses belong only to this exact on-disk build)

| Function / source line | Observed operation | Limit |
| --- | --- | --- |
| `main.loadSkillResourceTables`, `skill_catalog.go:124` | Loads `skill_new.ini` as the first table; its helper `main.loadSkillResourceTables.func1` calls `main.loadINISections`. | Static code path; not a measured successful load. |
| `main.loadCombatSkillCatalog`, `skill_catalog.go:714, 724–741` | Loads the tables, iterates the first skill table's section keys, and populates the catalog for supported script types. | Does not guarantee a definition is produced for every section. |
| `main.(*combatSkillCatalog).definition`, `skill_catalog.go:752, 757–758` | Consults internal definition/cache maps and has a missing-key return path. | No 5675-specific breakpoint was run. |
| `main.handleSkillCustom`, `skill_combat.go:2140, 2145, 2154–2155, 2277, 2322` | Checks learned level, calls `definition`, includes a WuJi variant fallback, then calls `beginSkillUse` and `stagePlayerSkillEffects` on the applicable path. | Alternate branches and in-game result remain unverified. |
| `main.loadSkillInitViews` / `main.loadINISections` | Separately load initialization views; the parser invokes `strings.TrimSpace`. | Initialization ID matching does not repair the ordinary catalog key. |

**Interpretation:** A client/server skill use referring to the JSON ID `ȭ` is a credible ordinary-catalog lookup-miss candidate because that ID is not a `skill_new.ini` key. This is stronger than an ID-name inventory mismatch, but **not** proof that a live cast fails: handler branches (including WuJi), runtime state, learned levels, player saves, actual client IDs, damage and cooldown were not exercised. Do not relabel `5675` as an implemented or missing gameplay skill solely on this result.

## Next skill-only validation gate

Verify the exact client skill ID and a controlled `5675` cast on an isolated Windows test server with expendable character data; observe the `definition` lookup and persisted skill ID before considering a coordinated resource/EXE change. No source is present for rebuilding the Go server and an untested binary patch is not justified. This PR remains draft and must not be merged as a working game update.

Local verification in this continuation: 6 new synthetic cast-path tests plus 9 existing patch-safety tests passed (15 tests run locally). The 10 earlier runtime-audit tests were not re-run in this sandbox; no Windows gameplay test was run. No unrelated packet, login, NPC, or game feature work was performed.
