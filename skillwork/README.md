# Skill-only investigation: `StaticData=5675`

Date: 2026-09-22. **EXE unchanged. No new combat skill implemented or verified.** This directory intentionally does not work on login, unrelated opcodes, networking or other gameplay features.

## Grounded inputs

All counts below are from the user-supplied **server** archive (`九阴服务端-2026年9月21日更新.zip` nested inside the uploaded multipart archive), *not* a decoded official-client skill manifest. No original game binaries, full skill tables, character saves or login/session data are checked into this public repository.

- `data/skills.json`: roles `2` and `4`, each containing 17,633 distinct `config_id`s; their ID sets are equal.
- `data/技能数据.json`: 17,466 distinct template IDs; 167 numeric IDs are in the role sets but absent from the template.
- `resources/modern/share/skill/skill_new.ini`: 17,855 unique section IDs (decode section names with GB18030). Of these, 390 do not occur in the role set: 389 begin `wuji_`, and one is `裂天拳`. Conversely, 168 role IDs are not INI section names: 167 numeric IDs and `ȭ`.
- Among 17,465 *exactly matching* resource/role section names, `StaticData` matches for all 17,465. For matching entries declaring `ItemType` (17,427 entries) or `PauseTime` (2,185 entries), those fields also match the role values. This is a consistency check of **server data only**.

The `wuji_` count is **not** a list of missing skills to bulk-import. The compiled Go server exposes dedicated functions such as `main.loadWuJiCatalog`, `main.handleWuJiSubCommand`, `main.wujiVariantSkillFor`, `main.(*playerActor).pushWuJiSkillViews`, and `main.handleSkillCustom`. No runtime execution or successful WuJi cast has been proven by merely observing their symbols.

## One concrete ID mismatch

Server resource `skill_new.ini` contains a **unique** section `[裂天拳]` with `StaticData=5675`; `skill_static.ini` also contains section `[5675]`. Both `data/skills.json` (once per role) and `data/技能数据.json` (once) instead store `{"config_id":"ȭ", "static_data":5675, ...}` and do not contain `裂天拳` as a `config_id`. This is a concrete **server-resource versus server-JSON** ID mismatch. Whether the official client uses this ID, and whether the Go server accepts a corrected cast, remain unverified.

`skill_id_repair.py` locates the resource section by the unique static ID and creates an **optional data-only patch ZIP** containing replacement copies of precisely the two JSON files; it edits only the three `config_id` string values, preserving other JSON bytes and skill progress fields. Run in audit-only mode without `--output`; the source archive is never overwritten. It refuses unexpected role structure, wrong static ID, ambiguous resource IDs, name collisions and unexpected JSON layout.

```bash
python skillwork/skill_id_repair.py /path/to/nested_server.zip
python skillwork/skill_id_repair.py /path/to/nested_server.zip --output /path/to/skill_data_patch.zip
python -m unittest discover -s skillwork -p 'test_*.py' -v
```

**Do not install the patch on a live server without backups, persisted-ID migration and an isolated Windows client/server test.** Old saved references to `ȭ` are not migrated. This patch does **not** modify the EXE, add a new skill handler, validate damage/cooldown/buff logic, or establish official-client parity. It is provided as a narrowly scoped candidate fix, not a deployable completed feature.

## Provenance fingerprints

- Server EXE SHA-256: `c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c`.
- Original `data/skills.json` SHA-256: `e1e8937cd23236cf71e446e6a9d3387390f30aeadbafe03e6948c6def99d1059`; patched copy: `8c904792b019326544f4a962c48f02dec2bb58f8dcaa38df3df7653f71d4fe40`.
- Original `data/技能数据.json` SHA-256: `5711486a4e31a77573c6d0c3242d2824939b07867cade3afa3aea519d934e394`; patched copy: `ccd7ef0a65740ca9a1f37292419c3670975858930cbaa6364dee3c5baeb99039`.

Next skill-only validation requires determining which `wuji_` variants go through the dedicated WuJi runtime path and obtaining a comparable official-client skill manifest or controlled cast observation. Do not synthesize a skill implementation based only on name-set differences.
