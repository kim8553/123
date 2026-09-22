# Skill 5675 — isolated resource-only candidate (NOT DEPLOYABLE)

**Scope:** only `StaticData=5675` and the original supplied Go server build. Neither `main` nor the original server EXE, skill JSON, client binaries, account data or character saves is changed. **Never install on a production server, merge as a working game fix, or combine with the withdrawn `skill_id_5675_data_only_patch.zip`.**

## Why a candidate exists

The server role/template JSON and `data/faculty.json` use the skill ID `ȭ` (UTF-8 bytes `c8ad`); the server's `skill_init.ini` section also has the trimmed raw key `c8ad`. The ordinary skill catalog enumerates section keys from `skill_new.ini`, where the `StaticData=5675` section is instead raw bytes `c1d1ccecc8ad` (GB18030 renders them as `裂天拳`). The exact Go EXE's `combatSkillCatalog.definition` performs a string-key lookup and has a miss/false return; `handleSkillCustom` checks the result and may return before skill effects. **This identifies an ordinary-catalog lookup mismatch, not an observed real-world failure or proof of official-client compatibility.** A separate WuJi path and client-side identity still require runtime checks.

A read-only scan of the supplied server `data/` files and `resources/modern/share/skill/` files (excluding `.bak` files) found the full original `c1d1ccecc8ad` sequence only once, in `skill_new.ini`; unexamined files and runtime-generated references may still exist.

## Candidate changes and guards

`skill_5675_candidate.py` requires the exact original `skill_new.ini` SHA-256 `4263a384d38b40f50289b4121949d6fb497a56f0b482e7560f478cb6929b8056` and EXE SHA-256 `c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c`. It verifies the pinned EXE call graph, two INI views, JSON role/template identity and all three faculty roles. It replaces **one** original section header's raw bytes `5bc1d1ccecc8ad5d` with `5bc8ad5d`; it does not rewrite or transcode the rest of the INI. Exactly 17,855 section definitions remain, all other section identities and fields are preserved, and the JSON ID becomes a unique raw `skill_new.ini` key. It verifies the exact inverse replacement recreates the original bytes, then ZIP-tests its output.

The resulting experimental `skill_new.ini` SHA-256 is `652719c27441f46d9d06836147e80b4d6798e36597dacf77622785943a644b75`. The ZIP is handed directly to the user in chat, **not checked into this public repository** because it contains original game resources. The repository contains the generator, synthetic tests and redacted audit only.

```bash
python skillwork/skill_5675_candidate.py /path/to/original/nested_server.zip /path/to/9yin-game-native-menu.exe --output /path/to/skill_5675_catalog_candidate_LAB_ONLY.zip
python -m unittest discover -s skillwork -p 'test_*.py' -v
```

## Safety / validation boundary

The generated ZIP is **an unverified laboratory resource candidate**, not a functioning EXE patch or a new skill implementation. It has not been run with a Windows client/server, a learned test character, a cast request, damage/cooldown/buff validation or re-login/save migration. Before *any* isolated use, back up the original full `skill_new.ini` and all character saves; use a non-production server and test account. Test a pre-patch cast and the same cast with the candidate, collect only non-sensitive skill-specific outcomes, check learned level, effects, cooldown and save persistence, and restore the untouched original INI from the original archive if anything differs. Never replace JSON ID `ȭ` with `裂天拳` in this candidate.

The observed SHA-256 hashes and `skillwork/skill_5675_candidate_audit.json` are evidence of a narrowly bounded byte edit, **not** evidence of runtime correctness. Twenty synthetic unit tests passed locally this turn; no Windows integration test was possible in the sandbox.
