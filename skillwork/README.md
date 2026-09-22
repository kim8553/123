# 스킬 전용 조사: StaticData 5675 — 기존 패치 사용 금지

2026-09-22. **앞서 전달한 `skill_id_5675_data_only_patch.zip`을 적용하지 마세요.** 해당 후보 패치는 잘못된 단일 파일 비교에 기초했습니다. 이 PR은 서버 EXE 수정, 새로운 전투 스킬 구현 또는 Windows 게임 내 발동 검증을 포함하지 않습니다.

## 제공된 서버 파일에서 확인한 사실

아래는 본서버 클라이언트의 스킬 목록이 아니라 **사용자가 제공한 서버 압축 내부의 자료**입니다.

| 파일 | StaticData=5675의 관찰값 |
| --- | --- |
| `data/skills.json` | `config_id=ȭ` (역할 2·4 각각 한 건) |
| `data/技能数据.json` | `config_id=ȭ` (템플릿 한 건) |
| `resources/modern/share/skill/skill_init.ini` | UTF-8의 `[    ȭ]` — 선행 ASCII 공백 네 개; 공백 제거 후 `ȭ` |
| `resources/modern/share/skill/skill_new.ini` | GB18030에서 `[裂天拳]` |
| `resources/modern/share/skill/skill_static.ini` | 숫자 섹션 `[5675]`, `TaoLu=clone011` |

**이전 설명 정정:** `skill_init.ini`의 `[    拳]`이라는 표기는 파일을 잘못된 인코딩으로 해석해서 나온 것입니다. `skill_init.ini` 전체는 UTF-8로 정상 디코딩되며 섹션의 원본 바이트는 `5b20202020c8ad5d`입니다. `skill_new.ini`의 섹션 원본 바이트는 `5bc1d1ccecc8ad5d`이며, GB18030에서는 `裂天拳`입니다. JSON의 `ȭ`은 UTF-8 `c8ad`로서 `skill_init.ini`의 공백 제거 후 ID와 **바이트 단위로 일치**합니다. 이것만으로 실제 발동이나 저장 데이터 호환성이 입증되지는 않습니다.

## 스킬 데이터 전수 대조

`skillwork/skill_runtime_audit.py`는 두 INI 파일을 원본 바이트 기반으로 파싱하고 `StaticData`를 연결합니다. 공통 번호 **17,855개** 중 공백 제거 후 섹션 이름이 같은 번호는 **17,854개**, 다른 번호는 **5675 한 개**였습니다. 어느 쪽 파일에만 존재하는 `StaticData` 번호는 없었습니다. `skill_init.ini`에 섹션 중복 6개가 있고, 8240과 8454는 일부 필드 값이 다릅니다. 이 중복이 의도된 덮어쓰기인지 오류인지는 아직 확실하지 않습니다.

컴파일된 Go EXE의 `main.loadINISections` 디스어셈블리에서 `strings.TrimSpace` 호출과 스킬 초기화 로더 `main.loadSkillInitViews`의 해당 파서 호출을 확인했습니다. 그래서 선행 공백 제거를 검사에 반영했습니다. 이 검사는 실제 게임을 실행하는 에뮬레이터가 아니며 INI 로더의 모든 동작을 동일하게 재현한다고 주장하지 않습니다.

## 재현과 테스트

```bash
python skillwork/skill_runtime_audit.py /path/to/nested_server.zip --report audit.json
python -m unittest discover -s skillwork -p 'test_*.py' -v
```

새 감사 도구의 **합성 데이터 단위 테스트 10개**와 기존 패치 차단 도구의 **합성 테스트 9개**, 총 **19개**를 격리된 작업 공간에서 실행해 통과했습니다. 실제 제공 서버 압축으로 새 감사를 수행한 결과 `status=INVESTIGATION_REQUIRED`, `safe_to_patch=false`였습니다. `skillwork/skill_id_5675_blocked_audit.json`은 잘못된 인코딩 해석을 포함하는 이전 기록이므로 **폐기된 기록**입니다. 현재 결과는 `skillwork/skill_runtime_verified_audit.json`을 기준으로 확인하세요. 기존 `skill_id_repair.py`의 패치 생성 기능은 사용하지 마세요.

## 검증되지 않은 것

어느 ID가 해당 클라이언트에서 올바른 ID인지, 서버가 `5675`를 실제로 어떤 이름으로 조회하는지, 효과·쿨다운·피해 계산이 정상인지, 기존 캐릭터 저장 데이터에 대한 영향은 **알 수 없습니다**. 별도 전투 스킬 실행 경로 `main.loadCombatSkillCatalog`, `main.handleSkillCustom`, `main.loadSkillInitViews`가 존재한다는 사실만으로 스킬 구현이나 호환성이 확인되지는 않습니다. `wuji_` 항목을 숫자만 보고 일괄 추가하지 마세요.

**안전 경계:** 원본 EXE, 서버 압축, 캐릭터 저장 데이터, GitHub `main`은 이 조사에서 변경하지 않았습니다. PR은 스킬 데이터 분석용 초안으로 유지하고 완성된 게임 업데이트로 배포하지 마세요.
