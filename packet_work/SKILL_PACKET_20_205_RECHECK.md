# 스킬 패킷 20/205 재검증 — 관측 패킷과 서버 송신 코드 구분

2026-09-22. 읽기 전용, 제공된 서버 아카이브와 SHA-256 고정 Windows Go EXE 기준. **실제 현재 서버 송신 패킷을 확보하거나 EXE를 수정한 작업은 아닙니다.** 공개 GitHub에는 원본 패킷·주소·식별자·서버 바이너리를 올리지 않습니다.

## 공식 서버로 표시된 캡처(두 개의 *디코딩된 로그*) 재집계

원본 서버 아카이브 내 `artifacts/capture-players/out1/frames.log`와 `out2/frames.log`의 **S2C `opcode=0x1E`** 중, TVar 메시지 ID를 20 또는 205로 엄격하게 파싱했습니다. 로그의 동일한 출처/독립 세션 여부는 별도로 확인하지 못했으므로 “독립 실험 횟수”가 아닌 **로그에서 발견한 프레임 건수**입니다.

| 메시지 ID | 값 3개 | 값 4개 | 값 5개 | 값 6개 | 값 7개 | 값 9개 | 합계 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 20 | 2 | 28 | 0 | 1,269 | 0 | 27 | 1,326 |
| 205 | 0 | 2,148 | 24 | 7 | 4 | 0 | 2,183 |

`msgID=20` 값 6개짜리 1,269건은 전부 `int32(msgID) → object8 → NUL-terminated ASCII string → object8 → int32 → float32`로 파싱됐습니다. `msgID=205`의 값 5·6·7개 변형은 추가 `object8` 인자를 포함합니다. **메시지 ID만 가지고 고정 길이·인자 개수를 가정하면 실제 패킷을 누락합니다.** 이전 PR #3 설명의 “2,115건이 모두 값 4개”는 `capture-players/out2`와 `capture-fxgame-op2`의 *값 4개짜리만 검출하던 부분집합*에 해당하며, 전체 메시지 205에 대한 설명이 아닙니다.

## 현 서버 EXE 정적 검증

EXE SHA-256: `c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c`. `main.nativeSkillActionFrameCaster`의 0x917a48–0x917a62 호출부는 `opcode=0x1e`, `msgID=0x14(20)`, 추가 인자 5개로 `main.serverCustomIntMessageWithOpcode`를 호출합니다. 래퍼 0x85706f는 메시지 ID 1개를 추가하고 인코더 0x8573e3은 TVar 개수를 헤더에 기록합니다. 해당 빌드의 타입 생성 지점과 공식 패킷을 대조하면 **예상되는 6개 인자의 타입 시퀀스도 공식 1,269건과 같습니다.** 이는 *정적 구성의 형식 호환 후보*이지, 서버가 해당 바이트를 실제 송신했다는 증거는 아닙니다.

## 결론과 실제 비교를 막는 자료

- **확인됨:** 공식 캡처의 메시지 20·205에는 여러 인자 개수의 변형이 있고, 현 서버의 특정 메시지 20 송신 코드에서 추론한 형식은 공식의 값 6개 변형과 일치합니다.
- **미검증:** 두 서버의 실제 송신 바이트·객체 ID·값·시퀀스·특정 스킬 동작의 일치 여부. 현재 서버 `artifacts/capture-localsrv/cap.pcapng`에는 TCP 데이터 페이로드가 **0바이트**입니다.
- **확인되지 않은 주장 금지:** “패킷이 전부 같다”, “다르므로 스킬이 고장났다”, “패킷 수정/EXE 수정 완료”. 이전 스킬 `5675` 실험 패치는 적용하면 안 됩니다.

## 재현 및 새 로컬 기록을 받았을 때

```bash
python packet_work/skill_msg20_schema_audit.py /path/to/server_nested.zip /path/to/matching_server.exe --output audit.json
python -m unittest discover -s packet_work -p 'test_*.py' -v
# 테스트 서버에서 직접 얻은 디코딩 frames.log 가 있다면
python packet_work/skill_msg20_schema_audit.py /path/to/server_nested.zip /path/to/matching_server.exe --local-frames /path/to/local/frames.log --local-capture-confirmed --output local_audit.json
```

Windows의 *격리된 테스트 환경*에서 Wireshark/Npcap으로 실제 게임 연결 인터페이스(같은 PC라면 루프백 포함)와 **실제 확인된 게임 포트**만 캡처하고, 스킬 1회를 사용한 시각과 스킬 ID를 별도로 기록하십시오. 암호화된 PCAP만으로는 `frames.log`가 자동으로 생기지 않을 수 있으니 동일 빌드의 합법적 디코더로 해석한 결과가 필요합니다. IP·계정·캐릭터 정보가 포함된 원본 캡처는 공개 저장소에 게시하지 마십시오. 동일 조건의 양쪽 송신 패킷이 확보되기 전에는 길이·필드·값의 *직접* 일치 판정을 하지 않습니다.
