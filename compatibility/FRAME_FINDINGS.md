# Application-frame audit addendum (2026-09-22)

The provided server archive includes `artifacts/official_decode.py` / `artifacts/players_pipeline.py`, which describe an `EE EE` frame terminator, `EE 00` escape, and per-frame fixed XOR key `0xFA6D3BCC`. `frame_opcode_audit.py` implements **that existing decoding hypothesis** without requiring `tshark`, streams TCP segments per directional flow, skips retransmissions, separates gaps, and emits only numeric histograms; it does not upload or print captured contents. Decoding counts are candidates until validated against client/server behavior. The CLI does not automatically label traffic direction: pass the known game server port explicitly.

## Measurements on user-supplied captures

| Capture (identified by folder) | Supplied game server port | Candidate frames | S→C `0x1e` frames / parseable numeric custom IDs | C→S candidate frames |
| --- | ---: | ---: | ---: | ---: |
| `artifacts/capture-players/official_players.pcapng` | `7061` | 468 | 155 / 10 distinct IDs | 23 (`0x0a`: 13, `0x18`: 10) |
| `artifacts/capture-players/official_login2.pcapng` | `7064` | 38,347 | 9,146 / 85 distinct IDs | 2,780 |
| `artifacts/capture-localsrv/cap.pcapng` | not supplied | 0 | 0 / 0 | 0 |

For `official_players.pcapng`, numeric S→C custom IDs and occurrence counts are `18:14`, `19:5`, `20:28`, `24:28`, `43:1`, `205:46`, `229:3`, `294:10`, `337:19`, `711:1`. A numeric message ID is **not** a skill config ID. The empty loopback capture contains 2,509 packets but no parsable application TCP payload; it **cannot** be used for a packet-by-packet official-versus-local comparison. Different captures may cover different sessions and character/game states.

The official captures have frame candidates with plausible repeated opcodes and `0x1e` int32-first-argument layouts. They also include non-game control streams (such as port 6001); malformed escape counts can come from those streams and are **not evidence of protocol failure**.

### Reproduce privately

```bash
python3 compatibility/frame_opcode_audit.py --server-port 7061 '/private/capture-players/official_players.pcapng'
python3 compatibility/frame_opcode_audit.py --server-port 7064 '/private/capture-players/official_login2.pcapng'
python3 -m unittest discover -s compatibility -p 'test_*.py' -v
```

## Concrete remaining blocker

There is no comparable local-server application payload in the provided `capture-localsrv/cap.pcapng`, no validated official-client skill manifest extracted from the `PCK0` packages, and no Go source in the supplied server archive. Therefore this audit **does not establish an exact divergent field or a truly missing skill handler**. Do not change the executable or insert the 167 server-table-only IDs based on these observations. A patched Windows EXE, added gameplay skills, and Windows/game-client integration tests have not been produced.
