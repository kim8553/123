"""Compatibility shim for the existing skill-packets PCAPNG payload counter.

The new packet_work audit imports this module as `skill_packet_parity`, while the
previous audited implementation is kept under `skill-packets/` in this repo.
Only its conservative, address-free TCP payload statistics function is reused.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

previous = Path(__file__).resolve().parent.parent / 'skill-packets' / 'skill_packet_parity.py'
if not previous.is_file():
    raise RuntimeError(f'Required previous skill-packets parser missing: {previous}')
spec = spec_from_file_location('_existing_skill_packet_parity', previous)
if spec is None or spec.loader is None:
    raise RuntimeError('Could not load existing skill-packets parser')
module = module_from_spec(spec)
spec.loader.exec_module(module)
local_pcap_payload_stats = module.local_pcap_payload_stats
