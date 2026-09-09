# Testing

Run:

```bash
python -m pytest -q
python -m ruff check diodeshield tests training zeek
python -m diodeshield.cli --scenario protocol --count 30
```

The tests cover feature extraction, FFT outputs, Modbus parsing, fusion,
persistence, explanations, metadata-only spoof/alteration/behavior evidence, and
API health. The CLI is a reproducible synthetic integration smoke test. Zeek/TShark
and real PCAP replay require those system tools and are kept optional so the
receive-side core remains runnable on a workstation. The offline threat lab is the
preferred validation path; it never crafts malformed packets, spoofs a socket
identity, floods a remote host, or sends traffic into an OT network.
