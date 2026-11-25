# port-scanner

Scan a host for open TCP ports.

## Requirements

- Python 3 (standard library only — no third-party packages)

## How to run

```bash
cd 057-port-scanner
python3 main.py 127.0.0.1 --ports 22,80,443
```

Run `python3 main.py --help` to see all options.

## Example

```bash
python3 main.py 127.0.0.1 --ports 22,80,443
```

Sample output:

```
Scanning 127.0.0.1 (127.0.0.1): 3 port(s)...

Open (1):
  22/tcp  open  SSH
```

## Notes

Only scan hosts you own or have permission to scan. `--ports` accepts a range (`1-1024`), a list (`22,80,443`), or `common`. Tune speed with `--timeout` and `--workers`, and add `--show-closed` to list closed ports too.

## License

MIT — see [LICENSE](LICENSE).
