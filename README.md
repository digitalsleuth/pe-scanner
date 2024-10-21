# pe-scanner

A Python 3 rebuild of the [original pescanner.py](https://github.com/hiddenillusion/AnalyzePE/blob/master/pescanner.py) from Michael Ligh and updated by Glenn P. Edwards Jr.

## Updates

- Now uses capstone instead of pydasm to capture initial instructions  
  
- Argparse added to select clamscan binary path, userdb, yara rules, etc.

## Usage
```bash
usage: pe-scanner [-h] [-c <path-to-clamscan>] -f <input-file> [-u <userdb-file>] [-y <yara-rule>] [--verbose]

pe-scanner v2.0.0

optional arguments:
  -h, --help            show this help message and exit
  -c <path-to-clamscan>, --clamscan <path-to-clamscan>
                        Path to clamscan, will scan if chosen
  -f <input-file>, --file <input-file>
                        File to scan
  -u <userdb-file>, --userdb <userdb-file>
                        Path to your userdb.txt
  -y <yara-rule>, --yara <yara-rule>
                        Path to your yara rules
  --verbose             Verbose mode - print more detail to stdout
```
