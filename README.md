# NetOPS IP Range and Port Scanner

A lightweight and fast Tkinter-based IP range and port scanner with hostname resolution and CSV export. Built for quick internal network sweeps and diagnostics.

---

## 🚀 Features

- Scan an IP **range** or **CIDR block**
- **Ping sweep** to detect live hosts
- **Multithreaded port scanning** for faster results
- **Reverse DNS (PTR) hostname resolution**
  - Use system DNS, Google DNS, or custom DNS servers
- **Export results to CSV**
- Simple and responsive **Tkinter GUI**
- License prompt on startup (MIT)

---

## 🖥️ Requirements

- Python 3.7+
- Modules:
  - `tkinter` (built-in)
  - `ipaddress` (built-in in Python 3.3+)
  - `socket`, `subprocess`, `platform`, `threading`, `concurrent.futures`, `csv` (built-in)
  - `dnspython`: for reverse DNS lookups

### ✅ Install `dnspython`

```bash
pip install dnspython
