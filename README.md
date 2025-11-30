<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
</p>

<h1 align="center">
  <br>
  <pre>
  ___                   _
 |_ _|_ __  _ __  _   _| |_ ___ _ __
  | || '_ \| '_ \| | | | __/ _ \ '__|
  | || | | | |_) | |_| | ||  __/ |
 |___|_| |_| .__/ \__,_|\__\___|_|
           |_|
  </pre>
  <br>
  Form & Input Parameter Extractor
  <br>
</h1>

<p align="center">
  <b>A fast, concurrent web form scanner that extracts input parameters for security testing</b>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#options">Options</a>
</p>

---

## What is Inputer?

**Inputer** is a high-performance tool designed for bug bounty hunters and security researchers. It crawls web pages to discover form inputs, standalone input fields, and URL parameters - then generates fuzz-ready URLs for testing.

```bash
$ inputer -l urls.txt

https://target.com/search?q=FUZZ
https://target.com/login?username=FUZZ&password=FUZZ
https://target.com/api?id=FUZZ&action=FUZZ
```

---

## Features

| Feature | Description |
|---------|-------------|
| ⚡ **Concurrent Scanning** | Process hundreds of URLs simultaneously with configurable workers |
| 🔍 **Smart Detection** | Finds forms, standalone inputs, and URL parameter hints |
| 🎯 **Fuzz-Ready Output** | Generates URLs with `FUZZ` placeholders ready for tools like ffuf/nuclei |
| 🔄 **Auto Retry** | Automatic retry on failed requests with exponential backoff |
| 🌐 **Proxy Support** | Route traffic through Burp Suite or other proxies |
| 📊 **Progress Tracking** | Real-time progress bar for large scans |
| 🎨 **Colored Output** | Beautiful terminal output with color coding |
| 📁 **Flexible Output** | Output to stdout or save directly to file |
| 🔒 **TLS Options** | Skip certificate verification for testing |

---

## Installation

### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/user/inputer.git
cd inputer

# Build
go build -o inputer inputer.go

# Run
./inputer -h
```

### Option 2: One-liner

```bash
go build -o inputer inputer.go && sudo mv inputer /usr/local/bin/
```

### Option 3: Windows

```powershell
go build -o inputer.exe inputer.go
```

---

## Usage

### Basic Usage

```bash
# Scan URLs from a file
inputer -l urls.txt

# Save results to file
inputer -l urls.txt -o results.txt

# Silent mode (only output results)
inputer -l urls.txt -s
```

### Pipeline Usage

```bash
# Pipe to other tools
inputer -l urls.txt -s | nuclei -t xss.yaml

# From stdin
cat urls.txt | inputer -l /dev/stdin

# Chain with other tools
echo "https://target.com" | inputer -l /dev/stdin | httpx -silent
```

---

## Examples

### High-Performance Scanning

```bash
# 50 concurrent workers, 5 second timeout
inputer -l urls.txt -c 50 -t 5 -o results.txt
```

### Rate-Limited Scanning

```bash
# 100 requests per second with verbose output
inputer -l urls.txt -r 100 -v
```

### Through Proxy (Burp Suite)

```bash
# Route through Burp for inspection
inputer -l urls.txt -proxy http://127.0.0.1:8080 -insecure
```

### Include POST Forms

```bash
# Also extract POST form parameters
inputer -l urls.txt -post
```

### Custom User-Agent

```bash
# Use custom User-Agent
inputer -l urls.txt -ua "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
```

---

## Options

```
Usage: inputer -l <urls.txt> [options]

INPUT:
  -l string          File containing list of URLs to scan (required)

OUTPUT:
  -o string          Output file (default: stdout)
  -s                 Silent mode (only output results)
  -v                 Verbose output (show errors)
  -no-color          Disable colored output

PERFORMANCE:
  -c int             Number of concurrent workers (default: 10)
  -t int             HTTP timeout in seconds (default: 10)
  -r int             Rate limit - requests per second (default: 0 = unlimited)
  -delay int         Delay between requests in milliseconds

REQUESTS:
  -retries int       Number of retries for failed requests (default: 2)
  -ua string         Custom User-Agent header
  -follow            Follow redirects (default: true)
  -max-redirects int Maximum redirects to follow (default: 5)

FORMS:
  -post              Include POST forms in output

NETWORK:
  -proxy string      Proxy URL (e.g., http://127.0.0.1:8080)
  -insecure          Skip TLS certificate verification

INFO:
  -version           Show version
  -h                 Show help
```

---

## Output Format

### GET Forms
```
https://target.com/search?q=FUZZ&category=FUZZ
```

### POST Forms (with -post flag)
```
[POST] https://target.com/login (params: username=FUZZ&password=FUZZ)
```

---

## What It Detects

| Type | Example | Detection |
|------|---------|-----------|
| **Form Inputs** | `<form><input name="q"></form>` | ✅ Extracted |
| **Select Fields** | `<select name="category">` | ✅ Extracted |
| **Textarea** | `<textarea name="comment">` | ✅ Extracted |
| **Standalone Inputs** | `<input name="search">` (no form) | ✅ Extracted |
| **URL Hints** | `Use ?p1=...&p2=...` in page text | ✅ Fallback |

---

## Performance Tips

| URL Count | Recommended Settings |
|-----------|---------------------|
| < 100 | Default settings |
| 100 - 1,000 | `-c 30 -t 10` |
| 1,000 - 10,000 | `-c 50 -t 5 -r 200` |
| 10,000+ | `-c 100 -t 5 -r 500 -s -o results.txt` |

---

## Integration Examples

### With Nuclei
```bash
inputer -l urls.txt -s | nuclei -t vulnerabilities/
```

### With FFUF
```bash
inputer -l urls.txt -s | while read url; do
  ffuf -u "$url" -w wordlist.txt -mc 200
done
```

### With httpx
```bash
inputer -l urls.txt -s | httpx -silent -status-code
```

### Parallel Processing
```bash
inputer -l urls.txt -s | parallel -j 10 'curl -s "{}"'
```

---

## Contributing

Contributions are welcome! Feel free to:

- Report bugs
- Suggest features
- Submit pull requests

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ❤️ for the Bug Bounty Community
</p>

<p align="center">
  <a href="https://github.com/user/inputer/issues">Report Bug</a>
  ·
  <a href="https://github.com/user/inputer/issues">Request Feature</a>
</p>
