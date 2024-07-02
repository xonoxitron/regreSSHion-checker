# regreSSHion-checker

## 📜 Description

regreSSHion-checker is a lightweight, efficient tool designed to identify servers running vulnerable versions of OpenSSH, specifically targeting the recently discovered `regreSSHion` vulnerability (CVE-2024-6387). This tool facilitates rapid scanning of multiple IP addresses, domain names, and CIDR network ranges to detect potential vulnerabilities and ensure the security of your infrastructure.

![regreSSHion-checker](https://github.com/xonoxitron/regreSSHion-checker/blob/main/banner.png?raw=true)

## 🌟 Features

- **Rapid Scanning**: Quickly scan multiple IP addresses, domain names, and CIDR ranges for the CVE-2024-6387 vulnerability.
- **Banner Retrieval**: Efficiently retrieves SSH banners without authentication.
- **Concurrency**: Utilizes Go's concurrency model (goroutines) for parallel execution, significantly reducing scan times.
- **Clear Output**: Provides clear, emoji-coded output summarizing scan results.
- **Port Check**: Identifies closed ports and provides a summary of non-responsive hosts.

## 🛠️ Installing or Building

To install regreSSHion-checker from the GitHub repository, ensure you have Go installed and configured properly. Use the following command:

```bash
go get github.com/xonoxitron/regreSSHion-checker
```

After installation, you can use regreSSHion-checker as described in the usage section below.

To build `regreSSHion-checker` from source, ensure you have Go installed and follow these steps:

1. Clone the repository or download the source code.
   ```bash
   git clone https://github.com/your/repo.git
   cd regreSSHion-checker
   ```

2. Build the binary using `go build`.
   ```bash
   go build regreSSHion-checker.go
   ```

3. Optionally, you can set execute permissions.
   ```bash
   chmod +x regreSSHion-checker
   ```

Now you can use `./regreSSHion-checker` to scan for CVE-2024-6387 vulnerabilities in OpenSSH across your infrastructure.

## 🚀 Usage

```bash
./regreSSHion-checker <targets> [--port PORT]
```

### Examples

#### Single IP

```bash
./regreSSHion-checker 192.168.1.1
```

#### IPs from a list

```bash
./regreSSHion-checker -list ip_list.txt
```

#### Multiple IPs and Domains

```bash
./regreSSHion-checker 192.168.1.1 example.com 192.168.1.2
```

#### CIDR Range

```bash
./regreSSHion-checker 192.168.1.0/24
```

#### With Custom Port

```bash
./regreSSHion-checker 192.168.1.1 example.com --port 2222
```

### Output

The tool provides a summary of the scanned targets:

- 🛡️ Not Vulnerable: Servers running a non-vulnerable version of OpenSSH.
- 🚨 Vulnerable: Servers running a vulnerable version of OpenSSH.
- 🔒 Closed Ports: Count of servers with port 22 (or specified port) closed.
- 📊 Total Scanned: Total number of targets scanned.

```text
🛡️ Servers not vulnerable: 1

   [+] Server at 157.90.125.31 (running SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11)

🚨 Servers likely vulnerable: 2

   [+] Server at 4.231.170.121 (running SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10)
   [+] Server at 4.231.170.122 (running SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2)

🔒 Servers with port 22 closed: 254

📊 Total scanned targets: 257
```

## 📚 References
- [Qualys Blog on regreSSHion Vulnerability](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server)

---

### Notes:

- Ensure you have Go installed to compile and run the tool (`go build regreSSHion-checker.go`).
- Replace `regreSSHion-checker` with the name of the Go binary compiled from your source file.
- Adjust permissions if needed (`chmod +x regreSSHion-checker`) to execute the binary directly.

This README.md file now reflects the usage and features of the Go version of the regreSSHion-checker tool, providing users with clear instructions and examples for effective vulnerability scanning of OpenSSH servers.