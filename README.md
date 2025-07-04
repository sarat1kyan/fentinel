# FENTINEL: Universal Data Loss Prevention System 🔒🌐
```bash
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
█████╗  █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔══╝  ██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║     ███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Category](https://img.shields.io/badge/category-Software-red.svg)](https://github.com/sarat1kyan/Terminus)
[![Coverage](https://img.shields.io/badge/coverage-93%25-green.svg)](https://github.com/sarat1kyan/Terminus)
[![Compliance](https://img.shields.io/badge/compliance-CIS%20%7C%20ISO27001%20%7C%20NIST%20%7C%20STIG%20%7C%20PCI--DSS-green.svg)](https://github.com/sarat1kyan/Terminus)
[![Build Status](https://img.shields.io/badge/build-Stable%20%7C%20001278-brightgreen.svg)](https://github.com/sarat1kyan/Terminus)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OS](https://img.shields.io/badge/os-Linux%20%7C%20Windows%20%7C%20macOS-blue.svg)](https://www.python.org/downloads/)


**One Policy. All Platforms. Complete Protection.** FENTINEL is an open-source, cross-platform Data Loss Prevention solution that safeguards sensitive data across Linux, Windows, and macOS environments with military-grade precision.

## 🚀 Why FENTINEL?

| Feature | Benefit |
|---------|---------|
| 🔄 **Universal Policy Enforcement** | Define once, deploy everywhere - consistent protection across all OS environments |
| 🔍 **Real-time Data Monitoring** | Monitor data in motion, at rest, and in use with minimal performance impact |
| 🛡️ **Native OS Integration** | Leverages Windows ETW, macOS EndpointSecurity, and Linux eBPF for maximum efficiency |
| 📊 **Centralized Management** | Unified dashboard for policy management and incident response |
| ⚙️ **Automated Response** | Block, encrypt, quarantine, or alert on policy violations |

```mermaid
graph LR
A[Endpoint Agents] --> B[Policy Engine]
B --> C[Linux: eBPF/Auditd]
B --> D[Windows: ETW/WFP]
B --> E[macOS: EndpointSecurity]
C & D & E --> F[Central Dashboard]
F --> G[SIEM Integration]
```

## 🧩 Core Components

1. **Lightweight Agents** - Cross-platform binaries (5MB RAM avg)
2. **Policy Engine** - YAML/JSON-based rules with regex and ML detection
3. **Response Module** - Automated encryption, blocking, and quarantine
4. **Dashboard** - Real-time monitoring and alerting (Web UI)

## ⚡ Quick Start

### Prerequisites
- Python 3.8+
- Root/Admin privileges
- 100MB disk space

### Installation
```bash
# Linux (Debian/Ubuntu)
curl -sSL https://install.sentinelshield.io/linux | sudo bash

# Windows (PowerShell)
iwr -useb https://install.sentinelshield.io/win | iex

# macOS (Homebrew)
brew tap FENTINEL/tap
brew install FENTINEL
```

### Sample Policy
Create `policy.yaml`:
```yaml
policies:
  - id: PCI_PROTECTION
    name: "Block Credit Card Data"
    description: "Prevent PCI data exfiltration"
    triggers:
      - type: network
        protocol: [http, https, smtp]
        pattern: "\b(?:\d[ -]*?){13,16}\b"
      - type: file
        extensions: [txt, doc, pdf, xlsx]
        pattern: "\b(?:\d[ -]*?){13,16}\b"
    actions:
      network: block
      file: quarantine
      alert: critical
```

### Start Protection
```bash
sentinelctl start --policy policy.yaml
```

## 🛠️ Key Capabilities

### Data Monitoring Matrix
| Data Type | Linux | Windows | macOS |
|-----------|-------|---------|-------|
| **Network Traffic** | ✅ nftables | ✅ WFP | ✅ Network Extensions |
| **File Operations** | ✅ inotify | ✅ Minifilter | ✅ FSEvents |
| **Process Activity** | ✅ eBPF | ✅ ETW | ✅ EndpointSecurity |
| **Print/Clipboard** | ✅ CUPS | ✅ PrintMonitor | ✅ Pasteboard |

### Detection Methods
- **Regex Patterns** (SSN, PCI, API keys)
- **Machine Learning** (unstructured data)
- **File Fingerprinting**
- **Contextual Analysis** (user roles, location)
- **Custom Plugins**

## 📊 Dashboard Preview

```bash
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
█████╗  █████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔══╝  ██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║     ███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

[+] 12,847 files monitored
[+] 3,210 network connections analyzed
[!] 2 policy violations blocked

RECENT INCIDENTS:
2023-07-05 14:23:18 | BLOCKED | PCI_BLOCK | user@macbook | Credit card in email attachment
2023-07-05 13:47:12 | QUARANTINED | CONFIDENTIAL_DOCS | user@win-pc | Source code in cloud sync
```

## 🌐 Architecture Overview
```mermaid
graph TD
    A[Endpoint Agent] -->|Events| B(Policy Engine)
    B --> C{Detection Engine}
    C -->|Match| D[Response Module]
    D --> E[Block Network]
    D --> F[Encrypt File]
    D --> G[Quarantine]
    D --> H[Send Alert]
    B --> I[Central Dashboard]
    I --> J[SIEM Systems]
    I --> K[Audit Reports]
```

## 🧪 Testing Scenarios
1. **Linux Test**:  
   `echo "Credit Card: 4111-1111-1111-1111" > test.txt`  
   *Expected: File quarantined and alert triggered*

2. **Windows Test**:  
   Try emailing `SSN: 123-45-6789` via Outlook  
   *Expected: Email blocked*

3. **macOS Test**:  
   Copy sensitive data to external USB  
   *Expected: Operation blocked with admin alert*

## 🤝 Contributing
We welcome contributions! Please see our [Contribution Guidelines](CONTRIBUTING.md) and:
```bash
# Setup dev environment
git clone https://github.com/your-repo/FENTINEL.git
cd FENTINEL
pip install -r requirements-dev.txt

# Build agents
make build-all
```

## 📜 License
FENTINEL is released under the [MIT License](LICENSE). Enterprise support and advanced features available.

---
**Protect what matters.** Deploy FENTINEL in under 5 minutes and gain enterprise-grade DLP protection across your entire organization.  

[📚 Documentation](https://docs.sentinelshield.io) | [📦 Download](https://github.com/your-repo/releases) | [🐛 Report Issue](https://github.com/your-repo/issues)
