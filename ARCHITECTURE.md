# Kalitelligence Architecture

## Overview

Kalitelligence transforms Kali Linux into a comprehensive Threat Intelligence workstation. This document describes the system architecture, components, and data flows.

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         KALITELLIGENCE v2.0                              │
│                    Threat Intelligence Workstation                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│   User Layer  │          │ Control Layer │          │  Data Layer   │
│               │          │               │          │               │
│ • CLI Commands│◄────────►│ • Main Script │◄────────►│ • SQLite DB   │
│ • Web UI (✓)  │          │ • Automation  │          │ • Case Files  │
│ • API (✓)     │          │ • Scheduler   │          │ • Feed Cache  │
└───────────────┘          └───────────────┘          └───────────────┘
        │                           │                           │
        │                           ▼                           │
        │                  ┌───────────────┐                    │
        │                  │ Tool Layer    │                    │
        │                  │               │                    │
        │                  │ • OSINT Tools │                    │
        │                  │ • DFIR Tools  │                    │
        │                  │ • Network     │                    │
        │                  │ • Privacy     │                    │
        │                  └───────────────┘                    │
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    │
                                    ▼
                          ┌─────────────────┐
                          │ External Sources│
                          │                 │
                          │ • TI Feeds      │
                          │ • Target Systems│
                          │ • Cloud APIs    │
                          │ • Dark Web      │
                          └─────────────────┘
```

## Component Architecture

### Planned Modular Structure (v3.0)

```
kalitelligence/
├── bin/                          # Executable scripts
│   ├── kali-ti-suite            # Main installer
│   ├── ti-dashboard             # Live dashboard
│   ├── ti-report                # Report generator
│   ├── ti-health                # System health check
│   ├── ti-update                # Update manager
│   ├── ti-notify                # Notification handler
│   ├── quick-recon              # Reconnaissance orchestrator
│   ├── iocgrab                  # IOC extractor
│   ├── webshot                  # Screenshot tool
│   └── new-case                 # Case management
│
├── lib/                          # Core libraries
│   ├── core/
│   │   ├── logger.sh            # Logging utilities
│   │   ├── config.sh            # Configuration management
│   │   ├── validator.sh         # Input validation
│   │   └── utils.sh             # Common utilities
│   │
│   ├── installers/
│   │   ├── osint_tools.sh       # OSINT tool installer
│   │   ├── dfir_tools.sh        # DFIR tool installer
│   │   ├── network_tools.sh     # Network scanner installer
│   │   ├── privacy_tools.sh     # Privacy tool installer
│   │   └── ai_tools.sh          # AI/ML tool installer
│   │
│   ├── recon/
│   │   ├── subdomain_enum.sh    # Subdomain enumeration
│   │   ├── port_scan.sh         # Port scanning
│   │   ├── web_scan.sh          # Web application scanning
│   │   └── screenshot.sh        # Website screenshots
│   │
│   ├── intelligence/
│   │   ├── feed_manager.sh      # TI feed aggregation
│   │   ├── ioc_extractor.sh     # IOC extraction
│   │   ├── correlation.sh       # Data correlation
│   │   └── scoring.sh           # Threat scoring
│   │
│   ├── reporting/
│   │   ├── html_generator.sh    # HTML report generation
│   │   ├── markdown_gen.sh      # Markdown reports
│   │   ├── pdf_generator.sh     # PDF generation (✓)
│   │   └── templates/           # Report templates
│   │
│   └── integrations/
│       ├── slack.sh             # Slack integration
│       ├── discord.sh           # Discord integration
│       ├── misp.sh              # MISP integration (✓)
│       ├── opencti.sh           # OpenCTI integration (✓)
│       └── api_server.sh        # REST API server (✓)
│
├── config/                       # Configuration files
│   ├── defaults.conf            # Default settings
│   ├── tools.conf               # Tool configurations
│   ├── feeds.conf               # Feed configurations
│   └── presets/
│       ├── passive.conf
│       ├── darkweb.conf
│       ├── easm.conf
│       ├── dfir.conf
│       └── full.conf
│
├── tests/                        # Test suite
│   ├── unit/
│   │   ├── test_logger.sh
│   │   ├── test_validator.sh
│   │   └── test_config.sh
│   │
│   ├── integration/
│   │   ├── test_installation.sh
│   │   ├── test_recon.sh
│   │   └── test_reporting.sh
│   │
│   └── fixtures/
│       └── test_data/
│
├── docs/                         # Documentation
│   ├── user_guide.md
│   ├── admin_guide.md
│   ├── api_reference.md
│   └── troubleshooting.md
│
└── data/                         # Data schemas
    ├── sqlite_schema.sql
    ├── migrations/
    └── templates/
```

## Data Flow Architecture

### Reconnaissance Workflow

```
User Input (Domain/IP)
       │
       ▼
┌─────────────┐
│ Validation  │ → Sanitize input, check format
└─────────────┘
       │
       ▼
┌─────────────┐
│ Parallel    │ → Launch concurrent jobs
│ Orchestrator│
└─────────────┘
       │
       ├──────────┬──────────┬──────────┐
       ▼          ▼          ▼          ▼
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│Subdomain│ │ Port    │ │ Web     │ │ DNS     │
│Enum     │ │ Scan    │ │ Scan    │ │ Records │
└─────────┘ └─────────┘ └─────────┘ └─────────┘
       │          │          │          │
       └──────────┴──────────┴──────────┘
                      │
                      ▼
               ┌─────────────┐
               │ Aggregation │
               └─────────────┘
                      │
                      ▼
               ┌─────────────┐
               │ Correlation │
               └─────────────┘
                      │
                      ▼
               ┌─────────────┐
               │  Reporting  │
               └─────────────┘
                      │
                      ▼
               User Output / Storage
```

### Threat Intelligence Feed Processing

```
┌────────────┐    ┌────────────┐    ┌────────────┐
│  RSS/Atom  │    │   JSON     │    │    CSV     │
│   Feeds    │    │   APIs     │    │   Files    │
└────────────┘    └────────────┘    └────────────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
               ┌─────────────┐
               │  Fetchers   │
               │ (Parallel)  │
               └─────────────┘
                        │
                        ▼
               ┌─────────────┐
               │ Normalizer  │ → Convert to common format
               └─────────────┘
                        │
                        ▼
               ┌─────────────┐
               │ Deduplicator│ → Remove duplicates
               └─────────────┘
                        │
                        ▼
               ┌─────────────┐
               │   Enricher  │ → Add context/metadata
               └─────────────┘
                        │
                        ▼
               ┌─────────────┐
               │SQLite Store │ → Persistent storage
               └─────────────┘
                        │
                        ▼
               ┌─────────────┐
               │ Search/Index│ → Query interface
               └─────────────┘
```

## Security Architecture

### Current Security Model (v2.0)

```
┌─────────────────────────────────────────┐
│          Privilege Separation           │
├─────────────────────────────────────────┤
│                                         │
│  Root Level (Installation Only)         │
│  • Package installation                 │
│  • System configuration                 │
│  • Firewall setup                       │
│                                         │
│  User Level (Operations)                │
│  • Tool execution                       │
│  • Data storage                         │
│  • Report generation                    │
│                                         │
└─────────────────────────────────────────┘
```

### Target Security Model (v3.0)

```
┌─────────────────────────────────────────┐
│         Defense in Depth                │
├─────────────────────────────────────────┤
│                                         │
│  Layer 1: Input Validation              │
│  • Sanitize all user inputs             │
│  • Type checking                        │
│  • Range validation                     │
│                                         │
│  Layer 2: Access Control                │
│  • Role-based permissions               │
│  • API authentication                   │
│  • Audit logging                        │
│                                         │
│  Layer 3: Data Protection               │
│  • Encrypted storage (optional)         │
│  • Secure credential management         │
│  • Data retention policies              │
│                                         │
│  Layer 4: Network Security              │
│  • Firewall rules                       │
│  • Proxy support                        │
│  • Tor isolation                        │
│                                         │
│  Layer 5: Monitoring                    │
│  • Comprehensive logging                │
│  • Anomaly detection                    │
│  • Alert system                         │
│                                         │
└─────────────────────────────────────────┘
```

## Integration Points

### Current Integrations

| Integration | Status | Type | Description |
|-------------|--------|------|-------------|
| Slack | ✅ Implemented | Outbound | Alert notifications |
| Discord | ✅ Implemented | Outbound | Alert notifications |
| SQLite | ✅ Implemented | Internal | Data storage |
| Tor | ✅ Implemented | Network | Anonymity network |
| Docker | ✅ Implemented | Container | Tool isolation |

### Planned Integrations

| Integration | Priority | Type | Description |
|-------------|----------|------|-------------|
| MISP | High | Bi-directional | Threat intel sharing |
| OpenCTI | High | Bi-directional | Threat intel platform |
| TheHive | Medium | Outbound | Case management |
| Jira | Medium | Outbound | Ticket creation |
| Splunk | Medium | Outbound | SIEM integration |
| ELK Stack | Medium | Outbound | Log analysis |
| VirusTotal | High | Inbound | Enrichment API |
| Shodan | High | Inbound | Enrichment API |
| AlienVault OTX | Medium | Bi-directional | Threat intel sharing |

## Performance Architecture

### Parallel Processing Model

```
Main Process
     │
     ├─ Worker Pool (Configurable: default 4)
     │    ├─ Worker 1 → Task Queue
     │    ├─ Worker 2 → Task Queue
     │    ├─ Worker 3 → Task Queue
     │    └─ Worker 4 → Task Queue
     │
     ├─ Result Aggregator
     │
     └─ Progress Monitor
```

### Caching Strategy

```
┌─────────────┐
│ User Request│
└─────────────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│ Cache Check │────►│ Cache Hit   │───► Return Cached Result
└─────────────┘     └─────────────┘
       │
       │ Cache Miss
       ▼
┌─────────────┐
│ Execute     │
│ Operation   │
└─────────────┘
       │
       ▼
┌─────────────┐
│ Store in    │
│ Cache       │
└─────────────┘
       │
       ▼
┌─────────────┐
│ Return      │
│ Result      │
└─────────────┘
```

## Deployment Models

### Single-User Deployment (Current)

```
┌──────────────────────┐
│   Kali Linux VM      │
│                      │
│ ┌──────────────────┐ │
│ │  Kalitelligence  │ │
│ │    (Local)       │ │
│ └──────────────────┘ │
│                      │
│   Data: ~/OSINT/    │
│   Logs: /var/log/   │
└──────────────────────┘
```

### Multi-User Deployment (Planned)

```
┌────────────────────────────────────────┐
│         Central Server                 │
│  ┌──────────────────────────────────┐  │
│  │     Kalitelligence Server        │  │
│  │  • API Gateway                   │  │
│  │  • Job Queue                     │  │
│  │  • Database                      │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
           │              │
           │              │
    ┌──────┘              └──────┐
    │                            │
    ▼                            ▼
┌─────────┐                ┌─────────┐
│ Client 1│                │ Client 2│
│ (CLI)   │                │ (Web UI)│
└─────────┘                └─────────┘
```

## Monitoring & Observability

### Logging Architecture

```
Application Logs
       │
       ├─ /var/log/ti-suite/install-*.log  → Installation events
       ├─ /var/log/ti-suite/recon-*.log    → Reconnaissance operations
       ├─ /var/log/ti-suite/feeds-*.log    → Feed processing
       └─ /var/log/ti-suite/api-*.log      → API requests (planned)
       │
       ▼
Log Rotation (logrotate)
       │
       ▼
Retention Policy (30 days default)
```

### Metrics Collection (Planned)

- Installation time metrics
- Tool execution duration
- Success/failure rates
- Resource utilization
- Cache hit rates
- API response times

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Maintained By**: Kalitelligence Development Team
