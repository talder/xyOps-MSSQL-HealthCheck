<p align="center"><img src="https://raw.githubusercontent.com/talder/xyOps-MSSQL-HealthCheck/refs/heads/main/logo.png" height="108" alt="Logo"/></p>
<h1 align="center">VMware VM Operations</h1>

# xyOps MSSQL Health Check Plugin

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/yourusername/xyOps-MSSQL-HealtCheck/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![dbatools](https://img.shields.io/badge/dbatools-2.0+-green.svg)](https://dbatools.io)

A comprehensive, production-grade SQL Server health check plugin for xyOps that performs **72 detailed checks** across multiple servers, including Availability Group topologies, with actionable remediation steps.

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, system downtime, or other issues that may arise from the use of this software. Always test in non-production environments before running against production systems. By using this plugin, you acknowledge that you have read, understood, and accepted this disclaimer.

## Performance Impact Warning

**IMPORTANT:** This plugin performs 72 comprehensive health checks that can generate significant load on SQL Server instances, particularly when analyzing index fragmentation, query performance statistics, wait statistics, I/O latency, and multiple Availability Group replicas.

**Do not run during critical business hours or peak operation times on production systems.**

**Execution Time:** Expect 15-60+ minutes depending on the number of databases, database sizes, AG replicas, and server workload.

**Recommended Schedule:**
- **Monthly** - Ideal for most environments
- **Weekly** - Only during maintenance windows for high-change environments
- **After major changes** - During planned maintenance windows only
- **Before upgrades** - During change windows

**Best Practice:** Schedule during off-peak hours, maintenance windows, or weekends when production load is minimal.

## 🚀 Quick Start

Get started in 3 simple steps:

1. **Configure credentials** in xyOps Secret Vault:
   - `MSSQLHC_USERNAME` - Your SQL Server username
   - `MSSQLHC_PASSWORD` - Your SQL Server password
   - (Optional) `MSSQLHC_SERVER_ADMIN_USER` - Windows admin username for enhanced checks
   - (Optional) `MSSQLHC_SERVER_ADMIN_PASSWORD` - Windows admin password

2. **Run the plugin** in xyOps:
   - Enter your SQL Server hostname
   - Click Run

3. **Review the report** - Lean back and wait for the comprehensive Markdown report!

That's it! The plugin automatically discovers Availability Groups, connects to all replicas, and performs 72 health checks.

> **Note:** Server admin credentials enable enhanced checks for Lock Pages in Memory, Instant File Initialization, and Memory Configuration. They're optional but recommended for complete coverage (Windows only).

## Features

### Core Capabilities
- **Automatic AG Discovery** - Discovers and connects to all Availability Group partner replicas
- **Multi-Server Analysis** - Checks multiple SQL Server instances in a single execution
- **72 Comprehensive Checks** - Covers server health, security, database configuration, performance, and high availability
- **Flexible Check Filtering** - Exclude or include specific checks using numeric IDs or preset groups
- **Detailed Remediation** - Provides PowerShell, T-SQL, and manual step-by-step fixes for each issue
- **Professional Markdown Reports** - Clean, structured reports with table of contents
- **Executive Dashboard** - At-a-glance health score and statistics with exclusion tracking
- **Raw Data Export** - Complete diagnostic data in structured format
- **Microsoft Documentation Links** - Direct links to official documentation for each check

### Advanced Features
- **Check Exclusions** - Skip specific checks or entire categories
- **Check Inclusions** - Run only selected checks for targeted analysis
- **Preset Groups** - Use convenient shortcuts (security, performance, availability, backup, database)
- **Exclusion Tracking** - Document why checks were excluded with reason field
- **Table of Contents** - Navigate reports easily with automatic TOC generation
- **PDF Export** - Optional PDF conversion with pandoc or markdown-pdf
- **Cross-Platform** - Runs on Windows, Linux, and macOS with automatic OS detection

## 📋 Health Checks Performed

### Server Configuration & Health (14 checks)
- **Check 1: SQL Server Version & Updates** - Verifies version and patch level against latest CU
- **Check 2: Lock Pages In Memory** - Checks critical memory privilege for SQL Server
- **Check 3: Instant File Initialization** - Validates IFI privilege for fast database file growth
- **Check 4: Memory Configuration** - Reviews min/max server memory settings
- **Check 5: Last Backup** - Identifies databases without recent backups
- **Check 6: Database Percent Growth** - Detects improper percentage-based growth settings
- **Check 7: Recovery Model** - Validates recovery model matches backup strategy
- **Check 8: Virtual Log Files (VLFs)** - Detects excessive VLF fragmentation
- **Check 9: TempDB Configuration** - Verifies TempDB files, size, and growth settings
- **Check 10: Integrity Check (DBCC CHECKDB)** - Checks when last corruption check ran
- **Check 11: Index Fragmentation** - Identifies heavily fragmented indexes (>50%)
- **Check 12: Auto Shrink** - Detects dangerous auto shrink database option
- **Check 13: Auto Close** - Identifies problematic auto close setting
- **Check 14: Page Verify Option** - Validates page corruption detection settings

### Security & Compliance (21 checks)
- **Check 15: SA Account Status** - Verifies sa account is disabled or renamed
- **Check 16: Weak Passwords** - Tests for weak or blank SQL authentication passwords
- **Check 17: xp_cmdshell Configuration** - Verifies xp_cmdshell is disabled
- **Check 18: Orphaned Users** - Finds database users without server logins
- **Check 19: Database Ownership** - Validates database owners aren't user accounts
- **Check 20: Duplicate Indexes** - Identifies redundant/duplicate indexes wasting space
- **Check 21: Tables Without Primary Key** - Finds heap tables missing primary keys
- **Check 22: Tables Without Indexes** - Detects completely unindexed tables
- **Check 23: Foreign Keys Without Indexes** - Identifies FKs lacking supporting indexes
- **Check 24: Disabled/Untrusted Foreign Keys** - Finds broken or untrusted constraints
- **Check 33: Error Log Analysis** - Reviews error log for critical issues (24 hours)
- **Check 34: Failed Jobs** - Identifies failed SQL Agent jobs (24 hours)
- **Check 41: Server Role Membership** - Audits sysadmin role members
- **Check 42: Database Role Membership** - Checks elevated database role assignments
- **Check 48: Transparent Data Encryption (TDE)** - Checks TDE encryption status
- **Check 52: Certificate Expiration** - Monitors certificate expiration dates
- **Check 53: Authentication Mode** - Verifies Windows vs Mixed authentication
- **Check 54: Guest User Access** - Checks for guest user access vulnerabilities
- **Check 55: Public Role Permissions** - Audits permissions granted to public role
- **Check 56: SQL Server Audit Status** - Verifies SQL audit configuration
- **Check 70: SQL Agent Job Owners** - Checks jobs owned by sa or orphaned accounts

### Database Health & Design (11 checks)
- **Check 32: Obsolete Data Types** - Detects deprecated text/ntext/image types
- **Check 39: Small Data Types** - Identifies inefficient VARCHAR(1-3) usage
- **Check 40: Database Compatibility Level** - Checks database compatibility vs server version
- **Check 43: Oversized Indexes** - Finds indexes exceeding 900-byte key size limit
- **Check 45: Auto Growth Disabled** - Identifies database files without auto growth
- **Check 46: Disk Block Size (Allocation Unit)** - Verifies 64KB block size for SQL files
- **Check 47: Query Store Status** - Checks if Query Store is enabled (SQL 2016+)
- **Check 49: Database Snapshots** - Lists existing database snapshots
- **Check 50: Database Collation Mismatch** - Finds databases with non-standard collations
- **Check 51: Auto Create/Update Statistics** - Verifies automatic statistics settings
- **Check 71: Database Files on C: Drive** - Identifies data/log files on system drive

### Performance & Optimization (12 checks)
- **Check 25: Wait Statistics** - Analyzes top wait types over last 7 days
- **Check 26: Top Slow Queries** - Identifies slowest-performing queries
- **Check 27: Blocking Sessions** - Detects active blocking and lock contention
- **Check 28: Disk I/O Latency** - Measures disk read/write response times
- **Check 29: CPU Pressure** - Analyzes CPU signal waits and pressure indicators
- **Check 30: Memory Pressure** - Checks memory grant waits and PLE
- **Check 31: Deadlock History** - Reviews recent deadlock occurrences
- **Check 58: Backup Compression Default** - Verifies backup compression is enabled
- **Check 60: Max Degree of Parallelism (MAXDOP)** - Validates MAXDOP setting
- **Check 61: Cost Threshold for Parallelism** - Checks cost threshold configuration
- **Check 62: Optimize for Ad Hoc Workloads** - Verifies ad hoc plan caching optimization
- **Check 72: Default Fill Factor** - Checks server-wide fill factor setting

### High Availability & Disaster Recovery (7 checks)
- **Check 35: AG Synchronization Health** - Checks Availability Group sync status
- **Check 36: AG Data Latency** - Measures replication lag between AG replicas
- **Check 37: AG Failover Readiness** - Validates automatic failover configuration
- **Check 38: AG Listener Configuration** - Verifies AG listener settings and connectivity
- **Check 44: Cluster Quorum** - Checks Windows cluster quorum health
- **Check 57: Always On AG Endpoint Encryption** - Verifies AG endpoint encryption
- **Check 59: Database Mirroring Status** - Detects deprecated database mirroring usage

### Configuration & Operational (7 checks)
- **Check 63: Network Packet Size** - Checks network packet size setting
- **Check 64: Remote Admin Connections (DAC)** - Verifies DAC is enabled
- **Check 65: Instant File Initialization (IFI)** - Validates IFI privilege status
- **Check 66: Trace Flags** - Lists active trace flags on server
- **Check 67: Linked Servers** - Audits linked server configurations
- **Check 68: SQL Server Agent Status** - Verifies SQL Agent service is running
- **Check 69: Failed SQL Agent Jobs (Last 7 Days)** - Reviews job failure history

---

**Total: 72 comprehensive health checks across all categories**

## 🚀 Installation & Usage

### Prerequisites
- **xyOps** installed and configured
- **SQL Server 2012 or later** (all editions supported)
- **PowerShell 7+**
- **dbatools module** (auto-installed if missing)
- **Network access** to SQL Server instances
- **SQL Server credentials** with sysadmin or appropriate permissions

### Platform Support

This plugin runs on **Windows, Linux, and macOS**. The plugin automatically detects the operating system and adjusts functionality accordingly:

#### Windows (Recommended)
- **Full feature support** including all 72 checks
- **Server admin credentials** work for enhanced checks
- **WMI and remote PowerShell** available for advanced diagnostics
- **Optimal experience** with all features enabled

#### Linux and macOS
- **72 checks supported** with automatic fallbacks
- **T-SQL methods** used instead of WMI/remote PowerShell
- **Server admin credentials** automatically disabled (not applicable)
- **Affected checks** (4 total):
  - Check 2: Lock Pages In Memory - uses T-SQL detection
  - Check 3-4: Memory Configuration - T-SQL fallback
  - Check 46: Disk Block Size - requires Windows PowerShell Remoting with WMI (manual check required on Linux/macOS)
  - Check 65: Instant File Initialization - T-SQL detection (SQL 2016+)

**Note:** Check 46 (Disk Block Size) cannot be automated on Linux/macOS as it requires Windows PowerShell Remoting with WMI access to query disk allocation unit size. The check will report "Manual Check Required" and provide instructions to verify on the Windows SQL Server host.

**All other checks work identically across all platforms.**

The report will include a platform notice when executed on non-Windows systems.

### Setup in xyOps

1. **Install from xyOps Marketplace**
   - Navigate to xyOps Marketplace
   - Search for "MSSQL Health Check"
   - Click Install

2. **Configure Secret Vault (REQUIRED):**
   
   The plugin uses environment variables for credentials. In xyOps Secret Vault, create:
   
   **SQL Server Credentials (Required):**
   - **Variable Name:** `MSSQLHC_USERNAME`
     - **Value:** SQL Server username (e.g., `sa` or `domain\user`)
   
   - **Variable Name:** `MSSQLHC_PASSWORD`
     - **Value:** SQL Server password
   
   **Server Admin Credentials (Optional - Recommended):**
   - **Variable Name:** `MSSQLHC_SERVER_ADMIN_USER`
     - **Value:** Windows administrator username (e.g., `DOMAIN\Administrator`)
   
   - **Variable Name:** `MSSQLHC_SERVER_ADMIN_PASSWORD`
     - **Value:** Windows administrator password
   
   > **Note:** Server admin credentials enable enhanced checks that require direct server access (IFI, Memory, etc.) **on Windows systems only**. These credentials use WMI and remote PowerShell which are not available on Linux/macOS. The plugin automatically detects the OS and uses T-SQL fallback methods on non-Windows platforms.

### Credential Capabilities Comparison

| Check Category | With SQL Credentials Only | With Server Admin Credentials |
|----------------|--------------------------|-------------------------------|
| **SQL Server Version & Updates** | ✅ Full check | ✅ Full check |
| **Lock Pages In Memory** | ⚠️ T-SQL fallback | ✅ Full check |
| **Instant File Initialization** | ⚠️ T-SQL fallback (2016+) or manual check | ✅ Full check (all versions) |
| **Memory Configuration** | ⚠️ T-SQL fallback | ✅ Full check with server memory |
| **Database Health Checks** | ✅ Full check | ✅ Full check |
| **Security Checks** | ✅ Full check | ✅ Full check |
| **Performance Checks** | ✅ Full check | ✅ Full check |
| **Availability Group Checks** | ✅ Full check | ✅ Full check |
| **Overall Coverage** | ~90% (with fallbacks) | 100% (optimal) |

**Legend:**
- ✅ **Full check** - Complete automatic verification
- ⚠️ **T-SQL fallback** - Works via SQL queries, may have limitations
- ℹ️ **Manual check** - Requires manual verification with provided instructions

**Recommendation:** For optimal results, provide both SQL Server and Server Admin credentials. The plugin will automatically use the appropriate credential set for each check.

### Running a Health Check

1. **In xyOps GUI:**
   - Select the MSSQL Health Check plugin
   - Enter the **MSSQL Server** parameter (primary SQL Server hostname or IP)
   - Check **Use Encryption** if your environment requires encrypted connections
   - Check **Trust Certificate** if using self-signed certificates
   - (Optional) **Exclusions/Inclusions** - Filter specific checks
   - (Optional) **Export to PDF** - Enable PDF conversion (requires pandoc or markdown-pdf)
   - Click **Run**

2. **The plugin will:**
   - Detect the operating system and adjust features
   - Connect to the primary server
   - Auto-discover Availability Group partners (if configured)
   - Connect to all partner replicas
   - Perform comprehensive health checks on all servers
   - Generate professional Markdown report
   - (Optional) Convert to PDF if enabled
   - Display progress with detailed status messages

3. **View the report:**
   - The Markdown report (.md) will be automatically downloaded
   - PDF report (.pdf) included if PDF export was enabled
   - Open Markdown in any text editor or viewer
   - View PDF in any PDF reader

## 📊 Understanding the Report

### Executive Dashboard
The top section shows:
- **Overall Health Score** - Percentage of checks passed
- **Checks Passed** - Number of successful checks (green)
- **Warnings** - Issues requiring attention (yellow)
- **Failed Checks** - Critical problems (red)

### Health Score Interpretation
- **90-100%** 🟢 Excellent - Server is in great health
- **75-89%** 🔵 Good - Minor issues to address
- **60-74%** 🟡 Fair - Several improvements needed
- **Below 60%** 🔴 Poor - Significant issues requiring immediate attention

### Check Status Icons
- ✅ **Pass** - Check passed, no action needed
- ⚠️ **Warning** - Issue found, should be addressed
- ❌ **Error** - Critical issue, immediate action required
- ℹ️ **Info** - Informational, review recommended

### Remediation Sections
Each failed check includes:
1. **Impact** - Why this matters and potential consequences
2. **Current Configuration** - What was found
3. **Recommended Action** - What should be done
4. **PowerShell Remediation** - Copy-paste script to fix
5. **T-SQL Remediation** - SQL commands to fix
6. **Manual Steps** - GUI-based fix instructions
7. **Documentation** - Links to Microsoft docs
8. **Raw Data** - Complete diagnostic information

## 🔧 Configuration Examples

### Basic Usage (Standalone Server)
```
server: SQLPROD01
useencryption: ☐ (unchecked)
trustcert: ☐ (unchecked)
```

### Availability Group Environment
```
server: SQLPROD01  (Primary replica)
useencryption: ☑ (checked)
trustcert: ☑ (checked)
```
The plugin will automatically discover and check:
- SQLPROD01 (Primary)
- SQLPROD02 (Secondary)
- SQLPROD03 (Secondary)

### Named Instance
```
server: SQLSERVER\INSTANCE1
useencryption: ☐ (unchecked)
trustcert: ☐ (unchecked)
```

### With Always Encrypted
```
server: SQLPROD01
useencryption: ☑ (checked)
trustcert: ☑ (checked)
```

## 🎯 Best Practices

### Scheduling Health Checks
- **Production:** Weekly or monthly
- **Development/Test:** Monthly
- **After major changes:** Immediately
- **Before upgrades:** Always

### Credential Security

**SQL Server Credentials:**
- ✅ **DO:** Use dedicated SQL accounts with sysadmin or VIEW SERVER STATE permissions
- ✅ **DO:** Store credentials in xyOps Secret Vault
- ✅ **DO:** Rotate credentials regularly
- ❌ **DON'T:** Use sa account for health checks
- ❌ **DON'T:** Store credentials in scripts

**Server Admin Credentials (Optional):**
- ✅ **DO:** Use dedicated service account with minimal required permissions:
  - Read access to WMI/CIM for system information
  - Access to SQL Server service configuration
  - Read-only access to Windows security policies (for IFI check)
- ✅ **DO:** Store in xyOps Secret Vault separately from SQL credentials
- ✅ **DO:** Use domain accounts instead of local admin when possible
- ✅ **DO:** Regularly audit usage in xyOps logs
- ⚠️ **CAUTION:** These credentials have elevated Windows privileges
- ❌ **DON'T:** Use domain admin or enterprise admin accounts
- ❌ **DON'T:** Use the same account for multiple purposes

**When to Provide Server Admin Credentials:**
- ✅ When you want automatic IFI (Instant File Initialization) checks
- ✅ When you need accurate server memory reporting
- ✅ For complete Lock Pages in Memory verification
- ❌ Not required for basic health checks (90% of checks work without them)

### Report Management
- Archive reports for historical trending
- Review warnings before they become errors
- Track health score improvements over time
- Share reports with team for remediation planning

### PDF Export (Optional)

The plugin can automatically convert Markdown reports to PDF format. This requires installing a PDF converter on the xyOps Satellite server:

**Option 1: Pandoc (Recommended)**

Pandoc produces high-quality PDFs with proper formatting, table of contents, and pagination.

```bash
# Windows (Chocolatey)
choco install pandoc miktex

# Windows (winget)
winget install pandoc
winget install MiKTeX.MiKTeX

# macOS
brew install pandoc basictex

# Linux (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install pandoc texlive-xetex texlive-fonts-recommended

# Linux (RHEL/CentOS)
sudo yum install pandoc texlive-xetex
```

**Option 2: markdown-pdf (Alternative)**

Lighter weight but less formatting control:

```bash
npm install -g markdown-pdf
```

**Configuration:**

In the xyOps plugin settings:
- Set `exporttopdf` parameter to `true`
- Both Markdown (.md) and PDF (.pdf) files will be generated
- If no converter is installed, only the Markdown report is created (no error)

**Notes:**
- PDF export is completely optional
- Markdown reports are always generated regardless of PDF setting
- The plugin gracefully handles missing converters

## 🛠️ Troubleshooting

### "Failed to install required dbatools module"
**Solution:** Install manually:
```powershell
Install-Module -Name dbatools -Force -AllowClobber -Scope CurrentUser
```

### "Missing required parameters: MSSQLHC_USERNAME"
**Solution:** Configure environment variables in xyOps Secret Vault:
- Add `MSSQLHC_USERNAME` with SQL username
- Add `MSSQLHC_PASSWORD` with SQL password

### "Could not connect to partner replica"
**Solution:** 
- Verify network connectivity to partner servers
- Ensure credentials work on all replicas
- Check firewall rules for SQL Server port (default 1433)

### "Access denied" errors
**Solution:**
- Grant sysadmin role to health check account, OR
- Grant VIEW SERVER STATE, VIEW DATABASE STATE, and db_datareader

### Connection timeout
**Solution:**
- Increase connection timeout in dbatools
- Check network latency
- Verify SQL Server is online and accepting connections

## 📖 Additional Resources

### dbatools Documentation
- [Official Website](https://dbatools.io)
- [Command Reference](https://docs.dbatools.io)
- [Getting Started Guide](https://dbatools.io/getting-started/)

### Microsoft Documentation
- [SQL Server Best Practices](https://learn.microsoft.com/en-us/sql/sql-server/)
- [Availability Groups](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/)
- [Performance Tuning](https://learn.microsoft.com/en-us/sql/relational-databases/performance/)

### Community
- [dbatools Slack](https://dbatools.io/slack/)
- [SQL Server Community](https://sqlcommunity.com/)

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Ideas for Enhancements
- Add more checks (suggestions welcome!)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## 👤 Author

**Tim Alderweireldt**
- Plugin: xyOps MSSQL Health Check
- Year: 2026

## 🙏 Acknowledgments

- **dbatools team** - For the incredible PowerShell module
- **xyOps team** - For the automation platform
- **SQL Server community** - For best practices and feedback

## Version History

### v1.0.0 (2026-02-06)
- 72 comprehensive health checks
- Automatic AG discovery
- Multi-server support
- Check exclusions and inclusions feature
- Preset check groups (security, performance, availability, backup, database)
- Exclusion reason tracking and reporting
- Table of Contents in reports
- Professional Markdown reports
- Executive Dashboard with exclusion metrics
- Detailed remediation steps (PowerShell, T-SQL, manual)
- Raw data export
- Microsoft documentation links

---

**Need help?** Open an issue on GitHub or contact the author.

**Found this useful?** Star the repository and share with your team!
## Complete Health Checks Reference (72 Total)

### Server Health & Configuration (Checks 1-16)
1. SQL Server Version & Updates
2. Lock Pages In Memory
3. Max Server Memory Configuration
4. Min Server Memory Configuration  
5. Page Life Expectancy
6. Database Auto Close
7. Database Auto Shrink
8. Database Auto Growth Settings
9. Database Recovery Model
10. Database Backups (Last Full)
11. Database Backups (Last Differential)
12. Database Backups (Last Transaction Log)
13. Backup Compression
14. Virtual Log Files (VLFs)
15. Database Page Verification
16. Database File Growth Settings

### Performance & Monitoring (Checks 17-28)
17. Wait Statistics Analysis
18. Top CPU Consuming Queries
19. Top Memory Consuming Queries
20. Top I/O Consuming Queries
21. Top Slow Queries (Execution Time)
22. Blocking Sessions
23. Deadlock Detection
24. Index Fragmentation
25. Missing Indexes
26. Unused Indexes
27. Duplicate Indexes
28. TempDB Configuration

### Availability Groups (Checks 29-40)
29. AG Synchronization Health
30. AG Data Latency
31. AG Failover Readiness
32. AG Backup Preference
33. AG Read-Only Routing
34. AG Session Timeout
35. AG Listener Configuration
36. AG Replica Role
37. AG Database Synchronization State
38. AG Redo Queue Size
39. AG Log Send Queue Size
40. AG Automatic Seeding Status

### Database Health & Integrity (Checks 41-51)
41. Last DBCC CHECKDB
42. Database Corruption Detection
43. Suspect Pages
44. Database Owners
45. Orphaned Users
46. SQL Server Agent Jobs
47. Query Store Configuration
48. TDE (Transparent Data Encryption)
49. Database Snapshots
50. Database Collation Mismatch
51. Auto Statistics Configuration

### Security & Compliance (Checks 52-60)
52. Certificate Expiration
53. Authentication Mode
54. Guest User Access
55. Public Role Permissions
56. SQL Server Audit Configuration
57. SQL Logins with Weak Passwords
58. SA Account Status
59. xp_cmdshell Configuration
60. SQL Agent Job Owners

### Advanced Configuration (Checks 61-72)
61. Cost Threshold for Parallelism
62. Optimize for Ad Hoc Workloads
63. Network Packet Size
64. Remote Admin Connections (DAC)
65. Instant File Initialization
66. Trace Flags
67. Linked Servers
68. SQL Server Agent Status
69. Failed SQL Agent Jobs (Last 7 Days)
70. SQL Agent Job Owners
71. Database Files on C: Drive
72. Default Fill Factor

## Preset Check Groups

The plugin supports convenient preset groups for filtering checks:

### `security` Group (6 checks)
- Check 52: Certificate Expiration
- Check 53: Authentication Mode
- Check 54: Guest User Access
- Check 55: Public Role Permissions
- Check 56: SQL Server Audit
- Check 70: SQL Agent Job Owners

### `performance` Group (14 checks)
- Check 17: Wait Statistics
- Check 18: CPU Consuming Queries
- Check 19: Memory Consuming Queries
- Check 20: I/O Consuming Queries
- Check 21: Slow Queries
- Check 22: Blocking Sessions
- Check 23: Deadlock Detection
- Check 24: Index Fragmentation
- Check 25: Missing Indexes
- Check 60: MAXDOP
- Check 61: Cost Threshold
- Check 62: Ad Hoc Workloads
- Check 65: Instant File Initialization
- Check 72: Fill Factor

### `availability` Group (15 checks)
- Checks 29-40: All Availability Group checks
- Check 61: Cost Threshold (impacts AG performance)
- Check 62: Ad Hoc Workloads
- Check 63: Network Packet Size

### `backup` Group (4 checks)
- Check 10: Last Full Backup
- Check 11: Last Differential Backup
- Check 12: Last Transaction Log Backup
- Check 13: Backup Compression

### `database` Group (9 checks)
- Check 6: Auto Close
- Check 7: Auto Shrink
- Check 8: Auto Growth
- Check 9: Recovery Model
- Check 47: Query Store
- Check 48: TDE
- Check 49: Database Snapshots
- Check 50: Collation Mismatch
- Check 51: Auto Statistics

## Check Filtering (Exclusions & Inclusions)

### Using Exclusions
Skip specific checks or entire categories:

```
# Skip specific checks by number
exclusions: 11,34,54
exclusionreason: Checks not applicable to development environment

# Skip entire category
exclusions: security
exclusionreason: Security audit performed separately

# Mix numbers and groups
exclusions: performance,10,15
exclusionreason: Performance baseline established; backup checks handled by monitoring tool
```

### Using Inclusions
Run ONLY selected checks (faster, targeted analysis):

```
# Run only backup checks
inclusions: backup
exclusionreason: Quick backup validation after maintenance

# Run specific checks
inclusions: 1,29,30,31
exclusionreason: Version and AG health check only

# Run multiple categories
inclusions: security,backup
exclusionreason: Compliance audit - security and backup verification
```

### Important Notes
- **Cannot use both** exclusions and inclusions together
- Preset groups can be mixed with numeric check IDs
- Valid groups: `security`, `performance`, `availability`, `backup`, `database`
- Exclusion reason field is optional but recommended for documentation
- Excluded checks appear in report with count and reason
