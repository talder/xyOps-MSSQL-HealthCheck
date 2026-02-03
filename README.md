# xyOps MSSQL Health Check Plugin

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![dbatools](https://img.shields.io/badge/dbatools-2.0+-green.svg)](https://dbatools.io)

## ⚠️ IMPORTANT - READ BEFORE RUNNING

> **WARNING: Performance Impact on Production Systems**
> 
> This plugin performs 45+ comprehensive health checks that can generate **significant load** on your SQL Server instances, especially when analyzing:
> - Index fragmentation across all databases
> - Query performance statistics
> - Wait statistics analysis
> - I/O latency measurements
> - Multiple Availability Group replicas
> 
> **🚫 DO NOT run during critical operation hours or business hours on production systems**
> 
> **⏱️ EXECUTION TIME:** This plugin can take **15-60+ minutes** depending on:
> - Number of databases
> - Database sizes
> - Number of AG replicas
> - Server workload
> 
> **📅 RECOMMENDED SCHEDULE:**
> - ✅ **Monthly** - Ideal frequency for most environments
> - ✅ **Weekly** - For high-change environments (only during maintenance windows)
> - ❌ **Daily** - NOT RECOMMENDED (excessive load and unnecessary)
> - ✅ **After major changes** - During planned maintenance windows
> - ✅ **Before upgrades** - During change windows only
> 
> **🕐 BEST PRACTICE:** Schedule during off-peak hours, maintenance windows, or weekends when production load is minimal.

A comprehensive SQL Server health check plugin for xyOps that performs 45+ detailed checks across multiple servers, including Availability Group topologies, with actionable remediation steps.

## 🎯 Features

### Core Capabilities
- ✅ **Automatic AG Discovery** - Discovers and connects to all Availability Group partner replicas
- ✅ **Multi-Server Analysis** - Checks multiple SQL Server instances in a single execution
- ✅ **45+ Comprehensive Checks** - Covers server health, security, database health, performance, and high availability
- ✅ **Detailed Remediation** - Provides PowerShell, T-SQL, and manual step-by-step fixes for each issue
- ✅ **Beautiful HTML Reports** - Professional, interactive reports with collapsible sections
- ✅ **Executive Dashboard** - At-a-glance health score and statistics
- ✅ **Raw Data Export** - Complete diagnostic data included in collapsible sections
- ✅ **Microsoft Documentation Links** - Direct links to official documentation for each check

### Report Features
- 📊 **Health Score Calculation** - Overall health percentage based on check results
- 🎨 **Color-Coded Status** - Visual indicators (Pass ✅ / Warning ⚠️ / Error ❌ / Info ℹ️)
- 📱 **Responsive Design** - Works on desktop, tablet, and mobile
- 🖨️ **Print-Friendly** - Optimized for printing or PDF export
- 🔍 **Interactive Sections** - Click to expand/collapse detailed information
- 🔄 **AG Topology View** - Visual representation of Availability Group configuration

## 📋 Health Checks Performed

### Server Health (15 checks)
1. **SQL Server Version & Updates** - Verifies version and patch level
2. **Lock Pages In Memory** - Checks critical memory privilege
3. **Instant File Initialization** - Validates IFI for fast file growth
4. **Memory Settings** - Reviews min/max memory configuration
5. **Last Backup** - Identifies databases needing backup
6. **Database Percent Growth** - Finds improper growth settings
7. **Recovery Model** - Validates recovery model appropriateness
8. **Virtual Log Files (VLFs)** - Detects high VLF counts
9. **TempDB Configuration** - Checks TempDB best practices
10. **Integrity Check (DBCC CHECKDB)** - Verifies last integrity check
11. **Index Fragmentation** - Identifies heavily fragmented indexes
12. **Data vs Log Ratio** - Finds oversized log files
13. **Database Compatibility Level** - Checks compatibility settings
14. **Auto Shrink** - Detects dangerous auto shrink settings
15. **Auto Close** - Identifies auto close issues
16. **Auto Growth Disabled** - Finds files without auto growth
17. **Page Verify Option** - Validates page verification settings

### Security (8 checks)
1. **SA Account Status** - Checks if sa account is disabled
2. **Weak Passwords** - Tests for weak/blank SQL logins
3. **xp_cmdshell Configuration** - Verifies xp_cmdshell is disabled
4. **Server Role Membership** - Reviews sysadmin members
5. **Database Role Membership** - Checks elevated database roles
6. **Database Ownership** - Validates database owners
7. **Error Log Analysis** - Reviews login failures and errors
8. **Failed Jobs** - Identifies failed SQL Agent jobs
9. **Orphaned Users** - Finds orphaned database users

### Database Health (8 checks)
1. **Duplicate Indexes** - Identifies redundant indexes
2. **Tables Without Primary Key** - Finds tables missing PKs
3. **Tables Without Index** - Detects completely unindexed tables
4. **Foreign Keys Without Index** - Identifies FKs needing indexes
5. **Disabled/Untrusted Foreign Keys** - Finds broken FKs
6. **Obsolete Data Types** - Detects text/ntext/image usage
7. **Small Data Types** - Identifies inefficient VARCHAR(1-3)
8. **Oversized Indexes** - Finds indexes exceeding 900 bytes

### Performance (7 checks)
1. **Wait Statistics** - Analyzes top waits (last 7 days)
2. **Top Slow Queries** - Identifies top 10 slowest queries
3. **Blocking Sessions** - Detects current blocking
4. **Deadlock History** - Reviews recent deadlocks
5. **Disk I/O Latency** - Measures disk response times
6. **CPU Pressure** - Checks CPU utilization patterns
7. **Memory Pressure** - Analyzes memory grant issues

### High Availability (7 checks)
1. **AG Synchronization Health** - Checks sync status
2. **AG Failover Readiness** - Validates failover capability
3. **AG Data Latency** - Measures replication lag
4. **AG Listener Configuration** - Verifies listener settings
5. **Cluster Quorum** - Checks cluster health (if clustered)
6. **Always On Failover Cluster** - Validates FCI configuration
7. **Backup Preference** - Reviews AG backup settings

## 🚀 Installation & Usage

### Prerequisites
- **xyOps** installed and configured
- **PowerShell 5.1+** or **PowerShell 7+**
- **dbatools module** (auto-installed if missing)
- **Network access** to SQL Server instances
- **SQL Server credentials** with sysadmin or appropriate permissions

### Setup in xyOps

1. **Install from xyOps Marketplace**
   - Navigate to xyOps Marketplace
   - Search for "MSSQL Health Check"
   - Click Install

2. **Configure Secret Vault (REQUIRED):**
   
   The plugin uses environment variables for credentials. In xyOps Secret Vault, create:
   
   - **Variable Name:** `MSSQLHC_USERNAME`
     - **Value:** SQL Server username (e.g., `sa` or `domain\user`)
   
   - **Variable Name:** `MSSQLHC_PASSWORD`
     - **Value:** SQL Server password

### Running a Health Check

1. **In xyOps GUI:**
   - Select the MSSQL Health Check plugin
   - Enter the **MSSQL Server** parameter (primary SQL Server hostname or IP)
   - Check **Use Encryption** if your environment requires encrypted connections
   - Check **Trust Certificate** if using self-signed certificates
   - Click **Run**

2. **The plugin will:**
   - Connect to the primary server
   - Auto-discover Availability Group partners (if configured)
   - Connect to all partner replicas
   - Perform comprehensive health checks on all servers
   - Generate a beautiful HTML report
   - Display progress with detailed status messages

3. **View the report:**
   - The HTML report will be automatically downloaded
   - Open in any modern web browser
   - Click on check titles to expand/collapse details

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
- ✅ **DO:** Use dedicated SQL accounts with read-only sysadmin
- ✅ **DO:** Store credentials in xyOps Secret Vault
- ✅ **DO:** Rotate credentials regularly
- ❌ **DON'T:** Use sa account for health checks
- ❌ **DON'T:** Store credentials in scripts

### Report Management
- Archive reports for historical trending
- Review warnings before they become errors
- Track health score improvements over time
- Share reports with team for remediation planning

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

## 📌 Version History

### v1.0.0 (2026-02-03)
- Initial release
- 45+ comprehensive health checks
- Automatic AG discovery
- Multi-server support
- Beautiful HTML reports
- Detailed remediation steps
- PowerShell, T-SQL, and manual fixes
- Raw data export

---

**Need help?** Open an issue on GitHub or contact the author.

**Found this useful?** Star the repository and share with your team!
