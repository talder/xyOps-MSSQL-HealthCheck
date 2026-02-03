# (c)2026 Tim Alderweireldt - xyOps MSSQL Health Check Plugin - PowerShell Version
# Comprehensive SQL Server Health Check with AG support, detailed remediation, and multi-server comparison

function Write-Output-JSON {
    param($Object)
    $json = $Object | ConvertTo-Json -Compress -Depth 100
    Write-Output $json
    [Console]::Out.Flush()
}

function Send-Progress {
    param([double]$Value, [string]$Message = "")
    if ($Message) {
        Write-Host $Message
    }
    Write-Output-JSON @{ xy = 1; progress = $Value }
}

function Send-Success {
    param([string]$Description = "Health check completed successfully")
    Write-Output-JSON @{ xy = 1; code = 0; description = $Description }
}

function Send-Error {
    param([int]$Code, [string]$Description)
    Write-Output-JSON @{ xy = 1; code = $Code; description = $Description }
}

# Read input from STDIN
$inputJson = [Console]::In.ReadToEnd()

try {
    $jobData = $inputJson | ConvertFrom-Json -AsHashtable
}
catch {
    Send-Error -Code 1 -Description "Failed to parse input JSON: $($_.Exception.Message)"
    exit 1
}

# Extract parameters
$params = $jobData.params

# Helper function to get parameter value case-insensitively
function Get-ParamValue {
    param($ParamsObject, [string]$ParamName)
    if ($ParamsObject -is [hashtable]) {
        foreach ($key in $ParamsObject.Keys) {
            if ($key -ieq $ParamName) {
                return $ParamsObject[$key]
            }
        }
        return $null
    } else {
        $prop = $ParamsObject.PSObject.Properties | Where-Object { $_.Name -ieq $ParamName } | Select-Object -First 1
        if ($prop) { return $prop.Value }
        return $null
    }
}

# Get parameters
$server = Get-ParamValue -ParamsObject $params -ParamName 'server'
$username = $env:MSSQLHC_USERNAME
$password = $env:MSSQLHC_PASSWORD
$useencryptionRaw = Get-ParamValue -ParamsObject $params -ParamName 'useencryption'
$trustcertRaw = Get-ParamValue -ParamsObject $params -ParamName 'trustcert'

# Validate required parameters
$missing = @()
if ([string]::IsNullOrWhiteSpace($server)) { $missing += 'server' }
if ([string]::IsNullOrWhiteSpace($username)) { $missing += 'MSSQLHC_USERNAME (environment variable)' }
if ([string]::IsNullOrWhiteSpace($password)) { $missing += 'MSSQLHC_PASSWORD (environment variable)' }

if ($missing.Count -gt 0) {
    Send-Error -Code 2 -Description "Missing required parameters: $($missing -join ', '). Credentials must be provided via secret vault environment variables."
    exit 1
}

try {
    # Check if dbatools module is installed
    Send-Progress -Value 0.01 -Message "Checking for dbatools module..."
    
    if (-not (Get-Module -ListAvailable -Name dbatools)) {
        try {
            Write-Host "dbatools module not found, attempting to install..."
            Install-Module -Name dbatools -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "dbatools module installed successfully"
        }
        catch {
            Send-Error -Code 3 -Description "Failed to install required dbatools module: $($_.Exception.Message)"
            exit 1
        }
    }
    
    # Import dbatools module
    Send-Progress -Value 0.02 -Message "Importing dbatools module..."
    Import-Module dbatools -ErrorAction Stop
    
    # Build connection parameters
    Send-Progress -Value 0.03 -Message "Preparing connection parameters..."
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
    
    $connectParams = @{
        SqlCredential = $credential
    }
    
    if ($useencryptionRaw -eq $true -or $useencryptionRaw -eq "true" -or $useencryptionRaw -eq "True") {
        $connectParams['EncryptConnection'] = $true
    }
    if ($trustcertRaw -eq $true -or $trustcertRaw -eq "true" -or $trustcertRaw -eq "True") {
        $connectParams['TrustServerCertificate'] = $true
    }
    
    Send-Progress -Value 0.04 -Message "Connecting to primary server: $server..."
    $primaryConnection = Connect-DbaInstance -SqlInstance $server @connectParams
    
    # Initialize comprehensive results
    $healthCheckResults = @{
        CheckDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        PrimaryServer = $server
        IsAGEnvironment = $false
        AvailabilityGroups = @()
        Servers = @{}
        ExecutiveSummary = @{
            TotalServers = 0
            TotalChecks = 0
            PassedChecks = 0
            WarningChecks = 0
            FailedChecks = 0
        }
    }
    
    # Discover AG partners
    $serversToCheck = @($primaryConnection)
    $serverNames = @($primaryConnection.Name)
    
    Send-Progress -Value 0.05 -Message "Detecting Availability Groups and partner replicas..."
    
    if ($primaryConnection.IsHadrEnabled) {
        $healthCheckResults.IsAGEnvironment = $true
        Write-Host "✓ HADR is enabled - discovering AG topology..."
        
        try {
            $ags = Get-DbaAvailabilityGroup -SqlInstance $primaryConnection
            
            foreach ($ag in $ags) {
                Write-Host "  → Processing AG: $($ag.Name)"
                
                $agDetail = @{
                    Name = $ag.Name
                    PrimaryReplica = $ag.PrimaryReplica
                    LocalReplicaRole = $ag.LocalReplicaRole.ToString()
                    AutomatedBackupPreference = $ag.AutomatedBackupPreference.ToString()
                    Replicas = @()
                    Databases = @()
                    SynchronizationHealth = @()
                }
                
                # Get replica details
                $replicas = Get-DbaAgReplica -SqlInstance $primaryConnection -AvailabilityGroup $ag.Name
                
                foreach ($replica in $replicas) {
                    $replicaInfo = @{
                        Name = $replica.Name
                        Role = $replica.Role.ToString()
                        AvailabilityMode = $replica.AvailabilityMode.ToString()
                        FailoverMode = $replica.FailoverMode.ToString()
                        ConnectionState = $replica.ConnectionState.ToString()
                    }
                    $agDetail.Replicas += $replicaInfo
                    
                    # Connect to partner replicas
                    if ($replica.Name -ne $primaryConnection.Name -and $serverNames -notcontains $replica.Name) {
                        try {
                            Write-Host "    → Connecting to partner replica: $($replica.Name)..."
                            $partnerConn = Connect-DbaInstance -SqlInstance $replica.Name @connectParams
                            $serversToCheck += $partnerConn
                            $serverNames += $replica.Name
                            Write-Host "    ✓ Connected successfully"
                        }
                        catch {
                            Write-Host "    ✗ Could not connect to partner: $($_.Exception.Message)"
                        }
                    }
                }
                
                # Get AG database information
                $agDatabases = Get-DbaAgDatabase -SqlInstance $primaryConnection -AvailabilityGroup $ag.Name
                foreach ($agDb in $agDatabases) {
                    $agDetail.Databases += @{
                        Name = $agDb.Name
                        SynchronizationState = $agDb.SynchronizationState.ToString()
                        IsJoined = $agDb.IsJoined
                    }
                }
                
                $healthCheckResults.AvailabilityGroups += $agDetail
            }
        }
        catch {
            Write-Host "⚠ Warning: Could not retrieve complete AG information: $($_.Exception.Message)"
        }
    }
    
    $healthCheckResults.ExecutiveSummary.TotalServers = $serversToCheck.Count
    Write-Host "`n=== Starting health checks on $($serversToCheck.Count) server(s) ===" 
    
    # Calculate progress increments
    $totalServers = $serversToCheck.Count
    $progressPerServer = 0.85 / $totalServers
    $currentServerIndex = 0
    
    # Process each server
    foreach ($conn in $serversToCheck) {
        $currentServerIndex++
        $serverName = $conn.Name
        $serverProgress = 0.05 + (($currentServerIndex - 1) * $progressPerServer)
        
        Send-Progress -Value $serverProgress -Message "`n[$currentServerIndex/$totalServers] Starting comprehensive health check for: $serverName"
        
        $serverResults = @{
            ServerName = $serverName
            ServerInfo = @{}
            Checks = @()
        }
        
        # Progress tracking for checks within this server
        $totalChecks = 45
        $checkProgress = $progressPerServer / $totalChecks
        $currentCheck = 0
        
        # ============================================================================
        # COLLECT SERVER INFORMATION
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] Collecting server information..."
        
        $serverResults.ServerInfo = @{
            ServerName = $conn.Name
            Version = $conn.VersionString
            VersionMajor = $conn.VersionMajor
            Edition = $conn.Edition
            ProductLevel = $conn.ProductLevel
            ProductUpdateLevel = if ([string]::IsNullOrWhiteSpace($conn.ProductUpdateLevel)) { "RTM (Not Patched)" } else { $conn.ProductUpdateLevel }
            BuildNumber = $conn.BuildNumber
            IsClustered = $conn.IsClustered
            IsHadrEnabled = $conn.IsHadrEnabled
            Collation = $conn.Collation
            InstanceName = $conn.InstanceName
            PhysicalMemoryMB = $conn.PhysicalMemory
            Processors = $conn.Processors
        }
        
        # ============================================================================
        # CHECK 1: SQL SERVER VERSION & UPDATES
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [1/$totalChecks] Checking SQL Server version and patch level..."
        
        $versionCheck = @{
            Category = "Server Health"
            CheckName = "SQL Server Version & Updates"
            Status = "ℹ️ Review Required"
            Severity = "Info"
            Description = "Verifies SQL Server version and checks if latest updates are installed"
            Impact = "Outdated versions may contain security vulnerabilities, bugs, and miss performance improvements. Microsoft releases cumulative updates (CUs) regularly with fixes and enhancements."
            CurrentValue = @{
                Version = $conn.VersionString
                Edition = $conn.Edition
                ProductLevel = $conn.ProductLevel
                PatchLevel = $serverResults.ServerInfo.ProductUpdateLevel
                BuildNumber = $conn.BuildNumber
            }
            RecommendedAction = "Review and install the latest Cumulative Update for your SQL Server version. Always test updates in non-production environments first."
            RemediationSteps = @{
                PowerShell = @"
# Download latest CU from Microsoft Update Catalog
# https://www.catalog.update.microsoft.com/
# Install using Windows Update or manual installation

# Check current version
Invoke-DbaQuery -SqlInstance '$serverName' -Query "SELECT @@VERSION"

# After installing CU, verify new version
Test-DbaBuild -SqlInstance '$serverName' -Latest
"@
                TSQL = @"
-- Check current version and build
SELECT 
    SERVERPROPERTY('ProductVersion') AS Version,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('Edition') AS Edition,
    @@VERSION AS FullVersion;

-- Check installed updates
SELECT * FROM sys.dm_os_windows_info;
"@
            }
            Documentation = @(
                "https://learn.microsoft.com/en-us/troubleshoot/sql/releases/download-and-install-latest-updates",
                "https://learn.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server"
            )
            RawData = @{
                VersionString = $conn.VersionString
                BuildNumber = $conn.BuildNumber
                ProductLevel = $conn.ProductLevel
                ProductUpdateLevel = $serverResults.ServerInfo.ProductUpdateLevel
                Edition = $conn.Edition
            }
        }
        $serverResults.Checks += $versionCheck
        
        # ============================================================================
        # CHECK 2: LOCK PAGES IN MEMORY
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [2/$totalChecks] Checking Lock Pages In Memory privilege..."
        
        try {
            $lockPages = Test-DbaMaxMemory -SqlInstance $conn
            $hasLockPages = $lockPages.SqlMaxMB -gt 0 -and $lockPages.SqlMaxMB -lt $lockPages.TotalMB
            
            $lpimCheck = @{
                Category = "Server Health"
                CheckName = "Lock Pages In Memory"
                Status = if ($hasLockPages) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($hasLockPages) { "Pass" } else { "Warning" }
                Description = "Verifies that the SQL Server service account has 'Lock Pages in Memory' privilege"
                Impact = "Without this privilege, Windows can page out SQL Server's buffer pool memory to disk during memory pressure, causing severe performance degradation. This is critical for production servers."
                CurrentValue = @{
                    LockPagesEnabled = $hasLockPages
                    MaxServerMemoryMB = $lockPages.SqlMaxMB
                    TotalServerMemoryMB = $lockPages.TotalMB
                }
                RecommendedAction = if ($hasLockPages) { "Lock Pages in Memory is properly configured" } else { "Grant 'Lock Pages in Memory' user right to SQL Server service account and restart SQL Server service" }
                RemediationSteps = @{
                    PowerShell = @"
# Step 1: Identify SQL Server service account
`$serviceAccount = (Get-WmiObject Win32_Service | Where-Object {`$_.Name -like 'MSSQL*' -and `$_.Name -notlike '*Agent*'}).StartName
Write-Host "SQL Server Service Account: `$serviceAccount"

# Step 2: Export current security policy
secedit /export /cfg C:\secpol.cfg

# Step 3: Add Lock Pages privilege
`$content = Get-Content C:\secpol.cfg
`$newContent = @()
foreach (`$line in `$content) {
    if (`$line -match 'SeLockMemoryPrivilege') {
        if (`$line -notmatch [regex]::Escape(`$serviceAccount)) {
            `$line = `$line.TrimEnd() + ",`$serviceAccount"
        }
    }
    `$newContent += `$line
}
`$newContent | Set-Content C:\secpol.cfg

# Step 4: Apply new policy
secedit /configure /db C:\windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS

# Step 5: Clean up
Remove-Item C:\secpol.cfg

# Step 6: Restart SQL Server (IMPORTANT!)
Write-Host "Please restart SQL Server service for changes to take effect"
Restart-DbaService -SqlInstance '$serverName' -Type Engine -Force
"@
                    TSQL = @"
-- Verify Lock Pages in Memory after restart
-- Check if buffer pool is locked in memory
SELECT 
    osn.node_id,
    osn.memory_node_id,
    osn.node_state_desc,
    om.locked_page_allocations_kb / 1024 AS LockedPagesMemoryMB
FROM sys.dm_os_memory_nodes om
INNER JOIN sys.dm_os_nodes osn ON om.memory_node_id = osn.memory_node_id
WHERE osn.node_state_desc <> 'ONLINE DAC';

-- If locked_page_allocations_kb > 0, Lock Pages is working
"@
                    Manual = @"
1. Open Local Security Policy (secpol.msc)
2. Navigate to: Local Policies → User Rights Assignment
3. Double-click "Lock pages in memory"
4. Click "Add User or Group"
5. Enter the SQL Server service account name
6. Click OK
7. Restart SQL Server service
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/enable-the-lock-pages-in-memory-option-windows"
                )
                RawData = $lockPages
            }
            $serverResults.Checks += $lpimCheck
        }
        catch {
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Lock Pages In Memory"
                Status = "❌ Error"
                Severity = "Error"
                Description = "Could not check Lock Pages in Memory privilege"
                Error = $_.Exception.Message
            }
        }
        
        # ============================================================================
        # CHECK 3: INSTANT FILE INITIALIZATION
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [3/$totalChecks] Checking Instant File Initialization..."
        
        try {
            $ifi = Test-DbaInstanceFileInitialization -SqlInstance $conn
            
            $ifiCheck = @{
                Category = "Server Health"
                CheckName = "Instant File Initialization (IFI)"
                Status = if ($ifi.IfiEnabled) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($ifi.IfiEnabled) { "Pass" } else { "Warning" }
                Description = "Checks if Instant File Initialization is enabled for faster data file operations"
                Impact = "Without IFI, data file growth operations must zero-write all new space, which can take significant time for large files. This causes blocking, timeouts, and performance issues during autogrowth events. IFI allows near-instant file growth for data files (not log files)."
                CurrentValue = @{
                    IFIEnabled = $ifi.IfiEnabled
                }
                RecommendedAction = if ($ifi.IfiEnabled) { "Instant File Initialization is enabled" } else { "Grant 'Perform Volume Maintenance Tasks' privilege to SQL Server service account" }
                RemediationSteps = @{
                    PowerShell = @"
# Step 1: Identify SQL Server service account
`$serviceAccount = (Get-WmiObject Win32_Service | Where-Object {`$_.Name -like 'MSSQL*' -and `$_.Name -notlike '*Agent*'}).StartName
Write-Host "SQL Server Service Account: `$serviceAccount"

# Step 2: Export current security policy
secedit /export /cfg C:\secpol.cfg

# Step 3: Add Perform Volume Maintenance Tasks privilege
`$content = Get-Content C:\secpol.cfg
`$newContent = @()
foreach (`$line in `$content) {
    if (`$line -match 'SeManageVolumePrivilege') {
        if (`$line -notmatch [regex]::Escape(`$serviceAccount)) {
            `$line = `$line.TrimEnd() + ",`$serviceAccount"
        }
    }
    `$newContent += `$line
}
`$newContent | Set-Content C:\secpol.cfg

# Step 4: Apply new policy
secedit /configure /db C:\windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS

# Step 5: Clean up
Remove-Item C:\secpol.cfg

# Step 6: Restart SQL Server
Restart-DbaService -SqlInstance '$serverName' -Type Engine -Force

# Step 7: Verify IFI is enabled
Test-DbaInstanceFileInitialization -SqlInstance '$serverName'
"@
                    TSQL = @"
-- Enable trace flag 3004 to log file initialization info
DBCC TRACEON(3004, -1);

-- Create a test database to verify IFI
-- Check SQL Server error log for messages
-- With IFI: You'll see instant initialization
-- Without IFI: You'll see "Zeroing" messages

-- View error log
EXEC sp_readerrorlog;
"@
                    Manual = @"
1. Open Local Security Policy (secpol.msc)
2. Navigate to: Local Policies → User Rights Assignment
3. Double-click "Perform volume maintenance tasks"
4. Click "Add User or Group"
5. Enter the SQL Server service account
6. Click OK
7. Restart SQL Server service
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-instant-file-initialization"
                )
                RawData = $ifi
            }
            $serverResults.Checks += $ifiCheck
        }
        catch {
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Instant File Initialization"
                Status = "❌ Error"
                Severity = "Error"
                Description = "Could not check Instant File Initialization"
                Error = $_.Exception.Message
            }
        }
        
        # ============================================================================
        # CHECK 4: MEMORY CONFIGURATION
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [4/$totalChecks] Checking memory configuration..."
        
        try {
            $memory = Get-DbaMaxMemory -SqlInstance $conn
            $recommended = [math]::Round($memory.TotalMB * 0.75)
            $isConfigured = $memory.SqlMaxMB -gt 0 -and $memory.SqlMaxMB -lt $memory.TotalMB -and $memory.SqlMaxMB -ge $recommended * 0.9
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Memory Configuration"
                Status = if ($isConfigured) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isConfigured) { "Pass" } else { "Warning" }
                Description = "Validates SQL Server min/max memory settings against best practices"
                Impact = "Incorrect memory settings can cause OS instability (if max too high) or SQL Server memory starvation (if max too low). Min memory should be at least 25% of max to prevent excessive memory deallocations."
                CurrentValue = @{
                    MinMemoryMB = $memory.SqlMinMB
                    MaxMemoryMB = $memory.SqlMaxMB
                    TotalServerMemoryMB = $memory.TotalMB
                    RecommendedMaxMB = $recommended
                    RecommendedMinMB = [math]::Round($recommended * 0.25)
                }
                RecommendedAction = if ($isConfigured) { "Memory is properly configured" } else { "Set max server memory to ~75% of total RAM ($recommended MB) and min to ~25% of max" }
                RemediationSteps = @{
                    PowerShell = @"
# Set recommended memory settings
Set-DbaMaxMemory -SqlInstance '$serverName' -Max $recommended

# Verify settings
Get-DbaMaxMemory -SqlInstance '$serverName'
"@
                    TSQL = @"
-- Set max server memory (MB)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'max server memory (MB)', $recommended;
RECONFIGURE;

-- Verify
EXEC sp_configure 'max server memory';
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-memory-server-configuration-options"
                )
                RawData = $memory
            }
        } catch {
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Memory Configuration"
                Status = "❌ Error"
                Severity = "Error"
                Description = "Could not check memory configuration"
                Error = $_.Exception.Message
            }
        }
        
        # ============================================================================
        # CHECK 5: LAST BACKUP
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [5/$totalChecks] Checking backup status..."
        
        try {
            $lastBackup = Get-DbaLastBackup -SqlInstance $conn | Where-Object { $_.Database -notin @('master','model','msdb','tempdb') }
            $oldBackups = $lastBackup | Where-Object { $_.LastFullBackup -lt (Get-Date).AddDays(-1) }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Last Backup"
                Status = if ($oldBackups.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($oldBackups.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies all user databases have been backed up within the last 24 hours"
                Impact = "Databases without recent backups risk significant data loss in case of hardware failure, corruption, or accidental deletion. RPO will be severely impacted."
                CurrentValue = @{
                    DatabasesWithOldBackups = $oldBackups.Count
                    TotalUserDatabases = $lastBackup.Count
                }
                RecommendedAction = if ($oldBackups.Count -eq 0) { "All databases backed up regularly" } else { "Schedule daily full backups for all production databases" }
                RemediationSteps = @{
                    PowerShell = "Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | Backup-DbaDatabase -Type Full -CompressBackup"
                    TSQL = "-- Use maintenance plans or Ola Hallengren scripts for automated backups"
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/backup-restore/back-up-and-restore-of-sql-server-databases"
                )
                RawData = $oldBackups
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Last Backup"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check backups"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 6: DATABASE PERCENT GROWTH
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [6/$totalChecks] Checking database growth settings..."
        
        try {
            $dbFiles = Get-DbaDbFile -SqlInstance $conn
            $percentGrowth = $dbFiles | Where-Object { $_.Growth -gt 0 -and $_.Growth -lt 100 }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Database Percent Growth"
                Status = if ($percentGrowth.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($percentGrowth.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies database files using percentage-based autogrowth instead of fixed size"
                Impact = "Percentage growth causes exponentially larger autogrowth events as files grow, leading to performance issues and file fragmentation. Fixed growth (e.g., 512MB) is more predictable and performs better."
                CurrentValue = @{
                    FilesWithPercentGrowth = $percentGrowth.Count
                    TotalFiles = $dbFiles.Count
                }
                RecommendedAction = if ($percentGrowth.Count -eq 0) { "All files use fixed growth" } else { "Change to fixed growth: 512MB for data files, 256MB for log files" }
                RemediationSteps = @{
                    PowerShell = @"
# Change all percent growth to fixed size (512MB for data, 256MB for logs)
Get-DbaDbFile -SqlInstance '$serverName' | Where-Object { `$_.Growth -lt 100 } | ForEach-Object {
    `$growthMB = if (`$_.TypeDescription -eq 'LOG') { 256 } else { 512 }
    Set-DbaDbFileGrowth -SqlInstance '$serverName' -Database `$_.Database -FileGroup `$_.FileGroupName -GrowthType MB -Growth `$growthMB
}
"@
                    TSQL = @"
-- Change data files to 512MB fixed growth
ALTER DATABASE [DatabaseName] 
MODIFY FILE (NAME = N'DataFileName', FILEGROWTH = 512MB);

-- Change log files to 256MB fixed growth
ALTER DATABASE [DatabaseName] 
MODIFY FILE (NAME = N'LogFileName', FILEGROWTH = 256MB);
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-file-and-filegroup-options"
                )
                RawData = $percentGrowth | Select-Object Database, LogicalName, Growth, Type
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Database Percent Growth"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check growth settings"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 7: RECOVERY MODEL
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [7/$totalChecks] Checking recovery models..."
        
        try {
            $recoveryModel = Get-DbaDbRecoveryModel -SqlInstance $conn | Where-Object { $_.Database -notin @('master','model','msdb','tempdb') }
            $simpleInProd = $recoveryModel | Where-Object { $_.RecoveryModel -eq 'Simple' -and $_.Database -notlike '*test*' -and $_.Database -notlike '*dev*' }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Recovery Model"
                Status = if ($simpleInProd.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($simpleInProd.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Validates recovery model settings are appropriate for production vs non-production databases"
                Impact = "SIMPLE recovery prevents point-in-time recovery and transaction log backups. Production databases should use FULL recovery for maximum data protection. Non-production can use SIMPLE to avoid log file growth."
                CurrentValue = @{
                    SimpleModeInProduction = $simpleInProd.Count
                    TotalUserDatabases = $recoveryModel.Count
                }
                RecommendedAction = if ($simpleInProd.Count -eq 0) { "Recovery models are appropriate" } else { "Change production databases to FULL recovery and take a full backup" }
                RemediationSteps = @{
                    PowerShell = @"
# Change to FULL recovery for production databases
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | 
    Where-Object { `$_.RecoveryModel -eq 'Simple' -and `$_.Name -notlike '*test*' } |
    Set-DbaDbRecoveryModel -RecoveryModel Full

# Take full backup after changing to FULL
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | 
    Where-Object { `$_.RecoveryModel -eq 'Full' } |
    Backup-DbaDatabase -Type Full
"@
                    TSQL = @"
-- Change to FULL recovery
ALTER DATABASE [DatabaseName] SET RECOVERY FULL;

-- IMPORTANT: Take full backup to enable log backups
BACKUP DATABASE [DatabaseName] TO DISK = 'C:\\Backup\\DatabaseName_Full.bak' WITH COMPRESSION;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/backup-restore/recovery-models-sql-server"
                )
                RawData = $simpleInProd | Select-Object Database, RecoveryModel
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Recovery Model"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check recovery models"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 8: VIRTUAL LOG FILES (VLF)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [8/$totalChecks] Analyzing virtual log files..."
        
        try {
            $vlfs = Measure-DbaDbVirtualLogFile -SqlInstance $conn
            $highVlf = $vlfs | Where-Object { $_.Total -gt 500 }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Virtual Log Files (VLF)"
                Status = if ($highVlf.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($highVlf.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Detects databases with excessive VLF counts which impact performance"
                Impact = "High VLF counts (>500) slow down database recovery, log backups, transaction log operations, and can cause performance degradation. Caused by small autogrowth increments or percent-based growth."
                CurrentValue = @{
                    DatabasesWithHighVLF = $highVlf.Count
                    HighestVLFCount = if ($highVlf) { ($highVlf | Measure-Object -Property Total -Maximum).Maximum } else { 0 }
                }
                RecommendedAction = if ($highVlf.Count -eq 0) { "VLF counts are healthy" } else { "Shrink and regrow transaction logs during maintenance window (REQUIRES DOWNTIME)" }
                RemediationSteps = @{
                    PowerShell = @"
# WARNING: This requires a maintenance window and can take significant time
# Backup logs first if in FULL recovery
Get-DbaDatabase -SqlInstance '$serverName' | Where-Object { `$_.RecoveryModel -eq 'Full' } | 
    Backup-DbaDatabase -Type Log

# Shrink log files (one at a time, during maintenance window)
`$db = Get-DbaDatabase -SqlInstance '$serverName' -Database 'DatabaseName'
`$logFile = `$db.LogFiles[0].Name
Invoke-DbaQuery -SqlInstance '$serverName' -Database `$db.Name -Query "DBCC SHRINKFILE(`$logFile, 1)"

# Regrow to appropriate size with proper VLFs
Invoke-DbaQuery -SqlInstance '$serverName' -Database `$db.Name -Query "ALTER DATABASE [`$(`$db.Name)] MODIFY FILE (NAME = N'`$logFile', SIZE = 4096MB, FILEGROWTH = 512MB)"
"@
                    TSQL = @"
-- Step 1: Backup log if in FULL recovery
BACKUP LOG [DatabaseName] TO DISK = 'C:\\Backup\\DatabaseName_Log.trn';

-- Step 2: Shrink log file
USE [DatabaseName];
DBCC SHRINKFILE(N'DatabaseName_log', 1);

-- Step 3: Regrow to proper size (creates optimal VLF structure)
ALTER DATABASE [DatabaseName] 
MODIFY FILE (NAME = N'DatabaseName_log', SIZE = 4096MB, FILEGROWTH = 512MB);

-- Verify VLF count
DBCC LOGINFO;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/manage-the-size-of-the-transaction-log-file"
                )
                RawData = $highVlf | Select-Object Database, Total, Active, Status
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Virtual Log Files"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check VLF counts"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 9: TEMPDB CONFIGURATION
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [9/$totalChecks] Checking TempDB configuration..."
        
        try {
            $tempdb = Test-DbaTempDbConfiguration -SqlInstance $conn
            $issues = $tempdb | Where-Object { $_.IsBestPractice -eq $false }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "TempDB Configuration"
                Status = if ($issues.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($issues.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Validates TempDB follows best practices (file count, size, growth)"
                Impact = "Improper TempDB configuration causes contention, allocation issues, and poor performance. Should have one data file per CPU core (max 8), all files same size, and proper growth settings."
                CurrentValue = @{
                    ConfigurationIssues = $issues.Count
                    TotalChecks = $tempdb.Count
                }
                RecommendedAction = if ($issues.Count -eq 0) { "TempDB is properly configured" } else { "Add data files (1 per CPU, max 8) and ensure all files are same size" }
                RemediationSteps = @{
                    PowerShell = @"
# Get CPU count
`$cores = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
`$fileCount = [Math]::Min(`$cores, 8)

# Add TempDB files if needed
1..`$fileCount | ForEach-Object {
    `$fileName = "tempdev`$_"
    `$query = "IF NOT EXISTS (SELECT 1 FROM sys.master_files WHERE database_id = 2 AND name = '`$fileName') BEGIN ALTER DATABASE tempdb ADD FILE (NAME = N'`$fileName', FILENAME = N'C:\\SQLData\\`$fileName.ndf', SIZE = 8GB, FILEGROWTH = 512MB); END"
    Invoke-DbaQuery -SqlInstance '$serverName' -Database master -Query `$query
}
"@
                    TSQL = @"
-- Add TempDB data files (one per CPU core, max 8)
-- All files should be same size
ALTER DATABASE tempdb ADD FILE (
    NAME = N'tempdev2',
    FILENAME = N'C:\\SQLData\\tempdev2.ndf',
    SIZE = 8GB,
    FILEGROWTH = 512MB
);

-- Repeat for tempdev3, tempdev4, etc.
-- Set all files to same size
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/tempdb-database"
                )
                RawData = $issues | Select-Object Rule, Recommended, CurrentSetting, IsBestPractice
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "TempDB Configuration"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check TempDB"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 10: INTEGRITY CHECK (DBCC CHECKDB)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [10/$totalChecks] Checking database integrity history..."
        
        try {
            $lastGoodCheckDb = Get-DbaLastGoodCheckDb -SqlInstance $conn
            $oldChecks = $lastGoodCheckDb | Where-Object { $_.LastGoodCheckDb -lt (Get-Date).AddDays(-30) -and $_.Database -notin @('tempdb') }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Integrity Check (DBCC CHECKDB)"
                Status = if ($oldChecks.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($oldChecks.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies databases have had integrity checks (DBCC CHECKDB) within the last 30 days"
                Impact = "Undetected corruption can lead to data loss, database unavailability, and restore failures. Regular integrity checks (weekly minimum) are critical for early corruption detection."
                CurrentValue = @{
                    DatabasesNeedingCheck = $oldChecks.Count
                    OldestCheck = if ($oldChecks) { ($oldChecks | Sort-Object LastGoodCheckDb | Select-Object -First 1).LastGoodCheckDb } else { "N/A" }
                }
                RecommendedAction = if ($oldChecks.Count -eq 0) { "All databases checked recently" } else { "Run DBCC CHECKDB on all databases during maintenance window (HIGH I/O IMPACT)" }
                RemediationSteps = @{
                    PowerShell = @"
# Run integrity check on all user databases
# WARNING: This is I/O intensive - schedule during maintenance window
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | 
    ForEach-Object {
        Write-Host "Checking: `$(`$_.Name)"
        Invoke-DbaDbccCheckDb -SqlInstance '$serverName' -Database `$_.Name
    }
"@
                    TSQL = @"
-- Run DBCC CHECKDB on all user databases
-- Schedule during maintenance window due to I/O impact
DECLARE @db VARCHAR(100)
DECLARE db_cursor CURSOR FOR
SELECT name FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb')
AND state_desc = 'ONLINE'

OPEN db_cursor
FETCH NEXT FROM db_cursor INTO @db

WHILE @@FETCH_STATUS = 0
BEGIN
    PRINT 'Checking: ' + @db
    EXEC('DBCC CHECKDB([' + @db + ']) WITH NO_INFOMSGS')
    FETCH NEXT FROM db_cursor INTO @db
END

CLOSE db_cursor
DEALLOCATE db_cursor
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/database-console-commands/dbcc-checkdb-transact-sql"
                )
                RawData = $oldChecks | Select-Object Database, LastGoodCheckDb, DaysSinceLastGoodCheckDb, Status
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Integrity Check"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check integrity history"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 11: INDEX FRAGMENTATION
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [11/$totalChecks] Checking index fragmentation..."
        
        try {
            $fragmentation = Get-DbaDbFragmentation -SqlInstance $conn
            $highlyFragmented = $fragmentation | Where-Object { $_.FragmentationPercent -gt 50 -and $_.PageCount -gt 1000 }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Index Fragmentation"
                Status = if ($highlyFragmented.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($highlyFragmented.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies heavily fragmented indexes (>50% with >1000 pages)"
                Impact = "Fragmented indexes cause excessive I/O, slower queries, and wasted storage space. Fragmentation >30% should be rebuilt, 10-30% can be reorganized. Regular maintenance is critical for performance."
                CurrentValue = @{
                    HighlyFragmentedIndexes = $highlyFragmented.Count
                    WorstFragmentation = if ($highlyFragmented) { [math]::Round(($highlyFragmented | Measure-Object -Property FragmentationPercent -Maximum).Maximum, 2) } else { 0 }
                }
                RecommendedAction = if ($highlyFragmented.Count -eq 0) { "No heavily fragmented indexes" } else { "Rebuild indexes >30%, reorganize 10-30% during maintenance window" }
                RemediationSteps = @{
                    PowerShell = @"
# Rebuild heavily fragmented indexes (>30%)
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | 
    Invoke-DbaDbShrink -RebuildIndexes -FragmentationLevel 30

# Or use Ola Hallengren maintenance solution
Install-DbaMaintenanceSolution -SqlInstance '$serverName' -Solution IndexOptimize
"@
                    TSQL = @"
-- Rebuild indexes with >30% fragmentation
DECLARE @TableName VARCHAR(255)
DECLARE @IndexName VARCHAR(255)
DECLARE @SchemaName VARCHAR(255)

DECLARE index_cursor CURSOR FOR
SELECT 
    OBJECT_SCHEMA_NAME(ips.object_id) AS SchemaName,
    OBJECT_NAME(ips.object_id) AS TableName,
    i.name AS IndexName
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
INNER JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
WHERE ips.avg_fragmentation_in_percent > 30
AND ips.page_count > 1000

OPEN index_cursor
FETCH NEXT FROM index_cursor INTO @SchemaName, @TableName, @IndexName

WHILE @@FETCH_STATUS = 0
BEGIN
    PRINT 'Rebuilding: ' + @SchemaName + '.' + @TableName + '.' + @IndexName
    EXEC('ALTER INDEX [' + @IndexName + '] ON [' + @SchemaName + '].[' + @TableName + '] REBUILD WITH (ONLINE = ON)')
    FETCH NEXT FROM index_cursor INTO @SchemaName, @TableName, @IndexName
END

CLOSE index_cursor
DEALLOCATE index_cursor
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/indexes/reorganize-and-rebuild-indexes"
                )
                RawData = $highlyFragmented | Select-Object Database, Schema, Table, IndexName, FragmentationPercent, PageCount | Sort-Object -Property FragmentationPercent -Descending
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Index Fragmentation"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check fragmentation"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 12: AUTO SHRINK
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [12/$totalChecks] Checking auto shrink settings..."
        
        try {
            $autoShrink = Get-DbaDbAutoShrink -SqlInstance $conn
            $enabled = $autoShrink | Where-Object { $_.AutoShrink -eq $true }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Auto Shrink"
                Status = if ($enabled.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($enabled.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Detects databases with auto shrink enabled (should be disabled)"
                Impact = "Auto shrink causes severe performance degradation through constant shrink/grow cycles, index fragmentation, and blocked operations. It's almost never appropriate for production databases."
                CurrentValue = @{
                    DatabasesWithAutoShrink = $enabled.Count
                }
                RecommendedAction = if ($enabled.Count -eq 0) { "Auto shrink disabled on all databases" } else { "Disable auto shrink immediately on all databases" }
                RemediationSteps = @{
                    PowerShell = @"
# Disable auto shrink on all databases
Get-DbaDatabase -SqlInstance '$serverName' | 
    Where-Object { `$_.AutoShrink -eq `$true } |
    Set-DbaDbAutoShrink -AutoShrink Disabled
"@
                    TSQL = @"
-- Disable auto shrink
ALTER DATABASE [DatabaseName] SET AUTO_SHRINK OFF;

-- Verify
SELECT name, is_auto_shrink_on 
FROM sys.databases 
WHERE is_auto_shrink_on = 1;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-properties-options-page"
                )
                RawData = $enabled | Select-Object Database, AutoShrink
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Auto Shrink"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check auto shrink"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 13: AUTO CLOSE
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [13/$totalChecks] Checking auto close settings..."
        
        try {
            $autoClose = Get-DbaDbAutoClose -SqlInstance $conn
            $enabled = $autoClose | Where-Object { $_.AutoClose -eq $true }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Auto Close"
                Status = if ($enabled.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($enabled.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Detects databases with auto close enabled (should be disabled)"
                Impact = "Auto close causes databases to be closed and reopened repeatedly, leading to connection timeouts, slow first queries, and resource overhead. Only useful for 32-bit SQL Express with many databases."
                CurrentValue = @{
                    DatabasesWithAutoClose = $enabled.Count
                }
                RecommendedAction = if ($enabled.Count -eq 0) { "Auto close disabled on all databases" } else { "Disable auto close on all production databases" }
                RemediationSteps = @{
                    PowerShell = @"
# Disable auto close on all databases
Get-DbaDatabase -SqlInstance '$serverName' | 
    Where-Object { `$_.AutoClose -eq `$true } |
    Set-DbaDbAutoClose -AutoClose Disabled
"@
                    TSQL = @"
-- Disable auto close
ALTER DATABASE [DatabaseName] SET AUTO_CLOSE OFF;

-- Verify
SELECT name, is_auto_close_on 
FROM sys.databases 
WHERE is_auto_close_on = 1;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-properties-options-page"
                )
                RawData = $enabled | Select-Object Database, AutoClose
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Auto Close"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check auto close"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 14: PAGE VERIFY OPTION
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [14/$totalChecks] Checking page verify settings..."
        
        try {
            $pageVerify = Get-DbaDbPageVerify -SqlInstance $conn
            $notChecksum = $pageVerify | Where-Object { $_.PageVerify -ne 'CHECKSUM' }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Page Verify Option"
                Status = if ($notChecksum.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($notChecksum.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies all databases use CHECKSUM for page verification"
                Impact = "CHECKSUM is the best method for detecting I/O corruption. TORN_PAGE_DETECTION is less effective, and NONE provides no protection. CHECKSUM has negligible performance impact on modern hardware."
                CurrentValue = @{
                    DatabasesNotUsingChecksum = $notChecksum.Count
                }
                RecommendedAction = if ($notChecksum.Count -eq 0) { "All databases using CHECKSUM" } else { "Set PAGE_VERIFY to CHECKSUM for all databases" }
                RemediationSteps = @{
                    PowerShell = @"
# Set page verify to CHECKSUM for all databases
Get-DbaDatabase -SqlInstance '$serverName' | 
    Where-Object { `$_.PageVerify -ne 'Checksum' } |
    Set-DbaDbPageVerify -PageVerify Checksum
"@
                    TSQL = @"
-- Set page verify to CHECKSUM
ALTER DATABASE [DatabaseName] SET PAGE_VERIFY CHECKSUM;

-- Verify all databases
SELECT name, page_verify_option_desc 
FROM sys.databases 
WHERE page_verify_option_desc <> 'CHECKSUM';
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-properties-options-page"
                )
                RawData = $notChecksum | Select-Object Database, PageVerify
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Page Verify"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check page verify"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 15: SA ACCOUNT STATUS (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [15/$totalChecks] Checking SA account status..."
        
        try {
            $saLogin = Get-DbaLogin -SqlInstance $conn -Login 'sa'
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "SA Account Status"
                Status = if ($saLogin.IsDisabled) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($saLogin.IsDisabled) { "Pass" } else { "Warning" }
                Description = "Verifies that the built-in 'sa' account is disabled"
                Impact = "The 'sa' account is a well-known sysadmin account and prime target for brute-force attacks. Keeping it enabled increases security risk. Best practice: disable it and use Windows Authentication or named accounts."
                CurrentValue = @{
                    IsDisabled = $saLogin.IsDisabled
                    LastLogin = $saLogin.LastLogin
                }
                RecommendedAction = if ($saLogin.IsDisabled) { "SA account properly disabled" } else { "Disable sa account after ensuring alternative sysadmin access exists" }
                RemediationSteps = @{
                    PowerShell = @"
# IMPORTANT: Verify alternative sysadmin accounts first!
Get-DbaServerRoleMember -SqlInstance '$serverName' -ServerRole sysadmin

# If other sysadmins exist, disable sa
Disable-DbaLogin -SqlInstance '$serverName' -Login 'sa' -Confirm:`$false

# Verify
Get-DbaLogin -SqlInstance '$serverName' -Login 'sa' | Select-Object Name, IsDisabled
"@
                    TSQL = @"
-- IMPORTANT: Verify other sysadmin logins first!
SELECT p.name, p.type_desc
FROM sys.server_principals p
JOIN sys.server_role_members rm ON p.principal_id = rm.member_principal_id
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin' AND p.name <> 'sa';

-- If other sysadmins exist, disable sa
ALTER LOGIN [sa] DISABLE;

-- Verify
SELECT name, is_disabled FROM sys.server_principals WHERE name = 'sa';
"@
                    Manual = @"
1. CRITICAL: Ensure you have alternative sysadmin access first!
2. Open SQL Server Management Studio
3. Connect with non-sa sysadmin account
4. Expand Security → Logins
5. Right-click 'sa' → Properties
6. Check 'Login is disabled'
7. Click OK
8. Test: Try connecting with sa (should fail)
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server"
                )
                RawData = $saLogin | Select-Object Name, IsDisabled, CreateDate, LastLogin
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "SA Account"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check SA account"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 16: WEAK PASSWORDS (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [16/$totalChecks] Testing for weak passwords..."
        
        try {
            $weakPasswords = Test-DbaLoginPassword -SqlInstance $conn
            $weak = $weakPasswords | Where-Object { $_.PasswordIsWeak -eq $true -or $_.PasswordIsBlank -eq $true }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Weak Passwords"
                Status = if ($weak.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($weak.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Tests SQL logins for weak, blank, or commonly used passwords"
                Impact = "Weak passwords are easily compromised through brute-force or dictionary attacks, providing unauthorized access to your SQL Server. This is a critical security vulnerability."
                CurrentValue = @{
                    LoginsWithWeakPasswords = $weak.Count
                    WeakLogins = ($weak.Login -join ', ')
                }
                RecommendedAction = if ($weak.Count -eq 0) { "No weak passwords detected" } else { "Change all weak passwords immediately and enable password policy enforcement" }
                RemediationSteps = @{
                    PowerShell = @"
# Force password policy on SQL logins
Get-DbaLogin -SqlInstance '$serverName' -Type SQL | 
    Set-DbaLogin -PasswordPolicyEnforced

# Change specific weak password (interactive)
Set-DbaLogin -SqlInstance '$serverName' -Login 'LoginName' -SecurePassword (Read-Host -AsSecureString -Prompt 'Enter new password')
"@
                    TSQL = @"
-- Enable password policy enforcement
ALTER LOGIN [LoginName] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;

-- Change weak password
ALTER LOGIN [LoginName] WITH PASSWORD = 'NewStrongP@ssw0rd!';

-- Verify policy settings
SELECT name, is_policy_checked, is_expiration_checked
FROM sys.sql_logins
WHERE is_policy_checked = 0;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/password-policy"
                )
                RawData = $weak | Select-Object Login, PasswordIsWeak, PasswordIsBlank
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Weak Passwords"; Status = "❌ Error"; Severity = "Error"; Description = "Could not test passwords"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 17: XP_CMDSHELL CONFIGURATION (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [17/$totalChecks] Checking xp_cmdshell configuration..."
        
        try {
            $spConfig = Get-DbaSpConfigure -SqlInstance $conn -Name 'xp_cmdshell'
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "xp_cmdshell Configuration"
                Status = if ($spConfig.ConfiguredValue -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($spConfig.ConfiguredValue -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies that xp_cmdshell is disabled for security"
                Impact = "xp_cmdshell allows execution of operating system commands from SQL Server. If enabled, it provides a direct attack vector for SQL injection to gain OS-level access. Should only be enabled when absolutely necessary and with proper security controls."
                CurrentValue = @{
                    IsEnabled = $spConfig.ConfiguredValue -eq 1
                    ConfigValue = $spConfig.ConfiguredValue
                    RunValue = $spConfig.RunningValue
                }
                RecommendedAction = if ($spConfig.ConfiguredValue -eq 0) { "xp_cmdshell is properly disabled" } else { "Disable xp_cmdshell unless specifically required" }
                RemediationSteps = @{
                    PowerShell = @"
# Disable xp_cmdshell
Set-DbaSpConfigure -SqlInstance '$serverName' -Name 'xp_cmdshell' -Value 0

# Verify
Get-DbaSpConfigure -SqlInstance '$serverName' -Name 'xp_cmdshell'
"@
                    TSQL = @"
-- Disable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Verify
EXEC sp_configure 'xp_cmdshell';
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql"
                )
                RawData = $spConfig
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "xp_cmdshell"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check xp_cmdshell"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 18: ORPHANED USERS (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [18/$totalChecks] Checking for orphaned users..."
        
        try {
            $orphanedUsers = Get-DbaDbOrphanUser -SqlInstance $conn
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Orphaned Users"
                Status = if ($orphanedUsers.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($orphanedUsers.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies database users without corresponding server logins"
                Impact = "Orphaned users cannot log in and represent security clutter. They may indicate deleted logins that still have database access defined, or issues after database restores/migrations. Clean up improves security and maintainability."
                CurrentValue = @{
                    OrphanedUserCount = $orphanedUsers.Count
                }
                RecommendedAction = if ($orphanedUsers.Count -eq 0) { "No orphaned users found" } else { "Remove orphaned users or remap to correct logins" }
                RemediationSteps = @{
                    PowerShell = @"
# Option 1: Repair orphaned users (map to logins with same name)
Repair-DbaDbOrphanUser -SqlInstance '$serverName' -RemoveNotExisting

# Option 2: Remove orphaned users
Get-DbaDbOrphanUser -SqlInstance '$serverName' | 
    Remove-DbaDbUser

# Option 3: Manually map user to login
Repair-DbaDbOrphanUser -SqlInstance '$serverName' -Database 'DatabaseName' -User 'UserName' -Login 'LoginName'
"@
                    TSQL = @"
-- Find orphaned users
USE [DatabaseName];
SELECT 
    dp.name AS UserName,
    dp.type_desc AS UserType
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE sp.sid IS NULL
AND dp.type IN ('S','U')
AND dp.name NOT IN ('guest','INFORMATION_SCHEMA','sys');

-- Option 1: Remap user to login with same name
ALTER USER [UserName] WITH LOGIN = [LoginName];

-- Option 2: Drop orphaned user
DROP USER [UserName];
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server"
                )
                RawData = $orphanedUsers | Select-Object Database, User
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Orphaned Users"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check orphaned users"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 19: DATABASE OWNERSHIP (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [19/$totalChecks] Checking database ownership..."
        
        try {
            $dbOwners = Test-DbaDbOwner -SqlInstance $conn
            $notSa = $dbOwners | Where-Object { $_.OwnerMatch -eq $false }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Database Ownership"
                Status = if ($notSa.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($notSa.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies all databases are owned by 'sa' for consistency"
                Impact = "Databases owned by regular accounts can cause issues if that account is deleted or permissions change. Best practice is to have all databases owned by 'sa' (even if sa is disabled) for consistency and to avoid ownership chain issues."
                CurrentValue = @{
                    DatabasesNotOwnedBySA = $notSa.Count
                }
                RecommendedAction = if ($notSa.Count -eq 0) { "All databases owned by sa" } else { "Change database ownership to 'sa'" }
                RemediationSteps = @{
                    PowerShell = @"
# Change all database owners to sa
Set-DbaDbOwner -SqlInstance '$serverName' -TargetLogin sa

# Verify
Get-DbaDbOwner -SqlInstance '$serverName'
"@
                    TSQL = @"
-- Change database owner to sa
ALTER AUTHORIZATION ON DATABASE::[DatabaseName] TO sa;

-- Change all databases to sa
DECLARE @db VARCHAR(100)
DECLARE db_cursor CURSOR FOR
SELECT name FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb')
AND SUSER_SNAME(owner_sid) <> 'sa'

OPEN db_cursor
FETCH NEXT FROM db_cursor INTO @db

WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC('ALTER AUTHORIZATION ON DATABASE::[' + @db + '] TO sa')
    FETCH NEXT FROM db_cursor INTO @db
END

CLOSE db_cursor
DEALLOCATE db_cursor
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql"
                )
                RawData = $notSa | Select-Object Database, Owner, OwnerMatch
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Database Ownership"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check database ownership"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 20: DUPLICATE INDEXES (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [20/$totalChecks] Checking for duplicate indexes..."
        
        try {
            $duplicateIndexes = Find-DbaDuplicateIndex -SqlInstance $conn
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Duplicate Indexes"
                Status = if ($duplicateIndexes.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($duplicateIndexes.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies redundant/duplicate indexes that waste space and slow down writes"
                Impact = "Duplicate indexes waste disk space, increase backup/restore time, and slow down INSERT/UPDATE/DELETE operations because SQL Server must maintain multiple identical indexes. They provide no query performance benefit."
                CurrentValue = @{
                    DuplicateIndexCount = $duplicateIndexes.Count
                }
                RecommendedAction = if ($duplicateIndexes.Count -eq 0) { "No duplicate indexes found" } else { "Drop duplicate indexes after verifying query plans don't rely on them" }
                RemediationSteps = @{
                    PowerShell = @"
# Find duplicate indexes
`$dupes = Find-DbaDuplicateIndex -SqlInstance '$serverName'

# Review before dropping
`$dupes | Select-Object DatabaseName, TableName, IndexName, KeyColumns

# Drop duplicate indexes (BE CAREFUL - verify first!)
# `$dupes | Remove-DbaIndex -Confirm:`$false
"@
                    TSQL = @"
-- Find duplicate indexes manually
SELECT 
    t.name AS TableName,
    i1.name AS Index1,
    i2.name AS Index2
FROM sys.indexes i1
INNER JOIN sys.indexes i2 ON i1.object_id = i2.object_id
INNER JOIN sys.tables t ON i1.object_id = t.object_id
WHERE i1.index_id < i2.index_id
AND i1.type = i2.type
-- Add more logic to compare columns

-- Drop duplicate index (after verification!)
DROP INDEX [IndexName] ON [SchemaName].[TableName];
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/indexes/indexes"
                )
                RawData = $duplicateIndexes | Select-Object DatabaseName, TableName, IndexName, KeyColumns
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Duplicate Indexes"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check for duplicates"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 21: TABLES WITHOUT PRIMARY KEY (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [21/$totalChecks] Checking for tables without primary keys..."
        
        try {
            $tablesNoPK = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    SUM(p.rows) AS RowCount
FROM sys.tables t
LEFT JOIN sys.indexes i ON t.object_id = i.object_id AND i.is_primary_key = 1
INNER JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
WHERE i.object_id IS NULL
AND t.is_ms_shipped = 0
GROUP BY SCHEMA_NAME(t.schema_id), t.name
ORDER BY RowCount DESC;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $tablesNoPK += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            RowCount = $_.RowCount
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Tables Without Primary Key"
                Status = if ($tablesNoPK.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($tablesNoPK.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies tables without primary keys"
                Impact = "Tables without primary keys can cause data integrity issues, duplicate rows, poor query performance, and problems with replication/change tracking. Primary keys ensure row uniqueness and enable efficient lookups."
                CurrentValue = @{
                    TablesWithoutPK = $tablesNoPK.Count
                }
                RecommendedAction = if ($tablesNoPK.Count -eq 0) { "All tables have primary keys" } else { "Add primary keys to tables or document why they're not needed" }
                RemediationSteps = @{
                    PowerShell = @"
# Review tables without primary keys
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT SCHEMA_NAME(schema_id) + '.' + name AS TableName
FROM sys.tables t
WHERE NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = t.object_id AND is_primary_key = 1)
'@

# Add primary key requires manual analysis of appropriate column(s)
"@
                    TSQL = @"
-- Add primary key to existing table
ALTER TABLE [SchemaName].[TableName]
ADD CONSTRAINT PK_TableName PRIMARY KEY CLUSTERED ([ColumnName]);

-- Add identity column and primary key
ALTER TABLE [SchemaName].[TableName]
ADD ID INT IDENTITY(1,1);

ALTER TABLE [SchemaName].[TableName]
ADD CONSTRAINT PK_TableName PRIMARY KEY CLUSTERED (ID);

-- Add composite primary key
ALTER TABLE [SchemaName].[TableName]
ADD CONSTRAINT PK_TableName PRIMARY KEY CLUSTERED ([Column1], [Column2]);
"@
                    Manual = @"
1. Analyze each table to determine appropriate primary key column(s)
2. Verify data uniqueness: SELECT Column, COUNT(*) FROM Table GROUP BY Column HAVING COUNT(*) > 1
3. If duplicates exist, clean data first
4. Add primary key constraint
5. Consider adding identity column if no natural key exists
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/tables/primary-and-foreign-key-constraints"
                )
                RawData = $tablesNoPK | Select-Object Database, Schema, Table, RowCount
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Tables Without Primary Key"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check tables"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 22: TABLES WITHOUT INDEXES (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [22/$totalChecks] Checking for tables without indexes..."
        
        try {
            $tablesNoIndex = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    SUM(p.rows) AS RowCount
FROM sys.tables t
LEFT JOIN sys.indexes i ON t.object_id = i.object_id AND i.type > 0
INNER JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
WHERE i.object_id IS NULL
AND t.is_ms_shipped = 0
GROUP BY SCHEMA_NAME(t.schema_id), t.name
HAVING SUM(p.rows) > 1000
ORDER BY RowCount DESC;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $tablesNoIndex += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            RowCount = $_.RowCount
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Tables Without Indexes"
                Status = if ($tablesNoIndex.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($tablesNoIndex.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies tables with >1000 rows that have no indexes (heaps)"
                Impact = "Tables without indexes (heaps) cause full table scans on every query, leading to poor performance, high I/O, and blocking. While small tables may not need indexes, tables with >1000 rows typically benefit from at least a clustered index."
                CurrentValue = @{
                    TablesWithoutIndexes = $tablesNoIndex.Count
                }
                RecommendedAction = if ($tablesNoIndex.Count -eq 0) { "All large tables have indexes" } else { "Add clustered indexes to heap tables with significant row counts" }
                RemediationSteps = @{
                    PowerShell = @"
# Find heap tables with row counts
`$heaps = Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    DB_NAME() AS DatabaseName,
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    SUM(p.rows) AS RowCount
FROM sys.tables t
INNER JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id = 0
GROUP BY t.schema_id, t.name
HAVING SUM(p.rows) > 1000
'@

`$heaps | Format-Table
"@
                    TSQL = @"
-- Create clustered index on heap table
CREATE CLUSTERED INDEX IX_TableName_ColumnName 
ON [SchemaName].[TableName] ([ColumnName]);

-- If table has primary key, make it clustered
ALTER TABLE [SchemaName].[TableName]
DROP CONSTRAINT PK_ConstraintName;

ALTER TABLE [SchemaName].[TableName]
ADD CONSTRAINT PK_ConstraintName PRIMARY KEY CLUSTERED ([ColumnName]);

-- Find missing index recommendations
SELECT 
    migs.avg_user_impact,
    mid.statement,
    mid.equality_columns,
    mid.inequality_columns,
    mid.included_columns
FROM sys.dm_db_missing_index_details mid
JOIN sys.dm_db_missing_index_groups mig ON mid.index_handle = mig.index_handle
JOIN sys.dm_db_missing_index_group_stats migs ON mig.index_group_handle = migs.group_handle
ORDER BY migs.avg_user_impact DESC;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/indexes/heaps-tables-without-clustered-indexes"
                )
                RawData = $tablesNoIndex | Select-Object Database, Schema, Table, RowCount
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Tables Without Indexes"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check tables"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 23: FOREIGN KEYS WITHOUT INDEXES (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [23/$totalChecks] Checking foreign keys without indexes..."
        
        try {
            $fkNoIndex = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    OBJECT_SCHEMA_NAME(fk.parent_object_id) AS SchemaName,
    OBJECT_NAME(fk.parent_object_id) AS TableName,
    fk.name AS ForeignKeyName,
    COL_NAME(fkc.parent_object_id, fkc.parent_column_id) AS ColumnName
FROM sys.foreign_keys fk
INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
WHERE NOT EXISTS (
    SELECT 1
    FROM sys.index_columns ic
    WHERE ic.object_id = fkc.parent_object_id
    AND ic.column_id = fkc.parent_column_id
    AND ic.index_column_id = 1
)
ORDER BY SchemaName, TableName;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $fkNoIndex += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            ForeignKey = $_.ForeignKeyName
                            Column = $_.ColumnName
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Foreign Keys Without Indexes"
                Status = if ($fkNoIndex.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($fkNoIndex.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies foreign key columns without supporting indexes"
                Impact = "Foreign key columns without indexes cause table scans during DELETE/UPDATE operations on the parent table, and slow JOIN queries. This leads to blocking, deadlocks, and poor performance in multi-table operations."
                CurrentValue = @{
                    ForeignKeysWithoutIndexes = $fkNoIndex.Count
                }
                RecommendedAction = if ($fkNoIndex.Count -eq 0) { "All foreign keys have indexes" } else { "Create indexes on foreign key columns" }
                RemediationSteps = @{
                    PowerShell = @"
# Script to create indexes on FK columns
`$fks = Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT DISTINCT
    DB_NAME() AS DatabaseName,
    OBJECT_SCHEMA_NAME(fk.parent_object_id) AS SchemaName,
    OBJECT_NAME(fk.parent_object_id) AS TableName,
    COL_NAME(fkc.parent_object_id, fkc.parent_column_id) AS ColumnName
FROM sys.foreign_keys fk
INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
WHERE NOT EXISTS (
    SELECT 1 FROM sys.index_columns ic
    WHERE ic.object_id = fkc.parent_object_id AND ic.column_id = fkc.parent_column_id
)
'@

`$fks | ForEach-Object {
    Write-Host "CREATE INDEX IX_`$(`$_.TableName)_`$(`$_.ColumnName) ON [`$(`$_.SchemaName)].[`$(`$_.TableName)] ([`$(`$_.ColumnName)]);"
}
"@
                    TSQL = @"
-- Create index on foreign key column
CREATE NONCLUSTERED INDEX IX_TableName_FKColumn
ON [SchemaName].[TableName] ([FKColumn]);

-- Create covering index if needed for common queries
CREATE NONCLUSTERED INDEX IX_TableName_FKColumn
ON [SchemaName].[TableName] ([FKColumn])
INCLUDE ([OtherColumn1], [OtherColumn2]);
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/tables/primary-and-foreign-key-constraints"
                )
                RawData = $fkNoIndex | Select-Object Database, Schema, Table, ForeignKey, Column
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Foreign Keys Without Indexes"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check foreign keys"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 24: DISABLED OR UNTRUSTED FOREIGN KEYS (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [24/$totalChecks] Checking disabled/untrusted foreign keys..."
        
        try {
            $untrustedFK = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    OBJECT_SCHEMA_NAME(parent_object_id) AS SchemaName,
    OBJECT_NAME(parent_object_id) AS TableName,
    name AS ForeignKeyName,
    is_disabled,
    is_not_trusted
FROM sys.foreign_keys
WHERE is_disabled = 1 OR is_not_trusted = 1
ORDER BY SchemaName, TableName;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $untrustedFK += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            ForeignKey = $_.ForeignKeyName
                            IsDisabled = $_.is_disabled
                            IsNotTrusted = $_.is_not_trusted
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Disabled/Untrusted Foreign Keys"
                Status = if ($untrustedFK.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($untrustedFK.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies foreign keys that are disabled or not trusted"
                Impact = "Disabled foreign keys don't enforce referential integrity, allowing orphaned records. Untrusted foreign keys (is_not_trusted=1) prevent the query optimizer from using them for query optimization, resulting in suboptimal execution plans and poor performance."
                CurrentValue = @{
                    DisabledOrUntrustedFKs = $untrustedFK.Count
                    DisabledCount = ($untrustedFK | Where-Object { $_.IsDisabled }).Count
                    UntrustedCount = ($untrustedFK | Where-Object { $_.IsNotTrusted }).Count
                }
                RecommendedAction = if ($untrustedFK.Count -eq 0) { "All foreign keys are enabled and trusted" } else { "Re-enable and validate foreign keys to ensure data integrity" }
                RemediationSteps = @{
                    PowerShell = @"
# Find untrusted foreign keys
`$untrusted = Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    DB_NAME() AS DatabaseName,
    OBJECT_SCHEMA_NAME(parent_object_id) AS SchemaName,
    OBJECT_NAME(parent_object_id) AS TableName,
    name AS ForeignKeyName
FROM sys.foreign_keys
WHERE is_not_trusted = 1
'@

# Generate fix scripts
`$untrusted | ForEach-Object {
    Write-Host "ALTER TABLE [`$(`$_.SchemaName)].[`$(`$_.TableName)] WITH CHECK CHECK CONSTRAINT [`$(`$_.ForeignKeyName)];"
}
"@
                    TSQL = @"
-- Re-enable disabled foreign key
ALTER TABLE [SchemaName].[TableName] 
CHECK CONSTRAINT [FK_Name];

-- Make untrusted foreign key trusted (validates existing data)
ALTER TABLE [SchemaName].[TableName] 
WITH CHECK CHECK CONSTRAINT [FK_Name];

-- Find all untrusted FKs
SELECT 
    OBJECT_SCHEMA_NAME(parent_object_id) AS SchemaName,
    OBJECT_NAME(parent_object_id) AS TableName,
    name AS ConstraintName
FROM sys.foreign_keys
WHERE is_not_trusted = 1;

-- Fix all untrusted FKs in database (generate script)
SELECT 
    'ALTER TABLE [' + OBJECT_SCHEMA_NAME(parent_object_id) + '].[' + 
    OBJECT_NAME(parent_object_id) + '] WITH CHECK CHECK CONSTRAINT [' + 
    name + '];' AS FixScript
FROM sys.foreign_keys
WHERE is_not_trusted = 1;
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/tables/primary-and-foreign-key-constraints",
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-table-transact-sql"
                )
                RawData = $untrustedFK | Select-Object Database, Schema, Table, ForeignKey, IsDisabled, IsNotTrusted
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Disabled/Untrusted Foreign Keys"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check foreign keys"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 25: WAIT STATISTICS (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [25/$totalChecks] Analyzing wait statistics..."
        
        try {
            $waitStats = Get-DbaWaitStatistic -SqlInstance $conn -Threshold 1 | Select-Object -First 10
            $topWaitType = $waitStats | Select-Object -First 1
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Wait Statistics"
                Status = if ($topWaitType.WaitType -match 'SLEEP|BROKER|XE_') { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($topWaitType.WaitType -match 'SLEEP|BROKER|XE_') { "Pass" } else { "Warning" }
                Description = "Analyzes top wait types indicating performance bottlenecks"
                Impact = @"
Wait statistics reveal where SQL Server spends time waiting. Common problematic waits:
- PAGEIOLATCH_*: Disk I/O bottleneck (slow storage or memory pressure)
- LCK_*: Blocking/locking issues
- CXPACKET/CXCONSUMER: Parallelism issues
- SOS_SCHEDULER_YIELD: CPU pressure
- WRITELOG: Transaction log bottleneck
- RESOURCE_SEMAPHORE: Memory grant waits (queries waiting for memory)
"@
                CurrentValue = @{
                    TopWaitType = $topWaitType.WaitType
                    WaitTimeMs = [math]::Round($topWaitType.WaitTime.TotalMilliseconds, 0)
                    PercentageOfTotal = [math]::Round($topWaitType.Percentage, 2)
                }
                RecommendedAction = if ($topWaitType.WaitType -match 'SLEEP|BROKER|XE_') { "Wait statistics appear normal" } else { "Investigate and address top wait types" }
                RemediationSteps = @{
                    PowerShell = @"
# Get detailed wait statistics
Get-DbaWaitStatistic -SqlInstance '$serverName' | Select-Object -First 20

# Reset wait statistics (after analysis)
# Invoke-DbaQuery -SqlInstance '$serverName' -Query 'DBCC SQLPERF(''sys.dm_os_wait_stats'', CLEAR)'

# Continuous monitoring
while (`$true) {
    Get-DbaWaitStatistic -SqlInstance '$serverName' -Threshold 5 | Format-Table
    Start-Sleep -Seconds 30
}
"@
                    TSQL = @"
-- Get wait statistics
SELECT TOP 10
    wait_type,
    wait_time_ms,
    wait_time_ms * 100.0 / SUM(wait_time_ms) OVER() AS percentage,
    waiting_tasks_count,
    wait_time_ms / NULLIF(waiting_tasks_count, 0) AS avg_wait_time_ms
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'RESOURCE_QUEUE', 'SLEEP_TASK',
    'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH', 'WAITFOR', 'LOGMGR_QUEUE',
    'CHECKPOINT_QUEUE', 'REQUEST_FOR_DEADLOCK_SEARCH', 'XE_TIMER_EVENT',
    'BROKER_TO_FLUSH', 'BROKER_TASK_STOP', 'CLR_MANUAL_EVENT',
    'CLR_AUTO_EVENT', 'DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT',
    'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP'
)
AND wait_time_ms > 0
ORDER BY wait_time_ms DESC;

-- Reset wait statistics (use carefully!)
-- DBCC SQLPERF('sys.dm_os_wait_stats', CLEAR);
"@
                    Manual = @"
1. Identify top wait types using above queries
2. Research wait type meaning at: https://www.sqlskills.com/help/waits/
3. Common remediation by wait type:
   - PAGEIOLATCH: Add memory, faster storage, optimize queries
   - LCK_M: Reduce transaction duration, add indexes, review locking hints
   - CXPACKET: Adjust MAXDOP, update statistics, optimize queries
   - WRITELOG: Faster log disk, reduce transaction size
   - RESOURCE_SEMAPHORE: Add memory, optimize memory-intensive queries
4. Monitor trends over time, not just snapshots
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-wait-stats-transact-sql",
                    "https://www.sqlskills.com/help/waits/"
                )
                RawData = $waitStats | Select-Object WaitType, WaitTime, Percentage, WaitingTasksCount
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Wait Statistics"; Status = "❌ Error"; Severity = "Error"; Description = "Could not get wait stats"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 26: TOP SLOW QUERIES (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [26/$totalChecks] Analyzing slow queries..."
        
        try {
            $slowQueries = Find-DbaTopResourceUsage -SqlInstance $conn -Type Duration -Limit 10
            $avgDuration = if ($slowQueries) { ($slowQueries | Measure-Object -Property Duration -Average).Average } else { 0 }
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Top Slow Queries"
                Status = if ($avgDuration -lt 5000) { "✅ Pass" } elseif ($avgDuration -lt 30000) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($avgDuration -lt 5000) { "Pass" } elseif ($avgDuration -lt 30000) { "Warning" } else { "Error" }
                Description = "Identifies the slowest running queries based on execution duration"
                Impact = "Slow queries consume server resources, cause blocking, increase wait times for other queries, and degrade user experience. They often indicate missing indexes, poor query design, or outdated statistics."
                CurrentValue = @{
                    AverageDurationMs = [math]::Round($avgDuration, 0)
                    SlowQueryCount = $slowQueries.Count
                }
                RecommendedAction = if ($avgDuration -lt 5000) { "Query performance appears acceptable" } else { "Optimize slow queries using execution plans and indexing" }
                RemediationSteps = @{
                    PowerShell = @"
# Find top slow queries by duration
Find-DbaTopResourceUsage -SqlInstance '$serverName' -Type Duration -Limit 20 | 
    Select-Object QueryHash, Duration, ExecutionCount, DatabaseName |
    Format-Table

# Get query text and execution plan
`$slowQuery = Find-DbaTopResourceUsage -SqlInstance '$serverName' -Type Duration -Limit 1
Invoke-DbaQuery -SqlInstance '$serverName' -Query `$slowQuery.QueryText

# Analyze execution plan
Get-DbaExecutionPlan -SqlInstance '$serverName' -Database 'DatabaseName'
"@
                    TSQL = @"
-- Top 20 slowest queries by average duration
SELECT TOP 20
    qs.execution_count,
    qs.total_elapsed_time / 1000 AS total_elapsed_time_ms,
    qs.total_elapsed_time / qs.execution_count / 1000 AS avg_elapsed_time_ms,
    qs.total_worker_time / 1000 AS total_cpu_time_ms,
    qs.total_logical_reads,
    SUBSTRING(st.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset
            WHEN -1 THEN DATALENGTH(st.text)
            ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2) + 1) AS query_text,
    qp.query_plan
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) qp
ORDER BY qs.total_elapsed_time / qs.execution_count DESC;

-- Find queries with high logical reads (often need indexes)
SELECT TOP 20
    qs.execution_count,
    qs.total_logical_reads,
    qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
    SUBSTRING(st.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset
            WHEN -1 THEN DATALENGTH(st.text)
            ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2) + 1) AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
ORDER BY qs.total_logical_reads DESC;
"@
                    Manual = @"
1. Identify slow queries using above scripts
2. Capture actual execution plan (Ctrl+M in SSMS, then run query)
3. Look for:
   - Table scans / Index scans on large tables
   - Missing index suggestions
   - Implicit conversions
   - Key lookups
   - Sort/Hash operations
4. Add appropriate indexes
5. Update statistics: EXEC sp_updatestats
6. Consider query rewrite if needed
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance/execution-plans",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-exec-query-stats-transact-sql"
                )
                RawData = $slowQueries | Select-Object Duration, ExecutionCount, DatabaseName, QueryHash -First 10
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Top Slow Queries"; Status = "❌ Error"; Severity = "Error"; Description = "Could not analyze queries"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 27: BLOCKING SESSIONS (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [27/$totalChecks] Checking for blocking sessions..."
        
        try {
            $blocking = Get-DbaProcess -SqlInstance $conn | Where-Object { $_.BlockingSpid -gt 0 }
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Blocking Sessions"
                Status = if ($blocking.Count -eq 0) { "✅ Pass" } elseif ($blocking.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($blocking.Count -eq 0) { "Pass" } elseif ($blocking.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Identifies sessions that are blocking other sessions"
                Impact = "Blocking occurs when one session holds locks that another session needs, causing the second session to wait. Excessive blocking leads to query timeouts, poor performance, and user complaints. Can indicate long-running transactions or missing indexes."
                CurrentValue = @{
                    BlockedSessionCount = $blocking.Count
                }
                RecommendedAction = if ($blocking.Count -eq 0) { "No blocking detected" } else { "Investigate and resolve blocking chains" }
                RemediationSteps = @{
                    PowerShell = @"
# Get current blocking
Get-DbaProcess -SqlInstance '$serverName' | 
    Where-Object { `$_.BlockingSpid -gt 0 } |
    Select-Object Spid, BlockingSpid, Login, Database, Program, Status, Command |
    Format-Table

# Get blocking tree
Get-DbaBlockingChain -SqlInstance '$serverName'

# Kill blocking session (use with caution!)
# Stop-DbaProcess -SqlInstance '$serverName' -Spid 123 -Confirm:`$false
"@
                    TSQL = @"
-- Find blocking sessions
SELECT 
    blocked.session_id AS BlockedSessionID,
    blocking.session_id AS BlockingSessionID,
    DB_NAME(blocked.database_id) AS DatabaseName,
    blocked.wait_type,
    blocked.wait_time / 1000 AS wait_time_seconds,
    blocked.wait_resource,
    blocking_text.text AS BlockingQuery,
    blocked_text.text AS BlockedQuery
FROM sys.dm_exec_requests blocked
INNER JOIN sys.dm_exec_requests blocking ON blocked.blocking_session_id = blocking.session_id
CROSS APPLY sys.dm_exec_sql_text(blocking.sql_handle) blocking_text
CROSS APPLY sys.dm_exec_sql_text(blocked.sql_handle) blocked_text
WHERE blocked.blocking_session_id > 0;

-- Get blocking chain
WITH BlockingChain AS (
    SELECT 
        session_id,
        blocking_session_id,
        wait_type,
        wait_time,
        0 AS Level
    FROM sys.dm_exec_requests
    WHERE blocking_session_id = 0
    AND session_id IN (SELECT blocking_session_id FROM sys.dm_exec_requests WHERE blocking_session_id > 0)
    
    UNION ALL
    
    SELECT 
        r.session_id,
        r.blocking_session_id,
        r.wait_type,
        r.wait_time,
        bc.Level + 1
    FROM sys.dm_exec_requests r
    INNER JOIN BlockingChain bc ON r.blocking_session_id = bc.session_id
)
SELECT * FROM BlockingChain ORDER BY Level, session_id;

-- Kill session (use carefully!)
-- KILL 123;
"@
                    Manual = @"
1. Identify head blocker (session blocking others but not blocked itself)
2. Check what the head blocker is doing
3. Options:
   - Wait for transaction to complete
   - Kill the blocking session if appropriate (KILL spid)
   - Optimize queries to reduce transaction duration
   - Add READ UNCOMMITTED or NOLOCK hints (if dirty reads acceptable)
   - Review locking strategy and isolation levels
4. Long-term: Add indexes, reduce transaction scope, use snapshot isolation
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/sql-server-transaction-locking-and-row-versioning-guide",
                    "https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/performance/understand-resolve-blocking"
                )
                RawData = $blocking | Select-Object Spid, BlockingSpid, Login, Database, Command, Status
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Blocking Sessions"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check blocking"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 28: DISK I/O LATENCY (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [28/$totalChecks] Checking disk I/O latency..."
        
        try {
            $query = @"
SELECT 
    DB_NAME(vfs.database_id) AS DatabaseName,
    mf.physical_name,
    vfs.num_of_reads,
    vfs.num_of_writes,
    CASE WHEN vfs.num_of_reads = 0 THEN 0 ELSE vfs.io_stall_read_ms / vfs.num_of_reads END AS avg_read_latency_ms,
    CASE WHEN vfs.num_of_writes = 0 THEN 0 ELSE vfs.io_stall_write_ms / vfs.num_of_writes END AS avg_write_latency_ms
FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
INNER JOIN sys.master_files mf ON vfs.database_id = mf.database_id AND vfs.file_id = mf.file_id
WHERE vfs.num_of_reads > 0 OR vfs.num_of_writes > 0
ORDER BY (CASE WHEN vfs.num_of_reads = 0 THEN 0 ELSE vfs.io_stall_read_ms / vfs.num_of_reads END) DESC;
"@
            $ioLatency = Invoke-DbaQuery -SqlInstance $conn -Query $query
            $maxReadLatency = ($ioLatency | Measure-Object -Property avg_read_latency_ms -Maximum).Maximum
            $maxWriteLatency = ($ioLatency | Measure-Object -Property avg_write_latency_ms -Maximum).Maximum
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Disk I/O Latency"
                Status = if ($maxReadLatency -lt 20 -and $maxWriteLatency -lt 20) { "✅ Pass" } elseif ($maxReadLatency -lt 50 -and $maxWriteLatency -lt 50) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($maxReadLatency -lt 20 -and $maxWriteLatency -lt 20) { "Pass" } elseif ($maxReadLatency -lt 50 -and $maxWriteLatency -lt 50) { "Warning" } else { "Error" }
                Description = "Measures disk I/O response times"
                Impact = @"
High disk latency directly impacts query performance. Acceptable latency:
- Excellent: <10ms read, <5ms write
- Good: 10-20ms read, 5-10ms write
- Fair: 20-50ms read, 10-20ms write
- Poor: >50ms read, >20ms write

High latency causes PAGEIOLATCH waits, slow queries, and poor user experience. Often indicates storage issues or memory pressure.
"@
                CurrentValue = @{
                    MaxReadLatencyMs = [math]::Round($maxReadLatency, 2)
                    MaxWriteLatencyMs = [math]::Round($maxWriteLatency, 2)
                }
                RecommendedAction = if ($maxReadLatency -lt 20 -and $maxWriteLatency -lt 20) { "Disk I/O performance is good" } else { "Investigate and improve disk I/O performance" }
                RemediationSteps = @{
                    PowerShell = @"
# Get I/O latency statistics
Get-DbaDiskSpace -ComputerName '$serverName'

# Detailed I/O stats
`$query = @'
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    file_id,
    io_stall_read_ms,
    num_of_reads,
    CASE WHEN num_of_reads = 0 THEN 0 ELSE io_stall_read_ms / num_of_reads END AS avg_read_latency_ms,
    io_stall_write_ms,
    num_of_writes,
    CASE WHEN num_of_writes = 0 THEN 0 ELSE io_stall_write_ms / num_of_writes END AS avg_write_latency_ms
FROM sys.dm_io_virtual_file_stats(NULL, NULL)
WHERE num_of_reads > 0 OR num_of_writes > 0
ORDER BY avg_read_latency_ms DESC
'@

Invoke-DbaQuery -SqlInstance '$serverName' -Query `$query | Format-Table
"@
                    TSQL = @"
-- Detailed I/O latency by database file
SELECT 
    DB_NAME(vfs.database_id) AS DatabaseName,
    mf.physical_name,
    mf.type_desc AS FileType,
    vfs.num_of_reads,
    vfs.num_of_writes,
    vfs.io_stall_read_ms,
    vfs.io_stall_write_ms,
    CASE WHEN vfs.num_of_reads = 0 THEN 0 
         ELSE vfs.io_stall_read_ms / vfs.num_of_reads END AS avg_read_latency_ms,
    CASE WHEN vfs.num_of_writes = 0 THEN 0 
         ELSE vfs.io_stall_write_ms / vfs.num_of_writes END AS avg_write_latency_ms,
    (vfs.io_stall_read_ms + vfs.io_stall_write_ms) / 
        NULLIF(vfs.num_of_reads + vfs.num_of_writes, 0) AS avg_total_latency_ms
FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
INNER JOIN sys.master_files mf ON vfs.database_id = mf.database_id AND vfs.file_id = mf.file_id
WHERE vfs.num_of_reads > 0 OR vfs.num_of_writes > 0
ORDER BY avg_total_latency_ms DESC;
"@
                    Manual = @"
1. Check storage hardware performance
2. Verify RAID configuration (RAID 10 recommended for logs, RAID 5/6/10 for data)
3. Separate data and log files on different physical disks
4. Add more RAM to reduce disk I/O via buffer cache
5. Consider SSD/NVMe storage for better performance
6. Check for disk queue length in OS performance monitor
7. Optimize queries to reduce I/O (add indexes, update statistics)
8. Review file placement - ensure files on fastest available storage
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-io-virtual-file-stats-transact-sql",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/monitor-and-enforce-best-practices-by-using-policy-based-management"
                )
                RawData = $ioLatency | Select-Object DatabaseName, physical_name, avg_read_latency_ms, avg_write_latency_ms
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Disk I/O Latency"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check I/O latency"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 29: CPU PRESSURE (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [29/$totalChecks] Checking CPU pressure..."
        
        try {
            $query = @"
SELECT 
    @@CPU_BUSY / (@@TIMETICKS / 1000.0) AS cpu_busy_time_ms,
    @@IDLE / (@@TIMETICKS / 1000.0) AS idle_time_ms,
    @@CPU_BUSY * 100.0 / (@@CPU_BUSY + @@IDLE) AS cpu_utilization_pct
"@
            $cpuStats = Invoke-DbaQuery -SqlInstance $conn -Query $query
            $cpuPct = [math]::Round($cpuStats.cpu_utilization_pct, 2)
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "CPU Pressure"
                Status = if ($cpuPct -lt 70) { "✅ Pass" } elseif ($cpuPct -lt 85) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($cpuPct -lt 70) { "Pass" } elseif ($cpuPct -lt 85) { "Warning" } else { "Error" }
                Description = "Monitors CPU utilization and pressure"
                Impact = "High CPU utilization (>80% sustained) causes slow query response, increased wait times (SOS_SCHEDULER_YIELD), and can lead to query timeouts. Often caused by poorly optimized queries, missing indexes, excessive parallelism, or insufficient CPU resources."
                CurrentValue = @{
                    CPUUtilizationPercent = $cpuPct
                }
                RecommendedAction = if ($cpuPct -lt 70) { "CPU utilization is healthy" } else { "Investigate and reduce CPU pressure" }
                RemediationSteps = @{
                    PowerShell = @"
# Get CPU-intensive queries
Find-DbaTopResourceUsage -SqlInstance '$serverName' -Type CPU -Limit 20 |
    Select-Object ExecutionCount, TotalCPU, AvgCPU, DatabaseName |
    Format-Table

# Monitor CPU over time
`$counter = Get-DbaPerformanceCounter -SqlInstance '$serverName' -Counter 'Processor:% Processor Time:_Total'
`$counter

# Get current CPU usage
Get-DbaCpuUsage -SqlInstance '$serverName'
"@
                    TSQL = @"
-- Top CPU-consuming queries
SELECT TOP 20
    qs.execution_count,
    qs.total_worker_time / 1000 AS total_cpu_time_ms,
    qs.total_worker_time / qs.execution_count / 1000 AS avg_cpu_time_ms,
    qs.total_elapsed_time / qs.execution_count / 1000 AS avg_elapsed_time_ms,
    SUBSTRING(st.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset
            WHEN -1 THEN DATALENGTH(st.text)
            ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2) + 1) AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
ORDER BY qs.total_worker_time DESC;

-- Check for SOS_SCHEDULER_YIELD waits (CPU pressure indicator)
SELECT 
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    wait_time_ms * 100.0 / SUM(wait_time_ms) OVER() AS percentage
FROM sys.dm_os_wait_stats
WHERE wait_type = 'SOS_SCHEDULER_YIELD'
AND wait_time_ms > 0;

-- Check MAXDOP setting
EXEC sp_configure 'max degree of parallelism';
"@
                    Manual = @"
1. Identify CPU-intensive queries using above scripts
2. Optimize queries:
   - Add missing indexes
   - Update statistics
   - Rewrite inefficient queries
   - Reduce data scans
3. Review MAXDOP settings (consider setting to number of physical cores)
4. Consider query hints to limit parallelism for specific queries
5. Add more CPU cores if consistently high (>80%)
6. Implement resource governor to limit CPU for specific workloads
7. Schedule heavy batch jobs during off-peak hours
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance/monitor-and-tune-for-performance",
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-max-degree-of-parallelism-server-configuration-option"
                )
                RawData = $cpuStats
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "CPU Pressure"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check CPU pressure"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 30: MEMORY PRESSURE (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [30/$totalChecks] Checking memory pressure..."
        
        try {
            $query = @"
SELECT 
    (SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page life expectancy') AS page_life_expectancy,
    (SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Lazy writes/sec' AND object_name LIKE '%Buffer Manager%') AS lazy_writes_per_sec,
    (SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page reads/sec' AND object_name LIKE '%Buffer Manager%') AS page_reads_per_sec,
    (SELECT SUM(pages_kb) FROM sys.dm_os_memory_clerks WHERE type = 'MEMORYCLERK_SQLBUFFERPOOL') / 1024 AS buffer_pool_mb
"@
            $memStats = Invoke-DbaQuery -SqlInstance $conn -Query $query
            $ple = $memStats.page_life_expectancy
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Memory Pressure"
                Status = if ($ple -gt 300) { "✅ Pass" } elseif ($ple -gt 100) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($ple -gt 300) { "Pass" } elseif ($ple -gt 100) { "Warning" } else { "Error" }
                Description = "Monitors memory pressure using Page Life Expectancy and other indicators"
                Impact = @"
Page Life Expectancy (PLE) measures how long pages stay in buffer cache before being flushed:
- Excellent: >300 seconds
- Good: 150-300 seconds
- Warning: 100-150 seconds
- Critical: <100 seconds

Low PLE indicates memory pressure, causing:
- Increased disk I/O (PAGEIOLATCH waits)
- Poor query performance
- Buffer cache thrashing
- High lazy writes
"@
                CurrentValue = @{
                    PageLifeExpectancy = $ple
                    LazyWritesPerSec = $memStats.lazy_writes_per_sec
                    PageReadsPerSec = $memStats.page_reads_per_sec
                    BufferPoolMB = [math]::Round($memStats.buffer_pool_mb, 0)
                }
                RecommendedAction = if ($ple -gt 300) { "Memory pressure is acceptable" } else { "Increase SQL Server max memory or add more RAM" }
                RemediationSteps = @{
                    PowerShell = @"
# Get memory configuration
Get-DbaMaxMemory -SqlInstance '$serverName'

# Set max memory (leave 4GB for OS on dedicated server)
`$totalMemoryGB = (Get-DbaCmObject -ComputerName '$serverName' -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
`$maxMemoryMB = (`$totalMemoryGB - 4) * 1024
Set-DbaMaxMemory -SqlInstance '$serverName' -MaxMB `$maxMemoryMB

# Monitor memory usage
Get-DbaMemoryUsage -SqlInstance '$serverName'

# Check for memory clerks consuming memory
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT TOP 20
    type,
    SUM(pages_kb) / 1024 AS size_mb
FROM sys.dm_os_memory_clerks
GROUP BY type
ORDER BY SUM(pages_kb) DESC
'@
"@
                    TSQL = @"
-- Page Life Expectancy
SELECT 
    object_name,
    counter_name,
    cntr_value AS page_life_expectancy_seconds
FROM sys.dm_os_performance_counters
WHERE counter_name = 'Page life expectancy';

-- Memory pressure indicators
SELECT 
    counter_name,
    cntr_value
FROM sys.dm_os_performance_counters
WHERE object_name LIKE '%Buffer Manager%'
AND counter_name IN (
    'Page life expectancy',
    'Lazy writes/sec',
    'Page reads/sec',
    'Page writes/sec',
    'Checkpoint pages/sec'
);

-- Memory clerks
SELECT TOP 20
    type,
    SUM(pages_kb) / 1024 AS size_mb
FROM sys.dm_os_memory_clerks
GROUP BY type
ORDER BY size_mb DESC;

-- Check max server memory
EXEC sp_configure 'max server memory';
"@
                    Manual = @"
1. Monitor PLE over time - look for trends
2. Add more RAM to the server
3. Increase max server memory setting (leave 4-6GB for OS)
4. Reduce unnecessary memory usage:
   - Review ad-hoc query plans (enable 'optimize for ad hoc workloads')
   - Clear procedure cache if needed (DBCC FREEPROCCACHE)
   - Identify memory-intensive queries
5. Optimize queries to reduce memory grants
6. Consider adding more frequent index maintenance
7. Review data compression options
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance-monitor/sql-server-buffer-manager-object",
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-memory-server-configuration-options"
                )
                RawData = $memStats
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Memory Pressure"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check memory pressure"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 31: DEADLOCK HISTORY (Performance)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [31/$totalChecks] Checking deadlock history..."
        
        try {
            # Check for deadlock extended events session
            $deadlockQuery = @"
SELECT 
    CAST(target_data AS XML) AS deadlock_xml
FROM sys.dm_xe_session_targets st
INNER JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address
WHERE s.name = 'system_health'
AND st.target_name = 'ring_buffer';
"@
            $deadlockData = Invoke-DbaQuery -SqlInstance $conn -Query $deadlockQuery
            
            # Count deadlocks from system health (simplified approach)
            $deadlockCount = 0
            if ($deadlockData -and $deadlockData.deadlock_xml) {
                $xmlData = [xml]$deadlockData.deadlock_xml
                $deadlockEvents = $xmlData.SelectNodes("//event[@name='xml_deadlock_report']")
                $deadlockCount = $deadlockEvents.Count
            }
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Deadlock History"
                Status = if ($deadlockCount -eq 0) { "✅ Pass" } elseif ($deadlockCount -lt 10) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($deadlockCount -eq 0) { "Pass" } elseif ($deadlockCount -lt 10) { "Warning" } else { "Error" }
                Description = "Analyzes deadlock occurrences from system health session"
                Impact = "Deadlocks occur when two or more transactions block each other by holding locks on resources the other transactions need. This causes SQL Server to kill one transaction (deadlock victim) to resolve the deadlock. Frequent deadlocks indicate poor application design, missing indexes, or improper locking strategies."
                CurrentValue = @{
                    DeadlockCount = $deadlockCount
                }
                RecommendedAction = if ($deadlockCount -eq 0) { "No deadlocks detected" } elseif ($deadlockCount -lt 10) { "Review and minimize deadlocks" } else { "Investigate and resolve frequent deadlocks" }
                RemediationSteps = @{
                    PowerShell = @"
# Get deadlock information from system health
`$query = @'
WITH DeadlockData AS (
    SELECT 
        CAST(target_data AS XML) AS TargetData
    FROM sys.dm_xe_session_targets st
    INNER JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address
    WHERE s.name = ''system_health''
    AND st.target_name = ''ring_buffer''
)
SELECT 
    event_data.value(''(@timestamp)[1]'', ''datetime2'') AS DeadlockTime,
    event_data.query(''.'') AS DeadlockGraph
FROM DeadlockData
CROSS APPLY TargetData.nodes(''//RingBufferTarget/event[@name=""xml_deadlock_report""]'') AS XEventData(event_data)
ORDER BY DeadlockTime DESC
'@

Invoke-DbaQuery -SqlInstance '$serverName' -Query `$query

# Enable deadlock trace flag for detailed logging
# Invoke-DbaQuery -SqlInstance '$serverName' -Query 'DBCC TRACEON(1222, -1)'
"@
                    TSQL = @"
-- Get recent deadlocks from system health
WITH DeadlockData AS (
    SELECT 
        CAST(target_data AS XML) AS TargetData
    FROM sys.dm_xe_session_targets st
    INNER JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address
    WHERE s.name = 'system_health'
    AND st.target_name = 'ring_buffer'
)
SELECT 
    event_data.value('(@timestamp)[1]', 'datetime2') AS DeadlockTime,
    event_data.query('.') AS DeadlockGraph
FROM DeadlockData
CROSS APPLY TargetData.nodes('//RingBufferTarget/event[@name="xml_deadlock_report"]') AS XEventData(event_data)
ORDER BY DeadlockTime DESC;

-- Enable deadlock trace flag (persists until restart)
DBCC TRACEON(1222, -1);

-- Create extended event session for deadlock monitoring
CREATE EVENT SESSION [DeadlockMonitoring] ON SERVER 
ADD EVENT sqlserver.xml_deadlock_report
ADD TARGET package0.event_file(SET filename=N'C:\\DeadlockMonitoring.xel')
WITH (MAX_MEMORY=4096 KB, EVENT_RETENTION_MODE=ALLOW_SINGLE_EVENT_LOSS, 
      MAX_DISPATCH_LATENCY=30 SECONDS, MAX_EVENT_SIZE=0 KB, 
      MEMORY_PARTITION_MODE=NONE, TRACK_CAUSALITY=OFF, STARTUP_STATE=ON);
GO

ALTER EVENT SESSION [DeadlockMonitoring] ON SERVER STATE = START;
GO
"@
                    Manual = @"
1. Review deadlock graphs in SSMS (look for deadlock icon in error log)
2. Identify victim and survivor transactions
3. Common solutions:
   - Access tables in same order across all transactions
   - Keep transactions short
   - Add appropriate indexes to reduce lock escalation
   - Use NOLOCK hint for read queries (if dirty reads acceptable)
   - Implement retry logic in application
   - Use snapshot isolation level
4. Enable trace flag 1222 for detailed deadlock info in error log
5. Monitor with Extended Events
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/sql-server-transaction-locking-and-row-versioning-guide",
                    "https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/performance/understand-resolve-sql-server-blocking-problems"
                )
                RawData = @{ DeadlockCount = $deadlockCount }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Deadlock History"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check deadlocks"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 32: OBSOLETE DATA TYPES (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [32/$totalChecks] Checking for obsolete data types..."
        
        try {
            $obsoleteTypes = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    c.name AS ColumnName,
    ty.name AS DataType
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
WHERE ty.name IN ('text', 'ntext', 'image', 'timestamp')
ORDER BY SchemaName, TableName, ColumnName;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $obsoleteTypes += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            Column = $_.ColumnName
                            DataType = $_.DataType
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Obsolete Data Types"
                Status = if ($obsoleteTypes.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($obsoleteTypes.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies usage of deprecated data types (text, ntext, image, timestamp)"
                Impact = "Obsolete data types like text, ntext, and image are deprecated and will be removed in future SQL Server versions. They have limitations (can't be used in variables, parameters, poor performance) and should be replaced with varchar(max), nvarchar(max), and varbinary(max). The timestamp data type is confusing (it's not a date/time) and should be rowversion."
                CurrentValue = @{
                    ObsoleteColumnCount = $obsoleteTypes.Count
                }
                RecommendedAction = if ($obsoleteTypes.Count -eq 0) { "No obsolete data types found" } else { "Migrate to modern data types: varchar(max), nvarchar(max), varbinary(max), rowversion" }
                RemediationSteps = @{
                    PowerShell = @"
# Find obsolete data types
`$query = @'
SELECT 
    DB_NAME() AS DatabaseName,
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    c.name AS ColumnName,
    ty.name AS DataType
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
WHERE ty.name IN (''text'', ''ntext'', ''image'', ''timestamp'')
'@

Invoke-DbaQuery -SqlInstance '$serverName' -Query `$query | Format-Table
"@
                    TSQL = @"
-- Find all obsolete data types
SELECT 
    DB_NAME() AS DatabaseName,
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    c.name AS ColumnName,
    ty.name AS OldDataType,
    CASE ty.name
        WHEN 'text' THEN 'VARCHAR(MAX)'
        WHEN 'ntext' THEN 'NVARCHAR(MAX)'
        WHEN 'image' THEN 'VARBINARY(MAX)'
        WHEN 'timestamp' THEN 'ROWVERSION'
    END AS RecommendedType
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
WHERE ty.name IN ('text', 'ntext', 'image', 'timestamp');

-- Example migration from text to varchar(max)
ALTER TABLE [SchemaName].[TableName]
ALTER COLUMN [ColumnName] VARCHAR(MAX);

-- Example migration from ntext to nvarchar(max)
ALTER TABLE [SchemaName].[TableName]
ALTER COLUMN [ColumnName] NVARCHAR(MAX);

-- Example migration from image to varbinary(max)
ALTER TABLE [SchemaName].[TableName]
ALTER COLUMN [ColumnName] VARBINARY(MAX);

-- Example migration from timestamp to rowversion
ALTER TABLE [SchemaName].[TableName]
ALTER COLUMN [ColumnName] ROWVERSION;
"@
                    Manual = @"
1. Test migration in non-production environment first
2. Check for dependencies (views, stored procedures, triggers)
3. Create backup before migration
4. Migration steps:
   - text → VARCHAR(MAX)
   - ntext → NVARCHAR(MAX)
   - image → VARBINARY(MAX)
   - timestamp → ROWVERSION
5. Update application code to handle new data types
6. Test thoroughly before production deployment
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/data-types/ntext-text-and-image-transact-sql",
                    "https://learn.microsoft.com/en-us/sql/database-engine/deprecated-database-engine-features-in-sql-server-2016"
                )
                RawData = $obsoleteTypes | Select-Object Database, Schema, Table, Column, DataType
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Obsolete Data Types"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check data types"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 33: ERROR LOG ANALYSIS (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [33/$totalChecks] Analyzing error log..."
        
        try {
            # Get recent error log entries (last 24 hours)
            $errorLog = Get-DbaErrorLog -SqlInstance $conn -After (Get-Date).AddDays(-1) | 
                Where-Object { $_.Text -match 'error|failed|failure|warning' -and $_.Text -notmatch 'without errors' }
            
            $criticalErrors = $errorLog | Where-Object { $_.Text -match 'severe|critical|fatal|stack dump' }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Error Log Analysis"
                Status = if ($criticalErrors.Count -eq 0) { "✅ Pass" } elseif ($criticalErrors.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($criticalErrors.Count -eq 0) { "Pass" } elseif ($criticalErrors.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Reviews SQL Server error log for critical errors and warnings in last 24 hours"
                Impact = "Error logs contain important information about server health, failed logins, corruption, out-of-memory conditions, and other issues. Critical errors can indicate serious problems requiring immediate attention. Regular monitoring prevents small issues from becoming major outages."
                CurrentValue = @{
                    TotalErrorsLast24h = $errorLog.Count
                    CriticalErrorCount = $criticalErrors.Count
                }
                RecommendedAction = if ($criticalErrors.Count -eq 0) { "No critical errors in last 24 hours" } else { "Review and address critical errors immediately" }
                RemediationSteps = @{
                    PowerShell = @"
# Get error log entries from last 24 hours
Get-DbaErrorLog -SqlInstance '$serverName' -After (Get-Date).AddDays(-1) |
    Where-Object { `$_.Text -match 'error|failed|failure' } |
    Select-Object LogDate, Source, Text |
    Format-Table -AutoSize

# Get login failures (potential security issue)
Get-DbaErrorLog -SqlInstance '$serverName' -After (Get-Date).AddDays(-1) |
    Where-Object { `$_.Text -match 'Login failed' } |
    Select-Object LogDate, Text

# Search for specific error
Get-DbaErrorLog -SqlInstance '$serverName' -Text 'corruption'

# Cycle error log (creates new log file)
Invoke-DbaQuery -SqlInstance '$serverName' -Query 'EXEC sp_cycle_errorlog'
"@
                    TSQL = @"
-- Read current error log
EXEC sp_readerrorlog 0, 1;

-- Search for failed logins
EXEC sp_readerrorlog 0, 1, 'Login failed';

-- Search for severity 17+ errors
EXEC sp_readerrorlog 0, 1, 'Severity: 17';
EXEC sp_readerrorlog 0, 1, 'Severity: 18';
EXEC sp_readerrorlog 0, 1, 'Severity: 19';
EXEC sp_readerrorlog 0, 1, 'Severity: 20';

-- Cycle error log
EXEC sp_cycle_errorlog;

-- Configure number of error log files to keep
EXEC xp_instance_regwrite 
    N'HKEY_LOCAL_MACHINE', 
    N'Software\\Microsoft\\MSSQLServer\\MSSQLServer',
    N'NumErrorLogs', REG_DWORD, 30;
"@
                    Manual = @"
1. Review error log daily for critical issues
2. Common items to look for:
   - Failed login attempts (security)
   - I/O errors (hardware issues)
   - Out of memory errors
   - Database corruption warnings
   - SQL Server service restarts
   - Backup failures
3. Set up SQL Agent alerts for critical errors
4. Configure error log to keep more history (default is 6)
5. Consider third-party monitoring tools
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance/view-the-sql-server-error-log-sql-server-management-studio",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors"
                )
                RawData = $criticalErrors | Select-Object LogDate, Source, Text -First 20
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Error Log Analysis"; Status = "❌ Error"; Severity = "Error"; Description = "Could not read error log"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 34: FAILED JOBS (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [34/$totalChecks] Checking for failed jobs..."
        
        try {
            # Get failed jobs in last 24 hours
            $failedJobs = Get-DbaAgentJobHistory -SqlInstance $conn -StartDate (Get-Date).AddDays(-1) |
                Where-Object { $_.Status -eq 'Failed' }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Failed Jobs"
                Status = if ($failedJobs.Count -eq 0) { "✅ Pass" } elseif ($failedJobs.Count -lt 3) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($failedJobs.Count -eq 0) { "Pass" } elseif ($failedJobs.Count -lt 3) { "Warning" } else { "Error" }
                Description = "Identifies SQL Agent jobs that have failed in the last 24 hours"
                Impact = "Failed jobs can indicate backup failures, maintenance issues, ETL problems, or other critical tasks not completing. This can lead to data loss, compliance issues, performance degradation, and business process disruptions."
                CurrentValue = @{
                    FailedJobCount = $failedJobs.Count
                }
                RecommendedAction = if ($failedJobs.Count -eq 0) { "No failed jobs in last 24 hours" } else { "Review and fix failed job errors" }
                RemediationSteps = @{
                    PowerShell = @"
# Get failed jobs in last 24 hours
Get-DbaAgentJobHistory -SqlInstance '$serverName' -StartDate (Get-Date).AddDays(-1) |
    Where-Object { `$_.Status -eq 'Failed' } |
    Select-Object RunDate, JobName, StepName, Message |
    Format-Table -AutoSize

# Get job details
Get-DbaAgentJob -SqlInstance '$serverName' | 
    Select-Object Name, Enabled, LastRunDate, LastRunOutcome |
    Where-Object { `$_.LastRunOutcome -eq 'Failed' }

# Run specific job manually
Start-DbaAgentJob -SqlInstance '$serverName' -Job 'JobName'
"@
                    TSQL = @"
-- Get failed jobs in last 24 hours
SELECT 
    j.name AS JobName,
    h.step_name AS StepName,
    msdb.dbo.agent_datetime(h.run_date, h.run_time) AS RunDateTime,
    h.run_duration,
    CASE h.run_status
        WHEN 0 THEN 'Failed'
        WHEN 1 THEN 'Succeeded'
        WHEN 2 THEN 'Retry'
        WHEN 3 THEN 'Canceled'
        WHEN 4 THEN 'In Progress'
    END AS Status,
    h.message
FROM msdb.dbo.sysjobhistory h
INNER JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
WHERE h.run_status = 0  -- Failed
AND msdb.dbo.agent_datetime(h.run_date, h.run_time) >= DATEADD(HOUR, -24, GETDATE())
ORDER BY RunDateTime DESC;

-- Get all jobs with last run status
SELECT 
    j.name AS JobName,
    j.enabled,
    CASE ja.last_run_outcome
        WHEN 0 THEN 'Failed'
        WHEN 1 THEN 'Succeeded'
        WHEN 3 THEN 'Canceled'
        WHEN 5 THEN 'Unknown'
    END AS LastRunOutcome,
    msdb.dbo.agent_datetime(ja.last_run_date, ja.last_run_time) AS LastRunDateTime
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobactivity ja ON j.job_id = ja.job_id
WHERE ja.last_run_outcome = 0
OR ja.last_run_outcome IS NULL;
"@
                    Manual = @"
1. Review failed job error messages
2. Common failure reasons:
   - Permission issues
   - Disk space full
   - Network connectivity problems
   - Database offline/unavailable
   - Lock timeouts
3. Fix underlying issue
4. Re-run job manually to verify fix
5. Set up job failure notifications via Database Mail
6. Review job history regularly
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/ssms/agent/view-job-activity",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-tables/dbo-sysjobhistory-transact-sql"
                )
                RawData = $failedJobs | Select-Object RunDate, JobName, StepName, Message -First 10
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Failed Jobs"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check jobs"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 35: AG SYNCHRONIZATION HEALTH (High Availability)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [35/$totalChecks] Checking AG synchronization health..."
        
        try {
            # Check if server has availability groups
            $agReplicas = Get-DbaAgReplica -SqlInstance $conn
            
            if ($agReplicas) {
                $syncIssues = $agReplicas | Where-Object { 
                    $_.SynchronizationHealth -ne 'Healthy' -or 
                    $_.ConnectedState -ne 'Connected' -or
                    $_.Role -eq 'Unknown'
                }
                
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Synchronization Health"
                    Status = if ($syncIssues.Count -eq 0) { "✅ Pass" } else { "❌ Error" }
                    Severity = if ($syncIssues.Count -eq 0) { "Pass" } else { "Error" }
                    Description = "Monitors Always On Availability Group replica synchronization health"
                    Impact = "Unhealthy AG synchronization means secondary replicas are not keeping up with the primary, which can lead to data loss during failover, increased RTO/RPO, and inability to use secondaries for read-only workloads. Critical for high availability and disaster recovery."
                    CurrentValue = @{
                        TotalReplicas = $agReplicas.Count
                        UnhealthyReplicas = $syncIssues.Count
                        ReplicaDetails = ($agReplicas | Select-Object Name, Role, SynchronizationHealth, ConnectedState)
                    }
                    RecommendedAction = if ($syncIssues.Count -eq 0) { "All AG replicas are healthy" } else { "Investigate and resolve AG synchronization issues immediately" }
                    RemediationSteps = @{
                        PowerShell = @"
# Get AG replica health
Get-DbaAgReplica -SqlInstance '$serverName' |
    Select-Object AvailabilityGroup, Name, Role, SynchronizationHealth, ConnectedState |
    Format-Table

# Get AG database synchronization state
Get-DbaAgDatabase -SqlInstance '$serverName' |
    Select-Object AvailabilityGroup, DatabaseName, SynchronizationState, SynchronizationHealth |
    Format-Table

# Check data latency
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    ar.replica_server_name,
    db_name(drs.database_id) AS DatabaseName,
    drs.synchronization_state_desc,
    drs.synchronization_health_desc,
    drs.log_send_queue_size,
    drs.redo_queue_size
FROM sys.dm_hadr_database_replica_states drs
INNER JOIN sys.availability_replicas ar ON drs.replica_id = ar.replica_id
ORDER BY drs.log_send_queue_size DESC
'@
"@
                        TSQL = @"
-- AG replica health overview
SELECT 
    ar.replica_server_name,
    ars.role_desc,
    ars.connected_state_desc,
    ars.synchronization_health_desc,
    ars.last_connect_error_description
FROM sys.dm_hadr_availability_replica_states ars
INNER JOIN sys.availability_replicas ar ON ars.replica_id = ar.replica_id;

-- AG database synchronization details
SELECT 
    ar.replica_server_name,
    DB_NAME(drs.database_id) AS DatabaseName,
    drs.synchronization_state_desc,
    drs.synchronization_health_desc,
    drs.log_send_queue_size AS LogSendQueueKB,
    drs.log_send_rate AS LogSendRateKB_Per_Sec,
    drs.redo_queue_size AS RedoQueueKB,
    drs.redo_rate AS RedoRateKB_Per_Sec,
    drs.last_commit_time
FROM sys.dm_hadr_database_replica_states drs
INNER JOIN sys.availability_replicas ar ON drs.replica_id = ar.replica_id
ORDER BY drs.log_send_queue_size DESC;

-- Check for suspended data movement
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    is_suspended,
    suspend_reason_desc
FROM sys.dm_hadr_database_replica_states
WHERE is_suspended = 1;
"@
                        Manual = @"
1. Check network connectivity between replicas
2. Verify endpoint certificates are valid
3. Check if data movement is suspended (resume if needed)
4. Review log send/redo queue sizes:
   - High log send queue: Network or secondary performance issue
   - High redo queue: Secondary can't keep up with redo
5. Consider:
   - Increase network bandwidth
   - Improve secondary server performance
   - Change to asynchronous mode if synchronous is impacting primary
6. Resume suspended databases: ALTER DATABASE [DB] SET HADR RESUME
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/monitor-availability-groups-transact-sql",
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/troubleshoot-availability-group-exceeded-rpo"
                    )
                    RawData = $agReplicas | Select-Object Name, Role, AvailabilityGroup, SynchronizationHealth, ConnectedState
                }
            } else {
                # No AGs configured - skip check
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Synchronization Health"
                    Status = "ℹ️ Info"
                    Severity = "Info"
                    Description = "No Availability Groups configured on this server"
                    Impact = "N/A"
                    CurrentValue = @{ AGCount = 0 }
                    RecommendedAction = "No action needed - server is not part of an Availability Group"
                    RemediationSteps = @{}
                    Documentation = @()
                    RawData = @{}
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "AG Synchronization Health"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check AG health"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 36: AG DATA LATENCY (High Availability)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [36/$totalChecks] Checking AG data latency..."
        
        try {
            $agDatabases = Get-DbaAgDatabase -SqlInstance $conn
            
            if ($agDatabases) {
                # Check for high latency (log send queue or redo queue)
                $highLatency = $agDatabases | Where-Object {
                    $_.LogSendQueueSize -gt 10240 -or  # > 10MB
                    $_.RedoQueueSize -gt 10240          # > 10MB
                }
                
                $maxLogSendQueue = ($agDatabases | Measure-Object -Property LogSendQueueSize -Maximum).Maximum
                $maxRedoQueue = ($agDatabases | Measure-Object -Property RedoQueueSize -Maximum).Maximum
                
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Data Latency"
                    Status = if ($highLatency.Count -eq 0) { "✅ Pass" } elseif ($highLatency.Count -lt 3) { "⚠️ Warning" } else { "❌ Error" }
                    Severity = if ($highLatency.Count -eq 0) { "Pass" } elseif ($highLatency.Count -lt 3) { "Warning" } else { "Error" }
                    Description = "Measures data replication latency in Availability Groups"
                    Impact = @"
High AG data latency indicates secondaries are falling behind the primary:
- Log Send Queue: Data waiting to be sent from primary to secondary (network or primary bottleneck)
- Redo Queue: Data waiting to be applied on secondary (secondary performance bottleneck)

High latency increases RPO (potential data loss on failover), prevents readable secondaries from having current data, and indicates the AG may not meet SLA requirements.
"@
                    CurrentValue = @{
                        DatabasesWithHighLatency = $highLatency.Count
                        MaxLogSendQueueKB = [math]::Round($maxLogSendQueue, 0)
                        MaxRedoQueueKB = [math]::Round($maxRedoQueue, 0)
                    }
                    RecommendedAction = if ($highLatency.Count -eq 0) { "AG latency is acceptable" } else { "Investigate and reduce AG replication latency" }
                    RemediationSteps = @{
                        PowerShell = @"
# Check AG latency details
Get-DbaAgDatabase -SqlInstance '$serverName' |
    Select-Object AvailabilityGroup, DatabaseName, ReplicaServerName, 
                  LogSendQueueSize, RedoQueueSize, LogSendRate, RedoRate |
    Where-Object { `$_.LogSendQueueSize -gt 1024 -or `$_.RedoQueueSize -gt 1024 } |
    Format-Table

# Monitor latency over time
while (`$true) {
    Get-DbaAgDatabase -SqlInstance '$serverName' |
        Select-Object DatabaseName, ReplicaServerName, LogSendQueueSize, RedoQueueSize |
        Format-Table
    Start-Sleep -Seconds 10
}
"@
                        TSQL = @"
-- Detailed AG latency monitoring
SELECT 
    ag.name AS AvailabilityGroup,
    ar.replica_server_name AS ReplicaServer,
    DB_NAME(drs.database_id) AS DatabaseName,
    drs.synchronization_state_desc AS SyncState,
    drs.log_send_queue_size AS LogSendQueueKB,
    drs.log_send_rate AS LogSendRateKB_Sec,
    CASE 
        WHEN drs.log_send_rate > 0 
        THEN drs.log_send_queue_size / drs.log_send_rate 
        ELSE NULL 
    END AS EstimatedLogSendCatchupTime_Sec,
    drs.redo_queue_size AS RedoQueueKB,
    drs.redo_rate AS RedoRateKB_Sec,
    CASE 
        WHEN drs.redo_rate > 0 
        THEN drs.redo_queue_size / drs.redo_rate 
        ELSE NULL 
    END AS EstimatedRedoCatchupTime_Sec,
    drs.last_commit_time,
    drs.last_hardened_time
FROM sys.dm_hadr_database_replica_states drs
INNER JOIN sys.availability_replicas ar ON drs.replica_id = ar.replica_id
INNER JOIN sys.availability_groups ag ON ar.group_id = ag.group_id
WHERE drs.is_local = 0  -- Remote replicas only
ORDER BY drs.log_send_queue_size DESC;

-- Check estimated data loss (seconds)
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    DATEDIFF(SECOND, last_commit_time, GETDATE()) AS SecondsSinceLastCommit,
    log_send_queue_size AS LogSendQueueKB
FROM sys.dm_hadr_database_replica_states
WHERE is_local = 0
AND log_send_queue_size > 0;
"@
                        Manual = @"
1. Identify bottleneck:
   - High log send queue: Network or primary disk issue
   - High redo queue: Secondary CPU/disk/memory issue
2. For log send queue issues:
   - Check network bandwidth and latency between replicas
   - Verify primary server isn't overloaded
   - Consider compression on AG endpoint
3. For redo queue issues:
   - Improve secondary server performance (faster CPU/disk)
   - Reduce transaction log activity on primary
   - Consider changing to async mode for distant replicas
4. Monitor trends - spikes vs. sustained high latency
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/monitor-performance-for-always-on-availability-groups",
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/troubleshoot-availability-group-exceeded-rpo"
                    )
                    RawData = $agDatabases | Select-Object AvailabilityGroup, DatabaseName, ReplicaServerName, LogSendQueueSize, RedoQueueSize
                }
            } else {
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Data Latency"
                    Status = "ℹ️ Info"
                    Severity = "Info"
                    Description = "No Availability Groups configured"
                    Impact = "N/A"
                    CurrentValue = @{ AGCount = 0 }
                    RecommendedAction = "No action needed"
                    RemediationSteps = @{}
                    Documentation = @()
                    RawData = @{}
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "AG Data Latency"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check AG latency"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 37: AG FAILOVER READINESS (High Availability)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [37/$totalChecks] Checking AG failover readiness..."
        
        try {
            $agReplicas = Get-DbaAgReplica -SqlInstance $conn
            
            if ($agReplicas) {
                # Check for replicas that cannot be automatic failover targets
                $notReadyForFailover = $agReplicas | Where-Object {
                    $_.FailoverMode -ne 'Automatic' -or
                    $_.AvailabilityMode -ne 'SynchronousCommit' -or
                    $_.SynchronizationHealth -ne 'Healthy'
                }
                
                $automaticFailoverReplicas = $agReplicas | Where-Object { $_.FailoverMode -eq 'Automatic' }
                
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Failover Readiness"
                    Status = if ($automaticFailoverReplicas.Count -ge 1 -and $notReadyForFailover.Count -eq 0) { "✅ Pass" } elseif ($automaticFailoverReplicas.Count -ge 1) { "⚠️ Warning" } else { "❌ Error" }
                    Severity = if ($automaticFailoverReplicas.Count -ge 1 -and $notReadyForFailover.Count -eq 0) { "Pass" } elseif ($automaticFailoverReplicas.Count -ge 1) { "Warning" } else { "Error" }
                    Description = "Evaluates AG replicas' readiness for automatic failover"
                    Impact = "Automatic failover requires at least one secondary replica configured with synchronous-commit mode and automatic failover mode, and it must be healthy. Without proper failover configuration, the AG cannot automatically recover from primary failure, resulting in downtime until manual intervention."
                    CurrentValue = @{
                        TotalReplicas = $agReplicas.Count
                        AutomaticFailoverReplicas = $automaticFailoverReplicas.Count
                        ReplicasNotReady = $notReadyForFailover.Count
                    }
                    RecommendedAction = if ($automaticFailoverReplicas.Count -ge 1 -and $notReadyForFailover.Count -eq 0) { "AG failover configuration is correct" } else { "Configure at least one secondary for automatic failover" }
                    RemediationSteps = @{
                        PowerShell = @"
# Check failover configuration
Get-DbaAgReplica -SqlInstance '$serverName' |
    Select-Object AvailabilityGroup, Name, Role, AvailabilityMode, FailoverMode, SynchronizationHealth |
    Format-Table

# Set replica to automatic failover
Set-DbaAgReplica -SqlInstance '$serverName' -Replica 'ReplicaName' `
    -AvailabilityMode SynchronousCommit `
    -FailoverMode Automatic
"@
                        TSQL = @"
-- Check current AG configuration
SELECT 
    ag.name AS AvailabilityGroup,
    ar.replica_server_name AS ReplicaServer,
    ar.availability_mode_desc AS AvailabilityMode,
    ar.failover_mode_desc AS FailoverMode,
    ars.role_desc AS CurrentRole,
    ars.synchronization_health_desc AS SyncHealth
FROM sys.availability_replicas ar
INNER JOIN sys.dm_hadr_availability_replica_states ars ON ar.replica_id = ars.replica_id
INNER JOIN sys.availability_groups ag ON ar.group_id = ag.group_id
ORDER BY ag.name, ar.replica_server_name;

-- Configure replica for automatic failover
ALTER AVAILABILITY GROUP [AGName]
MODIFY REPLICA ON N'ReplicaServerName'
WITH (
    AVAILABILITY_MODE = SYNCHRONOUS_COMMIT,
    FAILOVER_MODE = AUTOMATIC
);

-- Test manual failover (does not actually fail over)
ALTER AVAILABILITY GROUP [AGName] FAILOVER;
"@
                        Manual = @"
1. Verify at least one secondary replica is configured:
   - Availability Mode: Synchronous Commit
   - Failover Mode: Automatic
   - Synchronization Health: Healthy
2. For proper HA, configure 2 automatic failover replicas
3. Test failover regularly during maintenance windows
4. Document failover procedures
5. Ensure Windows Server Failover Cluster quorum is healthy
6. Verify network connectivity between all replicas
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/failover-and-failover-modes-always-on-availability-groups",
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/perform-a-planned-manual-failover-of-an-availability-group-sql-server"
                    )
                    RawData = $agReplicas | Select-Object Name, AvailabilityGroup, AvailabilityMode, FailoverMode, SynchronizationHealth
                }
            } else {
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Failover Readiness"
                    Status = "ℹ️ Info"
                    Severity = "Info"
                    Description = "No Availability Groups configured"
                    Impact = "N/A"
                    CurrentValue = @{ AGCount = 0 }
                    RecommendedAction = "No action needed"
                    RemediationSteps = @{}
                    Documentation = @()
                    RawData = @{}
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "AG Failover Readiness"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check failover readiness"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 38: AG LISTENER CONFIGURATION (High Availability)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [38/$totalChecks] Checking AG listener configuration..."
        
        try {
            $agListeners = Get-DbaAgListener -SqlInstance $conn
            $availabilityGroups = Get-DbaAvailabilityGroup -SqlInstance $conn
            
            if ($availabilityGroups) {
                # Check if each AG has a listener
                $agsWithoutListener = $availabilityGroups | Where-Object {
                    $agName = $_.Name
                    -not ($agListeners | Where-Object { $_.AvailabilityGroup -eq $agName })
                }
                
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Listener Configuration"
                    Status = if ($agsWithoutListener.Count -eq 0 -and $agListeners.Count -gt 0) { "✅ Pass" } elseif ($agListeners.Count -gt 0) { "⚠️ Warning" } else { "❌ Error" }
                    Severity = if ($agsWithoutListener.Count -eq 0 -and $agListeners.Count -gt 0) { "Pass" } elseif ($agListeners.Count -gt 0) { "Warning" } else { "Error" }
                    Description = "Verifies that Availability Group listeners are properly configured"
                    Impact = "AG listeners provide a virtual network name that client applications connect to, allowing transparent failover. Without listeners, applications must manually update connection strings when a failover occurs. Listeners are essential for seamless HA."
                    CurrentValue = @{
                        TotalAvailabilityGroups = $availabilityGroups.Count
                        ConfiguredListeners = $agListeners.Count
                        AGsWithoutListener = $agsWithoutListener.Count
                    }
                    RecommendedAction = if ($agsWithoutListener.Count -eq 0 -and $agListeners.Count -gt 0) { "All AGs have listeners configured" } else { "Configure listeners for all Availability Groups" }
                    RemediationSteps = @{
                        PowerShell = @"
# List all AG listeners
Get-DbaAgListener -SqlInstance '$serverName' |
    Select-Object AvailabilityGroup, Name, PortNumber, IpAddress |
    Format-Table

# Create a new listener
New-DbaAgListener -SqlInstance '$serverName' `
    -AvailabilityGroup 'AGName' `
    -Name 'AGListenerName' `
    -IPAddress '10.0.0.100' `
    -SubnetMask '255.255.255.0' `
    -Port 1433

# Test listener connectivity
Test-DbaConnection -SqlInstance 'AGListenerName'
"@
                        TSQL = @"
-- View all AG listeners
SELECT 
    ag.name AS AvailabilityGroup,
    agl.dns_name AS ListenerName,
    agl.port AS Port,
    aglip.ip_address AS IPAddress,
    aglip.ip_subnet_mask AS SubnetMask
FROM sys.availability_group_listeners agl
INNER JOIN sys.availability_groups ag ON agl.group_id = ag.group_id
INNER JOIN sys.availability_group_listener_ip_addresses aglip ON agl.listener_id = aglip.listener_id
ORDER BY ag.name;

-- Create a new listener (run on primary replica)
ALTER AVAILABILITY GROUP [AGName]
ADD LISTENER N'AGListenerName' (
    WITH IP ((N'10.0.0.100', N'255.255.255.0')),
    PORT = 1433
);

-- Test connection to listener
SELECT @@SERVERNAME AS CurrentServer;
"@
                        Manual = @"
1. Plan listener configuration:
   - Unique DNS name
   - Static IP address(es) on AG subnet(s)
   - Port (typically 1433)
2. Create listener using PowerShell or T-SQL
3. Configure DNS to resolve listener name
4. Update client connection strings to use listener name
5. Test failover to ensure listener redirects properly
6. Consider read-only routing for read-scale scenarios
7. Document listener configuration
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/create-or-configure-an-availability-group-listener-sql-server",
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/listeners-client-connectivity-application-failover"
                    )
                    RawData = $agListeners | Select-Object AvailabilityGroup, Name, PortNumber, IpAddress
                }
            } else {
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "AG Listener Configuration"
                    Status = "ℹ️ Info"
                    Severity = "Info"
                    Description = "No Availability Groups configured"
                    Impact = "N/A"
                    CurrentValue = @{ AGCount = 0 }
                    RecommendedAction = "No action needed"
                    RemediationSteps = @{}
                    Documentation = @()
                    RawData = @{}
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "AG Listener Configuration"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check listeners"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 39: SMALL DATA TYPES (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [39/$totalChecks] Checking for inefficient small data types..."
        
        try {
            $smallTypes = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    c.name AS ColumnName,
    ty.name AS DataType,
    CASE ty.name
        WHEN 'tinyint' THEN 'SMALLINT or INT'
        WHEN 'char' THEN 'VARCHAR'
        WHEN 'nchar' THEN 'NVARCHAR'
    END AS SuggestedType
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
WHERE ty.name IN ('tinyint', 'char', 'nchar')
AND c.max_length <= 10
ORDER BY SchemaName, TableName, ColumnName;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $smallTypes += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            Column = $_.ColumnName
                            DataType = $_.DataType
                            Suggested = $_.SuggestedType
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Small Data Types"
                Status = if ($smallTypes.Count -eq 0) { "✅ Pass" } elseif ($smallTypes.Count -lt 20) { "ℹ️ Info" } else { "⚠️ Warning" }
                Severity = if ($smallTypes.Count -eq 0) { "Pass" } else { "Info" }
                Description = "Identifies potentially inefficient use of small fixed-width data types"
                Impact = @"
Small data types like TINYINT, CHAR, and NCHAR can cause issues:
- TINYINT: Limited range (0-255), often insufficient and requires ALTER TABLE later
- CHAR/NCHAR: Fixed width means wasted space with padding, poor for variable-length data
- Small fixed types can cause more ALTER TABLE operations as business grows

This is informational - sometimes these types are appropriate, but review usage.
"@
                CurrentValue = @{
                    SmallTypeColumnCount = $smallTypes.Count
                }
                RecommendedAction = if ($smallTypes.Count -eq 0) { "No concerning small data types found" } else { "Review small data types for appropriateness" }
                RemediationSteps = @{
                    PowerShell = @"
# Find small data types
`$query = @'
SELECT 
    DB_NAME() AS DatabaseName,
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    c.name AS ColumnName,
    ty.name AS DataType
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
WHERE ty.name IN (''tinyint'', ''char'', ''nchar'')
'@

Invoke-DbaQuery -SqlInstance '$serverName' -Query `$query | Format-Table
"@
                    TSQL = @"
-- Review usage of small data types
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    c.name AS ColumnName,
    ty.name AS CurrentDataType,
    c.max_length,
    CASE ty.name
        WHEN 'tinyint' THEN 'Consider SMALLINT or INT if range may grow'
        WHEN 'char' THEN 'Consider VARCHAR to avoid padding waste'
        WHEN 'nchar' THEN 'Consider NVARCHAR to avoid padding waste'
    END AS Recommendation
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
WHERE ty.name IN ('tinyint', 'char', 'nchar');

-- Example: Change TINYINT to SMALLINT
ALTER TABLE [SchemaName].[TableName]
ALTER COLUMN [ColumnName] SMALLINT;

-- Example: Change CHAR to VARCHAR
ALTER TABLE [SchemaName].[TableName]
ALTER COLUMN [ColumnName] VARCHAR(50);
"@
                    Manual = @"
1. Review each flagged column
2. Consider:
   - TINYINT: Is 0-255 range sufficient long-term?
   - CHAR/NCHAR: Is data truly fixed-width, or is VARCHAR better?
3. For status codes, TINYINT might be appropriate
4. For country codes, CHAR(2) is fine (ISO standard)
5. Change only when beneficial - don't change for the sake of it
6. Test in dev environment before production changes
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/data-types/data-types-transact-sql",
                    "https://learn.microsoft.com/en-us/sql/t-sql/data-types/int-bigint-smallint-and-tinyint-transact-sql"
                )
                RawData = $smallTypes | Select-Object Database, Schema, Table, Column, DataType, Suggested
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Small Data Types"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check data types"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 40: DATABASE COMPATIBILITY LEVEL (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [40/$totalChecks] Checking database compatibility levels..."
        
        try {
            $serverVersion = (Get-DbaDbEngineEdition -SqlInstance $conn).Version
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            $outdatedCompatibility = $databases | Where-Object {
                $_.Compatibility -lt $serverVersion
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Database Compatibility Level"
                Status = if ($outdatedCompatibility.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($outdatedCompatibility.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies databases are using current SQL Server compatibility level"
                Impact = "Databases with outdated compatibility levels cannot use newer query optimizer improvements, features, or performance enhancements. This can result in suboptimal query plans and missed performance gains. However, upgrading compatibility level can change query behavior, so test thoroughly."
                CurrentValue = @{
                    ServerVersion = $serverVersion
                    DatabasesWithOldCompatibility = $outdatedCompatibility.Count
                }
                RecommendedAction = if ($outdatedCompatibility.Count -eq 0) { "All databases use current compatibility level" } else { "Test and upgrade database compatibility levels" }
                RemediationSteps = @{
                    PowerShell = @"
# Check compatibility levels
Get-DbaDatabase -SqlInstance '$serverName' |
    Select-Object Name, Compatibility, Status |
    Format-Table

# Upgrade database compatibility (test first!)
Set-DbaDbCompatibility -SqlInstance '$serverName' -Database 'DatabaseName' -CompatibilityLevel 150

# Use Query Store to monitor after compatibility upgrade
Set-DbaDbQueryStoreOption -SqlInstance '$serverName' -Database 'DatabaseName' -State ReadWrite
"@
                    TSQL = @"
-- Check current compatibility levels
SELECT 
    name AS DatabaseName,
    compatibility_level AS CompatibilityLevel,
    CASE compatibility_level
        WHEN 80 THEN 'SQL Server 2000'
        WHEN 90 THEN 'SQL Server 2005'
        WHEN 100 THEN 'SQL Server 2008/2008R2'
        WHEN 110 THEN 'SQL Server 2012'
        WHEN 120 THEN 'SQL Server 2014'
        WHEN 130 THEN 'SQL Server 2016'
        WHEN 140 THEN 'SQL Server 2017'
        WHEN 150 THEN 'SQL Server 2019'
        WHEN 160 THEN 'SQL Server 2022'
    END AS CompatibilityVersion
FROM sys.databases
WHERE database_id > 4
ORDER BY compatibility_level, name;

-- Upgrade compatibility level (test in dev first!)
ALTER DATABASE [DatabaseName] SET COMPATIBILITY_LEVEL = 150;

-- Enable Query Store before upgrade (recommended)
ALTER DATABASE [DatabaseName] SET QUERY_STORE = ON;
ALTER DATABASE [DatabaseName] SET QUERY_STORE (OPERATION_MODE = READ_WRITE);

-- After upgrade, monitor for regression
-- Use Query Store to compare pre/post performance
"@
                    Manual = @"
1. IMPORTANT: Test compatibility upgrade in non-production first
2. Enable Query Store before upgrading compatibility
3. Upgrade procedure:
   a. Enable Query Store on database
   b. Run workload to establish baseline
   c. Upgrade compatibility level
   d. Monitor Query Store for regressions
   e. Use Query Store hints to force old plans if needed
4. Benefits of newer compatibility:
   - Intelligent Query Processing features
   - Better cardinality estimator
   - Adaptive query processing
   - Scalar UDF inlining
5. Test for 1-2 weeks before declaring success
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-compatibility-level",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance/intelligent-query-processing"
                )
                RawData = $outdatedCompatibility | Select-Object Name, Compatibility, Status
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Database Compatibility Level"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check compatibility"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 41: SERVER ROLE MEMBERSHIP (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [41/$totalChecks] Checking server role membership..."
        
        try {
            # Get members of privileged server roles
            $query = @"
SELECT 
    r.name AS RoleName,
    m.name AS MemberName,
    m.type_desc AS MemberType
FROM sys.server_role_members srm
INNER JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
INNER JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id
WHERE r.name IN ('sysadmin', 'securityadmin', 'serveradmin', 'setupadmin', 'processadmin')
AND m.name NOT IN ('sa', '##MS_PolicyEventProcessingLogin##')
ORDER BY r.name, m.name;
"@
            $roleMembers = Invoke-DbaQuery -SqlInstance $conn -Query $query
            $sysadminMembers = $roleMembers | Where-Object { $_.RoleName -eq 'sysadmin' }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Server Role Membership"
                Status = if ($sysadminMembers.Count -le 3) { "✅ Pass" } elseif ($sysadminMembers.Count -le 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($sysadminMembers.Count -le 3) { "Pass" } elseif ($sysadminMembers.Count -le 5) { "Warning" } else { "Error" }
                Description = "Reviews membership in privileged server roles"
                Impact = "Excessive membership in privileged server roles (especially sysadmin) violates principle of least privilege and creates security risk. Sysadmin role has unrestricted access to all SQL Server resources. Limit membership to only essential accounts and use more granular permissions when possible."
                CurrentValue = @{
                    TotalPrivilegedMembers = $roleMembers.Count
                    SysadminMembers = $sysadminMembers.Count
                }
                RecommendedAction = if ($sysadminMembers.Count -le 3) { "Server role membership appears reasonable" } else { "Review and reduce privileged role memberships" }
                RemediationSteps = @{
                    PowerShell = @"
# List all server role members
Get-DbaServerRoleMember -SqlInstance '$serverName' |
    Where-Object { `$_.Role -in @('sysadmin','securityadmin','serveradmin') } |
    Select-Object Role, Member |
    Format-Table

# Remove user from sysadmin role
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
ALTER SERVER ROLE sysadmin DROP MEMBER [LoginName]
'@

# Grant more granular permissions instead
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
GRANT VIEW SERVER STATE TO [LoginName]
GRANT ALTER ANY DATABASE TO [LoginName]
'@
"@
                    TSQL = @"
-- List all privileged role members
SELECT 
    r.name AS RoleName,
    m.name AS MemberName,
    m.type_desc AS MemberType,
    m.create_date,
    m.modify_date
FROM sys.server_role_members srm
INNER JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
INNER JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id
WHERE r.name IN ('sysadmin', 'securityadmin', 'serveradmin', 'setupadmin', 'processadmin')
ORDER BY r.name, m.name;

-- Remove member from sysadmin role
ALTER SERVER ROLE sysadmin DROP MEMBER [LoginName];

-- Add to less privileged role or grant specific permissions
ALTER SERVER ROLE dbcreator ADD MEMBER [LoginName];

-- Or grant granular permissions
GRANT VIEW SERVER STATE TO [LoginName];
GRANT ALTER ANY DATABASE TO [LoginName];
"@
                    Manual = @"
1. Review each privileged role member
2. Verify business justification for elevated access
3. Remove unnecessary members
4. Replace sysadmin with more granular permissions when possible:
   - For DBAs: Consider custom server roles with specific permissions
   - For app accounts: Use database-level roles instead
   - For monitoring: VIEW SERVER STATE is often sufficient
5. Document all privileged access
6. Implement regular access reviews
7. Use Windows groups for easier management
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/grant-a-permission-to-a-principal"
                )
                RawData = $roleMembers | Select-Object RoleName, MemberName, MemberType
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Server Role Membership"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check server roles"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 42: DATABASE ROLE MEMBERSHIP (Security)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [42/$totalChecks] Checking database role membership..."
        
        try {
            $excessiveDbRoles = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    r.name AS RoleName,
    m.name AS MemberName,
    m.type_desc AS MemberType
FROM sys.database_role_members drm
INNER JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
INNER JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
WHERE r.name IN ('db_owner', 'db_securityadmin', 'db_accessadmin')
AND m.name NOT IN ('dbo', 'guest')
ORDER BY r.name, m.name;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $excessiveDbRoles += [PSCustomObject]@{
                            Database = $db.Name
                            Role = $_.RoleName
                            Member = $_.MemberName
                            MemberType = $_.MemberType
                        }
                    }
                }
            }
            
            $dbOwnerMembers = $excessiveDbRoles | Where-Object { $_.Role -eq 'db_owner' }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Database Role Membership"
                Status = if ($dbOwnerMembers.Count -eq 0) { "✅ Pass" } elseif ($dbOwnerMembers.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($dbOwnerMembers.Count -eq 0) { "Pass" } elseif ($dbOwnerMembers.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Reviews membership in privileged database roles"
                Impact = "Excessive membership in db_owner role violates least privilege principle. db_owner members have full control over the database including ability to drop it, modify security, and access all data. Use more granular roles (db_datareader, db_datawriter, db_ddladmin) when possible."
                CurrentValue = @{
                    TotalPrivilegedMembers = $excessiveDbRoles.Count
                    DbOwnerMembers = $dbOwnerMembers.Count
                }
                RecommendedAction = if ($dbOwnerMembers.Count -eq 0) { "Database role membership is appropriate" } else { "Review and reduce db_owner role membership" }
                RemediationSteps = @{
                    PowerShell = @"
# List database role members
Get-DbaDbRoleMember -SqlInstance '$serverName' |
    Where-Object { `$_.Role -eq 'db_owner' } |
    Select-Object Database, Role, Member |
    Format-Table

# Remove user from db_owner
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'DatabaseName' -Query @'
ALTER ROLE db_owner DROP MEMBER [UserName]
'@

# Add to appropriate role instead
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'DatabaseName' -Query @'
ALTER ROLE db_datareader ADD MEMBER [UserName]
ALTER ROLE db_datawriter ADD MEMBER [UserName]
'@
"@
                    TSQL = @"
-- List privileged database role members
USE [DatabaseName];
SELECT 
    r.name AS RoleName,
    m.name AS MemberName,
    m.type_desc AS MemberType
FROM sys.database_role_members drm
INNER JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
INNER JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
WHERE r.name IN ('db_owner', 'db_securityadmin', 'db_accessadmin')
ORDER BY r.name, m.name;

-- Remove member from db_owner
ALTER ROLE db_owner DROP MEMBER [UserName];

-- Add to less privileged roles
ALTER ROLE db_datareader ADD MEMBER [UserName];
ALTER ROLE db_datawriter ADD MEMBER [UserName];

-- Grant specific permissions if needed
GRANT EXECUTE ON SCHEMA::dbo TO [UserName];
GRANT CREATE TABLE TO [UserName];
"@
                    Manual = @"
1. Review each db_owner member
2. Determine actual permissions needed
3. Use appropriate built-in roles:
   - db_datareader: Read all data
   - db_datawriter: Modify all data
   - db_ddladmin: DDL operations
   - db_executor: Execute stored procedures
4. Or create custom database roles with specific permissions
5. Remove from db_owner
6. Test application after permission changes
7. Document permission model
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine"
                )
                RawData = $excessiveDbRoles | Select-Object Database, Role, Member, MemberType
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Database Role Membership"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check database roles"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 43: OVERSIZED INDEXES (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [43/$totalChecks] Checking for oversized indexes..."
        
        try {
            $oversizedIndexes = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    OBJECT_SCHEMA_NAME(i.object_id) AS SchemaName,
    OBJECT_NAME(i.object_id) AS TableName,
    i.name AS IndexName,
    COUNT(*) AS ColumnCount,
    SUM(c.max_length) AS TotalKeySize
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE i.type IN (1, 2)  -- Clustered and nonclustered
AND ic.is_included_column = 0  -- Key columns only
GROUP BY i.object_id, i.name
HAVING COUNT(*) > 10 OR SUM(c.max_length) > 900
ORDER BY TotalKeySize DESC;
"@
                $result = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                if ($result) {
                    $result | ForEach-Object { 
                        $oversizedIndexes += [PSCustomObject]@{
                            Database = $db.Name
                            Schema = $_.SchemaName
                            Table = $_.TableName
                            IndexName = $_.IndexName
                            ColumnCount = $_.ColumnCount
                            TotalKeySize = $_.TotalKeySize
                        }
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Oversized Indexes"
                Status = if ($oversizedIndexes.Count -eq 0) { "✅ Pass" } elseif ($oversizedIndexes.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($oversizedIndexes.Count -eq 0) { "Pass" } elseif ($oversizedIndexes.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Identifies indexes with excessive columns or total key size >900 bytes"
                Impact = "Oversized indexes (>900 bytes key size or >10 key columns) waste space, slow DML operations, and can cause performance issues. SQL Server has a 900-byte limit on index keys (excluding included columns). Large indexes also increase buffer pool pressure and I/O overhead."
                CurrentValue = @{
                    OversizedIndexCount = $oversizedIndexes.Count
                }
                RecommendedAction = if ($oversizedIndexes.Count -eq 0) { "No oversized indexes found" } else { "Review and optimize oversized indexes" }
                RemediationSteps = @{
                    PowerShell = @"
# Find oversized indexes
`$query = @'
SELECT 
    DB_NAME() AS DatabaseName,
    OBJECT_SCHEMA_NAME(i.object_id) AS SchemaName,
    OBJECT_NAME(i.object_id) AS TableName,
    i.name AS IndexName,
    COUNT(*) AS KeyColumnCount,
    SUM(c.max_length) AS TotalKeySize
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE ic.is_included_column = 0
GROUP BY i.object_id, i.name
HAVING COUNT(*) > 10 OR SUM(c.max_length) > 900
'@

Invoke-DbaQuery -SqlInstance '$serverName' -Query `$query | Format-Table
"@
                    TSQL = @"
-- Find oversized indexes with details
SELECT 
    OBJECT_SCHEMA_NAME(i.object_id) AS SchemaName,
    OBJECT_NAME(i.object_id) AS TableName,
    i.name AS IndexName,
    i.type_desc AS IndexType,
    COUNT(*) AS KeyColumnCount,
    SUM(c.max_length) AS TotalKeySize,
    STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) AS KeyColumns
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE ic.is_included_column = 0
GROUP BY i.object_id, i.name, i.type_desc
HAVING COUNT(*) > 10 OR SUM(c.max_length) > 900
ORDER BY TotalKeySize DESC;

-- Option 1: Drop and recreate with fewer key columns, move extras to INCLUDE
DROP INDEX [IndexName] ON [SchemaName].[TableName];

CREATE NONCLUSTERED INDEX [IndexName]
ON [SchemaName].[TableName] ([KeyColumn1], [KeyColumn2])
INCLUDE ([Column3], [Column4], [Column5]);  -- Move these to INCLUDE

-- Option 2: Drop unused oversized index
DROP INDEX [IndexName] ON [SchemaName].[TableName];
"@
                    Manual = @"
1. Review each oversized index
2. Analyze index usage:
   - Use sys.dm_db_index_usage_stats
   - Check if index is actually used
3. Options to fix:
   - Move some columns to INCLUDE clause (doesn't count toward 900 byte limit)
   - Split into multiple smaller indexes
   - Remove unnecessary columns
   - Drop if not used
4. Test query performance after changes
5. Remember: Wide indexes trade space/write performance for read performance
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/indexes/indexes",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/sql-server-index-design-guide"
                )
                RawData = $oversizedIndexes | Select-Object Database, Schema, Table, IndexName, ColumnCount, TotalKeySize
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Oversized Indexes"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check indexes"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 44: CLUSTER QUORUM (High Availability)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [44/$totalChecks] Checking cluster quorum..."
        
        try {
            # Check if server is in a Windows cluster
            $query = @"
SELECT 
    SERVERPROPERTY('IsClustered') AS IsClustered,
    SERVERPROPERTY('IsHadrEnabled') AS IsHadrEnabled;
"@
            $clusterInfo = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            if ($clusterInfo.IsClustered -eq 1) {
                # Try to get cluster quorum info via PowerShell remoting or WMI
                try {
                    $quorumQuery = "SELECT * FROM MSCluster_ResourceGroup WHERE Name = 'Cluster Group'"
                    # This is a simplified check - in real scenarios, might need more robust cluster checking
                    
                    $serverResults.Checks += @{
                        Category = "High Availability"
                        CheckName = "Cluster Quorum"
                        Status = "ℹ️ Info"
                        Severity = "Info"
                        Description = "Server is clustered - manual quorum verification recommended"
                        Impact = "Windows Server Failover Cluster quorum determines which nodes can form a functioning cluster. Improper quorum configuration can lead to split-brain scenarios or cluster failure. Critical for AG and FCI high availability."
                        CurrentValue = @{
                            IsClustered = $true
                            IsHadrEnabled = $clusterInfo.IsHadrEnabled -eq 1
                        }
                        RecommendedAction = "Verify cluster quorum health using Windows Failover Cluster Manager or PowerShell"
                        RemediationSteps = @{
                            PowerShell = @"
# Check cluster quorum (run on Windows Server with cluster role)
Get-ClusterQuorum

# Get cluster nodes and their state
Get-ClusterNode | Select-Object Name, State, NodeWeight

# Get detailed cluster information
Get-Cluster | Select-Object Name, QuorumType, QuorumResource

# Test cluster quorum
Test-Cluster -Cluster 'ClusterName' -Include 'Inventory','Network','System Configuration'
"@
                            TSQL = @"
-- Check if clustered and HADR enabled
SELECT 
    SERVERPROPERTY('IsClustered') AS IsClustered,
    SERVERPROPERTY('IsHadrEnabled') AS IsHadrEnabled,
    SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS NodeName,
    SERVERPROPERTY('ServerName') AS ServerName;

-- Check cluster nodes (SQL 2012+)
SELECT 
    member_name AS NodeName,
    member_type_desc AS MemberType,
    member_state_desc AS State,
    number_of_quorum_votes AS QuorumVotes
FROM sys.dm_hadr_cluster_members;

-- Check cluster network info
SELECT 
    member_name AS NodeName,
    network_subnet_ip,
    network_subnet_prefix_length,
    is_public,
    is_ipv4
FROM sys.dm_hadr_cluster_networks;
"@
                            Manual = @"
1. Open Failover Cluster Manager on Windows Server
2. Check cluster quorum configuration:
   - Node Majority (odd number of nodes)
   - Node and Disk Majority (even nodes + witness disk)
   - Node and File Share Majority (even nodes + witness share)
3. Verify quorum votes:
   - Each node should have appropriate vote weight
   - Witness (disk/file share) should have 1 vote
4. Best practices:
   - Use Node Majority for odd number of nodes (3, 5, etc.)
   - Use Node and File Share Majority for even nodes
   - Place witness in separate datacenter for DR
5. Monitor cluster events in Windows Event Viewer
6. Test cluster failover regularly
"@
                        }
                        Documentation = @(
                            "https://learn.microsoft.com/en-us/windows-server/failover-clustering/manage-cluster-quorum",
                            "https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/windows/wsfc-quorum-modes-and-voting-configuration-sql-server"
                        )
                        RawData = $clusterInfo
                    }
                } catch {
                    $serverResults.Checks += @{ Category = "High Availability"; CheckName = "Cluster Quorum"; Status = "⚠️ Warning"; Severity = "Warning"; Description = "Server is clustered but quorum details unavailable"; Error = $_.Exception.Message }
                }
            } else {
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "Cluster Quorum"
                    Status = "ℹ️ Info"
                    Severity = "Info"
                    Description = "Server is not part of a Windows cluster"
                    Impact = "N/A"
                    CurrentValue = @{ IsClustered = $false }
                    RecommendedAction = "No action needed - server is standalone"
                    RemediationSteps = @{}
                    Documentation = @()
                    RawData = @{}
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "Cluster Quorum"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check cluster status"; Error = $_.Exception.Message }
        }
        
        # ============================================================================
        # CHECK 45: AUTO GROWTH DISABLED (Database Health)
        # ============================================================================
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [45/$totalChecks] Checking for disabled auto growth..."
        
        try {
            $query = @"
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    name AS FileName,
    type_desc AS FileType,
    physical_name AS PhysicalPath,
    size * 8 / 1024 AS SizeMB,
    CASE 
        WHEN max_size = -1 THEN 'Unlimited'
        WHEN max_size = 0 THEN 'Disabled'
        ELSE CAST(max_size * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END AS MaxSize,
    CASE 
        WHEN is_percent_growth = 1 THEN CAST(growth AS VARCHAR(10)) + '%'
        ELSE CAST(growth * 8 / 1024 AS VARCHAR(10)) + ' MB'
    END AS GrowthSetting,
    CASE 
        WHEN growth = 0 THEN 'Disabled'
        ELSE 'Enabled'
    END AS AutoGrowth
FROM sys.master_files
WHERE database_id > 4  -- Exclude system databases
AND growth = 0  -- Auto growth disabled
ORDER BY DatabaseName, type_desc;
"@
            $noAutoGrowth = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Auto Growth Disabled"
                Status = if ($noAutoGrowth.Count -eq 0) { "✅ Pass" } elseif ($noAutoGrowth.Count -lt 3) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($noAutoGrowth.Count -eq 0) { "Pass" } elseif ($noAutoGrowth.Count -lt 3) { "Warning" } else { "Error" }
                Description = "Identifies database files with auto growth disabled"
                Impact = "Files with auto growth disabled will eventually run out of space, causing INSERT/UPDATE failures, transaction log full errors (9002), and potential database downtime. While manual growth management is valid in some scenarios, disabled auto growth is risky without proper monitoring and proactive space management."
                CurrentValue = @{
                    FilesWithNoAutoGrowth = $noAutoGrowth.Count
                }
                RecommendedAction = if ($noAutoGrowth.Count -eq 0) { "All files have auto growth enabled" } else { "Enable auto growth with appropriate settings" }
                RemediationSteps = @{
                    PowerShell = @"
# Check file growth settings
Get-DbaDbFile -SqlInstance '$serverName' |
    Select-Object Database, LogicalName, FileType, Growth, GrowthType, MaxSize |
    Where-Object { `$_.Growth -eq 0 } |
    Format-Table

# Enable auto growth on data file (256MB increments)
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
ALTER DATABASE [DatabaseName]
MODIFY FILE (NAME = N''LogicalFileName'', FILEGROWTH = 256MB)
'@

# Enable auto growth on log file (512MB increments)
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
ALTER DATABASE [DatabaseName]
MODIFY FILE (NAME = N''LogicalFileName'', FILEGROWTH = 512MB)
'@
"@
                    TSQL = @"
-- Check current file growth settings
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    name AS LogicalName,
    type_desc AS FileType,
    CASE 
        WHEN is_percent_growth = 1 THEN CAST(growth AS VARCHAR) + '%'
        ELSE CAST(growth * 8 / 1024 AS VARCHAR) + ' MB'
    END AS GrowthSetting,
    growth AS RawGrowth
FROM sys.master_files
WHERE database_id > 4
ORDER BY DatabaseName, type_desc;

-- Enable auto growth on data file (fixed size recommended over percent)
ALTER DATABASE [DatabaseName]
MODIFY FILE (
    NAME = N'LogicalFileName',
    FILEGROWTH = 256MB,
    MAXSIZE = UNLIMITED
);

-- Enable auto growth on log file
ALTER DATABASE [DatabaseName]
MODIFY FILE (
    NAME = N'LogicalFileName_Log',
    FILEGROWTH = 512MB,
    MAXSIZE = UNLIMITED
);

-- Best practice: Use fixed MB/GB growth, not percent
-- Data files: 256MB - 1GB increments
-- Log files: 512MB - 4GB increments
"@
                    Manual = @"
1. Review files with disabled auto growth
2. Determine if intentional (some high-end environments pre-size files)
3. If not intentional, enable auto growth:
   - Use fixed size (MB/GB) not percentage
   - Data files: 256MB-1GB increments
   - Log files: 512MB-4GB increments
   - Set reasonable MAXSIZE (not unlimited if disk space limited)
4. Consider pre-growing files to avoid fragmentation
5. Monitor disk space proactively
6. Set up alerts for low disk space
7. Document file growth strategy
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-files-and-filegroups",
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-file-and-filegroup-options"
                )
                RawData = $noAutoGrowth | Select-Object DatabaseName, FileName, FileType, SizeMB, MaxSize
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Auto Growth Disabled"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check auto growth"; Error = $_.Exception.Message }
        }
        
        Write-Host "[$serverName] Completed all $($serverResults.Checks.Count) checks!"
        
        # Store server results
        $healthCheckResults.Servers[$serverName] = $serverResults
        
        # Update executive summary
        foreach ($check in $serverResults.Checks) {
            $healthCheckResults.ExecutiveSummary.TotalChecks++
            if ($check.Status -like "*Pass*" -or $check.Status -like "*✅*") {
                $healthCheckResults.ExecutiveSummary.PassedChecks++
            }
            elseif ($check.Status -like "*Warning*" -or $check.Status -like "*⚠️*") {
                $healthCheckResults.ExecutiveSummary.WarningChecks++
            }
            else {
                $healthCheckResults.ExecutiveSummary.FailedChecks++
            }
        }
    }
    
    # ============================================================================
    # GENERATE COMPREHENSIVE MARKDOWN REPORT
    # ============================================================================
    
    Send-Progress -Value 0.92 -Message "Generating comprehensive Markdown report..."
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $reportDate = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "SQLServer_HealthCheck_${reportDate}.md"
    
    # Calculate overall health score
    $totalChecks = $healthCheckResults.ExecutiveSummary.TotalChecks
    $passedChecks = $healthCheckResults.ExecutiveSummary.PassedChecks
    $healthScore = if ($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 1) } else { 0 }
    
    # Delete file if exists
    if (Test-Path $filename) { Remove-Item $filename -Force }
    
    # Helper function
    function Add-ToReport {
        param([string]$Content)
        Add-Content -Path $filename -Value $Content -Encoding UTF8
    }
    
    # Header
    Add-ToReport "# SQL Server Comprehensive Health Check Report"
    Add-ToReport "="*60
    Add-ToReport ""
    Add-ToReport "**Report Date:** $timestamp"
    Add-ToReport "**Primary Server:** $($healthCheckResults.PrimaryServer)"
    Add-ToReport "**Servers Analyzed:** $($healthCheckResults.ExecutiveSummary.TotalServers)"
    Add-ToReport "**AG Environment:** $(if($healthCheckResults.IsAGEnvironment){'Yes'}else{'No'})"
    Add-ToReport ""
    Add-ToReport "---"
    Add-ToReport ""
    
    # Executive Dashboard
    Add-ToReport "## Executive Dashboard"
    Add-ToReport "-"*30
    Add-ToReport ""
    Add-ToReport "| Metric                    | Value |"
    Add-ToReport "|---------------------------|-------|"
    Add-ToReport "| **Overall Health Score**  | **${healthScore}%** |"
    Add-ToReport "| Checks Passed             | $($healthCheckResults.ExecutiveSummary.PassedChecks) |"
    Add-ToReport "| Warnings                  | $($healthCheckResults.ExecutiveSummary.WarningChecks) |"
    Add-ToReport "| Failed                    | $($healthCheckResults.ExecutiveSummary.FailedChecks) |"
    Add-ToReport "| Total Checks              | $($healthCheckResults.ExecutiveSummary.TotalChecks) |"
    Add-ToReport ""
    Add-ToReport "---"
    Add-ToReport ""
    
    # AG Section
    if ($healthCheckResults.IsAGEnvironment) {
        Send-Progress -Value 0.93 -Message "Writing Availability Group information..."
        Add-ToReport "## Availability Groups Configuration"
        Add-ToReport "-"*30
        Add-ToReport ""
        
        foreach ($ag in $healthCheckResults.AvailabilityGroups) {
            Add-ToReport "### $($ag.Name)"
            Add-ToReport ""
            Add-ToReport "- **Primary Replica:** $($ag.PrimaryReplica)"
            Add-ToReport "- **Backup Preference:** $($ag.AutomatedBackupPreference)"
            Add-ToReport "- **Replicas:**"
            foreach ($replica in $ag.Replicas) {
                Add-ToReport "  - **$($replica.Name)**: Role=$($replica.Role), Mode=$($replica.AvailabilityMode), Failover=$($replica.FailoverMode)"
            }
            Add-ToReport ""
        }
        Add-ToReport "---"
        Add-ToReport ""
    }
    
    # Server sections
    $serverCount = 0
    $totalServers = $healthCheckResults.Servers.Keys.Count
    foreach ($serverName in $healthCheckResults.Servers.Keys) {
        $serverCount++
        $serverProgress = 0.93 + (0.04 * ($serverCount / $totalServers))
        Send-Progress -Value $serverProgress -Message "Writing server report for $serverName..."
        
        $serverData = $healthCheckResults.Servers[$serverName]
        $serverInfo = $serverData.ServerInfo
        
        Add-ToReport "## Server: $serverName"
        Add-ToReport "-"*30
        Add-ToReport ""
        Add-ToReport "**Edition:** $($serverInfo.Edition)"
        Add-ToReport "**Version:** $($serverInfo.Version)"
        Add-ToReport "**Build:** $($serverInfo.BuildNumber)"
        Add-ToReport "**Patch Level:** $($serverInfo.ProductUpdateLevel)"
        Add-ToReport "**Memory:** $($serverInfo.PhysicalMemoryMB) MB"
        Add-ToReport "**Processors:** $($serverInfo.Processors)"
        Add-ToReport "**Collation:** $($serverInfo.Collation)"
        Add-ToReport ""
        Add-ToReport "---"
        Add-ToReport ""
        
        # Checks
        $checkNumber = 0
        $totalServerChecks = $serverData.Checks.Count
        foreach ($check in $serverData.Checks) {
            $checkNumber++
            
            Add-ToReport ""
            Add-ToReport ""
            Add-ToReport "### Check ${checkNumber}/${totalServerChecks}: $($check.CheckName)"
            Add-ToReport "---"
            Add-ToReport ""
            Add-ToReport "**Status:** $($check.Status)"
            Add-ToReport "**Category:** $($check.Category)"
            Add-ToReport ""
            Add-ToReport "**Description:** $($check.Description)"
            Add-ToReport ""
            
            if ($check.Impact) {
                $impactClean = $check.Impact -replace "`n", " " -replace "`r", ""
                Add-ToReport "**Impact:** $impactClean"
                Add-ToReport ""
            }
            
            if ($check.CurrentValue) {
                Add-ToReport "**Current Configuration:**"
                foreach ($key in $check.CurrentValue.Keys) {
                    $value = if ($check.CurrentValue[$key] -ne $null) { $check.CurrentValue[$key] } else { "(null)" }
                    Add-ToReport "- **${key}:** $value"
                }
                Add-ToReport ""
            }
            
            # Display detailed list of problematic items RIGHT AFTER current config
            if ($check.RawData) {
                try {
                    Add-ToReport "**Affected Items:**"
                    Add-ToReport ""
                    
                    # Convert to array if it's a single object
                    $dataItems = @($check.RawData)
                    
                    if ($dataItems.Count -gt 0 -and $dataItems.Count -le 100) {
                        # Get properties from first item to create table header
                        $firstItem = $dataItems[0]
                        $properties = $firstItem.PSObject.Properties.Name
                        
                        # Create markdown table
                        $headerRow = "| " + ($properties -join " | ") + " |"
                        $separatorRow = "|" + (($properties | ForEach-Object { "---" }) -join "|") + "|"
                        
                        Add-ToReport $headerRow
                        Add-ToReport $separatorRow
                        
                        # Add data rows
                        foreach ($item in $dataItems) {
                            $values = @()
                            foreach ($prop in $properties) {
                                $val = $item.$prop
                                if ($null -eq $val) { $val = "" }
                                $values += $val
                            }
                            $dataRow = "| " + ($values -join " | ") + " |"
                            Add-ToReport $dataRow
                        }
                    } elseif ($dataItems.Count -gt 100) {
                        Add-ToReport "*Too many items to display ($($dataItems.Count) items). Showing first 100:*"
                        Add-ToReport ""
                        
                        # Show first 100 items
                        $firstItem = $dataItems[0]
                        $properties = $firstItem.PSObject.Properties.Name
                        
                        $headerRow = "| " + ($properties -join " | ") + " |"
                        $separatorRow = "|" + (($properties | ForEach-Object { "---" }) -join "|") + "|"
                        
                        Add-ToReport $headerRow
                        Add-ToReport $separatorRow
                        
                        foreach ($item in $dataItems[0..99]) {
                            $values = @()
                            foreach ($prop in $properties) {
                                $val = $item.$prop
                                if ($null -eq $val) { $val = "" }
                                $values += $val
                            }
                            $dataRow = "| " + ($values -join " | ") + " |"
                            Add-ToReport $dataRow
                        }
                    }
                    Add-ToReport ""
                } catch {
                    # If table formatting fails, just skip
                }
            }
            
            if ($check.RecommendedAction) {
                Add-ToReport "**Recommended Action:** $($check.RecommendedAction)"
                Add-ToReport ""
            }
            
            if ($check.RemediationSteps) {
                Add-ToReport "**Remediation Steps:**"
                Add-ToReport ""
                
                if ($check.RemediationSteps.PowerShell) {
                    Add-ToReport "**PowerShell:**"
                    Add-ToReport '```powershell'
                    Add-ToReport $check.RemediationSteps.PowerShell
                    Add-ToReport '```'
                    Add-ToReport ""
                }
                if ($check.RemediationSteps.TSQL) {
                    Add-ToReport "**T-SQL:**"
                    Add-ToReport '```sql'
                    Add-ToReport $check.RemediationSteps.TSQL
                    Add-ToReport '```'
                    Add-ToReport ""
                }
                if ($check.RemediationSteps.Manual) {
                    Add-ToReport "**Manual Steps:**"
                    Add-ToReport '```'
                    Add-ToReport $check.RemediationSteps.Manual
                    Add-ToReport '```'
                    Add-ToReport ""
                }
            }
            
            if ($check.Documentation) {
                Add-ToReport "**Documentation:**"
                foreach ($link in $check.Documentation) {
                    Add-ToReport "- $link"
                }
                Add-ToReport ""
            }
            
            Add-ToReport "---"
            Add-ToReport ""
        }
    }
    
    # Footer
    Send-Progress -Value 0.97 -Message "Finalizing Markdown report..."
    Add-ToReport ""
    Add-ToReport "---"
    Add-ToReport ""
    Add-ToReport "## Report Information"
    Add-ToReport "-"*30
    Add-ToReport ""
    Add-ToReport "**SQL Server Health Check Report**"
    Add-ToReport "Generated by xyOps MSSQL Health Check Plugin"
    Add-ToReport "Copyright 2026 Tim Alderweireldt"
    Add-ToReport "Report Date: $timestamp"
    
    Write-Host ""
    Write-Host "Markdown report saved: $filename"
    
    # Output file reference to xyOps
    Send-Progress -Value 0.98 -Message "Finalizing report..."
    Write-Output-JSON @{
        xy = 1
        files = @(
            @{
                path = $filename
                name = $filename
            }
        )
    }
    
    Send-Progress -Value 1.0 -Message "Health check completed successfully!"
    
    $summary = "Health check completed successfully:`n"
    $summary += "  * Servers checked: $($healthCheckResults.ExecutiveSummary.TotalServers)`n"
    $summary += "  * Total checks: $($healthCheckResults.ExecutiveSummary.TotalChecks)`n"
    $summary += "  * Health score: $healthScore%`n"
    $summary += "  * Passed: $($healthCheckResults.ExecutiveSummary.PassedChecks)`n"
    $summary += "  * Warnings: $($healthCheckResults.ExecutiveSummary.WarningChecks)`n"
    $summary += "  * Failed: $($healthCheckResults.ExecutiveSummary.FailedChecks)"
    
    Send-Success -Description $summary
} # End of main try block
catch {
    Send-Error -Code 5 -Description "Error during health check: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    exit 1
}
