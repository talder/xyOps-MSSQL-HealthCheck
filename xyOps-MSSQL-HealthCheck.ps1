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

# Function to get latest CU information for SQL Server version
function Get-LatestCUInfo {
    param([int]$VersionMajor, [string]$BuildNumber)
    
    # Latest CU information as of February 2026
    # NOTE: Update this table periodically with latest CU information
    $cuInfo = @{
        16 = @{  # SQL Server 2022
            VersionName = "SQL Server 2022"
            LatestCU = "CU16"
            LatestBuild = "16.0.4165.4"
            DownloadLink = "https://www.microsoft.com/download/details.aspx?id=106034"
            KBArticle = "https://support.microsoft.com/help/5046862"
        }
        15 = @{  # SQL Server 2019
            VersionName = "SQL Server 2019"
            LatestCU = "CU30"
            LatestBuild = "15.0.4405.4"
            DownloadLink = "https://www.microsoft.com/download/details.aspx?id=100809"
            KBArticle = "https://support.microsoft.com/help/5046877"
        }
        14 = @{  # SQL Server 2017
            VersionName = "SQL Server 2017"
            LatestCU = "CU31"
            LatestBuild = "14.0.3465.1"
            DownloadLink = "https://www.microsoft.com/download/details.aspx?id=56128"
            KBArticle = "https://support.microsoft.com/help/5016884"
        }
        13 = @{  # SQL Server 2016
            VersionName = "SQL Server 2016 SP3"
            LatestCU = "SP3 + CU1"
            LatestBuild = "13.0.7000.253"
            DownloadLink = "https://www.microsoft.com/download/details.aspx?id=56840"
            KBArticle = "https://support.microsoft.com/help/5033583"
        }
        12 = @{  # SQL Server 2014
            VersionName = "SQL Server 2014 SP3"
            LatestCU = "SP3 + CU4"
            LatestBuild = "12.0.6449.1"
            DownloadLink = "https://www.microsoft.com/download/details.aspx?id=58213"
            KBArticle = "https://support.microsoft.com/help/4583462"
        }
        11 = @{  # SQL Server 2012
            VersionName = "SQL Server 2012 SP4"
            LatestCU = "SP4 (End of Support)"
            LatestBuild = "11.0.7507.2"
            DownloadLink = "https://www.microsoft.com/download/details.aspx?id=56040"
            KBArticle = "https://support.microsoft.com/help/4018073"
        }
    }
    
    if ($cuInfo.ContainsKey($VersionMajor)) {
        return $cuInfo[$VersionMajor]
    } else {
        return @{
            VersionName = "SQL Server (Unknown Version)"
            LatestCU = "Unknown"
            LatestBuild = "N/A"
            DownloadLink = "https://learn.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server"
            KBArticle = "https://learn.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server"
        }
    }
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
$serverAdminUser = $env:MSSQLHC_SERVER_ADMIN_USER
$serverAdminPassword = $env:MSSQLHC_SERVER_ADMIN_PASSWORD
$useencryptionRaw = Get-ParamValue -ParamsObject $params -ParamName 'useencryption'
$trustcertRaw = Get-ParamValue -ParamsObject $params -ParamName 'trustcert'

# Define check category mappings for preset groups
$checkGroups = @{
    'security' = @(52, 53, 54, 55, 56, 70)  # Auth mode, guest user, public role, cert expiry, audit, job owners
    'performance' = @(17, 18, 19, 20, 21, 22, 23, 24, 25, 60, 61, 62, 65, 72)  # Waits, CPU, memory, I/O, indexes, MAXDOP, cost threshold, ad hoc, IFI, fill factor
    'availability' = @(29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 61, 62, 63)  # AG checks
    'backup' = @(10, 11, 12, 13)  # Backup checks
    'database' = @(6, 7, 8, 9, 47, 48, 49, 50, 51)  # Database config checks
}

# Get exclusions and inclusions parameters
$exclusionsRaw = Get-ParamValue -ParamsObject $params -ParamName 'exclusions'
$inclusionsRaw = Get-ParamValue -ParamsObject $params -ParamName 'inclusions'
$exclusionReasonRaw = Get-ParamValue -ParamsObject $params -ParamName 'exclusionreason'
$exportToPdfRaw = Get-ParamValue -ParamsObject $params -ParamName 'exporttopdf'

# Validate mutual exclusivity
if (-not [string]::IsNullOrWhiteSpace($exclusionsRaw) -and -not [string]::IsNullOrWhiteSpace($inclusionsRaw)) {
    Send-Error -Code 10 -Description "Cannot use both 'exclusions' and 'inclusions' parameters together. Please use only one. Exclusions: skip specific checks. Inclusions: run ONLY specific checks."
    exit 1
}

# Parse exclusions (with preset groups)
$excludedChecks = @()
if (-not [string]::IsNullOrWhiteSpace($exclusionsRaw)) {
    $exclusionItems = $exclusionsRaw -split ',' | ForEach-Object { $_.Trim().ToLower() }
    
    foreach ($item in $exclusionItems) {
        if ($item -match '^\d+$') {
            # Numeric check number
            $checkNum = [int]$item
            if ($checkNum -gt 0 -and $checkNum -le 72) {
                $excludedChecks += $checkNum
            }
        } elseif ($checkGroups.ContainsKey($item)) {
            # Preset group
            $excludedChecks += $checkGroups[$item]
            Write-Host "ℹ️  Expanding preset group '$item': checks $($checkGroups[$item] -join ', ')"
        } else {
            Write-Host "⚠️  Warning: Unknown exclusion item '$item' - ignoring. Valid: 1-72, security, performance, availability, backup, database"
        }
    }
    
    $excludedChecks = $excludedChecks | Select-Object -Unique | Sort-Object
    
    if ($excludedChecks.Count -gt 0) {
        Write-Host "ℹ️  Excluding checks: $($excludedChecks -join ', ')"
        if (-not [string]::IsNullOrWhiteSpace($exclusionReasonRaw)) {
            Write-Host "ℹ️  Exclusion reason: $exclusionReasonRaw"
        }
    }
}

# Parse inclusions (with preset groups)
$includedChecks = @()
$useInclusions = $false
if (-not [string]::IsNullOrWhiteSpace($inclusionsRaw)) {
    $useInclusions = $true
    $inclusionItems = $inclusionsRaw -split ',' | ForEach-Object { $_.Trim().ToLower() }
    
    foreach ($item in $inclusionItems) {
        if ($item -match '^\d+$') {
            # Numeric check number
            $checkNum = [int]$item
            if ($checkNum -gt 0 -and $checkNum -le 72) {
                $includedChecks += $checkNum
            }
        } elseif ($checkGroups.ContainsKey($item)) {
            # Preset group
            $includedChecks += $checkGroups[$item]
            Write-Host "ℹ️  Expanding preset group '$item': checks $($checkGroups[$item] -join ', ')"
        } else {
            Write-Host "⚠️  Warning: Unknown inclusion item '$item' - ignoring. Valid: 1-72, security, performance, availability, backup, database"
        }
    }
    
    $includedChecks = $includedChecks | Select-Object -Unique | Sort-Object
    
    if ($includedChecks.Count -gt 0) {
        Write-Host "ℹ️  Running ONLY checks: $($includedChecks -join ', ')"
    } else {
        Write-Host "⚠️  Warning: No valid checks in inclusions list - running all checks"
        $useInclusions = $false
    }
}

# Validate required parameters
$missing = @()
if ([string]::IsNullOrWhiteSpace($server)) { $missing += 'server' }
if ([string]::IsNullOrWhiteSpace($username)) { $missing += 'MSSQLHC_USERNAME (environment variable)' }
if ([string]::IsNullOrWhiteSpace($password)) { $missing += 'MSSQLHC_PASSWORD (environment variable)' }

if ($missing.Count -gt 0) {
    Send-Error -Code 2 -Description "Missing required parameters: $($missing -join ', '). Credentials must be provided via secret vault environment variables."
    exit 1
}

# Detect operating system
$runningOnWindows = if ($PSVersionTable.PSVersion.Major -ge 6) {
    # PowerShell Core/7+ has built-in variables
    $IsWindows
} else {
    # Windows PowerShell 5.1 - always Windows
    $true
}

$osName = if ($runningOnWindows) {
    "Windows"
} elseif ($PSVersionTable.PSVersion.Major -ge 6 -and $IsLinux) {
    "Linux"
} elseif ($PSVersionTable.PSVersion.Major -ge 6 -and $IsMacOS) {
    "macOS"
} else {
    "Unknown"
}

Write-Host "Detected OS: $osName"

if (-not $runningOnWindows) {
    Write-Host "⚠️  Running on non-Windows system ($osName) - Windows-specific checks (WMI, remote PowerShell) will be disabled"
    Write-Host "   The following checks will use T-SQL fallback methods or be skipped:"
    Write-Host "   - Lock Pages In Memory (Check 2)"
    Write-Host "   - Memory Configuration with server-level access (Check 3-4)"
    Write-Host "   - Instant File Initialization (Check 65)"
}

# Check for optional server admin credentials
$hasServerAdminCreds = -not ([string]::IsNullOrWhiteSpace($serverAdminUser)) -and -not ([string]::IsNullOrWhiteSpace($serverAdminPassword))
$serverAdminCredential = $null

if (-not $runningOnWindows -and $hasServerAdminCreds) {
    Write-Host "ℹ️  Server admin credentials provided but running on $osName - credentials will not be used"
    Write-Host "   Windows-specific features (WMI, remote PowerShell) are not available on this platform"
    $hasServerAdminCreds = $false
    $serverAdminCredential = $null
} elseif ($hasServerAdminCreds) {
    Write-Host "[OK] Server admin credentials detected - enhanced checks will be available"
    $secureServerAdminPassword = ConvertTo-SecureString -String $serverAdminPassword -AsPlainText -Force
    $serverAdminCredential = New-Object System.Management.Automation.PSCredential($serverAdminUser, $secureServerAdminPassword)
} else {
    Write-Host "[INFO] Server admin credentials not provided - some checks will use fallback methods"
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
    
    # Suppress dbatools informational warnings (recovery forks, AG replica access, etc.)
    $WarningPreference = 'SilentlyContinue'
    
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
        ServerAdminCredsProvided = $hasServerAdminCreds
        RunningOS = $osName
        IsWindowsHost = $runningOnWindows
        ExcludedChecks = $excludedChecks
        ExclusionReason = if (-not [string]::IsNullOrWhiteSpace($exclusionReasonRaw)) { $exclusionReasonRaw } else { "" }
        ExclusionMode = if ($useInclusions) { "Inclusions" } elseif ($excludedChecks.Count -gt 0) { "Exclusions" } else { "None" }
        AvailabilityGroups = @()
        Servers = @{}
        ExecutiveSummary = @{
            TotalServers = 0
            TotalChecks = 0
            PassedChecks = 0
            WarningChecks = 0
            FailedChecks = 0
            ChecksUsingServerAdmin = 0
            ExcludedChecks = $excludedChecks.Count
        }
    }
    
    # Discover AG partners
    $serversToCheck = @($primaryConnection)
    $serverNames = @($primaryConnection.Name)
    
    Send-Progress -Value 0.05 -Message "Detecting Availability Groups and partner replicas..."
    
    if ($primaryConnection.IsHadrEnabled) {
        $healthCheckResults.IsAGEnvironment = $true
        Write-Host "[OK] HADR is enabled - discovering AG topology..."
        
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
                            Write-Host "    [OK] Connected successfully"
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
        $totalChecks = 72
        $checkProgress = $progressPerServer / $totalChecks
        $currentCheck = 0
        
        # Helper function to check if a check number is excluded
        function Should-SkipCheck {
            param([int]$CheckNumber, [string]$CheckName)
            
            $shouldSkip = $false
            
            # Check if using inclusions mode - skip if NOT in included list
            if ($script:useInclusions -and $script:includedChecks -notcontains $CheckNumber) {
                $shouldSkip = $true
            }
            # Check if using exclusions mode - skip if in excluded list
            elseif (-not $script:useInclusions -and $script:excludedChecks -contains $CheckNumber) {
                $shouldSkip = $true
            }
            
            if ($shouldSkip) {
                Write-Host "[$serverName] [Skipping check $CheckNumber/$totalChecks - Excluded by user]"
                $script:serverResults.Checks += @{
                    Category = "Excluded"
                    CheckName = "Check $CheckNumber - $CheckName"
                    Status = "⏭️ Excluded"
                    Severity = "Excluded"
                    Description = "This check was excluded by user request"
                    CheckNumber = $CheckNumber
                }
                $script:currentCheck++
                return $true
            }
            return $false
        }
        
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
        
        if (-not (Should-SkipCheck -CheckNumber 1 -CheckName "SQL Server Version & Updates")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [1/$totalChecks] Checking SQL Server version and patch level..."
        
        # Get latest CU information for this version
        $latestCU = Get-LatestCUInfo -VersionMajor $conn.VersionMajor -BuildNumber $conn.BuildNumber
        
        # Compare current build with latest
        $isUpToDate = $conn.BuildNumber -eq $latestCU.LatestBuild
        $needsUpdate = -not $isUpToDate
        
        $versionCheck = @{
            Category = "Server Health"
            CheckName = "SQL Server Version & Updates"
            Status = if ($isUpToDate) { "✅ Up to Date" } else { "ℹ️ Update Available" }
            Severity = if ($isUpToDate) { "Pass" } else { "Info" }
            Description = "Verifies SQL Server version and checks if latest updates are installed"
            Impact = "Outdated versions may contain security vulnerabilities, bugs, and miss performance improvements. Microsoft releases cumulative updates (CUs) regularly with fixes and enhancements. Staying current ensures optimal security, stability, and performance."
            CurrentValue = @{
                Version = $conn.VersionString
                Edition = $conn.Edition
                ProductLevel = $conn.ProductLevel
                PatchLevel = $serverResults.ServerInfo.ProductUpdateLevel
                BuildNumber = $conn.BuildNumber
                LatestAvailableCU = $latestCU.LatestCU
                LatestAvailableBuild = $latestCU.LatestBuild
                UpdateNeeded = $needsUpdate
            }
            RecommendedAction = if ($isUpToDate) { "Server is running the latest available update ($($latestCU.LatestCU))" } else { "Install the latest Cumulative Update ($($latestCU.LatestCU)) for $($latestCU.VersionName). Always test updates in non-production environments first." }
            RemediationSteps = @{
                PowerShell = @"
# Current Version: $($conn.VersionString) (Build $($conn.BuildNumber))
# Latest Available: $($latestCU.LatestCU) (Build $($latestCU.LatestBuild))

# Download latest CU from official Microsoft site:
# $($latestCU.DownloadLink)

# Check current version
Invoke-DbaQuery -SqlInstance '$serverName' -Query "SELECT @@VERSION"

# After installing CU, verify new version
Test-DbaBuild -SqlInstance '$serverName' -Latest

# Verify build number after update
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    SERVERPROPERTY('ProductVersion') AS Version,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('ProductUpdateLevel') AS PatchLevel
'@
"@
                TSQL = @"
-- Check current version and build
SELECT 
    SERVERPROPERTY('ProductVersion') AS Version,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('ProductUpdateLevel') AS PatchLevel,
    SERVERPROPERTY('Edition') AS Edition,
    @@VERSION AS FullVersion;

-- Check installed updates
SELECT * FROM sys.dm_os_windows_info;
"@
                Manual = @"
1. Download the latest Cumulative Update:
   - Latest CU: $($latestCU.LatestCU)
   - Download: $($latestCU.DownloadLink)
   - KB Article: $($latestCU.KBArticle)

2. Review the KB article for:
   - Known issues
   - Prerequisites
   - Installation instructions

3. Test the update in a non-production environment first

4. Schedule a maintenance window

5. Back up all databases before applying the update

6. Run the CU installer on each SQL Server instance

7. Restart SQL Server service if required

8. Verify the installation:
   SELECT @@VERSION;

9. Monitor for any issues post-installation
"@
            }
            Documentation = @(
                $latestCU.DownloadLink,
                $latestCU.KBArticle,
                "https://learn.microsoft.com/en-us/troubleshoot/sql/releases/download-and-install-latest-updates",
                "https://learn.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server"
            )
            RawData = @{
                VersionString = $conn.VersionString
                BuildNumber = $conn.BuildNumber
                ProductLevel = $conn.ProductLevel
                ProductUpdateLevel = $serverResults.ServerInfo.ProductUpdateLevel
                Edition = $conn.Edition
                LatestCU = $latestCU.LatestCU
                LatestBuild = $latestCU.LatestBuild
                DownloadLink = $latestCU.DownloadLink
                KBArticle = $latestCU.KBArticle
            }
        }
        $serverResults.Checks += $versionCheck
        }  # End Check 1
        
        # ============================================================================
        # CHECK 2: LOCK PAGES IN MEMORY
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 2 -CheckName "Lock Pages In Memory")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [2/$totalChecks] Checking Lock Pages In Memory privilege..."
        
        try {
            $lockPages = $null
            $checkMethod = "T-SQL"
            $usedServerAdmin = $false
            
            # Primary method: Use T-SQL (most reliable)
            try {
                # Get max memory and total memory
                $memQuery = @"
SELECT 
    (SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'max server memory (MB)') AS MaxMemoryMB,
    (SELECT CAST(total_physical_memory_kb/1024 AS bigint) FROM sys.dm_os_sys_memory) AS TotalMB
"@
                $memResult = Invoke-DbaQuery -SqlInstance $conn -Query $memQuery -ErrorAction Stop
                
                if (-not $memResult.TotalMB) {
                    # Try older SQL Server version syntax (pre-2012)
                    $memResult.TotalMB = (Invoke-DbaQuery -SqlInstance $conn -Query "SELECT CAST(physical_memory_kb/1024 AS bigint) AS TotalMB FROM sys.dm_os_sys_info" -ErrorAction SilentlyContinue).TotalMB
                }
                
                # If still no total memory, use from ServerInfo
                if (-not $memResult.TotalMB) {
                    $memResult.TotalMB = $serverResults.ServerInfo.PhysicalMemoryMB
                }
                
                # Try to get locked pages info (SQL 2012+ only, may not be available in all builds)
                $lockedPagesMB = 0
                try {
                    $lpQuery = "SELECT SUM(locked_page_allocations_kb) / 1024 AS LockedPagesMB FROM sys.dm_os_memory_nodes WHERE locked_page_allocations_kb > 0"
                    $lpResult = Invoke-DbaQuery -SqlInstance $conn -Query $lpQuery -ErrorAction Stop
                    $lockedPagesMB = if ($lpResult.LockedPagesMB) { $lpResult.LockedPagesMB } else { 0 }
                    $checkMethod = "T-SQL (sys.dm_os_memory_nodes)"
                } catch {
                    # locked_page_allocations_kb not available - try alternative methods
                    try {
                        $aweQuery = "SELECT CAST(value_in_use AS int) AS AWEEnabled FROM sys.configurations WHERE name = 'awe enabled'"
                        $aweResult = Invoke-DbaQuery -SqlInstance $conn -Query $aweQuery -ErrorAction SilentlyContinue
                        if ($aweResult.AWEEnabled -eq 1) {
                            $lockedPagesMB = -1  # Indicator for "possibly enabled via AWE"
                        }
                        $checkMethod = "T-SQL (legacy AWE check)"
                    } catch {
                        $checkMethod = "T-SQL (limited detection)"
                    }
                }
                
                $lockPages = [pscustomobject]@{
                    SqlMaxMB = $memResult.MaxMemoryMB
                    TotalMB = $memResult.TotalMB
                    LockedPagesMB = $lockedPagesMB
                }
            } catch {
                # T-SQL method failed - this shouldn't happen
                $lockPages = $null
            }
            
            if ($lockPages -and $lockPages.TotalMB) {
                # Check if locked pages are actually in use
                $hasLockPages = $false
                
                # Convert to number and check if > 0
                $lockedMB = 0
                if ($lockPages.LockedPagesMB -ne $null -and $lockPages.LockedPagesMB -ne "") {
                    try {
                        $lockedMB = [int]$lockPages.LockedPagesMB
                    } catch {
                        $lockedMB = 0
                    }
                }
                
                if ($lockedMB -gt 0) {
                    $hasLockPages = $true
                } elseif ($lockedMB -eq -1) {
                    # AWE enabled indicator
                    $hasLockPages = $true
                } elseif ($lockPages.SqlMaxMB -and $lockPages.SqlMaxMB -gt 0 -and $lockPages.TotalMB -and $lockPages.SqlMaxMB -lt $lockPages.TotalMB) {
                    # Heuristic: if max memory is set and not unlimited, LPIM might be configured
                    # This is not 100% accurate but better than nothing
                    $hasLockPages = $true
                }
                
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
                    LockedPagesMB = if ($lockPages.LockedPagesMB) { $lockPages.LockedPagesMB } else { "N/A" }
                    CheckMethod = $checkMethod
                    ServerAdminUsed = $usedServerAdmin
                }
                RecommendedAction = if ($hasLockPages) { "Lock Pages in Memory appears to be configured" } else { if ($hasServerAdminCreds) { "Grant 'Lock Pages in Memory' user right to SQL Server service account and restart SQL Server service" } else { "Provide MSSQLHC_SERVER_ADMIN credentials for accurate checking, or manually verify Lock Pages in Memory using the T-SQL query below" } }
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
            } else {
                # Could not determine LPIM status
                $serverResults.Checks += @{
                    Category = "Server Health"
                    CheckName = "Lock Pages In Memory"
                    Status = "ℹ️ Manual Check Required"
                    Severity = "Info"
                    Description = "Could not automatically determine Lock Pages in Memory status. Manual verification required."
                    Impact = "Without this privilege, Windows can page out SQL Server's buffer pool memory to disk during memory pressure, causing severe performance degradation. This is critical for production servers."
                    CurrentValue = @{
                        LockPagesEnabled = "Unknown"
                        ServerAdminCredsProvided = $hasServerAdminCreds
                        CheckMethod = $checkMethod
                    }
                    RecommendedAction = if ($hasServerAdminCreds) { "Could not determine LPIM status even with server admin credentials. Manually verify using the T-SQL query below." } else { "Provide MSSQLHC_SERVER_ADMIN credentials for automatic checking, or manually verify Lock Pages in Memory using the T-SQL query below." }
                    RemediationSteps = @{
                        PowerShell = @"
# Check Lock Pages in Memory via T-SQL
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    SUM(locked_page_allocations_kb) / 1024 AS LockedPagesMB
FROM sys.dm_os_memory_nodes;
-- If LockedPagesMB > 0, Lock Pages is working
'@

# Alternative: Check Windows security policy (requires server admin access)
secedit /export /cfg C:\secpol.cfg
`$content = Get-Content C:\secpol.cfg
`$content | Select-String 'SeLockMemoryPrivilege'
Remove-Item C:\secpol.cfg
"@
                        TSQL = @"
-- Check if Lock Pages in Memory is in use
SELECT 
    osn.node_id,
    osn.memory_node_id,
    om.locked_page_allocations_kb / 1024 AS LockedPagesMemoryMB
FROM sys.dm_os_memory_nodes om
INNER JOIN sys.dm_os_nodes osn ON om.memory_node_id = osn.memory_node_id
WHERE osn.node_state_desc <> 'ONLINE DAC';

-- If locked_page_allocations_kb > 0, Lock Pages is working
-- If all values are 0, Lock Pages is NOT configured
"@
                        Manual = @"
1. Connect to SQL Server Management Studio
2. Run the T-SQL query above to check locked_page_allocations_kb
3. If all values are 0, Lock Pages in Memory is NOT enabled:
   a. Open Local Security Policy (secpol.msc) on the SQL Server host
   b. Navigate to: Local Policies → User Rights Assignment
   c. Double-click "Lock pages in memory"
   d. Click "Add User or Group"
   e. Enter the SQL Server service account name
   f. Click OK
   g. Restart SQL Server service
4. Re-run the query to verify locked_page_allocations_kb > 0
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/enable-the-lock-pages-in-memory-option-windows",
                        "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-memory-nodes-transact-sql"
                    )
                    RawData = @{}
                }
            }
        }
        catch {
            Write-Host "[Check 2 Error] $($_.Exception.Message)"
            Write-Host "[Check 2 Stack] $($_.ScriptStackTrace)"
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Lock Pages In Memory"
                Status = "❌ Error"
                Severity = "Error"
                Description = "Unexpected error while checking Lock Pages in Memory: $($_.Exception.Message)"
                Impact = "Without this privilege, Windows can page out SQL Server's buffer pool memory to disk during memory pressure, causing severe performance degradation."
                CurrentValue = @{
                    Error = $_.Exception.Message
                    CheckMethod = if ($checkMethod) { $checkMethod } else { "Unknown" }
                    ServerAdminCredsProvided = $hasServerAdminCreds
                }
                RecommendedAction = "Review the error message and manually verify Lock Pages in Memory using the T-SQL query in the Remediation Steps."
                RemediationSteps = @{
                    TSQL = @"
-- Check if Lock Pages in Memory is in use
SELECT 
    CAST(value_in_use AS int) AS MaxMemoryMB
FROM sys.configurations 
WHERE name = 'max server memory (MB)';

-- Try to check locked pages (SQL 2012+ only)
-- If this fails, locked_page_allocations_kb column doesn't exist in your version
SELECT 
    osn.node_id,
    osn.memory_node_id,
    om.locked_page_allocations_kb / 1024 AS LockedPagesMemoryMB
FROM sys.dm_os_memory_nodes om
INNER JOIN sys.dm_os_nodes osn ON om.memory_node_id = osn.memory_node_id
WHERE osn.node_state_desc <> 'ONLINE DAC';
"@
                    Manual = @"
1. The automated check encountered an error
2. Manually verify Lock Pages in Memory:
   a. Connect to SQL Server Management Studio
   b. Run the T-SQL query above
   c. If locked_page_allocations_kb > 0, LPIM is enabled
   d. If the query fails or returns 0, LPIM may not be enabled
3. To enable LPIM:
   a. Open Local Security Policy (secpol.msc) on SQL Server host
   b. Navigate to: Local Policies → User Rights Assignment
   c. Double-click "Lock pages in memory"
   d. Add the SQL Server service account
   e. Restart SQL Server service
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/enable-the-lock-pages-in-memory-option-windows"
                )
                Error = $_.Exception.Message
                RawData = @{}
            }
        }
        }  # End Check 2
        
        # ============================================================================
        # CHECK 3: INSTANT FILE INITIALIZATION
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 3 -CheckName "Instant File Initialization")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [3/$totalChecks] Checking Instant File Initialization..."
        
        try {
            $ifiEnabled = $null
            $checkMethod = "Unknown"
            $errorDetails = ""
            $usedServerAdmin = $false
            
            # Try primary method with server admin credentials if available
            try {
                if ($hasServerAdminCreds) {
                    # Try with server admin credentials for better access
                    $ifi = Test-DbaInstanceFileInitialization -SqlInstance $conn -Credential $serverAdminCredential
                    $ifiEnabled = $ifi.IfiEnabled
                    $checkMethod = "dbatools with Server Admin credentials"
                    $usedServerAdmin = $true
                    $healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin++
                } else {
                    # Try without server admin credentials
                    $ifi = Test-DbaInstanceFileInitialization -SqlInstance $conn
                    $ifiEnabled = $ifi.IfiEnabled
                    $checkMethod = "dbatools (SQL credentials only)"
                }
            }
            catch {
                $errorDetails = $_.Exception.Message
                
                # Fallback: Check via T-SQL for SQL Server 2016+
                if ($conn.VersionMajor -ge 13) {
                    try {
                        $ifiQuery = "SELECT CASE WHEN EXISTS (SELECT * FROM sys.dm_server_services WHERE instant_file_initialization_enabled = 'Y') THEN 1 ELSE 0 END AS IFIEnabled"
                        $ifiResult = Invoke-DbaQuery -SqlInstance $conn -Query $ifiQuery
                        $ifiEnabled = $ifiResult.IFIEnabled -eq 1
                        $checkMethod = "T-SQL (sys.dm_server_services)"
                    }
                    catch {
                        # Cannot determine - mark as unknown
                        $ifiEnabled = $null
                        $errorDetails += "; Fallback also failed: " + $_.Exception.Message
                    }
                } else {
                    # SQL Server 2014 and older - cannot check programmatically
                    $ifiEnabled = $null
                    $errorDetails += "; SQL Server version too old for programmatic check (requires 2016+)"
                }
            }
            
            if ($null -ne $ifiEnabled) {
                $ifiCheck = @{
                    Category = "Server Health"
                    CheckName = "Instant File Initialization (IFI)"
                    Status = if ($ifiEnabled) { "✅ Pass" } else { "⚠️ Warning" }
                    Severity = if ($ifiEnabled) { "Pass" } else { "Warning" }
                    Description = "Checks if Instant File Initialization is enabled for faster data file operations"
                    Impact = "Without IFI, data file growth operations must zero-write all new space, which can take significant time for large files. This causes blocking, timeouts, and performance issues during autogrowth events. IFI allows near-instant file growth for data files (not log files)."
                    CurrentValue = @{
                        IFIEnabled = $ifiEnabled
                        CheckMethod = $checkMethod
                    }
                    RecommendedAction = if ($ifiEnabled) { "Instant File Initialization is enabled" } else { "Grant 'Perform Volume Maintenance Tasks' privilege to SQL Server service account and restart SQL Server" }
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
                RawData = @{
                    IFIEnabled = $ifiEnabled
                    CheckMethod = $checkMethod
                }
            }
            $serverResults.Checks += $ifiCheck
            } else {
                # Could not determine IFI status - provide manual check instructions
                $serverResults.Checks += @{
                    Category = "Server Health"
                    CheckName = "Instant File Initialization (IFI)"
                    Status = "ℹ️ Manual Check Required"
                    Severity = "Info"
                    Description = "Could not automatically determine IFI status. Manual verification required."
                    Impact = "Without IFI, data file growth operations must zero-write all new space, which can take significant time for large files. This causes blocking, timeouts, and performance issues during autogrowth events. IFI allows near-instant file growth for data files (not log files)."
                    CurrentValue = @{
                        IFIEnabled = "Unknown"
                        Reason = $errorDetails
                        SQLServerVersion = "$($conn.VersionMajor).$($conn.VersionMinor)"
                        ServerAdminCredsProvided = $hasServerAdminCreds
                    }
                    RecommendedAction = if ($hasServerAdminCreds) { "Could not determine IFI status even with server admin credentials. Manually verify using the methods below." } else { "Provide MSSQLHC_SERVER_ADMIN_USER and MSSQLHC_SERVER_ADMIN_PASSWORD credentials for automatic checking, or manually verify IFI status using the T-SQL or PowerShell methods provided below." }
                    RemediationSteps = @{
                        PowerShell = @"
# For SQL Server 2016 and later, check via T-SQL:
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT servicename, instant_file_initialization_enabled
FROM sys.dm_server_services 
WHERE servicename LIKE 'SQL Server%';
'@

# Alternative: Check Windows privilege directly (requires admin access to SQL Server host)
# Step 1: Identify SQL Server service account
`$serviceAccount = (Get-WmiObject Win32_Service | Where-Object {`$_.Name -like 'MSSQL*' -and `$_.Name -notlike '*Agent*'}).StartName
Write-Host "SQL Server Service Account: `$serviceAccount"

# Step 2: To enable IFI, grant 'Perform Volume Maintenance Tasks' privilege:
secedit /export /cfg C:\secpol.cfg
`$content = Get-Content C:\secpol.cfg
# Look for SeManageVolumePrivilege and verify service account is listed
`$content | Select-String 'SeManageVolumePrivilege'
"@
                        TSQL = @"
-- For SQL Server 2016+ (Version 13.0+)
-- Check IFI status
SELECT 
    servicename,
    instant_file_initialization_enabled,
    CASE instant_file_initialization_enabled
        WHEN 'Y' THEN 'IFI is ENABLED - Good!'
        WHEN 'N' THEN 'IFI is DISABLED - Consider enabling'
        ELSE 'Unknown status'
    END AS Status
FROM sys.dm_server_services 
WHERE servicename LIKE 'SQL Server%';

-- For SQL Server 2014 and older:
-- Enable trace flag 3004 and check error log
DBCC TRACEON(3004, -1);
-- Create a small test database and check the error log for initialization messages
-- Look for 'Zeroing' (IFI disabled) vs 'Instant' (IFI enabled) messages
EXEC sp_readerrorlog;
"@
                        Manual = @"
1. For SQL Server 2016+:
   - Run the T-SQL query above to check instant_file_initialization_enabled column
   
2. For SQL Server 2014 and older:
   - Enable trace flag 3004: DBCC TRACEON(3004, -1)
   - Create a test database
   - Check SQL Server error log for file initialization messages
   - With IFI: You'll see "instant" initialization
   - Without IFI: You'll see "Zeroing" messages

3. To enable IFI (all versions):
   - Open Local Security Policy (secpol.msc) on SQL Server host
   - Navigate to: Local Policies → User Rights Assignment
   - Double-click "Perform volume maintenance tasks"
   - Add the SQL Server service account
   - Restart SQL Server service

4. Verify after enabling:
   - For 2016+: Re-run the sys.dm_server_services query
   - For older: Check error log after creating a test database
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-instant-file-initialization",
                        "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-server-services-transact-sql"
                    )
                    RawData = @{
                        ErrorDetails = $errorDetails
                        VersionMajor = $conn.VersionMajor
                        CheckMethod = $checkMethod
                    }
                }
            }
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
        }  # End Check 3
        
        # ============================================================================
        # CHECK 4: MEMORY CONFIGURATION
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 4 -CheckName "Memory Configuration")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [4/$totalChecks] Checking memory configuration..."
        
        try {
            $memory = $null
            $method = "dbatools:Get-DbaMaxMemory"
            $usedServerAdmin = $false

            try {
                if ($hasServerAdminCreds) {
                    # Try with server admin credentials for complete memory information
                    $memory = Get-DbaMaxMemory -SqlInstance $conn -Credential $serverAdminCredential -EnableException
                    $method = "dbatools with Server Admin credentials"
                    $usedServerAdmin = $true
                    $healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin++
                } else {
                    $memory = Get-DbaMaxMemory -SqlInstance $conn -EnableException
                }
            } catch {
                $method = "T-SQL Fallback"
                # Fallback via T-SQL; requires VIEW SERVER STATE
                try {
                    $tsql = @"
SELECT 
    (SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'min server memory (MB)') AS MinMB,
    (SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'max server memory (MB)') AS MaxMB,
    (SELECT CAST(total_physical_memory_kb/1024 AS bigint) FROM sys.dm_os_sys_memory) AS TotalMB
"@
                    $row = Invoke-DbaQuery -SqlInstance $conn -Query $tsql | Select-Object -First 1
                    if (-not $row.TotalMB) {
                        # Older versions: sys.dm_os_sys_info
                        $row.TotalMB = (Invoke-DbaQuery -SqlInstance $conn -Query "SELECT CAST(physical_memory_kb/1024 AS bigint) AS TotalMB FROM sys.dm_os_sys_info").TotalMB | Select-Object -First 1
                    }
                    $memory = [pscustomobject]@{
                        SqlMinMB = [int]$row.MinMB
                        SqlMaxMB = [int]$row.MaxMB
                        TotalMB  = [int64]$row.TotalMB
                    }
                } catch {
                    # Final fallback to ServerInfo if present
                    $memory = [pscustomobject]@{
                        SqlMinMB = $null
                        SqlMaxMB = $null
                        TotalMB  = [int64]$serverResults.ServerInfo.PhysicalMemoryMB
                    }
                }
            }

            $totalMB = [int64]$memory.TotalMB
            $recommended = if ($totalMB -gt 0) { [math]::Round($totalMB * 0.75) } else { 0 }
            $isConfigured = ($memory.SqlMaxMB -gt 0 -and $totalMB -gt 0 -and $memory.SqlMaxMB -lt $totalMB -and $memory.SqlMaxMB -ge $recommended * 0.9)
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Memory Configuration"
                Status = if ($recommended -gt 0) { if ($isConfigured) { "✅ Pass" } else { "⚠️ Warning" } } else { "ℹ️ Info" }
                Severity = if ($recommended -gt 0) { if ($isConfigured) { "Pass" } else { "Warning" } } else { "Info" }
                Description = "Validates SQL Server min/max memory settings against best practices"
                Impact = "Incorrect memory settings can cause OS instability (if max too high) or SQL Server memory starvation (if max too low). Min memory should be at least 25% of max to prevent excessive memory deallocations."
                CurrentValue = @{
                    MinMemoryMB = $memory.SqlMinMB
                    MaxMemoryMB = $memory.SqlMaxMB
                    TotalServerMemoryMB = if ($totalMB -gt 0) { $totalMB } else { $null }
                    RecommendedMaxMB = $recommended
                    RecommendedMinMB = if ($recommended -gt 0) { [math]::Round($recommended * 0.25) } else { 0 }
                    CheckMethod = $method
                }
                RecommendedAction = if ($recommended -gt 0) { if ($isConfigured) { "Memory is properly configured" } else { "Set max server memory to ~75% of total RAM ($recommended MB) and min to ~25% of max" } } else { "Grant VIEW SERVER STATE and ensure Windows remoting/WMI access so total memory can be retrieved." }
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
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-memory-server-configuration-options",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-sys-memory-transact-sql",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-configurations-transact-sql"
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
        }  # End Check 4
        
        # ============================================================================
        # CHECK 5: LAST BACKUP
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 5 -CheckName "Last Backup")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [5/$totalChecks] Checking backup status..."
        
        try {
            $lastBackup = Get-DbaLastBackup -SqlInstance $serverName -SqlCredential $credential -ExcludeDatabase master,model,msdb,tempdb
            
            # Filter for databases with backups older than 24 hours
            $cutoffDate = (Get-Date).AddDays(-1)
            $oldBackups = @()
            foreach ($db in $lastBackup) {
                if (-not $db.LastFullBackup) {
                    $oldBackups += $db
                } else {
                    $backupDate = [datetime]$db.LastFullBackup
                    if ($backupDate -lt $cutoffDate) {
                        $oldBackups += $db
                    }
                }
            }
            
            # Convert to simple objects for table display
            $backupTable = @()
            foreach ($db in $lastBackup) {
                $backupTable += [PSCustomObject]@{
                    Database = $db.Database
                    LastFullBackup = if ($db.LastFullBackup) { $db.LastFullBackup.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
                    LastDiffBackup = if ($db.LastDiffBackup) { $db.LastDiffBackup.ToString("yyyy-MM-dd HH:mm") } else { "None" }
                    LastLogBackup = if ($db.LastLogBackup) { $db.LastLogBackup.ToString("yyyy-MM-dd HH:mm") } else { "None" }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Last Backup"
                Status = if ($oldBackups.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($oldBackups.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies all user databases have been backed up within the last 24 hours"
                Impact = "Databases without recent backups risk significant data loss in case of hardware failure, corruption, or accidental deletion. RPO will be severely impacted."
                CurrentValue = @{
                    DatabasesWithOldBackups = $oldBackups.Count
                    TotalUserDatabases = @($lastBackup).Count
                }
                RecommendedAction = if ($oldBackups.Count -eq 0) { "All databases backed up regularly" } else { "Schedule daily full backups for databases without recent backups" }
                RemediationSteps = @{
                    PowerShell = "Get-DbaDatabase -SqlInstance '$serverName' -SqlCredential `$credential -ExcludeSystem | Backup-DbaDatabase -Type Full -CompressBackup"
                    TSQL = "BACKUP DATABASE [DatabaseName] TO DISK = N'C:\\Backup\\DatabaseName_Full.bak' WITH COMPRESSION;"
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/backup-restore/back-up-and-restore-of-sql-server-databases"
                )
                RawData = $backupTable
            }
        } catch {
            $serverResults.Checks += @{ 
                Category = "Server Health"
                CheckName = "Last Backup"
                Status = "❌ Error"
                Severity = "Error"
                Description = "Could not check backups"
                Error = $_.Exception.Message
            }
        }
        }  # End Check 5
        
        # ============================================================================
        # CHECK 6: DATABASE PERCENT GROWTH
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 6 -CheckName "Database Percent Growth")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [6/$totalChecks] Checking database growth settings..."
        
        try {
            $dbFiles = Get-DbaDbFile -SqlInstance $conn -ExcludeDatabase master,model,msdb,tempdb
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
        }  # End Check 6
        
        # ============================================================================
        # CHECK 7: RECOVERY MODEL
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 7 -CheckName "Recovery Model")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [7/$totalChecks] Checking recovery models..."
        
        try {
            $recoveryModel = Get-DbaDbRecoveryModel -SqlInstance $serverName -SqlCredential $credential -ExcludeDatabase master,model,msdb,tempdb
            
            # Filter for production databases in SIMPLE mode
            $simpleInProd = @()
            foreach ($db in $recoveryModel) {
                if ($db.RecoveryModel -eq 'Simple' -and $db.Name -notlike '*test*' -and $db.Name -notlike '*dev*') {
                    $simpleInProd += $db
                }
            }
            
            # Convert ALL databases to simple objects for table display
            $recoveryTable = @()
            foreach ($db in $recoveryModel) {
                $recoveryTable += [PSCustomObject]@{
                    Database = $db.Name
                    RecoveryModel = $db.RecoveryModel
                }
            }
            
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "Recovery Model"
                Status = if ($simpleInProd.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($simpleInProd.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Validates recovery model settings are appropriate for production vs non-production databases"
                Impact = "SIMPLE recovery prevents point-in-time recovery and transaction log backups. Production databases should use FULL recovery for maximum data protection. Non-production can use SIMPLE to avoid log file growth."
                CurrentValue = @{
                    SimpleModeInProduction = $simpleInProd.Count
                    TotalUserDatabases = @($recoveryModel).Count
                }
                RecommendedAction = if ($simpleInProd.Count -eq 0) { "Recovery models are appropriate" } else { "Change production databases to FULL recovery and take a full backup" }
                RemediationSteps = @{
                    PowerShell = @"
# Change to FULL recovery for production databases
Get-DbaDatabase -SqlInstance '$serverName' -SqlCredential `$credential -ExcludeSystem | 
    Where-Object { `$_.RecoveryModel -eq 'Simple' -and `$_.Name -notlike '*test*' } |
    Set-DbaDbRecoveryModel -RecoveryModel Full

# Take full backup after changing to FULL
Get-DbaDatabase -SqlInstance '$serverName' -SqlCredential `$credential -ExcludeSystem | 
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
                RawData = $recoveryTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Recovery Model"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check recovery models"; Error = $_.Exception.Message }
        }
        }  # End Check 7
        
        # ============================================================================
        # CHECK 8: VIRTUAL LOG FILES (VLF)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 8 -CheckName "Virtual Log Files")) {
        
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
        }  # End Check 8
        
        # ============================================================================
        # CHECK 9: TEMPDB CONFIGURATION
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 9 -CheckName "TempDB Configuration")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [9/$totalChecks] Checking TempDB configuration..."
        
        try {
            $tempdb = Test-DbaTempDbConfig -SqlInstance $conn
            
            # Filter for issues
            $issues = @()
            foreach ($check in $tempdb) {
                if ($check.IsBestPractice -eq $false) {
                    $issues += $check
                }
            }
            
            # Convert ALL checks to simple objects for table display
            $tempdbTable = @()
            foreach ($check in $tempdb) {
                $tempdbTable += [PSCustomObject]@{
                    Rule = $check.Rule
                    Recommended = $check.Recommended
                    CurrentSetting = $check.CurrentSetting
                    IsBestPractice = $check.IsBestPractice
                }
            }
            $serverResults.Checks += @{
                Category = "Server Health"
                CheckName = "TempDB Configuration"
                Status = if ($issues.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($issues.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Validates TempDB follows best practices (file count, size, growth)"
                Impact = "Improper TempDB configuration causes contention, allocation issues, and poor performance. Should have one data file per CPU core (max 8), all files same size, and proper growth settings."
                CurrentValue = @{
                    ConfigurationIssues = $issues.Count
                    TotalChecks = @($tempdb).Count
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
                RawData = $tempdbTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "TempDB Configuration"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check TempDB"; Error = $_.Exception.Message }
        }
        }  # End Check 9
        
        # ============================================================================
        # CHECK 10: INTEGRITY CHECK (DBCC CHECKDB)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 10 -CheckName "Integrity Check")) {
        
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
        }  # End Check 10
        
        # ============================================================================
        # CHECK 11: INDEX FRAGMENTATION
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 11 -CheckName "Index Fragmentation")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [11/$totalChecks] Checking index fragmentation..."
        
        try {
            # Query to check index fragmentation across all user databases
            $query = @"
CREATE TABLE #TempResults (
    DatabaseName NVARCHAR(128),
    SchemaName NVARCHAR(128),
    TableName NVARCHAR(128),
    IndexName NVARCHAR(128),
    FragmentationPercent DECIMAL(5,2),
    PageCount BIGINT
)

DECLARE @SQL NVARCHAR(MAX)
DECLARE @DbName NVARCHAR(128)

DECLARE db_cursor CURSOR FOR
SELECT name FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb')
AND state_desc = 'ONLINE'

OPEN db_cursor
FETCH NEXT FROM db_cursor INTO @DbName

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @SQL = '
    USE [' + @DbName + ']
    INSERT INTO #TempResults
    SELECT 
        ''' + @DbName + ''' as DatabaseName,
        dbschemas.[name] as SchemaName,
        dbtables.[name] as TableName,
        dbindexes.[name] as IndexName,
        CAST(indexstats.avg_fragmentation_in_percent AS DECIMAL(5,2)) as FragmentationPercent,
        indexstats.page_count as PageCount
    FROM sys.dm_db_index_physical_stats (DB_ID(), NULL, NULL, NULL, NULL) AS indexstats
    INNER JOIN sys.tables dbtables on dbtables.[object_id] = indexstats.[object_id]
    INNER JOIN sys.schemas dbschemas on dbtables.[schema_id] = dbschemas.[schema_id]
    INNER JOIN sys.indexes AS dbindexes ON dbindexes.[object_id] = indexstats.[object_id]
        AND indexstats.index_id = dbindexes.index_id
    WHERE indexstats.database_id = DB_ID()
        AND indexstats.page_count > 1000
        AND dbindexes.[name] IS NOT NULL'
    
    EXEC sp_executesql @SQL
    FETCH NEXT FROM db_cursor INTO @DbName
END

CLOSE db_cursor
DEALLOCATE db_cursor

SELECT * FROM #TempResults ORDER BY FragmentationPercent DESC

DROP TABLE #TempResults
"@

            # Execute the query
            $fragmentation = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # Build full list with status, and filter problematic ones
            $allIndexes = @()
            $highlyFragmented = @()
            foreach ($idx in $fragmentation) {
                $status = if ($idx.FragmentationPercent -le 10) {
                    "✅ Good"
                } elseif ($idx.FragmentationPercent -le 30) {
                    "⚠️ Reorganize"
                } else {
                    "❌ Rebuild"
                }
                
                $allIndexes += [PSCustomObject]@{
                    Database = $idx.DatabaseName
                    Schema = $idx.SchemaName
                    Table = $idx.TableName
                    IndexName = $idx.IndexName
                    FragmentationPercent = $idx.FragmentationPercent
                    PageCount = $idx.PageCount
                    Status = $status
                }
                
                # Keep track of problematic indexes (>50%)
                if ($idx.FragmentationPercent -gt 50) {
                    $highlyFragmented += [PSCustomObject]@{
                        Database = $idx.DatabaseName
                        Schema = $idx.SchemaName
                        Table = $idx.TableName
                        IndexName = $idx.IndexName
                        FragmentationPercent = $idx.FragmentationPercent
                        PageCount = $idx.PageCount
                    }
                }
            }
            
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
                RawData = $allIndexes | Sort-Object -Property FragmentationPercent -Descending
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Index Fragmentation"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check fragmentation"; Error = $_.Exception.Message }
        }
        }  # End Check 11
        
        # ============================================================================
        # CHECK 12: AUTO SHRINK
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 12 -CheckName "Auto Shrink")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [12/$totalChecks] Checking auto shrink settings..."
        
        try {
            # Query all databases for auto shrink setting
            $query = @"
SELECT name AS DatabaseName, 
       DATABASEPROPERTYEX(name, 'IsAutoShrink') AS IsAutoShrink
FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb')
ORDER BY name;
"@
            $autoShrinkResults = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # Filter for databases with auto shrink enabled
            $enabled = @()
            foreach ($db in $autoShrinkResults) {
                if ($db.IsAutoShrink -eq 1) {
                    $enabled += $db
                }
            }
            
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
        }  # End Check 12
        
        # ============================================================================
        # CHECK 13: AUTO CLOSE
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 13 -CheckName "Auto Close")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [13/$totalChecks] Checking auto close settings..."
        
        try {
            # Query all databases for auto close setting
            $query = @"
SELECT name AS DatabaseName, 
       DATABASEPROPERTYEX(name, 'IsAutoClose') AS IsAutoClose
FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb')
ORDER BY name;
"@
            $autoCloseResults = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # Filter for databases with auto close enabled
            $enabled = @()
            foreach ($db in $autoCloseResults) {
                if ($db.IsAutoClose -eq 1) {
                    $enabled += $db
                }
            }
            
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
        }  # End Check 13
        
        # ============================================================================
        # CHECK 14: PAGE VERIFY OPTION
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 14 -CheckName "Page Verify Option")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [14/$totalChecks] Checking page verify settings..."
        
        try {
            # Query all databases for page verify setting
            $query = @"
SELECT name AS DatabaseName, 
       page_verify_option_desc AS PageVerify
FROM sys.databases
WHERE name NOT IN ('master','model','msdb','tempdb')
ORDER BY name;
"@
            $pageVerifyResults = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # Filter for databases not using CHECKSUM
            $notChecksum = @()
            foreach ($db in $pageVerifyResults) {
                if ($db.PageVerify -ne 'CHECKSUM') {
                    $notChecksum += $db
                }
            }
            
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
        }  # End Check 14
        
        # ============================================================================
        # CHECK 15: SA ACCOUNT STATUS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 15 -CheckName "SA Account Status")) {
        
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
        }  # End Check 15
        
        # ============================================================================
        # CHECK 16: WEAK PASSWORDS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 16 -CheckName "Weak Passwords")) {
        
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
        }  # End Check 16
        
        # ============================================================================
        # CHECK 17: XP_CMDSHELL CONFIGURATION (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 17 -CheckName "xp_cmdshell Configuration")) {
        
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
        }  # End Check 17
        
        # ============================================================================
        # CHECK 18: ORPHANED USERS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 18 -CheckName "Orphaned Users")) {
        
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
        }  # End Check 18
        
        # ============================================================================
        # CHECK 19: DATABASE OWNERSHIP (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 19 -CheckName "Database Ownership")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [19/$totalChecks] Checking database ownership..."
        
        try {
            # Query to get database ownership information
            $query = @"
SELECT 
    d.name AS DatabaseName,
    SUSER_SNAME(d.owner_sid) AS CurrentOwner,
    'sa' AS ExpectedOwner,
    CASE WHEN SUSER_SNAME(d.owner_sid) = 'sa' THEN 'True' ELSE 'False' END AS OwnerMatch
FROM sys.databases d
WHERE d.name NOT IN ('master','model','msdb','tempdb')
ORDER BY d.name;
"@
            
            $dbOwners = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # Filter for databases not owned by sa
            $notSa = @()
            foreach ($db in $dbOwners) {
                if ($db.OwnerMatch -eq 'False') {
                    $notSa += $db
                }
            }
            
            # Convert to simple objects for table display
            $ownerTable = @()
            foreach ($db in $notSa) {
                $ownerTable += [PSCustomObject]@{
                    Database = $db.DatabaseName
                    CurrentOwner = $db.CurrentOwner
                    ExpectedOwner = $db.ExpectedOwner
                    OwnerMatch = $db.OwnerMatch
                }
            }
            
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
                RawData = $ownerTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Database Ownership"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check database ownership"; Error = $_.Exception.Message }
        }
        }  # End Check 19
        
        # ============================================================================
        # CHECK 20: DUPLICATE INDEXES (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 20 -CheckName "Duplicate Indexes")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [20/$totalChecks] Checking for duplicate indexes..."
        
        try {
            # Get all duplicate indexes
            $allDuplicates = Find-DbaDbDuplicateIndex -SqlInstance $conn
            
            # Filter out system databases
            $duplicateIndexes = @()
            foreach ($dup in $allDuplicates) {
                if ($dup.DatabaseName -notin @('master','model','msdb','tempdb')) {
                    $duplicateIndexes += $dup
                }
            }
            
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
        }  # End Check 20
        
        # ============================================================================
        # CHECK 21: TABLES WITHOUT PRIMARY KEY (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 21 -CheckName "Tables Without Primary Key")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [21/$totalChecks] Checking for tables without primary keys..."
        
        try {
            $tablesNoPK = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    SUM(p.rows) AS [RowCount]
FROM sys.tables t
LEFT JOIN sys.indexes i ON t.object_id = i.object_id AND i.is_primary_key = 1
INNER JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
WHERE i.object_id IS NULL
AND t.is_ms_shipped = 0
GROUP BY SCHEMA_NAME(t.schema_id), t.name
ORDER BY [RowCount] DESC;
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
        }  # End Check 21
        
        # ============================================================================
        # CHECK 22: TABLES WITHOUT INDEXES (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 22 -CheckName "Tables Without Indexes")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [22/$totalChecks] Checking for tables without indexes..."
        
        try {
            $tablesNoIndex = @()
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    SCHEMA_NAME(t.schema_id) AS SchemaName,
    t.name AS TableName,
    SUM(p.rows) AS [RowCount]
FROM sys.tables t
LEFT JOIN sys.indexes i ON t.object_id = i.object_id AND i.type > 0
INNER JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
WHERE i.object_id IS NULL
AND t.is_ms_shipped = 0
GROUP BY SCHEMA_NAME(t.schema_id), t.name
HAVING SUM(p.rows) > 1000
ORDER BY [RowCount] DESC;
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
    SUM(p.rows) AS [RowCount]
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
        }  # End Check 22
        
        # ============================================================================
        # CHECK 23: FOREIGN KEYS WITHOUT INDEXES (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 23 -CheckName "Foreign Keys Without Indexes")) {
        
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
        }  # End Check 23
        
        # ============================================================================
        # CHECK 24: DISABLED OR UNTRUSTED FOREIGN KEYS (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 24 -CheckName "Disabled/Untrusted Foreign Keys")) {
        
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
        }  # End Check 24
        
        # ============================================================================
        # CHECK 25: WAIT STATISTICS (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 25 -CheckName "Wait Statistics")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [25/$totalChecks] Analyzing wait statistics..."
        
        try {
            $waitStats = Get-DbaWaitStatistic -SqlInstance $conn -Threshold 1 | Select-Object -First 10
            $topWaitType = $waitStats | Select-Object -First 1
            
            # Convert wait stats to simple table format
            $waitStatsTable = @()
            foreach ($wait in $waitStats) {
                $waitStatsTable += [PSCustomObject]@{
                    WaitType = $wait.WaitType
                    WaitTime = if ($wait.WaitTime) { [math]::Round($wait.WaitTime.TotalMilliseconds, 0) } else { 0 }
                    Percentage = if ($wait.Percentage) { [math]::Round($wait.Percentage, 2) } else { 0 }
                    WaitingTasksCount = if ($wait.WaitingTasksCount) { $wait.WaitingTasksCount } else { 0 }
                }
            }
            
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
                    WaitTimeMs = if ($topWaitType.WaitTime) { [math]::Round($topWaitType.WaitTime.TotalMilliseconds, 0) } else { 0 }
                    PercentageOfTotal = if ($topWaitType.Percentage) { [math]::Round($topWaitType.Percentage, 2) } else { 0 }
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
                RawData = $waitStatsTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Wait Statistics"; Status = "❌ Error"; Severity = "Error"; Description = "Could not get wait stats"; Error = $_.Exception.Message }
        }
        }  # End Check 25
        
        # ============================================================================
        # CHECK 26: TOP SLOW QUERIES (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 26 -CheckName "Top Slow Queries")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [26/$totalChecks] Analyzing slow queries..."
        
        try {
            # Use direct T-SQL query for accurate duration data
            $slowQueryQuery = @"
SELECT TOP 20
    qs.execution_count,
    qs.total_elapsed_time / 1000 AS total_elapsed_time_ms,
    qs.total_elapsed_time / qs.execution_count / 1000 AS avg_elapsed_time_ms,
    qs.total_worker_time / 1000 AS total_cpu_time_ms,
    qs.total_logical_reads,
    DB_NAME(CAST(pa.value AS INT)) AS DatabaseName,
    CONVERT(VARCHAR(64), qs.query_hash, 1) AS QueryHash,
    SUBSTRING(st.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset
            WHEN -1 THEN DATALENGTH(st.text)
            ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2) + 1) AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
OUTER APPLY sys.dm_exec_plan_attributes(qs.plan_handle) pa
WHERE pa.attribute = 'dbid'
ORDER BY qs.total_elapsed_time / qs.execution_count DESC;
"@
            
            $slowQueries = Invoke-DbaQuery -SqlInstance $conn -Query $slowQueryQuery
            $avgDuration = if ($slowQueries) { ($slowQueries | Measure-Object -Property avg_elapsed_time_ms -Average).Average } else { 0 }
            
            # Convert to simple objects for table display
            $queryTable = @()
            foreach ($query in $slowQueries) {
                $queryTable += [PSCustomObject]@{
                    AvgDurationMs = [math]::Round($query.avg_elapsed_time_ms, 0)
                    ExecutionCount = $query.execution_count
                    DatabaseName = if ($query.DatabaseName) { $query.DatabaseName } else { "N/A" }
                    QueryHash = if ($query.QueryHash) { $query.QueryHash } else { "N/A" }
                    TotalCPUMs = [math]::Round($query.total_cpu_time_ms, 0)
                    LogicalReads = $query.total_logical_reads
                }
            }
            
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
Get-DbaTopResourceUsage -SqlInstance '$serverName' -Type Duration -Limit 20 | 
    Select-Object QueryHash, AverageDuration, ExecutionCount, Database |
    Format-Table

# Get query text and execution plan
`$slowQuery = Get-DbaTopResourceUsage -SqlInstance '$serverName' -Type Duration -Limit 1
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
                RawData = $queryTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Top Slow Queries"; Status = "❌ Error"; Severity = "Error"; Description = "Could not analyze queries"; Error = $_.Exception.Message }
        }
        }  # End Check 26
        
        # ============================================================================
        # CHECK 27: BLOCKING SESSIONS (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 27 -CheckName "Blocking Sessions")) {
        
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
        }  # End Check 27
        
        # ============================================================================
        # CHECK 28: DISK I/O LATENCY (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 28 -CheckName "Disk I/O Latency")) {
        
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
        }  # End Check 28
        
        # ============================================================================
        # CHECK 29: CPU PRESSURE (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 29 -CheckName "CPU Pressure")) {
        
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
            
            # Convert to simple formatted table
            $cpuTable = @()
            $cpuTable += [PSCustomObject]@{
                CPUBusyTimeMs = [math]::Round($cpuStats.cpu_busy_time_ms, 2)
                IdleTimeMs = [math]::Round($cpuStats.idle_time_ms, 2)
                CPUUtilization = "$($cpuPct)%"
            }
            
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
Get-DbaTopResourceUsage -SqlInstance '$serverName' -Type CPU -Limit 20 |
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
                RawData = $cpuTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "CPU Pressure"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check CPU pressure"; Error = $_.Exception.Message }
        }
        }  # End Check 29
        
        # ============================================================================
        # CHECK 30: MEMORY PRESSURE (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 30 -CheckName "Memory Pressure")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [30/$totalChecks] Checking memory pressure..."
        
        try {
            $query = @"
SELECT 
    (SELECT TOP 1 cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page life expectancy' ORDER BY cntr_value DESC) AS page_life_expectancy,
    (SELECT TOP 1 cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Lazy writes/sec' AND object_name LIKE '%Buffer Manager%') AS lazy_writes_per_sec,
    (SELECT TOP 1 cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page reads/sec' AND object_name LIKE '%Buffer Manager%') AS page_reads_per_sec,
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
        }  # End Check 30
        
        # ============================================================================
        # CHECK 31: DEADLOCK HISTORY (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 31 -CheckName "Deadlock History")) {
        
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
        }  # End Check 31
        
        # ============================================================================
        # CHECK 32: OBSOLETE DATA TYPES (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 32 -CheckName "Obsolete Data Types")) {
        
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
        }  # End Check 32
        
        # ============================================================================
        # CHECK 33: ERROR LOG ANALYSIS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 33 -CheckName "Error Log Analysis")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [33/$totalChecks] Analyzing error log..."
        
        try {
            # Get recent error log entries using sp_readerrorlog (much faster than Get-DbaErrorLog)
            $query = @"
DECLARE @StartDate DATETIME = DATEADD(DAY, -1, GETDATE());

CREATE TABLE #ErrorLog (
    LogDate DATETIME,
    ProcessInfo NVARCHAR(50),
    [Text] NVARCHAR(MAX)
);

INSERT INTO #ErrorLog
EXEC sp_readerrorlog 0, 1;

SELECT 
    LogDate,
    ProcessInfo,
    [Text],
    CASE 
        WHEN [Text] LIKE '%severe%' OR [Text] LIKE '%critical%' OR [Text] LIKE '%fatal%' OR [Text] LIKE '%stack dump%' 
        THEN 1 
        ELSE 0 
    END AS IsCritical
FROM #ErrorLog
WHERE LogDate >= @StartDate
AND (
    [Text] LIKE '%error%' OR 
    [Text] LIKE '%failed%' OR 
    [Text] LIKE '%failure%' OR 
    [Text] LIKE '%warning%'
)
AND [Text] NOT LIKE '%without errors%'
ORDER BY LogDate DESC;

DROP TABLE #ErrorLog;
"@
            $errorLog = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $criticalErrors = $errorLog | Where-Object { $_.IsCritical -eq 1 }
            
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
        }  # End Check 33
        
        # ============================================================================
        # CHECK 34: FAILED JOBS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 34 -CheckName "Failed Jobs")) {
        
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
        }  # End Check 34
        
        # ============================================================================
        # CHECK 35: AG SYNCHRONIZATION HEALTH (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 35 -CheckName "AG Synchronization Health")) {
        
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
        }  # End Check 35
        
        # ============================================================================
        # CHECK 36: AG DATA LATENCY (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 36 -CheckName "AG Data Latency")) {
        
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
        }  # End Check 36
        
        # ============================================================================
        # CHECK 37: AG FAILOVER READINESS (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 37 -CheckName "AG Failover Readiness")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [37/$totalChecks] Checking AG failover readiness..."
        
        try {
            $agReplicas = Get-DbaAgReplica -SqlInstance $conn
            
            if ($agReplicas) {
                # Check for replicas that cannot be automatic failover targets
                $notReadyForFailover = $agReplicas | Where-Object {
                    $_.FailoverMode -ne 'Automatic' -or
                    $_.AvailabilityMode -ne 'SynchronousCommit' -or
                    ($_.SynchronizationHealth -and $_.SynchronizationHealth -ne 'Healthy')
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
        }  # End Check 37
        
        # ============================================================================
        # CHECK 38: AG LISTENER CONFIGURATION (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 38 -CheckName "AG Listener Configuration")) {
        
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
        }  # End Check 38
        
        # ============================================================================
        # CHECK 39: SMALL DATA TYPES (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 39 -CheckName "Small Data Types")) {
        
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
        }  # End Check 39
        
        # ============================================================================
        # CHECK 40: DATABASE COMPATIBILITY LEVEL (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 40 -CheckName "Database Compatibility Level")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [40/$totalChecks] Checking database compatibility levels..."
        
        try {
            # Get server compatibility level from connection object
            $serverCompatLevel = switch ($conn.VersionMajor) {
                9  { 90 }   # SQL 2005
                10 { 100 }  # SQL 2008/2008R2
                11 { 110 }  # SQL 2012
                12 { 120 }  # SQL 2014
                13 { 130 }  # SQL 2016
                14 { 140 }  # SQL 2017
                15 { 150 }  # SQL 2019
                16 { 160 }  # SQL 2022
                default { 150 }
            }
            
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            # Build list of all databases with compatibility info
            $allCompatibility = @()
            $outdatedCompatibility = @()
            foreach ($db in $databases) {
                $isCorrect = $db.CompatibilityLevel -eq $serverCompatLevel
                
                $allCompatibility += [PSCustomObject]@{
                    Database = $db.Name
                    CurrentCompatibility = $db.CompatibilityLevel
                    ServerCompatibility = $serverCompatLevel
                    IsCorrect = $isCorrect
                    Status = if ($isCorrect) { "✅ Correct" } else { "⚠️ Outdated" }
                }
                
                if ($db.CompatibilityLevel -lt $serverCompatLevel) {
                    $outdatedCompatibility += [PSCustomObject]@{
                        Database = $db.Name
                        CurrentCompatibility = $db.CompatibilityLevel
                        ServerCompatibility = $serverCompatLevel
                        Status = $db.Status
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Database Compatibility Level"
                Status = if ($outdatedCompatibility.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($outdatedCompatibility.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Verifies databases are using current SQL Server compatibility level"
                Impact = "Databases with outdated compatibility levels cannot use newer query optimizer improvements, features, or performance enhancements. This can result in suboptimal query plans and missed performance gains. However, upgrading compatibility level can change query behavior, so test thoroughly."
                CurrentValue = @{
                    ServerCompatibility = $serverCompatLevel
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
                RawData = $allCompatibility
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Database Compatibility Level"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check compatibility levels"; Error = $_.Exception.Message }
        }
        }  # End Check 40
        
        # ============================================================================
        # CHECK 41: SERVER ROLE MEMBERSHIP (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 41 -CheckName "Server Role Membership")) {
        
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
        }  # End Check 41
        
        # ============================================================================
        # CHECK 42: DATABASE ROLE MEMBERSHIP (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 42 -CheckName "Database Role Membership")) {
        
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
        }  # End Check 42
        
        # ============================================================================
        # CHECK 43: OVERSIZED INDEXES (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 43 -CheckName "Oversized Indexes")) {
        
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
        }  # End Check 43
        
        # ============================================================================
        # CHECK 44: CLUSTER QUORUM (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 44 -CheckName "Cluster Quorum")) {
        
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
                # Server is clustered - try to get detailed quorum info
                $quorumDetails = $null
                $checkMethod = "T-SQL (basic cluster detection)"
                $usedServerAdmin = $false
                
                # Try to get cluster member and quorum info via T-SQL
                try {
                    $clusterQuery = @"
SELECT 
    member_name AS NodeName,
    member_type_desc AS MemberType,
    member_state_desc AS State,
    number_of_quorum_votes AS QuorumVotes
FROM sys.dm_hadr_cluster_members;
"@
                    $quorumDetails = Invoke-DbaQuery -SqlInstance $conn -Query $clusterQuery
                    $checkMethod = "T-SQL (sys.dm_hadr_cluster_members)"
                } catch {
                    # Cannot get cluster details via T-SQL
                }
                
                # Try with server admin credentials if available and T-SQL failed
                if ($hasServerAdminCreds -and -not $quorumDetails) {
                    try {
                        # Extract hostname from SQL Server connection
                        $computerName = $conn.ComputerNamePhysicalNetBIOS
                        if ([string]::IsNullOrWhiteSpace($computerName)) {
                            $computerName = $serverName.Split('\\')[0].Split(',')[0]
                        }
                        
                        # Try to get cluster quorum info via CIM/WMI with server admin credentials
                        try {
                            # Use Invoke-Command to run Get-ClusterQuorum on the remote server
                            $scriptBlock = {
                                try {
                                    # Check if cluster cmdlets are available
                                    if (Get-Command Get-ClusterQuorum -ErrorAction SilentlyContinue) {
                                        $quorum = Get-ClusterQuorum
                                        $nodes = Get-ClusterNode | Select-Object Name, State, NodeWeight
                                        
                                        return @{
                                            Success = $true
                                            QuorumType = $quorum.QuorumType.ToString()
                                            QuorumResource = $quorum.QuorumResource.Name
                                            Nodes = $nodes
                                        }
                                    } else {
                                        return @{ Success = $false; Error = "Cluster cmdlets not available" }
                                    }
                                } catch {
                                    return @{ Success = $false; Error = $_.Exception.Message }
                                }
                            }
                            
                            $clusterResult = Invoke-Command -ComputerName $computerName -Credential $serverAdminCredential -ScriptBlock $scriptBlock -ErrorAction Stop
                            
                            if ($clusterResult.Success) {
                                $quorumDetails = [pscustomobject]@{
                                    QuorumType = $clusterResult.QuorumType
                                    QuorumResource = $clusterResult.QuorumResource
                                    Nodes = $clusterResult.Nodes
                                    TotalNodes = $clusterResult.Nodes.Count
                                    NodesWithVotes = ($clusterResult.Nodes | Where-Object { $_.NodeWeight -gt 0 }).Count
                                }
                                $checkMethod = "PowerShell Remoting with Server Admin credentials"
                                $usedServerAdmin = $true
                                $healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin++
                            }
                        } catch {
                            # PowerShell remoting failed, try CIM
                            try {
                                $cimSession = New-CimSession -ComputerName $computerName -Credential $serverAdminCredential -ErrorAction Stop
                                $clusterNodes = Get-CimInstance -CimSession $cimSession -Namespace "root\MSCluster" -ClassName "MSCluster_Node" -ErrorAction Stop
                                
                                if ($clusterNodes) {
                                    $quorumDetails = [pscustomobject]@{
                                        QuorumType = "Retrieved via CIM"
                                        Nodes = $clusterNodes | Select-Object Name, State
                                        TotalNodes = $clusterNodes.Count
                                    }
                                    $checkMethod = "CIM/WMI with Server Admin credentials"
                                    $usedServerAdmin = $true
                                    $healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin++
                                }
                                
                                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                            } catch {
                                # CIM also failed - server admin creds didn't help
                            }
                        }
                    } catch {
                        # Server admin access didn't help
                    }
                }
                
                # Determine status based on what we found
                if ($quorumDetails) {
                    # Build CurrentValue based on data source
                    $currentValue = @{
                        IsClustered = $true
                        IsHadrEnabled = $clusterInfo.IsHadrEnabled -eq 1
                        CheckMethod = $checkMethod
                        ServerAdminUsed = $usedServerAdmin
                    }
                    
                    # Add appropriate fields based on data source
                    if ($quorumDetails.QuorumType) {
                        # Data from PowerShell/CIM (server admin)
                        $currentValue['QuorumType'] = $quorumDetails.QuorumType
                        if ($quorumDetails.QuorumResource) {
                            $currentValue['QuorumResource'] = $quorumDetails.QuorumResource
                        }
                        $currentValue['TotalNodes'] = $quorumDetails.TotalNodes
                        if ($quorumDetails.NodesWithVotes) {
                            $currentValue['NodesWithVotes'] = $quorumDetails.NodesWithVotes
                        }
                    } else {
                        # Data from T-SQL
                        $currentValue['TotalNodes'] = $quorumDetails.Count
                        $currentValue['NodesWithVotes'] = ($quorumDetails | Where-Object { $_.QuorumVotes -gt 0 }).Count
                    }
                    
                    $serverResults.Checks += @{
                        Category = "High Availability"
                        CheckName = "Cluster Quorum"
                        Status = "✅ Pass"
                        Severity = "Pass"
                        Description = if ($usedServerAdmin) { "Server is clustered - quorum details retrieved via Windows" } else { "Server is clustered with visible quorum members via T-SQL" }
                        Impact = "Windows Server Failover Cluster quorum determines which nodes can form a functioning cluster. Improper quorum configuration can lead to split-brain scenarios or cluster failure. Critical for AG and FCI high availability."
                        CurrentValue = $currentValue
                        RecommendedAction = if ($usedServerAdmin) { "Cluster quorum configuration retrieved successfully. Review details and verify health regularly." } else { "Cluster quorum visible via T-SQL. Consider providing MSSQLHC_SERVER_ADMIN credentials for complete quorum configuration details." }
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
                        RawData = if ($quorumDetails.Nodes) { 
                            # Data from PowerShell/CIM (server admin)
                            $quorumDetails.Nodes | Select-Object Name, State, NodeWeight 
                        } else { 
                            # Data from T-SQL
                            $quorumDetails | Select-Object NodeName, MemberType, State, QuorumVotes 
                        }
                    }
                } else {
                    # Cannot get detailed quorum info - provide manual check guidance
                    $serverResults.Checks += @{
                        Category = "High Availability"
                        CheckName = "Cluster Quorum"
                        Status = "ℹ️ Manual Check Required"
                        Severity = "Info"
                        Description = "Server is clustered but quorum details cannot be retrieved automatically. Manual verification required."
                        Impact = "Windows Server Failover Cluster quorum determines which nodes can form a functioning cluster. Improper quorum configuration can lead to split-brain scenarios or cluster failure. Critical for AG and FCI high availability."
                        CurrentValue = @{
                            IsClustered = $true
                            IsHadrEnabled = $clusterInfo.IsHadrEnabled -eq 1
                            ServerAdminCredsProvided = $hasServerAdminCreds
                            CheckMethod = $checkMethod
                        }
                        RecommendedAction = if ($hasServerAdminCreds) { "Could not retrieve cluster quorum details even with server admin credentials. Manually verify using Windows Failover Cluster Manager or PowerShell on the cluster node." } else { "Provide MSSQLHC_SERVER_ADMIN credentials for enhanced cluster checking, or manually verify cluster quorum using Windows Failover Cluster Manager or the PowerShell commands below." }
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

-- Try to check cluster nodes (SQL 2012+)
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

Note: For SQL Server 2012+, you can query sys.dm_hadr_cluster_members via T-SQL
"@
                        }
                        Documentation = @(
                            "https://learn.microsoft.com/en-us/windows-server/failover-clustering/manage-cluster-quorum",
                            "https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/windows/wsfc-quorum-modes-and-voting-configuration-sql-server",
                            "https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-hadr-cluster-members-transact-sql"
                        )
                        RawData = @{
                            IsClustered = $true
                            IsHadrEnabled = $clusterInfo.IsHadrEnabled -eq 1
                        }
                    }
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
        }  # End Check 44
        
        # ============================================================================
        # CHECK 45: AUTO GROWTH DISABLED (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 45 -CheckName "Auto Growth Disabled")) {
        
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
        }  # End Check 45
        
        # ============================================================================
        # CHECK 46: DISK BLOCK SIZE (ALLOCATION UNIT SIZE)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 46 -CheckName "Disk Block Size")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [46/$totalChecks] Checking disk block size (allocation unit size)..."
        
        try {
            $blockSizeCheck = $null
            $checkMethod = "Unknown"
            $usedServerAdmin = $false
            
            # Check if running on non-Windows platform
            if (-not $isWindows) {
                $checkMethod = "Platform not supported: This check requires Windows PowerShell Remoting with WMI access (not available on $detectedOS)"
            }
            # Try to get disk block size via PowerShell remoting (requires server admin credentials and Windows)
            elseif ($hasServerAdminCreds) {
                try {
                    # Extract hostname from SQL Server connection
                    $computerName = $conn.ComputerNamePhysicalNetBIOS
                    if ([string]::IsNullOrWhiteSpace($computerName)) {
                        $computerName = $serverName.Split('\\')[0].Split(',')[0]
                    }
                    
                    # Get disk block size using PowerShell remoting
                    $scriptBlock = {
                        try {
                            # Get all drives
                            $drives = Get-WmiObject -Class Win32_Volume -Filter "DriveType=3" | 
                                Where-Object { $_.FileSystem -eq 'NTFS' } |
                                Select-Object Name, Label, FileSystem, BlockSize, Capacity, FreeSpace
                            
                            return @{
                                Success = $true
                                Drives = $drives
                            }
                        } catch {
                            return @{ Success = $false; Error = $_.Exception.Message }
                        }
                    }
                    
                    $driveResult = Invoke-Command -ComputerName $computerName -Credential $serverAdminCredential -ScriptBlock $scriptBlock -ErrorAction Stop
                    
                    if ($driveResult.Success) {
                        $blockSizeCheck = $driveResult.Drives
                        $checkMethod = "PowerShell Remoting with Server Admin credentials"
                        $usedServerAdmin = $true
                        $healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin++
                    }
                } catch {
                    # PowerShell remoting failed
                    $checkMethod = "PowerShell Remoting failed: $($_.Exception.Message)"
                }
            } else {
                $checkMethod = "Server Admin credentials not provided"
            }
            
            # Analyze results
            if ($blockSizeCheck) {
                # Convert block sizes and check for non-64KB volumes
                $driveTable = @()
                $incorrectBlockSize = @()
                
                foreach ($drive in $blockSizeCheck) {
                    $blockSizeKB = $drive.BlockSize / 1024
                    $isCorrect = $blockSizeKB -eq 64
                    
                    $driveTable += [PSCustomObject]@{
                        DriveName = $drive.Name
                        Label = if ($drive.Label) { $drive.Label } else { "N/A" }
                        FileSystem = $drive.FileSystem
                        BlockSizeKB = $blockSizeKB
                        CapacityGB = [math]::Round($drive.Capacity / 1GB, 2)
                        FreeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
                        Status = if ($isCorrect) { "✅ Correct (64KB)" } else { "❌ Incorrect ($blockSizeKB KB)" }
                    }
                    
                    if (-not $isCorrect) {
                        $incorrectBlockSize += [PSCustomObject]@{
                            DriveName = $drive.Name
                            Label = if ($drive.Label) { $drive.Label } else { "N/A" }
                            BlockSizeKB = $blockSizeKB
                            ExpectedKB = 64
                        }
                    }
                }
                
                $serverResults.Checks += @{
                    Category = "Server Health"
                    CheckName = "Disk Block Size (Allocation Unit Size)"
                    Status = if ($incorrectBlockSize.Count -eq 0) { "✅ Pass" } else { "❌ Error" }
                    Severity = if ($incorrectBlockSize.Count -eq 0) { "Pass" } else { "Error" }
                    Description = "Verifies that disk volumes have 64KB allocation unit size (block size)"
                    Impact = "SQL Server performs best with 64KB allocation unit size. Smaller block sizes (default 4KB) cause more I/O operations, increased fragmentation, and degraded performance. This is especially critical for database data and log files. The wrong block size can reduce I/O throughput by 30-40%."
                    CurrentValue = @{
                        VolumesChecked = $driveTable.Count
                        VolumesWithIncorrectBlockSize = $incorrectBlockSize.Count
                        CheckMethod = $checkMethod
                        ServerAdminUsed = $usedServerAdmin
                    }
                    RecommendedAction = if ($incorrectBlockSize.Count -eq 0) { "All volumes have correct 64KB block size" } else { "WARNING: Volumes with incorrect block size require reformatting. This requires data migration and downtime. Plan carefully!" }
                    RemediationSteps = @{
                        PowerShell = @"
# Check current block sizes on all NTFS volumes
Get-WmiObject -Class Win32_Volume -Filter "DriveType=3" | 
    Where-Object { `$_.FileSystem -eq 'NTFS' } |
    Select-Object Name, Label, FileSystem, 
        @{N='BlockSizeKB';E={`$_.BlockSize/1KB}}, 
        @{N='CapacityGB';E={[math]::Round(`$_.Capacity/1GB,2)}}, 
        @{N='FreeSpaceGB';E={[math]::Round(`$_.FreeSpace/1GB,2)}} |
    Format-Table -AutoSize

# WARNING: Changing block size requires reformatting the volume!
# This will DESTROY ALL DATA on the volume.
# You must:
# 1. Backup all databases
# 2. Stop SQL Server
# 3. Move/backup all files
# 4. Format with 64KB allocation unit size
# 5. Restore data
# 6. Start SQL Server
"@
                        TSQL = @"
-- Check which SQL Server files are on which drives
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    name AS LogicalFileName,
    type_desc AS FileType,
    physical_name AS PhysicalPath,
    size * 8 / 1024 AS SizeMB
FROM sys.master_files
ORDER BY physical_name;

-- Use this to plan which volumes need reformatting
"@
                        Manual = @"
**CRITICAL: Changing allocation unit size requires reformatting and causes DATA LOSS**

**Planning Steps:**
1. Identify which SQL Server files are on volumes with incorrect block size
2. Schedule maintenance window (requires significant downtime)
3. Full backup of all databases
4. Document current file locations

**Migration Process:**
1. Stop SQL Server service
2. Backup or move all files from the volume to temporary storage
3. Format volume with 64KB allocation unit:
   - Right-click drive in Disk Management
   - Format → Allocation unit size → 64 kilobytes
   - OR command line: format E: /FS:NTFS /A:64K /Q
4. Move SQL Server files back to formatted volume
5. Start SQL Server service
6. Verify databases are accessible

**Prevention:**
- Always format SQL Server volumes with 64KB allocation unit BEFORE installing SQL Server
- Standard for: Windows 2019/2022 + SQL Server 2016+
- Check new volumes before use

**Alternative (if reformatting not possible):**
- Migrate to new volume with correct block size
- Use Storage Migration Service
- Plan for new hardware with proper configuration
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-files-and-filegroups",
                        "https://techcommunity.microsoft.com/blog/dataplatformblog/sql-server-best-practices-–-selecting-storage-subsystem-disk-allocation-unit-size/298261",
                        "https://www.mssqltips.com/sqlservertip/7353/sql-server-disk-partition-alignment-allocation-unit-size/"
                    )
                    RawData = $driveTable
                }
            } else {
                # Could not check - provide manual instructions
                $serverResults.Checks += @{
                    Category = "Server Health"
                    CheckName = "Disk Block Size (Allocation Unit Size)"
                    Status = "ℹ️ Manual Check Required"
                    Severity = "Info"
                    Description = "Could not automatically check disk block size. Manual verification required."
                    Impact = "SQL Server performs best with 64KB allocation unit size. Smaller block sizes (default 4KB) cause more I/O operations, increased fragmentation, and degraded performance. This is especially critical for database data and log files."
                    CurrentValue = @{
                        ServerAdminCredsProvided = $hasServerAdminCreds
                        CheckMethod = $checkMethod
                    }
                    RecommendedAction = if (-not $isWindows) { "This check requires Windows PowerShell Remoting with WMI (not available on $detectedOS). Manually verify disk block size on the Windows SQL Server host using the PowerShell commands below." } elseif ($hasServerAdminCreds) { "Could not check block size even with server admin credentials. Manually verify using PowerShell commands below." } else { "Provide MSSQLHC_SERVER_ADMIN credentials for automatic checking (Windows only), or manually verify disk block size using the PowerShell commands below." }
                    RemediationSteps = @{
                        PowerShell = @"
# Check block size on all NTFS volumes (run on SQL Server host)
Get-WmiObject -Class Win32_Volume -Filter "DriveType=3" | 
    Where-Object { `$_.FileSystem -eq 'NTFS' } |
    Select-Object Name, Label, FileSystem, 
        @{N='BlockSizeKB';E={`$_.BlockSize/1KB}}, 
        @{N='CapacityGB';E={[math]::Round(`$_.Capacity/1GB,2)}} |
    Format-Table -AutoSize

# Expected: BlockSizeKB should be 64 for SQL Server volumes
# Default Windows format is 4KB - this is NOT optimal for SQL Server
"@
                        TSQL = @"
-- Check which volumes host SQL Server files
SELECT DISTINCT
    LEFT(physical_name, 3) AS Drive,
    COUNT(*) AS FileCount
FROM sys.master_files
GROUP BY LEFT(physical_name, 3)
ORDER BY Drive;
"@
                        Manual = @"
1. Log into SQL Server host with administrator credentials
2. Open PowerShell as Administrator
3. Run: Get-WmiObject -Class Win32_Volume -Filter "DriveType=3" | Where-Object { `$_.FileSystem -eq 'NTFS' } | Select-Object Name, @{N='BlockSizeKB';E={`$_.BlockSize/1KB}}
4. Verify all volumes used by SQL Server show 64KB
5. If any show 4KB (default), they should be reformatted with 64KB allocation unit size
6. Note: Reformatting requires moving data off the volume first (destructive operation)
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-files-and-filegroups",
                        "https://techcommunity.microsoft.com/blog/dataplatformblog/sql-server-best-practices-–-selecting-storage-subsystem-disk-allocation-unit-size/298261"
                    )
                    RawData = @{ CheckMethod = $checkMethod }
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Server Health"; CheckName = "Disk Block Size"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check disk block size"; Error = $_.Exception.Message }
        }
        }  # End Check 46
        
        # ============================================================================
        # CHECK 47: QUERY STORE STATUS (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 47 -CheckName "Query Store Status")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [47/$totalChecks] Checking Query Store status..."
        
        try {
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            $qsDisabled = @()
            $qsTable = @()
            
            foreach ($db in $databases) {
                # Query Store is only available in SQL 2016+ (version 13+)
                if ($conn.VersionMajor -ge 13) {
                    $query = @"
SELECT 
    actual_state_desc AS ActualState,
    readonly_reason,
    desired_state_desc AS DesiredState,
    current_storage_size_mb,
    max_storage_size_mb,
    query_capture_mode_desc AS CaptureMode
FROM sys.database_query_store_options;
"@
                    $qsInfo = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $query
                    
                    $isEnabled = $qsInfo.ActualState -ne 'OFF'
                    
                    $qsTable += [PSCustomObject]@{
                        Database = $db.Name
                        Status = if ($isEnabled) { "✅ Enabled" } else { "❌ Disabled" }
                        ActualState = if ($qsInfo.ActualState) { $qsInfo.ActualState } else { "OFF" }
                        DesiredState = if ($qsInfo.DesiredState) { $qsInfo.DesiredState } else { "OFF" }
                        StorageMB = if ($qsInfo.current_storage_size_mb) { $qsInfo.current_storage_size_mb } else { 0 }
                        MaxStorageMB = if ($qsInfo.max_storage_size_mb) { $qsInfo.max_storage_size_mb } else { 0 }
                        CaptureMode = if ($qsInfo.CaptureMode) { $qsInfo.CaptureMode } else { "NONE" }
                    }
                    
                    if (-not $isEnabled) {
                        $qsDisabled += $db.Name
                    }
                } else {
                    $qsTable += [PSCustomObject]@{
                        Database = $db.Name
                        Status = "ℹ️ Not Supported (SQL 2016+ required)"
                        ActualState = "N/A"
                        DesiredState = "N/A"
                        StorageMB = 0
                        MaxStorageMB = 0
                        CaptureMode = "N/A"
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Query Store Status"
                Status = if ($conn.VersionMajor -lt 13) { "ℹ️ Info" } elseif ($qsDisabled.Count -eq 0) { "✅ Pass" } elseif ($qsDisabled.Count -lt $databases.Count * 0.5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($conn.VersionMajor -lt 13) { "Info" } elseif ($qsDisabled.Count -eq 0) { "Pass" } elseif ($qsDisabled.Count -lt $databases.Count * 0.5) { "Warning" } else { "Error" }
                Description = "Verifies Query Store is enabled on user databases for performance monitoring"
                Impact = "Query Store is essential for modern SQL Server performance management. It captures query execution history, plans, and statistics, enabling identification of performance regressions, plan changes, and query tuning. Without Query Store, troubleshooting performance issues is significantly harder. Available in SQL Server 2016+."
                CurrentValue = @{
                    SQLServerVersion = $conn.VersionString
                    VersionSupportsQueryStore = $conn.VersionMajor -ge 13
                    DatabasesWithQSDisabled = $qsDisabled.Count
                    TotalDatabases = $databases.Count
                }
                RecommendedAction = if ($conn.VersionMajor -lt 13) { "Query Store requires SQL Server 2016 or later" } elseif ($qsDisabled.Count -eq 0) { "Query Store is enabled on all databases" } else { "Enable Query Store on production databases" }
                RemediationSteps = @{
                    PowerShell = @"
# Enable Query Store on specific database
Set-DbaDbQueryStoreOption -SqlInstance '$serverName' -Database 'DatabaseName' -State ReadWrite

# Enable on all user databases
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | 
    Set-DbaDbQueryStoreOption -State ReadWrite

# Configure Query Store with recommended settings
Set-DbaDbQueryStoreOption -SqlInstance '$serverName' -Database 'DatabaseName' `
    -State ReadWrite `
    -MaxStorageSize 1024 `
    -DataFlushInterval 900 `
    -CaptureMode Auto
"@
                    TSQL = @"
-- Enable Query Store (SQL 2016+)
ALTER DATABASE [DatabaseName] 
SET QUERY_STORE = ON;

-- Configure Query Store with recommended settings
ALTER DATABASE [DatabaseName]
SET QUERY_STORE (
    OPERATION_MODE = READ_WRITE,
    DATA_FLUSH_INTERVAL_SECONDS = 900,
    MAX_STORAGE_SIZE_MB = 1024,
    QUERY_CAPTURE_MODE = AUTO,
    SIZE_BASED_CLEANUP_MODE = AUTO,
    MAX_PLANS_PER_QUERY = 200
);

-- Check Query Store status
SELECT 
    name AS DatabaseName,
    is_query_store_on
FROM sys.databases
WHERE database_id > 4;
"@
                    Manual = @"
1. Query Store requires SQL Server 2016 (13.x) or later
2. Enable on production databases for performance monitoring
3. Recommended settings:
   - Operation Mode: READ_WRITE
   - Max Storage: 1GB (1024MB) or larger for busy databases
   - Data Flush Interval: 15 minutes (900 seconds)
   - Capture Mode: AUTO (captures relevant queries)
   - Cleanup Mode: AUTO (size-based)
4. Monitor Query Store storage usage regularly
5. Use Query Store reports in SSMS for performance analysis
6. Not recommended for: TempDB, very high transaction databases where overhead is critical
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance/monitoring-performance-by-using-the-query-store",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/performance/best-practice-with-the-query-store"
                )
                RawData = $qsTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Query Store Status"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check Query Store"; Error = $_.Exception.Message }
        }
        }  # End Check 47
        
        # ============================================================================
        # CHECK 48: TRANSPARENT DATA ENCRYPTION (TDE) (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 48 -CheckName "Transparent Data Encryption")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [48/$totalChecks] Checking Transparent Data Encryption status..."
        
        try {
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            $tdeTable = @()
            $unencryptedDbs = @()
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    d.name AS DatabaseName,
    ISNULL(e.encryption_state, 0) AS EncryptionState,
    CASE ISNULL(e.encryption_state, 0)
        WHEN 0 THEN 'No encryption'
        WHEN 1 THEN 'Unencrypted'
        WHEN 2 THEN 'Encryption in progress'
        WHEN 3 THEN 'Encrypted'
        WHEN 4 THEN 'Key change in progress'
        WHEN 5 THEN 'Decryption in progress'
        WHEN 6 THEN 'Protection change in progress'
    END AS EncryptionStateDesc,
    e.encryptor_type,
    e.percent_complete
FROM sys.databases d
LEFT JOIN sys.dm_database_encryption_keys e ON d.database_id = e.database_id
WHERE d.name = '$($db.Name)';
"@
                $tdeInfo = Invoke-DbaQuery -SqlInstance $conn -Query $query
                
                $isEncrypted = $tdeInfo.EncryptionState -eq 3
                
                $tdeTable += [PSCustomObject]@{
                    Database = $db.Name
                    Status = if ($isEncrypted) { "✅ Encrypted" } else { "❌ Not Encrypted" }
                    EncryptionState = $tdeInfo.EncryptionStateDesc
                    PercentComplete = if ($tdeInfo.percent_complete) { $tdeInfo.percent_complete } else { 0 }
                }
                
                if (-not $isEncrypted -and $tdeInfo.EncryptionState -ne 2) {
                    $unencryptedDbs += $db.Name
                }
            }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Transparent Data Encryption (TDE)"
                Status = if ($unencryptedDbs.Count -eq 0) { "✅ Pass" } elseif ($unencryptedDbs.Count -lt $databases.Count * 0.3) { "⚠️ Warning" } else { "ℹ️ Info" }
                Severity = if ($unencryptedDbs.Count -eq 0) { "Pass" } else { "Info" }
                Description = "Checks if databases are encrypted using Transparent Data Encryption (TDE)"
                Impact = "TDE provides encryption at rest for data and log files, protecting against unauthorized access to database files. Required for many compliance standards (PCI-DSS, HIPAA, GDPR). Without TDE, database files and backups are stored in plain text. Note: TDE is available in Enterprise Edition or can be licensed separately."
                CurrentValue = @{
                    TotalDatabases = $databases.Count
                    EncryptedDatabases = $databases.Count - $unencryptedDbs.Count
                    UnencryptedDatabases = $unencryptedDbs.Count
                }
                RecommendedAction = if ($unencryptedDbs.Count -eq 0) { "All databases are encrypted with TDE" } else { "Consider enabling TDE on databases containing sensitive data (requires Enterprise Edition or separate licensing)" }
                RemediationSteps = @{
                    PowerShell = @"
# Check TDE status
Get-DbaDbEncryption -SqlInstance '$serverName' | 
    Select-Object Database, EncryptionEnabled, EncryptionState |
    Format-Table

# Enable TDE (requires Enterprise Edition or Standard with TDE license)
# Step 1: Create master key in master database
Invoke-DbaQuery -SqlInstance '$serverName' -Database master -Query @'
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!'
'@

# Step 2: Create certificate in master database  
Invoke-DbaQuery -SqlInstance '$serverName' -Database master -Query @'
CREATE CERTIFICATE TDE_Cert WITH SUBJECT = 'TDE Certificate'
'@

# Step 3: Create database encryption key
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'YourDatabase' -Query @'
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDE_Cert
'@

# Step 4: Enable encryption
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'YourDatabase' -Query @'
ALTER DATABASE [YourDatabase] SET ENCRYPTION ON
'@

# IMPORTANT: Backup the certificate and private key!
Backup-DbaDbCertificate -SqlInstance '$serverName' -Certificate TDE_Cert -Path 'C:\\Backup\\Certificates'
"@
                    TSQL = @"
-- Step 1: Create master key in master (if not exists)
USE master;
GO
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'UseStrongPasswordHere!';
GO

-- Step 2: Create certificate for TDE
CREATE CERTIFICATE TDE_Cert 
WITH SUBJECT = 'Database Encryption Certificate';
GO

-- Step 3: Create database encryption key in user database
USE [YourDatabase];
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDE_Cert;
GO

-- Step 4: Enable encryption
ALTER DATABASE [YourDatabase] 
SET ENCRYPTION ON;
GO

-- Check encryption progress
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    encryption_state,
    percent_complete,
    CASE encryption_state
        WHEN 0 THEN 'No encryption'
        WHEN 1 THEN 'Unencrypted'
        WHEN 2 THEN 'Encryption in progress'
        WHEN 3 THEN 'Encrypted'
        WHEN 4 THEN 'Key change in progress'
        WHEN 5 THEN 'Decryption in progress'
    END AS State
FROM sys.dm_database_encryption_keys;
GO

-- CRITICAL: Backup certificate and private key
BACKUP CERTIFICATE TDE_Cert
TO FILE = 'C:\\Backup\\TDE_Cert.cer'
WITH PRIVATE KEY (
    FILE = 'C:\\Backup\\TDE_Cert_PrivateKey.pvk',
    ENCRYPTION BY PASSWORD = 'AnotherStrongPassword!'
);
GO
"@
                    Manual = @"
**CRITICAL PREREQUISITES:**
1. TDE requires SQL Server Enterprise Edition (or Standard Edition with TDE add-on license)
2. Performance impact: ~3-5% CPU overhead for encryption/decryption
3. ALWAYS backup the TDE certificate and private key - without them, encrypted databases cannot be restored!

**Implementation Steps:**
1. Verify licensing (Enterprise Edition or TDE license)
2. Create master key in master database
3. Create TDE certificate in master database
4. Backup certificate and private key to secure location (CRITICAL!)
5. Create database encryption key in target database
6. Enable encryption (ALTER DATABASE SET ENCRYPTION ON)
7. Monitor encryption progress (can take hours for large databases)
8. Store certificate backup in multiple secure locations
9. Document certificate password in secure password vault

**Important Notes:**
- Backups of encrypted databases are also encrypted
- Cannot restore encrypted backup without certificate
- TempDB is automatically encrypted when any database uses TDE
- Consider impact on Always On AG (certificate must exist on all replicas)
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/move-a-tde-protected-database-to-another-sql-server"
                )
                RawData = $tdeTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "TDE Status"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check TDE"; Error = $_.Exception.Message }
        }
        }  # End Check 48
        
        # ============================================================================
        # CHECK 49: DATABASE SNAPSHOTS (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 49 -CheckName "Database Snapshots")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [49/$totalChecks] Checking for database snapshots..."
        
        try {
            $query = @"
SELECT 
    d.name AS SnapshotName,
    s.name AS SourceDatabase,
    d.create_date AS CreatedDate,
    DATEDIFF(DAY, d.create_date, GETDATE()) AS AgeInDays,
    SUM(f.size) * 8 / 1024 AS SizeMB
FROM sys.databases d
INNER JOIN sys.databases s ON d.source_database_id = s.database_id
INNER JOIN sys.master_files f ON d.database_id = f.database_id
WHERE d.source_database_id IS NOT NULL
GROUP BY d.name, s.name, d.create_date
ORDER BY d.create_date DESC;
"@
            $snapshots = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $snapshotTable = @()
            $oldSnapshots = @()
            
            foreach ($snap in $snapshots) {
                $snapshotTable += [PSCustomObject]@{
                    SnapshotName = $snap.SnapshotName
                    SourceDatabase = $snap.SourceDatabase
                    CreatedDate = $snap.CreatedDate
                    AgeInDays = $snap.AgeInDays
                    SizeMB = $snap.SizeMB
                    Status = if ($snap.AgeInDays -gt 7) { "⚠️ Old (>7 days)" } else { "✅ Recent" }
                }
                
                if ($snap.AgeInDays -gt 7) {
                    $oldSnapshots += $snap.SnapshotName
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Database Snapshots"
                Status = if ($snapshots.Count -eq 0) { "✅ Pass" } elseif ($oldSnapshots.Count -gt 0) { "⚠️ Warning" } else { "ℹ️ Info" }
                Severity = if ($snapshots.Count -eq 0) { "Pass" } elseif ($oldSnapshots.Count -gt 0) { "Warning" } else { "Info" }
                Description = "Identifies database snapshots that may be consuming disk space"
                Impact = "Database snapshots are read-only point-in-time copies used for reporting or testing. They consume disk space as the source database changes. Old snapshots (>7 days) may indicate forgotten test snapshots that should be cleaned up. Snapshots can grow to significant sizes and impact performance if not managed."
                CurrentValue = @{
                    TotalSnapshots = $snapshots.Count
                    OldSnapshots = $oldSnapshots.Count
                }
                RecommendedAction = if ($snapshots.Count -eq 0) { "No database snapshots found" } elseif ($oldSnapshots.Count -gt 0) { "Review and remove old database snapshots" } else { "Recent snapshots found - verify they are still needed" }
                RemediationSteps = @{
                    PowerShell = @"
# List all database snapshots
Get-DbaDbSnapshot -SqlInstance '$serverName' | 
    Select-Object Name, SnapshotOf, CreateDate, SizeMB |
    Format-Table

# Remove specific snapshot
Remove-DbaDbSnapshot -SqlInstance '$serverName' -Snapshot 'SnapshotName' -Confirm:`$false

# Remove all snapshots for a database
Get-DbaDbSnapshot -SqlInstance '$serverName' -Database 'SourceDatabase' |
    Remove-DbaDbSnapshot -Confirm:`$false
"@
                    TSQL = @"
-- List all database snapshots
SELECT 
    d.name AS SnapshotName,
    s.name AS SourceDatabase,
    d.create_date AS CreatedDate,
    DATEDIFF(DAY, d.create_date, GETDATE()) AS AgeInDays
FROM sys.databases d
INNER JOIN sys.databases s ON d.source_database_id = s.database_id
WHERE d.source_database_id IS NOT NULL
ORDER BY d.create_date DESC;

-- Drop a database snapshot
DROP DATABASE [SnapshotName];
"@
                    Manual = @"
1. Review all existing snapshots
2. Verify each snapshot's purpose and owner
3. Remove snapshots that are:
   - Older than 7 days (unless documented reason to keep)
   - Created for testing and no longer needed
   - From databases that no longer exist
4. Document snapshot usage policy
5. Consider automating snapshot cleanup
6. Remember: Snapshots cannot be backed up and grow with source database changes
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-snapshots-sql-server"
                )
                RawData = $snapshotTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Database Snapshots"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check snapshots"; Error = $_.Exception.Message }
        }
        }  # End Check 49
        
        # ============================================================================
        # CHECK 50: DATABASE COLLATION MISMATCH (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 50 -CheckName "Database Collation Mismatch")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [50/$totalChecks] Checking database collation mismatches..."
        
        try {
            $serverCollation = $conn.Collation
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            $collationTable = @()
            $mismatchedDbs = @()
            
            foreach ($db in $databases) {
                $dbCollation = $db.Collation
                $isMatch = $dbCollation -eq $serverCollation
                
                $collationTable += [PSCustomObject]@{
                    Database = $db.Name
                    Collation = $dbCollation
                    ServerCollation = $serverCollation
                    Status = if ($isMatch) { "✅ Match" } else { "⚠️ Mismatch" }
                }
                
                if (-not $isMatch) {
                    $mismatchedDbs += $db.Name
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Database Collation Mismatch"
                Status = if ($mismatchedDbs.Count -eq 0) { "✅ Pass" } elseif ($mismatchedDbs.Count -lt 3) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($mismatchedDbs.Count -eq 0) { "Pass" } elseif ($mismatchedDbs.Count -lt 3) { "Warning" } else { "Error" }
                Description = "Checks if database collations differ from server collation"
                Impact = "Collation mismatches can cause comparison errors in queries joining temp tables or variables with database tables. TempDB uses server collation, so mismatches require COLLATE clauses in queries. Can also indicate restored databases from different servers. Not always a problem but should be documented and understood."
                CurrentValue = @{
                    ServerCollation = $serverCollation
                    DatabasesWithMismatch = $mismatchedDbs.Count
                    TotalDatabases = $databases.Count
                }
                RecommendedAction = if ($mismatchedDbs.Count -eq 0) { "All databases match server collation" } else { "Review collation mismatches - may require explicit COLLATE clauses in queries" }
                RemediationSteps = @{
                    PowerShell = @"
# Check collations
Get-DbaDbCollation -SqlInstance '$serverName' | 
    Select-Object Database, Collation, ServerCollation |
    Format-Table

# Check server collation
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT SERVERPROPERTY('Collation') AS ServerCollation
'@
"@
                    TSQL = @"
-- Check server and database collations
SELECT 
    name AS DatabaseName,
    collation_name AS DatabaseCollation,
    SERVERPROPERTY('Collation') AS ServerCollation,
    CASE 
        WHEN collation_name = CAST(SERVERPROPERTY('Collation') AS VARCHAR(100)) THEN 'Match'
        ELSE 'Mismatch'
    END AS Status
FROM sys.databases
WHERE database_id > 4
ORDER BY name;

-- Example query with explicit COLLATE (workaround for mismatches)
SELECT *
FROM MyTable t
INNER JOIN #TempTable tmp 
    ON t.StringColumn COLLATE DATABASE_DEFAULT = tmp.StringColumn;

-- WARNING: Changing database collation is complex and risky
-- It does NOT change existing column collations
-- Only changes default for new objects
ALTER DATABASE [DatabaseName] 
COLLATE SQL_Latin1_General_CP1_CI_AS;
"@
                    Manual = @"
**Understanding Collation Mismatches:**
1. Not always a problem - depends on query patterns
2. Common causes:
   - Restored from different server
   - Intentional (e.g., case-sensitive database)
   - Legacy databases migrated from older SQL versions

**When to Fix:**
- If queries fail with collation conflict errors
- If using temp tables/variables that join with database tables
- For consistency in new environments

**Important Notes:**
- Changing database collation does NOT change existing column collations
- Must rebuild all indexes and constraints after change
- Extensive testing required
- Often easier to use COLLATE clauses in problem queries

**Workaround:**
Use COLLATE DATABASE_DEFAULT in queries:
WHERE t.Column COLLATE DATABASE_DEFAULT = @Variable
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/collations/set-or-change-the-database-collation",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/collations/collation-and-unicode-support"
                )
                RawData = $collationTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Collation Mismatch"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check collations"; Error = $_.Exception.Message }
        }
        }  # End Check 50
        
        # ============================================================================
        # CHECK 51: AUTO CREATE/UPDATE STATISTICS (Database Health)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 51 -CheckName "Auto Create/Update Statistics")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [51/$totalChecks] Checking auto statistics settings..."
        
        try {
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            $statsTable = @()
            $disabledDbs = @()
            
            foreach ($db in $databases) {
                $autoCreate = $db.AutoCreateStatisticsEnabled
                $autoUpdate = $db.AutoUpdateStatisticsEnabled
                $autoUpdateAsync = $db.AutoUpdateStatisticsAsync
                
                $bothEnabled = $autoCreate -and $autoUpdate
                
                $statsTable += [PSCustomObject]@{
                    Database = $db.Name
                    AutoCreate = if ($autoCreate) { "✅ Enabled" } else { "❌ Disabled" }
                    AutoUpdate = if ($autoUpdate) { "✅ Enabled" } else { "❌ Disabled" }
                    AutoUpdateAsync = if ($autoUpdateAsync) { "✅ Enabled" } else { "❌ Disabled" }
                    Status = if ($bothEnabled) { "✅ Correct" } else { "❌ Issue" }
                }
                
                if (-not $bothEnabled) {
                    $disabledDbs += $db.Name
                }
            }
            
            $serverResults.Checks += @{
                Category = "Database Health"
                CheckName = "Auto Create/Update Statistics"
                Status = if ($disabledDbs.Count -eq 0) { "✅ Pass" } else { "❌ Error" }
                Severity = if ($disabledDbs.Count -eq 0) { "Pass" } else { "Error" }
                Description = "Verifies automatic statistics creation and updating is enabled"
                Impact = "Auto Create/Update Statistics are critical for query performance. Without them, the query optimizer lacks accurate data distribution information, leading to poor execution plans, full table scans, and performance degradation. These should almost always be enabled. Disabling them is rarely appropriate and causes significant performance issues."
                CurrentValue = @{
                    DatabasesWithDisabledStats = $disabledDbs.Count
                    TotalDatabases = $databases.Count
                }
                RecommendedAction = if ($disabledDbs.Count -eq 0) { "Statistics settings are correct on all databases" } else { "Enable auto create/update statistics immediately on affected databases" }
                RemediationSteps = @{
                    PowerShell = @"
# Check statistics settings
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem |
    Select-Object Name, AutoCreateStatisticsEnabled, AutoUpdateStatisticsEnabled, AutoUpdateStatisticsAsync |
    Format-Table

# Enable auto create statistics
Set-DbaDbAutoStatistics -SqlInstance '$serverName' -Database 'DatabaseName' -AutoCreateStatistics

# Enable auto update statistics  
Set-DbaDbAutoStatistics -SqlInstance '$serverName' -Database 'DatabaseName' -AutoUpdateStatistics

# Enable on all user databases
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem |
    Set-DbaDbAutoStatistics -AutoCreateStatistics -AutoUpdateStatistics
"@
                    TSQL = @"
-- Check current settings
SELECT 
    name AS DatabaseName,
    is_auto_create_stats_on AS AutoCreate,
    is_auto_update_stats_on AS AutoUpdate,
    is_auto_update_stats_async_on AS AutoUpdateAsync
FROM sys.databases
WHERE database_id > 4;

-- Enable auto create statistics
ALTER DATABASE [DatabaseName] 
SET AUTO_CREATE_STATISTICS ON;

-- Enable auto update statistics
ALTER DATABASE [DatabaseName] 
SET AUTO_UPDATE_STATISTICS ON;

-- Optional: Enable async stats update (for large databases)
ALTER DATABASE [DatabaseName] 
SET AUTO_UPDATE_STATISTICS_ASYNC ON;

-- Verify settings
SELECT DATABASEPROPERTYEX('DatabaseName', 'IsAutoCreateStatistics') AS AutoCreate,
       DATABASEPROPERTYEX('DatabaseName', 'IsAutoUpdateStatistics') AS AutoUpdate;
"@
                    Manual = @"
**CRITICAL: Auto statistics should almost always be enabled**

1. Enable AUTO_CREATE_STATISTICS
   - Creates statistics automatically on columns used in predicates
   - Essential for good query plans

2. Enable AUTO_UPDATE_STATISTICS
   - Updates statistics as data changes
   - Keeps optimizer information current

3. Consider AUTO_UPDATE_STATISTICS_ASYNC
   - For large, busy databases
   - Prevents queries from waiting for stats updates
   - Stats update happens in background

**When to Disable (RARE):**
- Never on OLTP databases
- Possibly on read-only data warehouses with manual maintenance
- Only if you have automated statistics maintenance

**Impact of Disabled Stats:**
- Poor execution plans
- Full table scans instead of index seeks
- Excessive memory grants
- Severe performance degradation
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/statistics/statistics",
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-set-options"
                )
                RawData = $statsTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Database Health"; CheckName = "Auto Statistics"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check statistics settings"; Error = $_.Exception.Message }
        }
        }  # End Check 51
        
        # ============================================================================
        # CHECK 52: CERTIFICATE EXPIRATION (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 52 -CheckName "Certificate Expiration")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [52/$totalChecks] Checking certificate expiration dates..."
        
        try {
            $query = @"
SELECT 
    name AS CertificateName,
    pvt_key_encryption_type_desc AS EncryptionType,
    start_date AS StartDate,
    expiry_date AS ExpiryDate,
    DATEDIFF(DAY, GETDATE(), expiry_date) AS DaysUntilExpiry,
    subject AS Subject
FROM sys.certificates
WHERE pvt_key_encryption_type_desc <> 'NA'
ORDER BY expiry_date;
"@
            $certificates = Invoke-DbaQuery -SqlInstance $conn -Database master -Query $query
            
            $certTable = @()
            $expiringCerts = @()
            $expiredCerts = @()
            
            foreach ($cert in $certificates) {
                $daysUntilExpiry = $cert.DaysUntilExpiry
                
                $certTable += [PSCustomObject]@{
                    Certificate = $cert.CertificateName
                    Subject = $cert.Subject
                    StartDate = $cert.StartDate
                    ExpiryDate = $cert.ExpiryDate
                    DaysUntilExpiry = $daysUntilExpiry
                    Status = if ($daysUntilExpiry -lt 0) { "❌ Expired" } elseif ($daysUntilExpiry -lt 30) { "❌ Critical (<30 days)" } elseif ($daysUntilExpiry -lt 90) { "⚠️ Warning (<90 days)" } else { "✅ Valid" }
                }
                
                if ($daysUntilExpiry -lt 0) {
                    $expiredCerts += $cert.CertificateName
                } elseif ($daysUntilExpiry -lt 90) {
                    $expiringCerts += $cert.CertificateName
                }
            }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Certificate Expiration"
                Status = if ($expiredCerts.Count -gt 0) { "❌ Error" } elseif ($expiringCerts.Count -gt 0) { "⚠️ Warning" } elseif ($certificates.Count -eq 0) { "ℹ️ Info" } else { "✅ Pass" }
                Severity = if ($expiredCerts.Count -gt 0) { "Error" } elseif ($expiringCerts.Count -gt 0) { "Warning" } else { "Pass" }
                Description = "Checks for expired or soon-to-expire certificates used for encryption"
                Impact = "Expired certificates can cause TDE-encrypted databases to become inaccessible, break Always On AG endpoint encryption, prevent database mirroring, and disrupt service broker communication. Certificate expiration is one of the most critical security incidents requiring immediate attention. Always On AG replicas may fail to synchronize if endpoint certificates expire."
                CurrentValue = @{
                    TotalCertificates = $certificates.Count
                    ExpiredCertificates = $expiredCerts.Count
                    ExpiringCertificates = $expiringCerts.Count
                }
                RecommendedAction = if ($expiredCerts.Count -gt 0) { "URGENT: Renew expired certificates immediately" } elseif ($expiringCerts.Count -gt 0) { "Renew certificates expiring within 90 days" } elseif ($certificates.Count -eq 0) { "No certificates with private keys found" } else { "All certificates are valid" }
                RemediationSteps = @{
                    PowerShell = @"
# Check certificate expiration
Invoke-DbaQuery -SqlInstance '$serverName' -Database master -Query @'
SELECT name, start_date, expiry_date, 
       DATEDIFF(DAY, GETDATE(), expiry_date) AS DaysUntilExpiry
FROM sys.certificates
WHERE pvt_key_encryption_type_desc <> 'NA'
ORDER BY expiry_date
'@ | Format-Table

# For TDE certificates - create new certificate and re-encrypt
# Step 1: Create new certificate with extended expiration
Invoke-DbaQuery -SqlInstance '$serverName' -Database master -Query @'
CREATE CERTIFICATE TDE_Cert_New
WITH SUBJECT = 'TDE Certificate 2026',
     EXPIRY_DATE = '2027-12-31'
'@

# Step 2: Backup the new certificate (CRITICAL!)
Backup-DbaDbCertificate -SqlInstance '$serverName' -Certificate TDE_Cert_New -Path 'C:\\Backup\\Certificates'

# Step 3: Re-encrypt database with new certificate
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'YourDatabase' -Query @'
ALTER DATABASE ENCRYPTION KEY
ENCRYPTION BY SERVER CERTIFICATE TDE_Cert_New
'@

# For Always On AG endpoint certificates - requires downtime coordination
"@
                    TSQL = @"
-- Check all certificates and expiration
SELECT 
    name AS CertificateName,
    subject,
    start_date,
    expiry_date,
    DATEDIFF(DAY, GETDATE(), expiry_date) AS DaysUntilExpiry,
    pvt_key_encryption_type_desc
FROM sys.certificates
ORDER BY expiry_date;

-- Create new certificate with explicit expiration date
USE master;
GO
CREATE CERTIFICATE TDE_Cert_New
WITH SUBJECT = 'TDE Certificate Renewal',
     EXPIRY_DATE = '2027-12-31';  -- Set appropriate date
GO

-- Backup new certificate (CRITICAL - do this before anything else!)
BACKUP CERTIFICATE TDE_Cert_New
TO FILE = 'C:\\Backup\\TDE_Cert_New.cer'
WITH PRIVATE KEY (
    FILE = 'C:\\Backup\\TDE_Cert_New_PrivateKey.pvk',
    ENCRYPTION BY PASSWORD = 'StrongPassword123!'
);
GO

-- Re-encrypt database with new certificate
USE [YourDatabase];
GO
ALTER DATABASE ENCRYPTION KEY
ENCRYPTION BY SERVER CERTIFICATE TDE_Cert_New;
GO

-- Drop old certificate (only after verifying new one works!)
-- USE master;
-- DROP CERTIFICATE TDE_Cert_Old;
"@
                    Manual = @"
**CRITICAL - Certificate Renewal Process:**

**For TDE Certificates:**
1. Create new certificate with extended expiration (3-5 years)
2. IMMEDIATELY backup new certificate and private key
3. Store backup in multiple secure locations
4. Re-encrypt database encryption key with new certificate
5. Test database restore on another server
6. Keep old certificate until all backups are using new certificate
7. Monitor backup retention period before removing old certificate

**For Always On AG Endpoint Certificates:**
1. Coordinate with all AG replicas
2. Create new certificate on all replicas
3. Requires brief AG synchronization pause
4. Update endpoint to use new certificate
5. Test AG synchronization after change

**Important:**
- ALWAYS backup new certificates before use
- Never drop old certificates until confirmed unnecessary
- Document certificate passwords in secure vault
- Set calendar reminders for renewal (90 days before expiry)
- Test certificate renewal process in non-prod first
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/statements/create-certificate-transact-sql",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/sql-server-certificates-and-asymmetric-keys"
                )
                RawData = $certTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Certificate Expiration"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check certificates"; Error = $_.Exception.Message }
        }
        }  # End Check 52
        
        # ============================================================================
        # CHECK 53: AUTHENTICATION MODE (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 53 -CheckName "Authentication Mode")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [53/$totalChecks] Checking authentication mode..."
        
        try {
            $query = @"
SELECT 
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication'
        WHEN 0 THEN 'Mixed Mode (Windows and SQL)'
    END AS AuthenticationMode,
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsWindowsAuthOnly
"@
            $authMode = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $isWindowsOnly = $authMode.IsWindowsAuthOnly -eq 1
            $authModeDesc = $authMode.AuthenticationMode
            
            # Check for SQL logins if in Mixed Mode
            $sqlLogins = @()
            if (-not $isWindowsOnly) {
                $loginQuery = @"
SELECT 
    name AS LoginName,
    create_date AS Created,
    CASE 
        WHEN is_disabled = 1 THEN 'Disabled'
        ELSE 'Enabled'
    END AS Status
FROM sys.sql_logins
WHERE name NOT IN ('sa')
ORDER BY name;
"@
                $sqlLoginsResult = Invoke-DbaQuery -SqlInstance $conn -Query $loginQuery
                foreach ($login in $sqlLoginsResult) {
                    $sqlLogins += [PSCustomObject]@{
                        Login = $login.LoginName
                        Created = $login.Created
                        Status = $login.Status
                    }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Authentication Mode"
                Status = if ($isWindowsOnly) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isWindowsOnly) { "Pass" } else { "Warning" }
                Description = "Checks if server is using Windows Authentication only (recommended) or Mixed Mode"
                Impact = "Windows Authentication is more secure (Kerberos, centralized password policies, account lockout, auditing). Mixed Mode allows SQL logins which are less secure (no domain policies, passwords stored in SQL, more vulnerable to brute force attacks). Many security standards and compliance frameworks require Windows Authentication. However, Mixed Mode may be necessary for legacy applications or cross-domain scenarios."
                CurrentValue = @{
                    AuthenticationMode = $authModeDesc
                    SQLLoginCount = $sqlLogins.Count
                }
                RecommendedAction = if ($isWindowsOnly) { "Using recommended Windows Authentication" } else { "Consider Windows Authentication if possible; if SQL logins are required, enforce strong password policies" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current authentication mode
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsWindowsAuthOnly
'@

# List SQL logins
Get-DbaLogin -SqlInstance '$serverName' -Type SQL | 
    Select-Object Name, CreateDate, IsDisabled |
    Format-Table

# Change to Windows Authentication only (requires restart)
# WARNING: Ensure you have Windows admin access before changing!
Set-DbaSpConfigure -SqlInstance '$serverName' -Name LoginMode -Value 1
Restart-DbaService -SqlInstance '$serverName'
"@
                    TSQL = @"
-- Check authentication mode
SELECT 
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication'
        WHEN 0 THEN 'Mixed Mode'
    END AS AuthenticationMode;

-- List all SQL logins
SELECT 
    name,
    create_date,
    is_disabled,
    is_policy_checked,
    is_expiration_checked
FROM sys.sql_logins
ORDER BY name;

-- To change authentication mode, modify registry and restart SQL Server
-- HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL{XX}.MSSQLSERVER\\MSSQLServer\\LoginMode
-- 1 = Windows Authentication
-- 2 = Mixed Mode
-- RESTART REQUIRED
"@
                    Manual = @"
**Changing Authentication Mode:**
1. SSMS → Right-click server → Properties → Security
2. Select "Windows Authentication mode"
3. Click OK
4. Restart SQL Server service (REQUIRED)

**Before Changing to Windows Auth:**
1. Identify all SQL logins in use
2. Create equivalent Windows/AD accounts
3. Grant same permissions to Windows accounts
4. Test application connectivity with Windows accounts
5. Document change window (requires restart)
6. Ensure you have Windows admin access!

**If Mixed Mode is Required:**
1. Enforce CHECK_POLICY on all SQL logins
2. Enforce CHECK_EXPIRATION where possible
3. Disable 'sa' account or rename it
4. Use strong, complex passwords (16+ characters)
5. Regular password rotation
6. Monitor failed login attempts
7. Limit SQL login usage to specific applications only

**Note:** Some scenarios legitimately require Mixed Mode:
- Cross-domain environments without trust
- Legacy applications that cannot use Windows Auth
- Certain third-party applications
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/choose-an-authentication-mode",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode"
                )
                RawData = if ($sqlLogins.Count -gt 0) { $sqlLogins } else { @([PSCustomObject]@{ AuthenticationMode = $authModeDesc; SQLLogins = "None" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Authentication Mode"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check authentication mode"; Error = $_.Exception.Message }
        }
        }  # End Check 53
        
        # ============================================================================
        # CHECK 54: GUEST USER ACCESS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 54 -CheckName "Guest User Access")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [54/$totalChecks] Checking guest user access..."
        
        try {
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            $guestTable = @()
            $guestEnabledDbs = @()
            
            foreach ($db in $databases) {
                $query = @"
SELECT 
    '$($db.Name)' AS DatabaseName,
    HAS_PERMS_BY_NAME('$($db.Name)', 'DATABASE', 'CONNECT', 'guest', 'DATABASE') AS GuestHasConnect
"@
                $guestCheck = Invoke-DbaQuery -SqlInstance $conn -Database master -Query $query
                
                $guestEnabled = $guestCheck.GuestHasConnect -eq 1
                
                $guestTable += [PSCustomObject]@{
                    Database = $db.Name
                    GuestUserEnabled = if ($guestEnabled) { "❌ Enabled" } else { "✅ Disabled" }
                    Status = if ($guestEnabled) { "⚠️ Risk" } else { "✅ Secure" }
                }
                
                if ($guestEnabled) {
                    $guestEnabledDbs += $db.Name
                }
            }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Guest User Access"
                Status = if ($guestEnabledDbs.Count -eq 0) { "✅ Pass" } elseif ($guestEnabledDbs.Count -lt 3) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($guestEnabledDbs.Count -eq 0) { "Pass" } elseif ($guestEnabledDbs.Count -lt 3) { "Warning" } else { "Error" }
                Description = "Identifies databases where the guest user has CONNECT permission"
                Impact = "Guest user allows any authenticated login to access a database without explicit permissions. This is a security risk as it grants unintended access. The guest user should be disabled in all databases except master, tempdb, and msdb where it's required by design. Enabled guest accounts can lead to data exposure and compliance violations."
                CurrentValue = @{
                    DatabasesWithGuestEnabled = $guestEnabledDbs.Count
                    TotalUserDatabases = $databases.Count
                }
                RecommendedAction = if ($guestEnabledDbs.Count -eq 0) { "Guest user is properly disabled" } else { "Revoke CONNECT permission from guest user on affected databases" }
                RemediationSteps = @{
                    PowerShell = @"
# Check guest user access across databases
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | ForEach-Object {
    `$db = `$_.Name
    Invoke-DbaQuery -SqlInstance '$serverName' -Database `$db -Query @'
SELECT 
    '`$db' AS DatabaseName,
    HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONNECT', 'guest', 'DATABASE') AS GuestHasConnect
'@ } | Format-Table
|
# Revoke guest access from specific database
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'DatabaseName' -Query @'
REVOKE CONNECT FROM GUEST
'@

# Revoke guest from all user databases (except system DBs)
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | ForEach-Object {
    Invoke-DbaQuery -SqlInstance '$serverName' -Database `$_.Name -Query 'REVOKE CONNECT FROM GUEST'
}
"@
                    TSQL = @"
-- Check if guest user has CONNECT in current database
SELECT 
    DB_NAME() AS DatabaseName,
    HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONNECT', 'guest', 'DATABASE') AS GuestHasConnect;

-- Revoke CONNECT from guest user
USE [DatabaseName];
GO
REVOKE CONNECT FROM GUEST;
GO

-- Check guest permissions
USE [DatabaseName];
GO
SELECT 
    dp.name AS UserName,
    dp.type_desc AS UserType,
    permission_name,
    state_desc
FROM sys.database_permissions p
INNER JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
WHERE dp.name = 'guest'
AND permission_name = 'CONNECT';
GO
"@
                    Manual = @"
**Disabling Guest User:**
1. Connect to each database
2. Execute: REVOKE CONNECT FROM GUEST
3. Verify with: HAS_PERMS_BY_NAME()

**Important Notes:**
- Guest user CANNOT be dropped (it's built-in)
- Can only revoke its CONNECT permission
- Must remain enabled in: master, tempdb, msdb
- Should be disabled in all user databases

**Testing After Revocation:**
1. Attempt to connect with login that has no explicit database access
2. Should receive error: "The server principal X is not able to access the database Y under the current security context"
3. This is expected behavior after disabling guest

**Security Best Practice:**
- Always explicitly grant database access
- Never rely on guest user for legitimate access
- Regularly audit guest user status
- Include in security compliance checks
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine",
                    "https://learn.microsoft.com/en-us/sql/t-sql/functions/has-perms-by-name-transact-sql"
                )
                RawData = $guestTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Guest User Access"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check guest user"; Error = $_.Exception.Message }
        }
        }  # End Check 54
        
        # ============================================================================
        # CHECK 55: PUBLIC ROLE PERMISSIONS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 55 -CheckName "Public Role Permissions")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [55/$totalChecks] Checking public role permissions..."
        
        try {
            # Check server-level public role permissions
            $serverPublicQuery = @"
SELECT 
    'SERVER' AS Scope,
    permission_name AS Permission,
    state_desc AS State,
    class_desc AS ObjectType
FROM sys.server_permissions
WHERE grantee_principal_id = SUSER_SID('public')
AND permission_name NOT IN ('CONNECT SQL', 'VIEW ANY DATABASE')  -- These are default/acceptable
ORDER BY permission_name;
"@
            $serverPublicPerms = Invoke-DbaQuery -SqlInstance $conn -Query $serverPublicQuery
            
            $publicPermsTable = @()
            $issuesFound = @()
            
            foreach ($perm in $serverPublicPerms) {
                $publicPermsTable += [PSCustomObject]@{
                    Scope = "Server"
                    Permission = $perm.Permission
                    State = $perm.State
                    ObjectType = $perm.ObjectType
                    Status = "⚠️ Review"
                }
                $issuesFound += "Server: $($perm.Permission)"
            }
            
            # Check database-level public role permissions
            $databases = Get-DbaDatabase -SqlInstance $conn -ExcludeSystem
            
            foreach ($db in $databases) {
                $dbPublicQuery = @"
SELECT 
    '$($db.Name)' AS DatabaseName,
    permission_name AS Permission,
    state_desc AS State,
    OBJECT_NAME(major_id) AS ObjectName,
    class_desc AS ObjectType
FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
AND class_desc <> 'DATABASE'  -- Ignore database-level default permissions
AND permission_name NOT IN ('SELECT', 'EXECUTE')  -- Focus on dangerous permissions
ORDER BY permission_name;
"@
                $dbPublicPerms = Invoke-DbaQuery -SqlInstance $conn -Database $db.Name -Query $dbPublicQuery
                
                foreach ($perm in $dbPublicPerms) {
                    $publicPermsTable += [PSCustomObject]@{
                        Scope = $db.Name
                        Permission = $perm.Permission
                        State = $perm.State
                        ObjectName = $perm.ObjectName
                        ObjectType = $perm.ObjectType
                        Status = "⚠️ Review"
                    }
                    $issuesFound += "$($db.Name): $($perm.Permission) on $($perm.ObjectName)"
                }
            }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "Public Role Permissions"
                Status = if ($issuesFound.Count -eq 0) { "✅ Pass" } elseif ($issuesFound.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($issuesFound.Count -eq 0) { "Pass" } elseif ($issuesFound.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Checks for excessive permissions granted to the public role"
                Impact = "The public role includes ALL logins - any permission granted to public is granted to everyone. Excessive public permissions can allow unauthorized access to sensitive data or operations. Common issues include public having access to sensitive stored procedures, views, or extended stored procedures (like xp_cmdshell). This is a major security vulnerability."
                CurrentValue = @{
                    ExcessivePermissions = $issuesFound.Count
                }
                RecommendedAction = if ($issuesFound.Count -eq 0) { "Public role has appropriate minimal permissions" } else { "Review and revoke excessive permissions from public role" }
                RemediationSteps = @{
                    PowerShell = @"
# Check server-level public permissions
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT permission_name, state_desc, class_desc
FROM sys.server_permissions
WHERE grantee_principal_id = SUSER_SID('public')
'@ | Format-Table

# Check database-level public permissions
Get-DbaDatabase -SqlInstance '$serverName' -ExcludeSystem | ForEach-Object {
    Write-Host "Checking `$(`$_.Name)..."
    Invoke-DbaQuery -SqlInstance '$serverName' -Database `$_.Name -Query @'
SELECT permission_name, state_desc, OBJECT_NAME(major_id) AS ObjectName
FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
'@ | Format-Table
}

# Revoke specific permission from public
Invoke-DbaQuery -SqlInstance '$serverName' -Database 'DatabaseName' -Query @'
REVOKE EXECUTE ON [ObjectName] FROM public
'@
"@
                    TSQL = @"
-- Check server-level public role permissions
SELECT 
    permission_name,
    state_desc,
    class_desc
FROM sys.server_permissions
WHERE grantee_principal_id = SUSER_SID('public')
ORDER BY permission_name;

-- Check database-level public role permissions
USE [DatabaseName];
GO
SELECT 
    permission_name,
    state_desc,
    OBJECT_NAME(major_id) AS ObjectName,
    class_desc
FROM sys.database_permissions
WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public')
ORDER BY permission_name;

-- Revoke permission from public
USE [DatabaseName];
GO
REVOKE EXECUTE ON [StoredProcedureName] FROM public;
GO

-- Common dangerous permissions to look for:
-- CONTROL, ALTER, TAKE OWNERSHIP, IMPERSONATE
-- EXECUTE on sensitive procedures
-- SELECT/UPDATE/DELETE on sensitive tables
"@
                    Manual = @"
**Reviewing Public Role Permissions:**

**Server Level:**
1. Review sys.server_permissions for public
2. Acceptable: CONNECT SQL, VIEW ANY DATABASE
3. Dangerous: CONTROL SERVER, ALTER ANY LOGIN, etc.

**Database Level:**
1. Check each user database
2. Acceptable: Minimal SELECT on system views
3. Dangerous: EXECUTE on stored procedures
4. Dangerous: Permissions on user tables/views

**Remediation Steps:**
1. Identify why permission was granted to public
2. Create specific role for intended users
3. Grant permission to specific role instead
4. Revoke from public
5. Test application functionality

**Common Issues:**
- Third-party apps that incorrectly use public
- Legacy scripts that grant to public
- Developers using public for convenience

**Best Practice:**
- Never grant permissions to public
- Use custom roles with specific membership
- Principle of least privilege
- Regular audits of public permissions
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine"
                )
                RawData = if ($publicPermsTable.Count -gt 0) { $publicPermsTable } else { @([PSCustomObject]@{ Status = "✅ Pass"; Message = "No excessive public permissions found" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Public Role Permissions"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check public role"; Error = $_.Exception.Message }
        }
        }  # End Check 55
        
        # ============================================================================
        # CHECK 56: SQL SERVER AUDIT STATUS (Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 56 -CheckName "SQL Server Audit Status")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [56/$totalChecks] Checking SQL Server Audit configuration..."
        
        try {
            # Check if SQL Server Audit is available (Enterprise/Standard Edition)
            $editionQuery = "SELECT SERVERPROPERTY('EngineEdition') AS Edition"
            $edition = Invoke-DbaQuery -SqlInstance $conn -Query $editionQuery
            $isAuditAvailable = $edition.Edition -in @(2, 3)  # 2=Standard, 3=Enterprise
            
            if ($isAuditAvailable) {
                # Check for server audits
                $auditQuery = @"
SELECT 
    name AS AuditName,
    type_desc AS AuditType,
    on_failure_desc AS OnFailure,
    is_state_enabled AS IsEnabled,
    queue_delay AS QueueDelayMs,
    audit_guid
FROM sys.server_audits
ORDER BY name;
"@
                $audits = Invoke-DbaQuery -SqlInstance $conn -Query $auditQuery
                
                # Check for audit specifications
                $auditSpecQuery = @"
SELECT 
    sa.name AS AuditName,
    sas.name AS SpecificationName,
    sas.is_state_enabled AS IsEnabled,
    sad.audit_action_name AS ActionName
FROM sys.server_audit_specifications sas
INNER JOIN sys.server_audit_specification_details sad ON sas.server_specification_id = sad.server_specification_id
INNER JOIN sys.server_audits sa ON sas.audit_guid = sa.audit_guid
ORDER BY sa.name, sas.name;
"@
                $auditSpecs = Invoke-DbaQuery -SqlInstance $conn -Query $auditSpecQuery
                
                $auditTable = @()
                foreach ($audit in $audits) {
                    $auditTable += [PSCustomObject]@{
                        AuditName = $audit.AuditName
                        Type = $audit.AuditType
                        Status = if ($audit.IsEnabled) { "✅ Enabled" } else { "❌ Disabled" }
                        OnFailure = $audit.OnFailure
                    }
                }
                
                $enabledAudits = @($audits | Where-Object { $_.IsEnabled -eq $true })
                
                $serverResults.Checks += @{
                    Category = "Security"
                    CheckName = "SQL Server Audit Status"
                    Status = if ($enabledAudits.Count -gt 0) { "✅ Pass" } else { "⚠️ Warning" }
                    Severity = if ($enabledAudits.Count -gt 0) { "Pass" } else { "Warning" }
                    Description = "Checks if SQL Server Audit is configured and enabled for compliance and security monitoring"
                    Impact = "SQL Server Audit provides comprehensive security auditing required for many compliance standards (PCI-DSS, HIPAA, SOX, GDPR). Without auditing, you cannot track failed login attempts, privilege escalation, data access, or security changes. Auditing is essential for forensics, compliance, and detecting security breaches. Many regulations require audit trails."
                    CurrentValue = @{
                        TotalAudits = $audits.Count
                        EnabledAudits = $enabledAudits.Count
                        AuditSpecifications = $auditSpecs.Count
                    }
                    RecommendedAction = if ($enabledAudits.Count -gt 0) { "SQL Server Audit is configured" } else { "Configure SQL Server Audit for security and compliance monitoring" }
                    RemediationSteps = @{
                        PowerShell = @"
# Check existing audits
Get-DbaServerAudit -SqlInstance '$serverName' | 
    Select-Object Name, Enabled, FilePath |
    Format-Table

# Create new audit
New-DbaServerAudit -SqlInstance '$serverName' `
    -Name 'MainAudit' `
    -FilePath 'C:\\SQLAudit' `
    -MaximumFileSize 100 `
    -MaximumFileSizeUnit MB `
    -Enable

# Create audit specification for failed logins
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
CREATE SERVER AUDIT SPECIFICATION [FailedLogins]
FOR SERVER AUDIT [MainAudit]
ADD (FAILED_LOGIN_GROUP)
WITH (STATE = ON)
'@

# View audit logs
Get-DbaServerAuditLog -SqlInstance '$serverName' -AuditName 'MainAudit' | 
    Select-Object EventTime, ActionId, Succeeded, ServerPrincipalName |
    Format-Table
"@
                        TSQL = @"
-- Create server audit
USE master;
GO
CREATE SERVER AUDIT [MainAudit]
TO FILE 
(
    FILEPATH = 'C:\\SQLAudit\\',
    MAXSIZE = 100 MB,
    MAX_ROLLOVER_FILES = 10,
    RESERVE_DISK_SPACE = OFF
)
WITH
(
    QUEUE_DELAY = 1000,
    ON_FAILURE = CONTINUE
);
GO

-- Enable the audit
ALTER SERVER AUDIT [MainAudit] WITH (STATE = ON);
GO

-- Create audit specification for common security events
CREATE SERVER AUDIT SPECIFICATION [SecurityEvents]
FOR SERVER AUDIT [MainAudit]
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
ADD (DATABASE_PERMISSION_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP)
WITH (STATE = ON);
GO

-- View audit configuration
SELECT name, type_desc, is_state_enabled
FROM sys.server_audits;

-- Read audit logs
SELECT 
    event_time,
    action_id,
    succeeded,
    server_principal_name,
    database_name,
    statement
FROM sys.fn_get_audit_file('C:\\SQLAudit\\*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
"@
                        Manual = @"
**Configuring SQL Server Audit:**

1. **Create Server Audit:**
   - SSMS → Security → Audits → New Audit
   - Choose destination (File, Application Log, Security Log)
   - Set file size limits and rollover policy
   - Enable the audit

2. **Create Audit Specifications:**
   - Server Audit Specification for server-level events
   - Database Audit Specification for database-level events

3. **Recommended Events to Audit:**
   - FAILED_LOGIN_GROUP (critical)
   - SUCCESSFUL_LOGIN_GROUP
   - SERVER_ROLE_MEMBER_CHANGE_GROUP
   - DATABASE_PERMISSION_CHANGE_GROUP
   - SCHEMA_OBJECT_ACCESS_GROUP (for sensitive tables)
   - BACKUP_RESTORE_GROUP

4. **Important Considerations:**
   - File location with adequate space
   - Regular review of audit logs
   - Automated alerts for critical events
   - Archive audit files for compliance retention
   - Protect audit files from tampering

5. **Monitoring:**
   - Set up SQL Agent job to monitor audit file size
   - Alert on FAILED_LOGIN spikes
   - Regular review of permission changes
   - Integration with SIEM if available
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine",
                        "https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification"
                    )
                    RawData = if ($auditTable.Count -gt 0) { $auditTable } else { @([PSCustomObject]@{ Status = "⚠️ Warning"; Message = "No SQL Server Audits configured" }) }
                }
            } else {
                $serverResults.Checks += @{
                    Category = "Security"
                    CheckName = "SQL Server Audit Status"
                    Status = "ℹ️ Info"
                    Severity = "Info"
                    Description = "SQL Server Audit is not available in this edition"
                    Impact = "SQL Server Audit requires Standard or Enterprise Edition. Consider upgrading or using alternative auditing methods like Extended Events, SQL Trace, or C2 Audit Mode."
                    CurrentValue = @{ Edition = "Express/Web/Developer" }
                    RecommendedAction = "Use Extended Events or SQL Trace for auditing, or upgrade to Standard/Enterprise Edition"
                    RemediationSteps = @{ PowerShell = "# SQL Server Audit requires Standard or Enterprise Edition"; TSQL = "-- Use Extended Events as alternative"; Manual = "Consider upgrading SQL Server edition for full audit capabilities" }
                    Documentation = @("https://learn.microsoft.com/en-us/sql/sql-server/editions-and-components-of-sql-server-2019")
                    RawData = @([PSCustomObject]@{ Status = "Not Available"; Reason = "Edition does not support SQL Server Audit" })
                }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "SQL Audit Status"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check SQL Server Audit"; Error = $_.Exception.Message }
        }
        }  # End Check 56
        
        # ============================================================================
        # CHECK 57: ALWAYS ON AG ENDPOINT ENCRYPTION (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 57 -CheckName "Always On AG Endpoint Encryption")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [57/$totalChecks] Checking Always On AG endpoint encryption..."
        
        try {
            # Check if Always On is enabled
            $query = "SELECT SERVERPROPERTY('IsHadrEnabled') AS IsHadrEnabled"
            $hadrEnabled = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            if ($hadrEnabled.IsHadrEnabled -eq 1) {
                # Check endpoint encryption
                $endpointQuery = @"
SELECT 
    e.name AS EndpointName,
    e.type_desc AS EndpointType,
    e.state_desc AS State,
    CASE e.protocol
        WHEN 1 THEN 'HTTP'
        WHEN 2 THEN 'TCP'
        WHEN 3 THEN 'Name Pipe'
        WHEN 4 THEN 'Shared Memory'
        WHEN 5 THEN 'VIA'
        ELSE 'Unknown'
    END AS Protocol,
    CASE e.encryption_algorithm
        WHEN 0 THEN 'None'
        WHEN 1 THEN 'RC4'
        WHEN 2 THEN 'AES'
        WHEN 3 THEN 'None'
        WHEN 4 THEN 'RC4'
        WHEN 5 THEN 'AES RC4'
        WHEN 6 THEN 'AES'
        ELSE 'Unknown'
    END AS EncryptionAlgorithm,
    CASE e.connection_auth
        WHEN 1 THEN 'NTLM'
        WHEN 2 THEN 'Kerberos'
        WHEN 3 THEN 'Negotiate'
        WHEN 4 THEN 'Certificate'
        WHEN 5 THEN 'NTLM Certificate'
        WHEN 6 THEN 'Kerberos Certificate'
        ELSE 'Unknown'
    END AS AuthenticationMode
FROM sys.database_mirroring_endpoints e
WHERE e.type = 4  -- DATABASE_MIRRORING type
ORDER BY e.name;
"@
                $endpoints = Invoke-DbaQuery -SqlInstance $conn -Query $endpointQuery
                
                $endpointTable = @()
                $unencryptedEndpoints = @()
                
                foreach ($ep in $endpoints) {
                    $isEncrypted = $ep.EncryptionAlgorithm -ne 'None'
                    
                    $endpointTable += [PSCustomObject]@{
                        Endpoint = $ep.EndpointName
                        State = $ep.State
                        Protocol = $ep.Protocol
                        Encryption = $ep.EncryptionAlgorithm
                        Authentication = $ep.AuthenticationMode
                        Status = if ($isEncrypted) { "✅ Encrypted" } else { "❌ Not Encrypted" }
                    }
                    
                    if (-not $isEncrypted) {
                        $unencryptedEndpoints += $ep.EndpointName
                    }
                }
                
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "Always On AG Endpoint Encryption"
                    Status = if ($unencryptedEndpoints.Count -eq 0) { "✅ Pass" } else { "❌ Error" }
                    Severity = if ($unencryptedEndpoints.Count -eq 0) { "Pass" } else { "Error" }
                    Description = "Verifies that Always On Availability Group endpoints use encryption"
                    Impact = "Unencrypted AG endpoints transmit data replication traffic in plain text over the network. This exposes sensitive data, including committed transactions, to network sniffing and man-in-the-middle attacks. AG endpoints should always use AES encryption for data protection. This is critical for compliance (PCI-DSS, HIPAA) and security best practices."
                    CurrentValue = @{
                        TotalEndpoints = $endpoints.Count
                        UnencryptedEndpoints = $unencryptedEndpoints.Count
                    }
                    RecommendedAction = if ($unencryptedEndpoints.Count -eq 0) { "All AG endpoints are encrypted" } else { "Enable encryption on AG endpoints immediately" }
                    RemediationSteps = @{
                        PowerShell = @"
# Check endpoint encryption
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT name, encryption_algorithm_desc 
FROM sys.database_mirroring_endpoints e
INNER JOIN sys.tcp_endpoints te ON e.endpoint_id = te.endpoint_id
'@ | Format-Table

# Modify endpoint to use encryption (requires AG downtime - coordinate with all replicas!)
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
ALTER ENDPOINT [Hadr_endpoint]
FOR DATABASE_MIRRORING (
    ENCRYPTION = REQUIRED ALGORITHM AES
)
'@
"@
                        TSQL = @"
-- Check current endpoint configuration
SELECT 
    e.name AS EndpointName,
    te.encryption_algorithm_desc AS Encryption,
    te.connection_auth_desc AS Authentication,
    e.state_desc AS State,
    e.port
FROM sys.database_mirroring_endpoints e
INNER JOIN sys.tcp_endpoints te ON e.endpoint_id = te.endpoint_id;

-- Enable encryption on endpoint
-- WARNING: This requires coordination with all AG replicas
-- All replicas must support the same encryption algorithm
ALTER ENDPOINT [Hadr_endpoint]
FOR DATABASE_MIRRORING (
    ENCRYPTION = REQUIRED ALGORITHM AES
);

-- Options:
-- ENCRYPTION = DISABLED (not recommended)
-- ENCRYPTION = SUPPORTED (allows but doesn't require)
-- ENCRYPTION = REQUIRED (recommended - forces encryption)

-- Available algorithms:
-- RC4 (deprecated, not recommended)
-- AES (recommended)
-- AES RC4 (supports both, negotiates to AES)
"@
                        Manual = @"
**Enabling AG Endpoint Encryption:**

**IMPORTANT - Requires coordination across all AG replicas:**
1. Plan maintenance window (brief AG sync interruption)
2. Verify all replicas support AES encryption
3. Apply change to all replicas simultaneously
4. Monitor AG synchronization after change

**Steps:**
1. Stop applications or set AG to synchronous mode
2. On each replica:
   ALTER ENDPOINT [Hadr_endpoint]
   FOR DATABASE_MIRRORING (
       ENCRYPTION = REQUIRED ALGORITHM AES
   )
3. Restart endpoints if needed
4. Verify AG synchronization resumes
5. Monitor for errors

**Best Practices:**
- Always use ENCRYPTION = REQUIRED
- Use AES algorithm (not RC4)
- Test in non-prod first
- Document endpoint certificates
- All replicas must have matching encryption settings

**Note:**
- Changing encryption requires brief connection interruption
- AG will automatically reconnect
- Monitor dm_hadr_availability_replica_states after change
"@
                    }
                    Documentation = @(
                        "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/database-mirroring-always-on-availability-groups-powershell",
                        "https://learn.microsoft.com/en-us/sql/database-engine/database-mirroring/transport-security-database-mirroring-always-on-availability"
                    )
                    RawData = $endpointTable
                }
            } else {
                # AG not configured - mark as skipped/N/A
                Write-Host "[$serverName] [Check 57 - Skipped: Always On AG not configured]"
                $serverResults.Checks += @{
                    Category = "High Availability"
                    CheckName = "Check 57 - Always On AG Endpoint Encryption"
                    Status = "⏭️ N/A"
                    Severity = "Excluded"
                    Description = "Always On Availability Groups is not enabled on this server"
                    Impact = "This check only applies to servers with Always On AG configured"
                    CurrentValue = @{ HadrEnabled = "No" }
                    RecommendedAction = "N/A - Always On AG not configured"
                    RemediationSteps = @{ PowerShell = "# Always On AG not enabled"; TSQL = "-- N/A"; Manual = "N/A" }
                    Documentation = @("https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/overview-of-always-on-availability-groups-sql-server")
                    RawData = @([PSCustomObject]@{ Status = "N/A"; Reason = "Always On AG not enabled" })
                }
                $currentCheck++  # Increment counter since we're skipping
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "AG Endpoint Encryption"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check endpoint encryption"; Error = $_.Exception.Message }
        }
        }  # End Check 57
        
        # ============================================================================
        # CHECK 58: BACKUP COMPRESSION DEFAULT (Performance/Configuration)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 58 -CheckName "Backup Compression Default")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [58/$totalChecks] Checking backup compression default setting..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue,
    description
FROM sys.configurations
WHERE name = 'backup compression default';
"@
            $backupCompression = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $isEnabled = $backupCompression.CurrentValue -eq 1
            
            $serverResults.Checks += @{
                Category = "Configuration"
                CheckName = "Backup Compression Default"
                Status = if ($isEnabled) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isEnabled) { "Pass" } else { "Warning" }
                Description = "Checks if backup compression is enabled by default"
                Impact = "Backup compression reduces backup file size by 50-70% and often increases backup speed due to reduced I/O. This saves disk space, reduces backup time, and decreases network bandwidth for backup copies. The CPU overhead is minimal on modern servers (typically 3-5%). Compression is especially beneficial for large databases and should be enabled unless CPU is severely constrained."
                CurrentValue = @{
                    BackupCompressionDefault = if ($isEnabled) { "Enabled" } else { "Disabled" }
                }
                RecommendedAction = if ($isEnabled) { "Backup compression is enabled" } else { "Enable backup compression default for reduced backup size and improved performance" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current setting
Get-DbaSpConfigure -SqlInstance '$serverName' -Name BackupCompressionDefault | Format-Table

# Enable backup compression default
Set-DbaSpConfigure -SqlInstance '$serverName' -Name BackupCompressionDefault -Value 1

# Verify setting
Get-DbaSpConfigure -SqlInstance '$serverName' -Name BackupCompressionDefault | Format-Table

# Test with a backup
Backup-DbaDatabase -SqlInstance '$serverName' -Database 'TestDB' -CompressBackup -Path 'C:\\Backup'
"@
                    TSQL = @"
-- Check current setting
EXEC sp_configure 'backup compression default';
GO

-- Enable backup compression default
EXEC sp_configure 'backup compression default', 1;
RECONFIGURE WITH OVERRIDE;
GO

-- Verify setting
SELECT name, value_in_use 
FROM sys.configurations 
WHERE name = 'backup compression default';
GO

-- Manual backup with compression (overrides default)
BACKUP DATABASE [YourDatabase]
TO DISK = 'C:\\Backup\\YourDatabase.bak'
WITH COMPRESSION;
GO

-- Check backup compression ratio
SELECT 
    database_name,
    backup_finish_date,
    compressed_backup_size / 1024 / 1024 AS CompressedSizeMB,
    backup_size / 1024 / 1024 AS UncompressedSizeMB,
    CAST((backup_size - compressed_backup_size) * 100.0 / backup_size AS DECIMAL(5,2)) AS CompressionPercent
FROM msdb.dbo.backupset
WHERE type = 'D'
ORDER BY backup_finish_date DESC;
"@
                    Manual = @"
**Enabling Backup Compression:**

1. **Via SSMS:**
   - Right-click server → Properties → Database Settings
   - Check "Compress backup"
   - Click OK

2. **Impact Analysis:**
   - Typical compression: 50-70% size reduction
   - CPU overhead: 3-5% during backup
   - I/O reduction: Significant (less data written)
   - Backup speed: Often faster due to reduced I/O

3. **Considerations:**
   - Available since SQL Server 2008 Enterprise
   - Available in all editions since SQL Server 2008 R2 SP1
   - No impact on restore speed
   - Compressed backups are same reliability as uncompressed

4. **When NOT to Enable:**
   - Severely CPU-constrained servers (rare)
   - If using hardware compression (tape drives)
   - If already using OS/filesystem compression

5. **Verification:**
   - Compare backup file sizes before/after
   - Monitor backup duration
   - Check CPU usage during backup
   - Typical savings: $1000s in storage costs annually
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/backup-restore/backup-compression-sql-server",
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/view-or-configure-the-backup-compression-default-server-configuration-option"
                )
                RawData = @([PSCustomObject]@{
                    Setting = "backup compression default"
                    ConfigValue = $backupCompression.ConfigValue
                    CurrentValue = $backupCompression.CurrentValue
                    Status = if ($isEnabled) { "✅ Enabled" } else { "❌ Disabled" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Configuration"; CheckName = "Backup Compression"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check backup compression"; Error = $_.Exception.Message }
        }
        }  # End Check 58
        
        # ============================================================================
        # CHECK 59: DATABASE MIRRORING STATUS (High Availability)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 59 -CheckName "Database Mirroring Status")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [59/$totalChecks] Checking for deprecated database mirroring..."
        
        try {
            $query = @"
SELECT 
    d.name AS DatabaseName,
    m.mirroring_state_desc AS MirroringState,
    m.mirroring_role_desc AS Role,
    m.mirroring_safety_level_desc AS SafetyLevel,
    m.mirroring_partner_instance AS Partner
FROM sys.database_mirroring m
INNER JOIN sys.databases d ON m.database_id = d.database_id
WHERE m.mirroring_guid IS NOT NULL;
"@
            $mirroring = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $mirrorTable = @()
            
            foreach ($db in $mirroring) {
                $mirrorTable += [PSCustomObject]@{
                    Database = $db.DatabaseName
                    MirroringState = $db.MirroringState
                    Role = $db.Role
                    SafetyLevel = $db.SafetyLevel
                    Partner = $db.Partner
                    Status = "⚠️ Deprecated"
                }
            }
            
            $serverResults.Checks += @{
                Category = "High Availability"
                CheckName = "Database Mirroring Status"
                Status = if ($mirroring.Count -eq 0) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($mirroring.Count -eq 0) { "Pass" } else { "Warning" }
                Description = "Identifies databases using deprecated database mirroring feature"
                Impact = "Database Mirroring has been deprecated since SQL Server 2012 and replaced by Always On Availability Groups. While still functional, it will be removed in a future version of SQL Server. AG offers superior features: multiple replicas, readable secondaries, automatic failover of multiple databases, better monitoring. New implementations should use Always On AG instead. Plan migration from mirroring to AG."
                CurrentValue = @{
                    MirroredDatabases = $mirroring.Count
                }
                RecommendedAction = if ($mirroring.Count -eq 0) { "No deprecated database mirroring in use" } else { "Plan migration from database mirroring to Always On Availability Groups" }
                RemediationSteps = @{
                    PowerShell = @"
# Check database mirroring status
Get-DbaDbMirror -SqlInstance '$serverName' | Format-Table

# Migration to Always On AG requires:
# 1. Enable Always On AG feature (requires restart)
Enable-DbaAgHadr -SqlInstance '$serverName' -Force
Restart-DbaService -SqlInstance '$serverName'

# 2. Create AG (example)
New-DbaAvailabilityGroup -SqlInstance '$serverName' `
    -Name 'AG_Name' `
    -Database 'YourDatabase' `
    -ClusterType Wsfc `
    -AvailabilityMode SynchronousCommit `
    -FailoverMode Automatic

# 3. Remove mirroring (after AG is established)
Remove-DbaDbMirror -SqlInstance '$serverName' -Database 'YourDatabase'
"@
                    TSQL = @"
-- Check database mirroring status
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    mirroring_state_desc,
    mirroring_role_desc,
    mirroring_partner_instance
FROM sys.database_mirroring
WHERE mirroring_guid IS NOT NULL;

-- Remove database mirroring (after AG is configured)
ALTER DATABASE [YourDatabase] 
SET PARTNER OFF;

-- Migration involves:
-- 1. Enable AlwaysOn_health extended event session
-- 2. Enable HADR via SQL Server Configuration Manager (requires restart)
-- 3. Create Windows Cluster or use existing
-- 4. Create Availability Group
-- 5. Add databases to AG
-- 6. Remove mirroring
-- 7. Test failover
"@
                    Manual = @"
**Migrating from Database Mirroring to Always On AG:**

**Prerequisites:**
1. SQL Server Enterprise Edition (Standard supports basic AG)
2. Windows Server Failover Cluster
3. Same SQL Server version on all replicas
4. All databases in FULL recovery model

**Migration Steps:**
1. Document existing mirroring configuration
2. Test AG in non-production
3. Enable AlwaysOn High Availability in SQL Configuration Manager
4. Restart SQL Server (required)
5. Create Availability Group
6. Add mirrored databases to AG
7. Configure listener
8. Update application connection strings
9. Test AG failover
10. Remove mirroring after successful validation

**Advantages of Always On AG over Mirroring:**
- Multiple secondary replicas (not just one mirror)
- Readable secondary replicas
- Automatic failover of multiple databases as a group
- Built-in health monitoring and diagnostics
- Supports up to 9 replicas
- Better integration with Azure

**Note:**
- Database mirroring still works but is deprecated
- Plan migration within next 1-2 years
- Migration requires planning and testing
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/database-mirroring/database-mirroring-sql-server",
                    "https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/overview-of-always-on-availability-groups-sql-server"
                )
                RawData = if ($mirrorTable.Count -gt 0) { $mirrorTable } else { @([PSCustomObject]@{ Status = "✅ Pass"; Message = "No database mirroring configured" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "High Availability"; CheckName = "Database Mirroring"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check database mirroring"; Error = $_.Exception.Message }
        }
        }  # End Check 59
        
        # ============================================================================
        # CHECK 60: MAX DEGREE OF PARALLELISM (MAXDOP) (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 60 -CheckName "Max Degree of Parallelism")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [60/$totalChecks] Checking MAXDOP configuration..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue
FROM sys.configurations
WHERE name = 'max degree of parallelism';
"@
            $maxdop = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # Get logical processor count
            $cpuQuery = "SELECT cpu_count FROM sys.dm_os_sys_info"
            $cpuInfo = Invoke-DbaQuery -SqlInstance $conn -Query $cpuQuery
            $cpuCount = $cpuInfo.cpu_count
            
            $currentMaxdop = $maxdop.CurrentValue
            
            # Recommended MAXDOP based on CPU count (following Microsoft guidelines)
            $recommendedMaxdop = if ($cpuCount -le 8) { $cpuCount } elseif ($cpuCount -le 16) { 8 } else { [math]::Floor($cpuCount / 2) }
            
            $isOptimal = ($currentMaxdop -gt 0 -and $currentMaxdop -le $recommendedMaxdop) -or ($currentMaxdop -eq $recommendedMaxdop)
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Max Degree of Parallelism (MAXDOP)"
                Status = if ($currentMaxdop -eq 0) { "❌ Error" } elseif ($isOptimal) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($currentMaxdop -eq 0) { "Error" } elseif ($isOptimal) { "Pass" } else { "Warning" }
                Description = "Checks if MAXDOP is configured optimally for the server's CPU count"
                Impact = "MAXDOP=0 (unlimited parallelism) can cause excessive parallelism, leading to CXPACKET waits, resource contention, and poor performance. Setting MAXDOP appropriately prevents single queries from monopolizing all CPUs. Microsoft recommends: ≤8 CPUs use CPU count, 8-16 CPUs use 8, >16 CPUs use half CPU count. Incorrect MAXDOP is a common cause of performance issues."
                CurrentValue = @{
                    CurrentMAXDOP = $currentMaxdop
                    RecommendedMAXDOP = $recommendedMaxdop
                    LogicalCPUs = $cpuCount
                }
                RecommendedAction = if ($currentMaxdop -eq 0) { "Set MAXDOP to $recommendedMaxdop immediately (currently unlimited)" } elseif ($isOptimal) { "MAXDOP is configured optimally" } else { "Consider adjusting MAXDOP to $recommendedMaxdop" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current MAXDOP
Get-DbaSpConfigure -SqlInstance '$serverName' -Name MaxDegreeOfParallelism | Format-Table

# Set MAXDOP to recommended value
Set-DbaSpConfigure -SqlInstance '$serverName' -Name MaxDegreeOfParallelism -Value $recommendedMaxdop

# Check CPU count
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    cpu_count AS LogicalCPUs,
    hyperthread_ratio AS HyperthreadRatio,
    cpu_count / hyperthread_ratio AS PhysicalCPUs
FROM sys.dm_os_sys_info
'@ | Format-Table
"@
                    TSQL = @"
-- Check current MAXDOP
EXEC sp_configure 'max degree of parallelism';
GO

-- Check CPU count
SELECT 
    cpu_count AS LogicalCPUs,
    hyperthread_ratio,
    cpu_count / hyperthread_ratio AS PhysicalCPUs
FROM sys.dm_os_sys_info;

-- Set MAXDOP (recommended value: $recommendedMaxdop for this server)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO
EXEC sp_configure 'max degree of parallelism', $recommendedMaxdop;
RECONFIGURE WITH OVERRIDE;
GO

-- Microsoft MAXDOP Guidelines:
-- ≤8 CPUs: MAXDOP = CPU count
-- 8-16 CPUs: MAXDOP = 8
-- >16 CPUs: MAXDOP = CPU count / 2
-- NUMA: Consider setting per-NUMA node
"@
                    Manual = @"
**Setting MAXDOP:**

**Microsoft Recommendations:**
- 8 or fewer CPUs: MAXDOP = number of CPUs
- 8 to 16 CPUs: MAXDOP = 8
- More than 16 CPUs: MAXDOP = half the CPU count
- For NUMA systems: Consider MAXDOP = CPUs per NUMA node

**Your Server:**
- Logical CPUs: $cpuCount
- Recommended MAXDOP: $recommendedMaxdop
- Current MAXDOP: $currentMaxdop

**Implementation:**
1. Test recommended value in non-production first
2. Monitor CXPACKET waits after change
3. Can be overridden per query with OPTION (MAXDOP N)
4. Database-scoped configuration available in SQL 2016+

**Special Cases:**
- OLTP workloads: May benefit from lower MAXDOP (2-4)
- Data warehouse: May use higher MAXDOP
- Monitor and adjust based on workload

**Immediate vs Advanced Config:**
- MAXDOP change takes effect immediately
- No restart required
- Test during low-activity period
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-max-degree-of-parallelism-server-configuration-option",
                    "https://support.microsoft.com/en-us/topic/recommendations-and-guidelines-for-the-max-degree-of-parallelism-configuration-option-in-sql-server-12659f9f-cf68-49b2-fea7-3429729e5c74"
                )
                RawData = @([PSCustomObject]@{
                    CurrentMAXDOP = $currentMaxdop
                    RecommendedMAXDOP = $recommendedMaxdop
                    LogicalCPUs = $cpuCount
                    Status = if ($isOptimal) { "✅ Optimal" } else { "⚠️ Needs Adjustment" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "MAXDOP"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check MAXDOP"; Error = $_.Exception.Message }
        }
        }  # End Check 60
        
        # ============================================================================
        # CHECK 61: COST THRESHOLD FOR PARALLELISM (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 61 -CheckName "Cost Threshold for Parallelism")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [61/$totalChecks] Checking cost threshold for parallelism..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue
FROM sys.configurations
WHERE name = 'cost threshold for parallelism';
"@
            $costThreshold = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $currentValue = $costThreshold.CurrentValue
            $recommendedMin = 50  # Microsoft's common recommendation
            
            $isOptimal = $currentValue -ge $recommendedMin
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Cost Threshold for Parallelism"
                Status = if ($currentValue -eq 5) { "❌ Error" } elseif ($isOptimal) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($currentValue -eq 5) { "Error" } elseif ($isOptimal) { "Pass" } else { "Warning" }
                Description = "Checks if cost threshold for parallelism is set appropriately (default of 5 is too low)"
                Impact = "Default value of 5 is extremely low, causing excessive parallelism for trivial queries. This wastes CPU resources, increases CXPACKET waits, and degrades performance. Small queries execute faster in serial. Microsoft commonly recommends 50 as starting point. Higher values (50-100) prevent unnecessary parallelism overhead. This is one of the most important settings to change from default."
                CurrentValue = @{
                    CurrentValue = $currentValue
                    RecommendedMinimum = $recommendedMin
                }
                RecommendedAction = if ($currentValue -eq 5) { "Increase cost threshold from default 5 to at least 50 immediately" } elseif ($isOptimal) { "Cost threshold is configured appropriately" } else { "Consider increasing to at least $recommendedMin" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current value
Get-DbaSpConfigure -SqlInstance '$serverName' -Name CostThresholdForParallelism | Format-Table

# Set to recommended value (start with 50, adjust based on workload)
Set-DbaSpConfigure -SqlInstance '$serverName' -Name CostThresholdForParallelism -Value 50

# Verify change
Get-DbaSpConfigure -SqlInstance '$serverName' -Name CostThresholdForParallelism | Format-Table
"@
                    TSQL = @"
-- Check current value
EXEC sp_configure 'cost threshold for parallelism';
GO

-- Set cost threshold (common starting point: 50)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO
EXEC sp_configure 'cost threshold for parallelism', 50;
RECONFIGURE WITH OVERRIDE;
GO

-- Verify change
SELECT name, value_in_use 
FROM sys.configurations 
WHERE name = 'cost threshold for parallelism';
"@
                    Manual = @"
**Cost Threshold for Parallelism:**

**The Problem:**
- Default value: 5 (unchanged since SQL Server 7.0 in 1998!)
- This default is way too low for modern servers
- Causes trivial queries to go parallel unnecessarily

**Recommendations:**
- Start with 50 (common Microsoft recommendation)
- Some experts recommend 50-100
- Tune based on your workload
- Higher values = less parallelism = fewer CXPACKET waits

**Current Value: $currentValue**
$(if ($currentValue -eq 5) { "⚠️ CRITICAL: Using default value of 5 - change immediately!" })

**Implementation:**
1. Change to 50 initially
2. Monitor CXPACKET waits after change
3. If CXPACKET waits persist, increase further
4. If queries become slower, decrease slightly
5. Typical sweet spot: 50-75

**Important Notes:**
- Change takes effect immediately
- No restart required
- Works in conjunction with MAXDOP
- First changed this, then tune MAXDOP
- Safe to change in production (non-disruptive)
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-cost-threshold-for-parallelism-server-configuration-option",
                    "https://www.brentozar.com/archive/2013/08/what-should-i-set-cost-threshold-for-parallelism-to/"
                )
                RawData = @([PSCustomObject]@{
                    CurrentValue = $currentValue
                    DefaultValue = 5
                    RecommendedMinimum = $recommendedMin
                    Status = if ($currentValue -eq 5) { "❌ Using Default (Too Low)" } elseif ($isOptimal) { "✅ Appropriate" } else { "⚠️ Consider Increasing" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Cost Threshold"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check cost threshold"; Error = $_.Exception.Message }
        }
        }  # End Check 61
        
        # ============================================================================
        # CHECK 62: OPTIMIZE FOR AD HOC WORKLOADS (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 62 -CheckName "Optimize for Ad Hoc Workloads")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [62/$totalChecks] Checking optimize for ad hoc workloads..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue
FROM sys.configurations
WHERE name = 'optimize for ad hoc workloads';
"@
            $adHoc = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $isEnabled = $adHoc.CurrentValue -eq 1
            
            # Check plan cache for ad hoc queries
            $planCacheQuery = @"
SELECT 
    objtype AS CacheType,
    COUNT(*) AS PlanCount,
    SUM(CAST(size_in_bytes AS BIGINT)) / 1024 / 1024 AS SizeMB,
    AVG(usecounts) AS AvgUseCount
FROM sys.dm_exec_cached_plans
GROUP BY objtype
ORDER BY SizeMB DESC;
"@
            $planCache = Invoke-DbaQuery -SqlInstance $conn -Query $planCacheQuery
            
            $adHocPlans = $planCache | Where-Object { $_.CacheType -eq 'Adhoc' }
            $adHocSizeMB = if ($adHocPlans) { [math]::Round($adHocPlans.SizeMB, 2) } else { 0 }
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Optimize for Ad Hoc Workloads"
                Status = if ($isEnabled) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isEnabled) { "Pass" } else { "Warning" }
                Description = "Checks if 'optimize for ad hoc workloads' is enabled to reduce plan cache bloat"
                Impact = "When disabled, SQL Server stores full execution plans for ad-hoc queries on first execution, wasting memory on single-use plans. Enabling this option stores only a small plan stub initially, saving ~50% of plan cache memory for ad-hoc queries. Full plan is cached only on second execution. Highly recommended for OLTP systems with many ad-hoc queries. Helps prevent plan cache bloat and memory pressure."
                CurrentValue = @{
                    OptimizeForAdHoc = if ($isEnabled) { "Enabled" } else { "Disabled" }
                    AdHocPlanCacheSizeMB = $adHocSizeMB
                }
                RecommendedAction = if ($isEnabled) { "Optimize for ad hoc workloads is enabled" } else { "Enable optimize for ad hoc workloads to reduce plan cache memory usage" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current setting
Get-DbaSpConfigure -SqlInstance '$serverName' -Name OptimizeForAdHocWorkloads | Format-Table

# Enable optimize for ad hoc workloads
Set-DbaSpConfigure -SqlInstance '$serverName' -Name OptimizeForAdHocWorkloads -Value 1

# Check plan cache usage
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    objtype,
    COUNT(*) AS PlanCount,
    SUM(CAST(size_in_bytes AS BIGINT)) / 1024 / 1024 AS SizeMB
FROM sys.dm_exec_cached_plans
GROUP BY objtype
ORDER BY SizeMB DESC
'@ | Format-Table
"@
                    TSQL = @"
-- Check current setting
EXEC sp_configure 'optimize for ad hoc workloads';
GO

-- Enable optimize for ad hoc workloads
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO
EXEC sp_configure 'optimize for ad hoc workloads', 1;
RECONFIGURE WITH OVERRIDE;
GO

-- Check plan cache for ad-hoc plans
SELECT 
    objtype AS PlanType,
    COUNT(*) AS PlanCount,
    SUM(CAST(size_in_bytes AS BIGINT)) / 1024 / 1024 AS CacheSizeMB,
    AVG(usecounts) AS AvgUseCount
FROM sys.dm_exec_cached_plans
GROUP BY objtype
ORDER BY CacheSizeMB DESC;

-- Find single-use ad-hoc plans (wasting memory)
SELECT 
    usecounts,
    size_in_bytes / 1024 AS SizeKB,
    CAST(cp.plan_handle AS VARCHAR(MAX)) AS PlanHandle,
    st.text AS QueryText
FROM sys.dm_exec_cached_plans cp
CROSS APPLY sys.dm_exec_sql_text(cp.plan_handle) st
WHERE cp.cacheobjtype = 'Compiled Plan'
AND cp.objtype = 'Adhoc'
AND cp.usecounts = 1
ORDER BY cp.size_in_bytes DESC;
"@
                    Manual = @"
**Optimize for Ad Hoc Workloads:**

**What It Does:**
- Stores small plan stub (few KB) on first execution
- Stores full plan only if query executes again
- Saves ~50% of plan cache for ad-hoc queries
- No performance impact on query execution

**When to Enable:**
- OLTP applications with many unique queries
- Applications that don't use parameterized queries
- When plan cache shows high 'Adhoc' memory usage
- Almost always beneficial (rare downsides)

**Current Status:**
- Enabled: $(if ($isEnabled) { 'Yes ✅' } else { 'No ❌' })
- Ad-hoc plan cache size: $adHocSizeMB MB

**Benefits:**
- Reduces memory pressure
- More room for frequently-used plans
- Prevents plan cache bloat
- No application changes required
- No query performance impact

**Implementation:**
1. Enable setting (takes effect immediately)
2. Monitor plan cache size over days/weeks
3. Existing plans remain cached
4. New ad-hoc plans use stub approach
5. Clear plan cache to see immediate effect (optional, disruptive)

**Note:**
- Safe to enable in production
- Immediate effect, no restart needed
- Recommended by Microsoft for most workloads
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/optimize-for-ad-hoc-workloads-server-configuration-option",
                    "https://www.sqlskills.com/blogs/kimberly/plan-cache-and-optimizing-for-adhoc-workloads/"
                )
                RawData = @([PSCustomObject]@{
                    Setting = "optimize for ad hoc workloads"
                    CurrentValue = if ($isEnabled) { "Enabled" } else { "Disabled" }
                    AdHocPlanCacheMB = $adHocSizeMB
                    Status = if ($isEnabled) { "✅ Enabled" } else { "❌ Disabled" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Ad Hoc Optimization"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check ad hoc optimization"; Error = $_.Exception.Message }
        }
        }  # End Check 62
        
        # ============================================================================
        # CHECK 63: NETWORK PACKET SIZE (Configuration)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 63 -CheckName "Network Packet Size")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [63/$totalChecks] Checking network packet size..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue
FROM sys.configurations
WHERE name = 'network packet size';
"@
            $packetSize = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $currentValue = $packetSize.CurrentValue
            $defaultValue = 4096
            
            $isDefault = $currentValue -eq $defaultValue
            
            $serverResults.Checks += @{
                Category = "Configuration"
                CheckName = "Network Packet Size"
                Status = if ($isDefault) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isDefault) { "Pass" } else { "Warning" }
                Description = "Checks if network packet size is set to default (4096 bytes)"
                Impact = "Default packet size of 4096 bytes is optimal for most workloads. Increasing it may improve bulk operations and large result sets but can increase memory usage and network congestion. Decreasing it can cause more network round trips. Microsoft recommends leaving at default unless specific performance testing shows benefit. Changing this setting rarely provides performance improvements and can cause issues. Only change if you have a specific reason and have tested thoroughly."
                CurrentValue = @{
                    CurrentPacketSize = $currentValue
                    DefaultPacketSize = $defaultValue
                }
                RecommendedAction = if ($isDefault) { "Network packet size is at recommended default" } else { "Consider returning to default 4096 unless specific tuning has proven beneficial" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current setting
Get-DbaSpConfigure -SqlInstance '$serverName' -Name NetworkPacketSize | Format-Table

# Reset to default if needed
Set-DbaSpConfigure -SqlInstance '$serverName' -Name NetworkPacketSize -Value 4096

# Verify change
Get-DbaSpConfigure -SqlInstance '$serverName' -Name NetworkPacketSize | Format-Table
"@
                    TSQL = @"
-- Check current value
EXEC sp_configure 'network packet size';
GO

-- Reset to default (4096)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO
EXEC sp_configure 'network packet size', 4096;
RECONFIGURE WITH OVERRIDE;
GO

-- Valid range: 512 to 32767 bytes
-- Default: 4096 bytes
"@
                    Manual = @"
**Network Packet Size:**

**Current Value: $currentValue bytes**
**Default: $defaultValue bytes**

**When to Change:**
- Rarely beneficial to change
- May help with bulk operations (8192)
- May help with large result sets
- Must test before implementing

**When NOT to Change:**
- Default works for 99% of workloads
- Can increase memory pressure
- Can cause network fragmentation
- No clear performance issue to solve

**Microsoft Guidance:**
- Leave at default unless testing proves benefit
- Application can override via connection string
- Server setting is just the default

**If Changed:**
1. Document why it was changed
2. Verify performance benefit
3. Monitor for issues:
   - Increased memory usage
   - Network errors
   - Slower small queries
4. Consider per-application setting instead

**Connection String Override:**
Applications can specify packet size:
"Packet Size=8192" in connection string

This is preferred over changing server default.
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-network-packet-size-server-configuration-option"
                )
                RawData = @([PSCustomObject]@{
                    Setting = "network packet size"
                    CurrentValue = $currentValue
                    DefaultValue = $defaultValue
                    Status = if ($isDefault) { "✅ Default" } else { "⚠️ Non-Default" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Configuration"; CheckName = "Network Packet Size"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check network packet size"; Error = $_.Exception.Message }
        }
        }  # End Check 63
        
        # ============================================================================
        # CHECK 64: REMOTE ADMIN CONNECTIONS (DAC) (Configuration)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 64 -CheckName "Remote Admin Connections (DAC)")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [64/$totalChecks] Checking remote DAC configuration..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue
FROM sys.configurations
WHERE name = 'remote admin connections';
"@
            $dac = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $isEnabled = $dac.CurrentValue -eq 1
            
            $serverResults.Checks += @{
                Category = "Configuration"
                CheckName = "Remote Admin Connections (DAC)"
                Status = if ($isEnabled) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isEnabled) { "Pass" } else { "Warning" }
                Description = "Checks if Dedicated Administrator Connection (DAC) is enabled for remote connections"
                Impact = "DAC provides emergency access when SQL Server is unresponsive. By default, DAC only works locally. Enabling remote DAC allows troubleshooting from management workstations when you cannot log into the server console. Essential for remote administration and critical troubleshooting scenarios. Recommended for production servers, especially clustered or Always On environments where physical access may be limited."
                CurrentValue = @{
                    RemoteDAC = if ($isEnabled) { "Enabled" } else { "Disabled" }
                }
                RecommendedAction = if ($isEnabled) { "Remote DAC is enabled for emergency access" } else { "Consider enabling remote DAC for emergency remote troubleshooting" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current setting
Get-DbaSpConfigure -SqlInstance '$serverName' -Name RemoteDacConnectionsEnabled | Format-Table

# Enable remote DAC
Set-DbaSpConfigure -SqlInstance '$serverName' -Name RemoteDacConnectionsEnabled -Value 1

# Verify
Get-DbaSpConfigure -SqlInstance '$serverName' -Name RemoteDacConnectionsEnabled | Format-Table

# Test DAC connection (from remote machine)
# sqlcmd -S ADMIN:ServerName -E -Q "SELECT @@SERVERNAME"
"@
                    TSQL = @"
-- Check current setting
EXEC sp_configure 'remote admin connections';
GO

-- Enable remote DAC
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO
EXEC sp_configure 'remote admin connections', 1;
RECONFIGURE WITH OVERRIDE;
GO

-- Test DAC (locally)
-- Connect using: ADMIN:ServerName in SSMS
"@
                    Manual = @"
**Dedicated Administrator Connection (DAC):**

**What is DAC:**
- Special diagnostic connection
- Always available even when server is unresponsive
- Limited to one connection at a time
- Bypasses resource governor
- Useful for emergency troubleshooting

**Remote DAC:**
- By default: DAC only works locally (console access)
- When enabled: Can connect via network
- Connect using: ADMIN:ServerName prefix

**When to Use DAC:**
- SQL Server is not responding
- Need to kill blocking processes
- Emergency maintenance
- Investigating performance issues
- Server at max connections

**Connection Examples:**
- SSMS: ADMIN:SERVERNAME\\INSTANCE
- sqlcmd: sqlcmd -S ADMIN:SERVERNAME -E
- Only one DAC connection allowed at a time

**Security:**
- Only sysadmin can use DAC
- Connection is logged
- Should be monitored/audited

**Recommendation:**
- Enable for production servers
- Essential for remote administration
- Document DAC usage procedures
- Test DAC connectivity periodically
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/diagnostic-connection-for-database-administrators",
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/remote-admin-connections-server-configuration-option"
                )
                RawData = @([PSCustomObject]@{
                    Setting = "remote admin connections"
                    CurrentValue = if ($isEnabled) { "Enabled" } else { "Disabled" }
                    Status = if ($isEnabled) { "✅ Enabled" } else { "❌ Disabled" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Configuration"; CheckName = "Remote DAC"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check DAC"; Error = $_.Exception.Message }
        }
        }  # End Check 64
        
        # ============================================================================
        # CHECK 65: INSTANT FILE INITIALIZATION (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 65 -CheckName "Instant File Initialization")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [65/$totalChecks] Checking instant file initialization..."
        
        try {
            # Check if SQL service account has SeManageVolumePrivilege (IFI)
            $query = "SELECT SERVERPROPERTY('InstanceName') AS InstanceName, SERVERPROPERTY('Edition') AS Edition"
            $instance = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            # IFI status is available in sys.dm_server_services (SQL 2016+) or error log
            $ifiQuery = @"
SELECT 
    instant_file_initialization_enabled AS IFIEnabled
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server%'
AND servicename NOT LIKE '%Agent%'
AND servicename NOT LIKE '%Browser%';
"@
            
            try {
                $ifiStatus = Invoke-DbaQuery -SqlInstance $conn -Query $ifiQuery
                $ifiEnabled = if ($ifiStatus -and $ifiStatus.IFIEnabled -ne $null) { $ifiStatus.IFIEnabled -eq 'Y' } else { $null }
            } catch {
                # Fallback for older SQL versions - check via error log
                $ifiEnabled = $null
            }
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Instant File Initialization (IFI)"
                Status = if ($ifiEnabled -eq $true) { "✅ Pass" } elseif ($ifiEnabled -eq $false) { "⚠️ Warning" } else { "ℹ️ Info" }
                Severity = if ($ifiEnabled -eq $true) { "Pass" } elseif ($ifiEnabled -eq $false) { "Warning" } else { "Info" }
                Description = "Checks if Instant File Initialization is enabled for faster database file operations"
                Impact = "IFI dramatically speeds up data file growth and database creation/restore by skipping zero-initialization. Without IFI, SQL Server must write zeros to entire file, which can take hours for large files. With IFI, file operations complete instantly. Essential for large databases. Does NOT apply to log files (always zero-initialized for safety). Minimal security consideration: Previously deleted disk data could be readable (rare concern)."
                CurrentValue = @{
                    IFIEnabled = if ($ifiEnabled -eq $true) { "Enabled" } elseif ($ifiEnabled -eq $false) { "Disabled" } else { "Unable to determine (check manually)" }
                }
                RecommendedAction = if ($ifiEnabled -eq $true) { "IFI is enabled" } elseif ($ifiEnabled -eq $false) { "Enable IFI to improve database file operations" } else { "Verify IFI status manually" }
                RemediationSteps = @{
                    PowerShell = @"
# Check IFI status (SQL 2016+)
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT instant_file_initialization_enabled
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server%'
'@ | Format-Table

# Enable IFI (requires local admin on server)
# Option 1: Use Local Security Policy GUI
# Option 2: Use PowerShell (run on SQL Server as admin):
`$sqlServiceAccount = (Get-Service 'MSSQLSERVER').StartName  # Adjust service name
secedit /export /cfg C:\\temp\\secpol.cfg
# Edit secpol.cfg to add SQL service account to SeManageVolumePrivilege
secedit /configure /db C:\\temp\\secpol.sdb /cfg C:\\temp\\secpol.cfg
# Then restart SQL Server service
"@
                    TSQL = @"
-- Check IFI status (SQL 2016+)
SELECT 
    servicename,
    instant_file_initialization_enabled AS IFI_Enabled
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server%';

-- Verify via error log (look for IFI message at startup)
EXEC xp_readerrorlog 0, 1, 'Database Instant File Initialization';

-- Note: Enabling IFI requires Windows-level permissions
-- Cannot be enabled via T-SQL
"@
                    Manual = @"
**Enabling Instant File Initialization:**

**Steps:**
1. Identify SQL Server service account
   - SQL Configuration Manager → SQL Server Services
   - Note the "Log On As" account

2. Grant SE_MANAGE_VOLUME_NAME privilege:
   **Option A - Local Security Policy (GUI):**
   - Run: secpol.msc
   - Local Policies → User Rights Assignment
   - "Perform volume maintenance tasks"
   - Add SQL service account
   
   **Option B - Command line:**
   - Run as Administrator
   - secpol.msc or use GPO

3. Restart SQL Server service (REQUIRED)

4. Verify in error log:
   - Look for "Database Instant File Initialization: enabled"

**Benefits:**
- Database restore: Hours → Minutes
- Data file growth: Seconds instead of minutes
- Database creation: Nearly instant
- TempDB recreate: Much faster (at startup)

**Security Consideration:**
- Deleted file contents might be readable
- Generally not a concern in practice
- Benefits far outweigh minimal risk

**Important:**
- Only affects DATA files (.mdf, .ndf)
- Does NOT affect LOG files (.ldf)
- Log files always zero-initialized (by design)

**Current Status:**
$(if ($ifiEnabled -eq $true) { '✅ Enabled' } elseif ($ifiEnabled -eq $false) { '❌ Disabled - Enable immediately!' } else { 'ℹ️ Unknown - Check manually' })
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-instant-file-initialization",
                    "https://www.brentozar.com/archive/2021/01/how-to-enable-instant-file-initialization/"
                )
                RawData = @([PSCustomObject]@{
                    Feature = "Instant File Initialization"
                    Status = if ($ifiEnabled -eq $true) { "✅ Enabled" } elseif ($ifiEnabled -eq $false) { "❌ Disabled" } else { "❓ Unknown" }
                    Note = if ($ifiEnabled -eq $null) { "Check sys.dm_server_services or error log manually" } else { "" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Instant File Init"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check IFI"; Error = $_.Exception.Message }
        }
        }  # End Check 65
        
        # ============================================================================
        # CHECK 66: TRACE FLAGS (Configuration)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 66 -CheckName "Trace Flags")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [66/$totalChecks] Checking trace flags..."
        
        try {
            $query = "DBCC TRACESTATUS(-1) WITH NO_INFOMSGS"
            $traceFlags = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $traceFlagTable = @()
            
            foreach ($tf in $traceFlags) {
                $tfNumber = $tf.TraceFlag
                $tfStatus = $tf.Status
                $tfGlobal = $tf.Global
                $tfSession = $tf.Session
                
                # Common/recommended trace flags
                $description = switch ($tfNumber) {
                    1117 { "Grow all files in filegroup equally (deprecated in SQL 2016+, use AUTOGROW_ALL_FILES)" }
                    1118 { "Reduce tempdb contention (deprecated in SQL 2016+, default behavior changed)" }
                    1222 { "Return resources involved in deadlocks in XML format" }
                    2528 { "Disable parallel checking of objects during DBCC CHECKDB" }
                    3226 { "Suppress successful backup messages in error log" }
                    4199 { "Enable query optimizer fixes (use with caution)" }
                    7412 { "Enable lightweight query execution statistics profiling" }
                    default { "Trace flag $tfNumber" }
                }
                
                $traceFlagTable += [PSCustomObject]@{
                    TraceFlag = $tfNumber
                    Status = if ($tfStatus -eq 1) { "✅ On" } else { "❌ Off" }
                    Global = $tfGlobal
                    Description = $description
                }
            }
            
            $serverResults.Checks += @{
                Category = "Configuration"
                CheckName = "Trace Flags"
                Status = if ($traceFlags.Count -eq 0) { "ℹ️ Info" } else { "ℹ️ Info" }
                Severity = "Info"
                Description = "Lists currently enabled trace flags for documentation and review"
                Impact = "Trace flags modify SQL Server behavior. Some are recommended (3226 for suppressing backup messages, 1222 for deadlock info). Others should be used with caution (4199 query optimizer changes). Trace flags 1117/1118 are no longer needed in SQL 2016+ due to default behavior changes. Document all trace flags and their purpose. Remove obsolete flags. Ensure flags are set at startup via -T parameter."
                CurrentValue = @{
                    TotalTraceFlags = $traceFlags.Count
                }
                RecommendedAction = if ($traceFlags.Count -eq 0) { "No trace flags enabled" } else { "Review trace flags for appropriateness and documentation" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current trace flags
Invoke-DbaQuery -SqlInstance '$serverName' -Query 'DBCC TRACESTATUS(-1) WITH NO_INFOMSGS' | Format-Table

# Common recommended trace flags:
# TF 3226 - Suppress successful backup messages
Invoke-DbaQuery -SqlInstance '$serverName' -Query 'DBCC TRACEON(3226, -1)'

# TF 1222 - Detailed deadlock information
Invoke-DbaQuery -SqlInstance '$serverName' -Query 'DBCC TRACEON(1222, -1)'

# Make trace flags permanent (add to startup)
# SQL Configuration Manager → SQL Server Properties → Startup Parameters
# Add: -T3226 -T1222
"@
                    TSQL = @"
-- Check enabled trace flags
DBCC TRACESTATUS(-1) WITH NO_INFOMSGS;

-- Enable trace flag (session-level)
DBCC TRACEON(3226);

-- Enable trace flag (global)
DBCC TRACEON(3226, -1);

-- Disable trace flag
DBCC TRACEOFF(3226, -1);

-- Common Trace Flags:
-- 3226: Suppress successful backup log entries
-- 1222: Deadlock details in XML format
-- 1117: Obsolete in SQL 2016+ (use AUTOGROW_ALL_FILES)
-- 1118: Obsolete in SQL 2016+ (uniform extent allocation default)
-- 4199: Enable optimizer hotfixes (test first!)
-- 7412: Lightweight query profiling (SQL 2016+)

-- To make permanent: add -T flag to startup parameters
"@
                    Manual = @"
**Common Trace Flags:**

**Recommended:**
- **TF 3226**: Suppress successful backup messages in error log
  - Reduces log noise
  - Safe to enable
  
- **TF 1222**: Return detailed deadlock information in XML
  - Essential for troubleshooting deadlocks
  - Recommended for production

**Caution:**
- **TF 4199**: Enable query optimizer fixes
  - Can change query plans
  - Test thoroughly before production
  - Better: Use query hint or database compat level

**Obsolete (SQL 2016+):**
- **TF 1117**: Even file growth in filegroup
  - Now default behavior via AUTOGROW_ALL_FILES
  - Remove if on SQL 2016+
  
- **TF 1118**: Uniform extent allocation
  - Now default for tempdb in SQL 2016+
  - Can remove for tempdb

**Making Trace Flags Permanent:**
1. SQL Configuration Manager
2. SQL Server Services → Right-click → Properties
3. Startup Parameters
4. Add: -T#### (e.g., -T3226)
5. Restart SQL Server (required)

**Current Trace Flags: $($traceFlags.Count)**
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/t-sql/database-console-commands/dbcc-traceon-transact-sql",
                    "https://learn.microsoft.com/en-us/sql/t-sql/database-console-commands/dbcc-tracestatus-transact-sql"
                )
                RawData = if ($traceFlagTable.Count -gt 0) { $traceFlagTable } else { @([PSCustomObject]@{ Status = "No trace flags enabled"; Message = "" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Configuration"; CheckName = "Trace Flags"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check trace flags"; Error = $_.Exception.Message }
        }
        }  # End Check 66
        
        # ============================================================================
        # CHECK 67: LINKED SERVERS (Configuration/Security)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 67 -CheckName "Linked Servers")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [67/$totalChecks] Checking linked servers configuration..."
        
        try {
            $query = @"
SELECT 
    s.name AS LinkedServerName,
    s.product AS Product,
    s.provider AS Provider,
    s.data_source AS DataSource,
    l.remote_name AS RemoteLogin,
    CASE l.uses_self_credential
        WHEN 1 THEN 'Self'
        ELSE 'Mapped'
    END AS CredentialType
FROM sys.servers s
LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1
ORDER BY s.name;
"@
            $linkedServers = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $linkedServerTable = @()
            
            foreach ($ls in $linkedServers) {
                $linkedServerTable += [PSCustomObject]@{
                    LinkedServer = $ls.LinkedServerName
                    Product = $ls.Product
                    Provider = $ls.Provider
                    DataSource = $ls.DataSource
                    CredentialType = $ls.CredentialType
                    Status = "ℹ️ Review"
                }
            }
            
            $serverResults.Checks += @{
                Category = "Configuration"
                CheckName = "Linked Servers"
                Status = if ($linkedServers.Count -eq 0) { "ℹ️ Info" } else { "ℹ️ Info" }
                Severity = "Info"
                Description = "Lists configured linked servers for security review and documentation"
                Impact = "Linked servers allow querying remote data sources but introduce security risks: stored credentials, potential SQL injection through dynamic SQL, performance issues with large result sets, and complex troubleshooting. Review all linked servers regularly: verify they're still needed, check credential storage, audit usage, consider alternatives like SSIS or application-layer integration. Orphaned or unused linked servers should be removed."
                CurrentValue = @{
                    TotalLinkedServers = $linkedServers.Count
                }
                RecommendedAction = if ($linkedServers.Count -eq 0) { "No linked servers configured" } else { "Review linked servers for security, usage, and necessity" }
                RemediationSteps = @{
                    PowerShell = @"
# List linked servers
Get-DbaLinkedServer -SqlInstance '$serverName' | Format-Table

# Test linked server connectivity
Test-DbaLinkedServer -SqlInstance '$serverName' | Format-Table

# Remove linked server (if not needed)
Remove-DbaLinkedServer -SqlInstance '$serverName' -LinkedServer 'ServerName' -Confirm:`$false
"@
                    TSQL = @"
-- List linked servers
SELECT * FROM sys.servers WHERE is_linked = 1;

-- List linked server logins
SELECT 
    s.name AS LinkedServer,
    l.local_principal_id,
    l.remote_name
FROM sys.linked_logins l
INNER JOIN sys.servers s ON l.server_id = s.server_id;

-- Test linked server
SELECT * FROM [LinkedServerName].master.sys.databases;

-- Drop linked server
EXEC sp_dropserver @server='LinkedServerName', @droplogins='droplogins';
"@
                    Manual = @"
**Linked Server Security Review:**

**Review Checklist:**
1. Is the linked server still needed?
2. Can this be replaced with:
   - SSIS package?
   - Application-layer integration?
   - Replication?
   - API call?

3. Security concerns:
   - How are credentials stored?
   - Are sa/admin accounts used?
   - Is self-credential mapping used?
   - Can access be restricted?

4. Performance:
   - Large result sets?
   - Frequent calls?
   - Network latency issues?

5. Maintenance:
   - Is this documented?
   - Is there an owner?
   - When was it last used?

**Best Practices:**
- Use Windows Authentication when possible
- Least privilege for remote logins
- Avoid sa or admin accounts
- Document purpose and owner
- Regular usage audit
- Remove unused linked servers
- Consider alternatives (SSIS, APIs)
- Monitor for failed connection attempts

**Current Count: $($linkedServers.Count)**
$(if ($linkedServers.Count -eq 0) { 'No linked servers configured' } else { 'Review each linked server for necessity' })
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine"
                )
                RawData = if ($linkedServerTable.Count -gt 0) { $linkedServerTable } else { @([PSCustomObject]@{ Status = "No linked servers"; Message = "" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Configuration"; CheckName = "Linked Servers"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check linked servers"; Error = $_.Exception.Message }
        }
        }  # End Check 67
        
        # ============================================================================
        # CHECK 68: SQL SERVER AGENT STATUS (Operational)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 68 -CheckName "SQL Server Agent Status")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [68/$totalChecks] Checking SQL Server Agent status..."
        
        try {
            $query = @"
SELECT 
    CASE WHEN EXISTS (SELECT 1 FROM master.dbo.sysprocesses WHERE program_name LIKE 'SQLAgent%')
        THEN 1
        ELSE 0
    END AS AgentRunning;
"@
            $agentStatus = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $isRunning = $agentStatus.AgentRunning -eq 1
            
            $serverResults.Checks += @{
                Category = "Operational"
                CheckName = "SQL Server Agent Status"
                Status = if ($isRunning) { "✅ Pass" } else { "❌ Error" }
                Severity = if ($isRunning) { "Pass" } else { "Error" }
                Description = "Checks if SQL Server Agent service is running"
                Impact = "SQL Server Agent is essential for automated tasks: backups, maintenance plans, SSIS packages, replication, alerts, and monitoring. If Agent is stopped, no jobs run, backups fail, and critical alerts don't fire. This can lead to data loss, full transaction logs, and undetected issues. Agent should always be running on production servers and set to automatic startup."
                CurrentValue = @{
                    AgentStatus = if ($isRunning) { "Running" } else { "Stopped" }
                }
                RecommendedAction = if ($isRunning) { "SQL Server Agent is running" } else { "Start SQL Server Agent immediately and set to automatic startup" }
                RemediationSteps = @{
                    PowerShell = @"
# Check Agent status
Get-DbaAgentServer -SqlInstance '$serverName' | Select-Object SqlInstance, IsRunning | Format-Table

# Start SQL Agent
Start-DbaAgentServer -SqlInstance '$serverName'

# Set SQL Agent to automatic startup
Set-DbaStartupParameter -SqlInstance '$serverName' -AgentStartup Automatic

# Alternative: Use services
Get-Service -Name 'SQLSERVERAGENT' | Start-Service
Set-Service -Name 'SQLSERVERAGENT' -StartupType Automatic
"@
                    TSQL = @"
-- Check if Agent is running
SELECT 
    CASE WHEN EXISTS (
        SELECT 1 FROM master.dbo.sysprocesses 
        WHERE program_name LIKE 'SQLAgent%'
    )
    THEN 'Running'
    ELSE 'Stopped'
    END AS AgentStatus;

-- Check via xp_servicecontrol
EXEC xp_servicecontrol 'QUERYSTATE', 'SQLSERVERAGENT';

-- Note: Starting Agent requires Windows-level access
-- Use Services.msc or PowerShell
"@
                    Manual = @"
**Starting SQL Server Agent:**

**Via Services:**
1. Run: services.msc
2. Find: SQL Server Agent (MSSQLSERVER) or (InstanceName)
3. Right-click → Start
4. Right-click → Properties
5. Startup type: Automatic
6. Click OK

**Via SQL Configuration Manager:**
1. SQL Server Configuration Manager
2. SQL Server Services
3. Right-click SQL Server Agent
4. Properties → Service tab
5. Start Mode: Automatic
6. Start the service

**Common Reasons Agent Stops:**
- Manual intervention
- Server restart (if not set to automatic)
- Service account password change
- Insufficient permissions
- Startup stored procedure failure

**Critical Impact if Stopped:**
- No backups run
- No maintenance tasks
- No alerts fire
- No monitoring
- Transaction logs fill up
- Replication stops

**Immediate Actions:**
1. Start Agent service
2. Set to automatic startup
3. Investigate why it stopped
4. Check error logs
5. Verify backups ran
6. Check transaction log space
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/ssms/agent/start-stop-or-pause-the-sql-server-agent-service",
                    "https://learn.microsoft.com/en-us/sql/ssms/agent/sql-server-agent"
                )
                RawData = @([PSCustomObject]@{
                    Service = "SQL Server Agent"
                    Status = if ($isRunning) { "✅ Running" } else { "❌ Stopped" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Operational"; CheckName = "SQL Agent Status"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check Agent status"; Error = $_.Exception.Message }
        }
        }  # End Check 68
        
        # ============================================================================
        # CHECK 69: FAILED SQL AGENT JOBS (Operational)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 69 -CheckName "Failed SQL Agent Jobs")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [69/$totalChecks] Checking for failed SQL Agent jobs..."
        
        try {
            $query = @"
SELECT TOP 20
    j.name AS JobName,
    jh.step_name AS StepName,
    jh.run_date AS RunDate,
    jh.run_time AS RunTime,
    jh.run_duration AS Duration,
    jh.message AS ErrorMessage
FROM msdb.dbo.sysjobhistory jh
INNER JOIN msdb.dbo.sysjobs j ON jh.job_id = j.job_id
WHERE jh.run_status = 0  -- Failed
AND jh.run_date >= CONVERT(INT, CONVERT(VARCHAR(8), DATEADD(DAY, -7, GETDATE()), 112))  -- Last 7 days
ORDER BY jh.run_date DESC, jh.run_time DESC;
"@
            $failedJobs = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $failedJobTable = @()
            
            foreach ($job in $failedJobs) {
                # Convert run_date and run_time to readable format
                $runDateStr = $job.RunDate.ToString()
                $runTimeStr = $job.RunTime.ToString().PadLeft(6, '0')
                $runDateTime = "$($runDateStr.Substring(0,4))-$($runDateStr.Substring(4,2))-$($runDateStr.Substring(6,2)) $($runTimeStr.Substring(0,2)):$($runTimeStr.Substring(2,2)):$($runTimeStr.Substring(4,2))"
                
                $failedJobTable += [PSCustomObject]@{
                    JobName = $job.JobName
                    StepName = $job.StepName
                    RunDateTime = $runDateTime
                    ErrorMessage = if ($job.ErrorMessage.Length -gt 100) { $job.ErrorMessage.Substring(0, 100) + "..." } else { $job.ErrorMessage }
                    Status = "❌ Failed"
                }
            }
            
            $serverResults.Checks += @{
                Category = "Operational"
                CheckName = "Failed SQL Agent Jobs (Last 7 Days)"
                Status = if ($failedJobs.Count -eq 0) { "✅ Pass" } elseif ($failedJobs.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($failedJobs.Count -eq 0) { "Pass" } elseif ($failedJobs.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Identifies SQL Agent jobs that have failed in the last 7 days"
                Impact = "Failed jobs indicate problems with backups, maintenance, ETL processes, or monitoring. Common causes: insufficient permissions, disk space, network issues, code errors. Failed backup jobs can lead to data loss. Failed maintenance jobs cause performance degradation and index fragmentation. Review and fix all failures promptly. Implement job failure alerts."
                CurrentValue = @{
                    FailedJobsLast7Days = $failedJobs.Count
                }
                RecommendedAction = if ($failedJobs.Count -eq 0) { "No failed jobs in last 7 days" } else { "Investigate and resolve $($failedJobs.Count) failed job execution(s)" }
                RemediationSteps = @{
                    PowerShell = @"
# List failed jobs
Get-DbaAgentJobHistory -SqlInstance '$serverName' -StartDate (Get-Date).AddDays(-7) -ExcludeJobSteps |
    Where-Object { `$_.Status -eq 'Failed' } |
    Select-Object JobName, StepName, RunDate, Message |
    Format-Table

# Get job details
Get-DbaAgentJob -SqlInstance '$serverName' | 
    Select-Object Name, IsEnabled, LastRunDate, LastRunOutcome |
    Format-Table

# Run a specific job manually
Start-DbaAgentJob -SqlInstance '$serverName' -Job 'JobName'

# Enable job failure alerts
# Configure via SQL Agent → Alerts → New Alert
"@
                    TSQL = @"
-- Failed jobs in last 7 days
SELECT 
    j.name AS JobName,
    jh.step_name AS StepName,
    CONVERT(VARCHAR(20), 
        CAST(CAST(jh.run_date AS CHAR(8)) AS DATETIME) + 
        CAST(STUFF(STUFF(RIGHT('000000' + CAST(jh.run_time AS VARCHAR(6)), 6), 5, 0, ':'), 3, 0, ':') AS DATETIME),
        120) AS RunDateTime,
    jh.message AS ErrorMessage
FROM msdb.dbo.sysjobhistory jh
INNER JOIN msdb.dbo.sysjobs j ON jh.job_id = j.job_id
WHERE jh.run_status = 0
AND jh.run_date >= CONVERT(INT, CONVERT(VARCHAR(8), DATEADD(DAY, -7, GETDATE()), 112))
ORDER BY jh.run_date DESC, jh.run_time DESC;

-- Get job configuration
SELECT 
    name,
    enabled,
    description
FROM msdb.dbo.sysjobs
ORDER BY name;

-- Run job manually
EXEC msdb.dbo.sp_start_job @job_name = 'JobName';
"@
                    Manual = @"
**Investigating Failed Jobs:**

1. **Review Error Message:**
   - Check job history in SSMS
   - SQL Server Agent → Jobs → Right-click → View History
   - Look for specific error codes/messages

2. **Common Failure Causes:**
   - Insufficient disk space
   - Permission issues
   - Network connectivity
   - Code/query errors
   - Timeouts
   - Missing dependencies

3. **Specific Job Types:**
   **Backup Jobs:**
   - Check disk space on backup location
   - Verify backup path exists and is accessible
   - Check SQL Agent service account permissions
   
   **Maintenance Jobs:**
   - Check for blocking/locks
   - Verify index maintenance window
   - Check tempdb space
   
   **ETL/SSIS Jobs:**
   - Verify source/destination connectivity
   - Check for data quality issues
   - Review SSIS package logs

4. **Set Up Alerts:**
   - Configure email notifications
   - Alert on job failures
   - Review daily

5. **Retry Failed Jobs:**
   - After fixing root cause
   - Test in non-production first
   - Monitor for success

**Current Failed Jobs: $($failedJobs.Count)**
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/ssms/agent/view-job-activity",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-tables/dbo-sysjobhistory-transact-sql"
                )
                RawData = if ($failedJobTable.Count -gt 0) { $failedJobTable } else { @([PSCustomObject]@{ Status = "✅ Pass"; Message = "No failed jobs in last 7 days" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Operational"; CheckName = "Failed Jobs"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check failed jobs"; Error = $_.Exception.Message }
        }
        }  # End Check 69
        
        # ============================================================================
        # CHECK 70: SQL AGENT JOB OWNER (Security/Operational)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 70 -CheckName "SQL Agent Job Owners")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [70/$totalChecks] Checking SQL Agent job owners..."
        
        try {
            $query = @"
SELECT 
    j.name AS JobName,
    SUSER_SNAME(j.owner_sid) AS JobOwner,
    j.enabled AS IsEnabled,
    CASE 
        WHEN SUSER_SNAME(j.owner_sid) = 'sa' THEN 1
        WHEN SUSER_SNAME(j.owner_sid) IS NULL THEN 1
        ELSE 0
    END AS IsIssue
FROM msdb.dbo.sysjobs j
ORDER BY IsIssue DESC, j.name;
"@
            $jobs = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $jobOwnerTable = @()
            $issueJobs = @()
            
            foreach ($job in $jobs) {
                $owner = $job.JobOwner
                $isIssue = $job.IsIssue -eq 1
                
                if ($isIssue) {
                    $issueJobs += $job.JobName
                }
                
                $jobOwnerTable += [PSCustomObject]@{
                    JobName = $job.JobName
                    JobOwner = if ($owner) { $owner } else { "<orphaned>" }
                    IsEnabled = if ($job.IsEnabled) { "✅ Yes" } else { "❌ No" }
                    Status = if ($isIssue) { "⚠️ Issue" } else { "✅ OK" }
                }
            }
            
            $serverResults.Checks += @{
                Category = "Security"
                CheckName = "SQL Agent Job Owners"
                Status = if ($issueJobs.Count -eq 0) { "✅ Pass" } elseif ($issueJobs.Count -lt 5) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($issueJobs.Count -eq 0) { "Pass" } elseif ($issueJobs.Count -lt 5) { "Warning" } else { "Error" }
                Description = "Checks for SQL Agent jobs owned by 'sa' or orphaned accounts"
                Impact = "Jobs owned by 'sa' are security risk and best practice violation. If sa is disabled, jobs fail. Jobs with orphaned owners (deleted accounts) cannot run. Best practice: create dedicated service account or use ##MS_SQLAgentUser## account for job ownership. Reassign job ownership from sa to proper account. Document job owners and ensure accounts are managed."
                CurrentValue = @{
                    TotalJobs = $jobs.Count
                    JobsWithIssues = $issueJobs.Count
                }
                RecommendedAction = if ($issueJobs.Count -eq 0) { "All jobs have appropriate owners" } else { "Reassign $($issueJobs.Count) job(s) from sa or orphaned accounts to proper service accounts" }
                RemediationSteps = @{
                    PowerShell = @"
# List jobs and their owners
Get-DbaAgentJob -SqlInstance '$serverName' | 
    Select-Object Name, OwnerLoginName, IsEnabled |
    Format-Table

# Find jobs owned by sa
Get-DbaAgentJob -SqlInstance '$serverName' |
    Where-Object { `$_.OwnerLoginName -eq 'sa' } |
    Select-Object Name, OwnerLoginName |
    Format-Table

# Change job owner
Set-DbaAgentJob -SqlInstance '$serverName' -Job 'JobName' -OwnerLogin 'DOMAIN\\ServiceAccount'

# Change all jobs from sa to sysadmin account
Get-DbaAgentJob -SqlInstance '$serverName' |
    Where-Object { `$_.OwnerLoginName -eq 'sa' } |
    Set-DbaAgentJob -OwnerLogin 'DOMAIN\\ServiceAccount'
"@
                    TSQL = @"
-- List jobs and owners
SELECT 
    name AS JobName,
    SUSER_SNAME(owner_sid) AS JobOwner,
    enabled AS IsEnabled
FROM msdb.dbo.sysjobs
ORDER BY SUSER_SNAME(owner_sid), name;

-- Find jobs owned by sa
SELECT name, SUSER_SNAME(owner_sid) AS Owner
FROM msdb.dbo.sysjobs
WHERE SUSER_SNAME(owner_sid) = 'sa';

-- Change job owner
USE msdb;
GO
EXEC sp_update_job 
    @job_name = 'JobName',
    @owner_login_name = 'DOMAIN\\ServiceAccount';
GO

-- Change all sa-owned jobs to another account
DECLARE @NewOwner NVARCHAR(128) = 'DOMAIN\\ServiceAccount';

DECLARE @JobName NVARCHAR(128);
DECLARE cur CURSOR FOR
    SELECT name 
    FROM msdb.dbo.sysjobs 
    WHERE SUSER_SNAME(owner_sid) = 'sa';

OPEN cur;
FETCH NEXT FROM cur INTO @JobName;

WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC msdb.dbo.sp_update_job 
        @job_name = @JobName,
        @owner_login_name = @NewOwner;
    
    FETCH NEXT FROM cur INTO @JobName;
END

CLOSE cur;
DEALLOCATE cur;
"@
                    Manual = @"
**SQL Agent Job Ownership Best Practices:**

**Why Not 'sa':**
1. Security risk (sa has unlimited power)
2. If sa is disabled, jobs fail
3. Best practice violation
4. Audit/compliance issues
5. Difficult to track actual job owner

**Recommended Ownership:**
- Use dedicated service account
- Domain account (preferred)
- Account with minimum necessary permissions
- Document account purpose
- Monitor account for changes

**Orphaned Job Owners:**
- Occur when owner account is deleted
- Jobs cannot run
- Must reassign to valid account

**Steps to Remediate:**
1. Identify all jobs owned by sa or orphaned
2. Create/identify proper service account
3. Grant necessary permissions to account
4. Reassign job ownership
5. Test jobs run successfully
6. Document new owner
7. Set policy: no jobs owned by sa

**Permission Requirements:**
- Job owner needs permissions to:
  - Execute job steps
  - Access databases used by job
  - Write to file system (for backups, exports)
  - Network access (for remote operations)

**Current Issues: $($issueJobs.Count)**
$(if ($issueJobs.Count -gt 0) { '⚠️ Jobs owned by sa or orphaned - reassign immediately' } else { '✅ All jobs have proper owners' })
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/ssms/agent/set-job-execution-shutdown-sql-server-management-studio",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-update-job-transact-sql"
                )
                RawData = $jobOwnerTable
            }
        } catch {
            $serverResults.Checks += @{ Category = "Security"; CheckName = "Job Owners"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check job owners"; Error = $_.Exception.Message }
        }
        }  # End Check 70
        
        # ============================================================================
        # CHECK 71: DATABASE FILES ON C: DRIVE (Configuration)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 71 -CheckName "Database Files on C: Drive")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [71/$totalChecks] Checking for database files on C: drive..."
        
        try {
            $query = @"
SELECT 
    d.name AS DatabaseName,
    f.name AS FileName,
    f.type_desc AS FileType,
    f.physical_name AS FilePath,
    f.size * 8 / 1024 AS SizeMB
FROM sys.master_files f
INNER JOIN sys.databases d ON f.database_id = d.database_id
WHERE f.physical_name LIKE 'C:%'
ORDER BY d.name, f.type_desc;
"@
            $filesOnC = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $filesTable = @()
            
            foreach ($file in $filesOnC) {
                $filesTable += [PSCustomObject]@{
                    Database = $file.DatabaseName
                    FileName = $file.FileName
                    FileType = $file.FileType
                    FilePath = $file.FilePath
                    SizeMB = $file.SizeMB
                    Status = "⚠️ On C: Drive"
                }
            }
            
            $serverResults.Checks += @{
                Category = "Configuration"
                CheckName = "Database Files on C: Drive"
                Status = if ($filesOnC.Count -eq 0) { "✅ Pass" } elseif ($filesOnC.Count -le 4) { "⚠️ Warning" } else { "❌ Error" }
                Severity = if ($filesOnC.Count -eq 0) { "Pass" } elseif ($filesOnC.Count -le 4) { "Warning" } else { "Error" }
                Description = "Identifies database files located on the C: (system) drive"
                Impact = "Database files should not be on C: drive (OS drive). Reasons: C: drive fills up causing OS instability, performance issues due to OS I/O contention, difficult to add more space, backup/restore complications. System databases (master, model, msdb) on C: may be acceptable but not ideal. User databases should ALWAYS be on dedicated drives. Risk of filling C: drive can crash server."
                CurrentValue = @{
                    FilesOnCDrive = $filesOnC.Count
                }
                RecommendedAction = if ($filesOnC.Count -eq 0) { "No database files on C: drive" } elseif ($filesOnC.Count -le 4) { "Consider moving system databases off C: drive" } else { "Move user databases off C: drive immediately" }
                RemediationSteps = @{
                    PowerShell = @"
# List files on C: drive
Get-DbaDatabaseFile -SqlInstance '$serverName' |
    Where-Object { `$_.PhysicalName -like 'C:*' } |
    Select-Object Database, FileGroupName, LogicalName, PhysicalName, Size |
    Format-Table

# Move database files (requires downtime)
# 1. Take database offline
Set-DbaDbState -SqlInstance '$serverName' -Database 'DatabaseName' -Offline

# 2. Move files at OS level
Move-Item 'C:\\SQLData\\Database.mdf' 'D:\\SQLData\\Database.mdf'
Move-Item 'C:\\SQLData\\Database_log.ldf' 'D:\\SQLLogs\\Database_log.ldf'

# 3. Update SQL Server file locations
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
ALTER DATABASE DatabaseName 
MODIFY FILE (NAME = DatabaseName_Data, FILENAME = 'D:\\SQLData\\Database.mdf');
ALTER DATABASE DatabaseName 
MODIFY FILE (NAME = DatabaseName_Log, FILENAME = 'D:\\SQLLogs\\Database_log.ldf');
'@

# 4. Bring database online
Set-DbaDbState -SqlInstance '$serverName' -Database 'DatabaseName' -Online
"@
                    TSQL = @"
-- List files on C: drive
SELECT 
    d.name AS DatabaseName,
    f.name AS LogicalName,
    f.type_desc AS FileType,
    f.physical_name AS PhysicalPath,
    f.size * 8 / 1024 AS SizeMB
FROM sys.master_files f
INNER JOIN sys.databases d ON f.database_id = d.database_id
WHERE f.physical_name LIKE 'C:%'
ORDER BY d.name;

-- Move database files (USER DATABASE)
-- Step 1: Take database offline
ALTER DATABASE [DatabaseName] SET OFFLINE;
GO

-- Step 2: Physically move files using Windows Explorer or PowerShell
-- From: C:\\SQLData\\Database.mdf
-- To:   D:\\SQLData\\Database.mdf

-- Step 3: Update file locations in SQL Server
ALTER DATABASE [DatabaseName]
MODIFY FILE (NAME = 'LogicalFileName', FILENAME = 'D:\\SQLData\\Database.mdf');
GO

ALTER DATABASE [DatabaseName]
MODIFY FILE (NAME = 'LogicalLogFileName', FILENAME = 'D:\\SQLLogs\\Database_log.ldf');
GO

-- Step 4: Bring database online
ALTER DATABASE [DatabaseName] SET ONLINE;
GO

-- For SYSTEM DATABASES (master, model, msdb):
-- Requires SQL Server service restart and startup parameter changes
-- More complex - see documentation
"@
                    Manual = @"
**Moving Database Files Off C: Drive:**

**User Databases:**
1. Schedule maintenance window
2. Take database offline
3. Move physical files:
   - .mdf (data) to D:\\SQLData (or dedicated data drive)
   - .ldf (log) to E:\\SQLLogs (or dedicated log drive)
4. Update file paths in SQL Server (ALTER DATABASE... MODIFY FILE)
5. Bring database online
6. Test application connectivity

**System Databases:**
More complex, requires:
1. Stop SQL Server service
2. Move files at OS level
3. Update startup parameters (-d, -l, -e)
4. Restart SQL Server
5. Verify success

**Best Practices:**
- Data files: Dedicated drive (D:, E:, etc.)
- Log files: Separate dedicated drive for performance
- TempDB: Separate dedicated drive (ideally SSD)
- Never mix OS and database files
- Keep 15-20% free space on data drives

**Why Not C: Drive:**
- OS needs space
- Performance: OS and DB I/O conflict
- Maintenance: Windows updates, patches
- Growth: C: typically smaller
- Risk: Filling C: can crash server

**Exceptions (acceptable but not ideal):**
- System databases on small/test servers
- Development environments
- SQL Express with small databases

**Current Files on C:: $($filesOnC.Count)**
$(if ($filesOnC.Count -gt 0) { '⚠️ Move user databases off C: drive' } else { '✅ No files on C: drive' })
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/move-database-files",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/databases/move-system-databases"
                )
                RawData = if ($filesTable.Count -gt 0) { $filesTable } else { @([PSCustomObject]@{ Status = "✅ Pass"; Message = "No database files on C: drive" }) }
            }
        } catch {
            $serverResults.Checks += @{ Category = "Configuration"; CheckName = "Files on C: Drive"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check C: drive files"; Error = $_.Exception.Message }
        }
        }  # End Check 71
        
        # ============================================================================
        # CHECK 72: DEFAULT FILL FACTOR (Performance)
        # ============================================================================
        
        if (-not (Should-SkipCheck -CheckNumber 72 -CheckName "Default Fill Factor")) {
        
        Send-Progress -Value ($serverProgress + ($currentCheck++ * $checkProgress)) -Message "[$serverName] [72/$totalChecks] Checking default fill factor..."
        
        try {
            $query = @"
SELECT 
    name,
    value AS ConfigValue,
    value_in_use AS CurrentValue
FROM sys.configurations
WHERE name = 'fill factor (%)';
"@
            $fillFactor = Invoke-DbaQuery -SqlInstance $conn -Query $query
            
            $currentValue = $fillFactor.CurrentValue
            $isDefault = $currentValue -eq 0
            
            $serverResults.Checks += @{
                Category = "Performance"
                CheckName = "Default Fill Factor"
                Status = if ($isDefault) { "✅ Pass" } else { "⚠️ Warning" }
                Severity = if ($isDefault) { "Pass" } else { "Warning" }
                Description = "Checks if server-wide default fill factor is set (should be 0/100)"
                Impact = "Server-wide fill factor of 0 (or 100) means indexes are filled completely, which is optimal for most workloads. Non-zero server-wide fill factor (e.g., 80) leaves space in index pages for updates, but applies to ALL indexes, wasting space for read-only tables. Problem: This is a server-wide setting affecting all new indexes. Better approach: leave server setting at 0 (default) and set fill factor per-index only where needed (high-update tables). Non-default server fill factor is usually a mistake."
                CurrentValue = @{
                    FillFactor = if ($currentValue -eq 0) { "0 (100% - Default)" } else { "$currentValue%" }
                }
                RecommendedAction = if ($isDefault) { "Fill factor is at recommended default (0)" } else { "Consider resetting to default (0) and using index-specific fill factor where needed" }
                RemediationSteps = @{
                    PowerShell = @"
# Check current fill factor
Get-DbaSpConfigure -SqlInstance '$serverName' -Name FillfactorPercentage | Format-Table

# Reset to default (0)
Set-DbaSpConfigure -SqlInstance '$serverName' -Name FillfactorPercentage -Value 0

# Verify
Get-DbaSpConfigure -SqlInstance '$serverName' -Name FillfactorPercentage | Format-Table

# Check indexes with custom fill factor
Invoke-DbaQuery -SqlInstance '$serverName' -Query @'
SELECT 
    OBJECT_SCHEMA_NAME(object_id) + '.' + OBJECT_NAME(object_id) AS TableName,
    name AS IndexName,
    fill_factor
FROM sys.indexes
WHERE fill_factor > 0
AND fill_factor < 100
ORDER BY OBJECT_NAME(object_id), name
'@ | Format-Table
"@
                    TSQL = @"
-- Check server-wide fill factor
EXEC sp_configure 'fill factor (%)';
GO

-- Reset to default
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO
EXEC sp_configure 'fill factor (%)', 0;
RECONFIGURE WITH OVERRIDE;
GO

-- Find indexes with custom fill factor
SELECT 
    DB_NAME() AS DatabaseName,
    OBJECT_SCHEMA_NAME(i.object_id) AS SchemaName,
    OBJECT_NAME(i.object_id) AS TableName,
    i.name AS IndexName,
    i.fill_factor AS FillFactor
FROM sys.indexes i
WHERE i.fill_factor > 0
AND i.fill_factor < 100
ORDER BY SchemaName, TableName, IndexName;

-- Set fill factor for specific index (proper way)
CREATE INDEX IX_IndexName
ON SchemaName.TableName (ColumnName)
WITH (FILLFACTOR = 80);  -- Only where needed!

-- Rebuild index with fill factor
ALTER INDEX IX_IndexName
ON SchemaName.TableName
REBUILD WITH (FILLFACTOR = 80);
"@
                    Manual = @"
**Fill Factor Explained:**

**What is Fill Factor:**
- Percentage of index page filled with data
- 0 or 100 = completely full (optimal for most)
- 80 = 20% empty space left for INSERTs/UPDATEs

**Server-Wide vs. Index-Specific:**
- **Server-wide (this check)**: Applies to ALL new indexes
- **Index-specific**: Set per index (recommended)

**When to Use Non-100 Fill Factor:**
- High-update tables with page splits
- Indexes on random key values (GUIDs)
- Specific problematic indexes only
- **NOT** server-wide!

**Why Server-Wide Fill Factor is Bad:**
1. Wastes space on read-only tables
2. Wastes space on clustered indexes (entire table)
3. Increases storage and memory requirements
4. Reduces buffer pool efficiency
5. Usually set by mistake or misunderstanding

**Best Practice:**
1. Keep server-wide at 0 (default)
2. Set fill factor on specific indexes only
3. Monitor page splits
4. Adjust per-index as needed
5. Document why custom fill factor was set

**Current Setting: $(if ($isDefault) { '0 (Default) ✅' } else { "$currentValue% ⚠️ Non-default" })**

**If Non-Default:**
1. Research why it was changed
2. Identify indexes that truly need custom fill factor
3. Set those indexes specifically
4. Reset server-wide to 0
5. Rebuild affected indexes

**Monitoring Page Splits:**
Use sys.dm_db_index_operational_stats to find:
- leaf_allocation_count (page splits)
- Consider fill factor 80-90 if excessive splits
"@
                }
                Documentation = @(
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-fill-factor-server-configuration-option",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/indexes/specify-fill-factor-for-an-index"
                )
                RawData = @([PSCustomObject]@{
                    Setting = "fill factor (%)"
                    CurrentValue = if ($currentValue -eq 0) { "0 (100% - Default)" } else { "$currentValue%" }
                    Status = if ($isDefault) { "✅ Default" } else { "⚠️ Non-Default" }
                })
            }
        } catch {
            $serverResults.Checks += @{ Category = "Performance"; CheckName = "Fill Factor"; Status = "❌ Error"; Severity = "Error"; Description = "Could not check fill factor"; Error = $_.Exception.Message }
        }
        }  # End Check 72
        
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
    Add-ToReport ""
    Add-ToReport "**Report Date:** $timestamp  "
    Add-ToReport "**Primary Server:** $($healthCheckResults.PrimaryServer)  "
    Add-ToReport "**Servers Analyzed:** $($healthCheckResults.ExecutiveSummary.TotalServers)  "
    Add-ToReport "**AG Environment:** $(if($healthCheckResults.IsAGEnvironment){'Yes'}else{'No'})  "
    Add-ToReport "**Execution Platform:** $($healthCheckResults.RunningOS)  "
    Add-ToReport "**Server Admin Credentials:** $(if($healthCheckResults.ServerAdminCredsProvided){'Provided'}else{'Not Provided'})  "
    if ($healthCheckResults.ServerAdminCredsProvided -and $healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin -gt 0) {
        Add-ToReport "**Checks Using Server Admin:** $($healthCheckResults.ExecutiveSummary.ChecksUsingServerAdmin)  "
    }
    
    # Add warning if running on non-Windows
    if (-not $healthCheckResults.IsWindowsHost) {
        Add-ToReport ""
        Add-ToReport "> **Platform Notice:** This health check was executed on $($healthCheckResults.RunningOS). Windows-specific checks (WMI, remote PowerShell) have been disabled or use T-SQL fallback methods. For optimal results including all enhanced checks, run this plugin from a Windows system."
    }
    
    Add-ToReport ""
    Add-ToReport "---"
    Add-ToReport ""
    
    # Executive Dashboard
    Add-ToReport "## Executive Dashboard"
    Add-ToReport ""
    Add-ToReport "| Metric                    | Value |"
    Add-ToReport "|---------------------------|-------|"
    Add-ToReport "| **Overall Health Score**  | **${healthScore}%** |"
    Add-ToReport "| Checks Passed             | $($healthCheckResults.ExecutiveSummary.PassedChecks) |"
    Add-ToReport "| Warnings                  | $($healthCheckResults.ExecutiveSummary.WarningChecks) |"
    Add-ToReport "| Failed                    | $($healthCheckResults.ExecutiveSummary.FailedChecks) |"
    Add-ToReport "| Total Checks              | $($healthCheckResults.ExecutiveSummary.TotalChecks) |"
    
    # Add exclusion information if checks were excluded/included
    if ($healthCheckResults.ExecutiveSummary.ExcludedChecks -gt 0) {
        Add-ToReport "| **Excluded Checks**       | **$($healthCheckResults.ExecutiveSummary.ExcludedChecks)** |"
        if ($healthCheckResults.ExclusionMode -eq "Inclusions") {
            Add-ToReport "| Exclusion Mode            | Inclusions (running ONLY selected checks) |"
        } else {
            Add-ToReport "| Exclusion Mode            | Exclusions (skipping selected checks) |"
        }
    }
    
    Add-ToReport ""
    
    # Show excluded checks list and reason if applicable
    if ($healthCheckResults.ExecutiveSummary.ExcludedChecks -gt 0) {
        Add-ToReport "**Excluded Checks:** $($healthCheckResults.ExcludedChecks -join ', ')  "
        if (-not [string]::IsNullOrWhiteSpace($healthCheckResults.ExclusionReason)) {
            Add-ToReport "**Exclusion Reason:** $($healthCheckResults.ExclusionReason)  "
        }
        Add-ToReport ""
    }
    
    Add-ToReport "---"
    Add-ToReport ""
    
    # Table of Contents
    Add-ToReport "## Table of Contents"
    Add-ToReport ""
    Add-ToReport "- [Executive Dashboard](#executive-dashboard)"
    Add-ToReport "- [Table of Contents](#table-of-contents)"
    if ($healthCheckResults.IsAGEnvironment -and $healthCheckResults.AvailabilityGroups.Count -gt 0) {
        Add-ToReport "- [Availability Groups Configuration](#availability-groups-configuration)"
    }
    
    # Add server sections with their checks
    foreach ($serverName in $healthCheckResults.Servers.Keys | Sort-Object) {
        $serverData = $healthCheckResults.Servers[$serverName]
        $anchorName = $serverName -replace '[^a-zA-Z0-9-]', '-' -replace '-+', '-' -replace '^-|-$', ''
        Add-ToReport "- [Server: $serverName](#server-$($anchorName.ToLower()))"
        
        # Add check subsections
        $checkNumber = 0
        foreach ($check in $serverData.Checks) {
            $checkNumber++
            # Create display text and matching anchor - include server name in heading for uniqueness
            $checkDisplayName = "[$serverName] Check $checkNumber of $($serverData.Checks.Count): $($check.CheckName)"
            # Create anchor to match the actual heading format with server name
            $checkAnchor = "$serverName-check-$checkNumber-of-$($serverData.Checks.Count)-$($check.CheckName)" -replace '[^a-zA-Z0-9-]', '-' -replace '-+', '-' -replace '^-|-$', ''
            Add-ToReport "  - [$checkDisplayName](#$($checkAnchor.ToLower()))"
        }
    }
    
    Add-ToReport ""
    Add-ToReport "---"
    Add-ToReport ""
    
    # AG Section
    Send-Progress -Value 0.93 -Message "Writing Availability Group information..."
    Add-ToReport "## Availability Groups Configuration"
    Add-ToReport ""
    
    if ($healthCheckResults.IsAGEnvironment -and $healthCheckResults.AvailabilityGroups.Count -gt 0) {
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
    } else {
        Add-ToReport "There are no availability groups configured on the analyzed servers."
        Add-ToReport ""
    }
    Add-ToReport "---"
    Add-ToReport ""
    
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
        Add-ToReport ""
        Add-ToReport "**Edition:** $($serverInfo.Edition)  "
        Add-ToReport "**Version:** $($serverInfo.Version)  "
        Add-ToReport "**Build:** $($serverInfo.BuildNumber)  "
        Add-ToReport "**Patch Level:** $($serverInfo.ProductUpdateLevel)  "
        Add-ToReport "**Memory:** $($serverInfo.PhysicalMemoryMB) MB  "
        Add-ToReport "**Processors:** $($serverInfo.Processors)  "
        Add-ToReport "**Collation:** $($serverInfo.Collation)  "
        Add-ToReport ""
        Add-ToReport "---"
        Add-ToReport ""
        
        # Checks
        $checkNumber = 0
        $totalServerChecks = $serverData.Checks.Count
        # Create server anchor for unique check IDs
        $serverAnchor = $serverName -replace '[^a-zA-Z0-9-]', '-' -replace '-+', '-' -replace '^-|-$', ''
        foreach ($check in $serverData.Checks) {
            $checkNumber++
            
            Add-ToReport ""
            Add-ToReport ""
            Add-ToReport "### [$serverName] Check ${checkNumber} of ${totalServerChecks}: $($check.CheckName)"
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
    Add-ToReport ""
    Add-ToReport "**SQL Server Health Check Report**"
    Add-ToReport "Generated by xyOps MSSQL Health Check Plugin"
    Add-ToReport "Copyright 2026 Tim Alderweireldt"
    Add-ToReport "Report Date: $timestamp"
    
    Write-Host ""
    Write-Host "Markdown report saved: $filename"
    
    # Export to PDF if requested
    $pdfFilename = $null
    $exportToPdf = $exportToPdfRaw -eq $true -or $exportToPdfRaw -eq "true" -or $exportToPdfRaw -eq "True"
    
    if ($exportToPdf) {
        Send-Progress -Value 0.95 -Message "Converting Markdown to PDF..."
        Write-Host "PDF export requested - converting Markdown to PDF..."
        
        try {
            # Check if pandoc is available
            $pandocAvailable = $null -ne (Get-Command pandoc -ErrorAction SilentlyContinue)
            
            if ($pandocAvailable) {
                # Use pandoc for conversion
                $pdfFilename = $filename -replace '\.md$', '.pdf'
                $pandocArgs = @(
                    $filename,
                    '-o', $pdfFilename,
                    '--pdf-engine=xelatex',
                    '-V', 'geometry:margin=1in',
                    '-V', 'fontsize=10pt',
                    '--toc',
                    '--toc-depth=3'
                )
                
                Write-Host "Converting with pandoc..."
                & pandoc $pandocArgs 2>&1 | Out-Null
                
                if (Test-Path $pdfFilename) {
                    Write-Host "PDF report saved: $pdfFilename"
                } else {
                    Write-Host "Warning: PDF conversion completed but file not found"
                    $pdfFilename = $null
                }
            } else {
                # Pandoc not available - try markdown-pdf via npm
                Write-Host "Pandoc not found, attempting markdown-pdf..."
                $markdownPdfAvailable = $null -ne (Get-Command markdown-pdf -ErrorAction SilentlyContinue)
                
                if ($markdownPdfAvailable) {
                    $pdfFilename = $filename -replace '\.md$', '.pdf'
                    & markdown-pdf $filename -o $pdfFilename 2>&1 | Out-Null
                    
                    if (Test-Path $pdfFilename) {
                        Write-Host "PDF report saved: $pdfFilename"
                    } else {
                        Write-Host "Warning: PDF conversion completed but file not found"
                        $pdfFilename = $null
                    }
                } else {
                    Write-Host "Warning: PDF export requested but no converter found (pandoc or markdown-pdf)"
                    Write-Host "Install pandoc: https://pandoc.org/installing.html"
                    Write-Host "Or install markdown-pdf: npm install -g markdown-pdf"
                    Write-Host "Markdown report will still be available."
                }
            }
        } catch {
            Write-Host "Warning: PDF conversion failed: $($_.Exception.Message)"
            Write-Host "Markdown report will still be available."
            $pdfFilename = $null
        }
    }
    
    # Output file references to xyOps
    Send-Progress -Value 0.98 -Message "Finalizing report..."
    $filesToExport = @(
        @{
            path = $filename
            name = $filename
        }
    )
    
    if ($pdfFilename -and (Test-Path $pdfFilename)) {
        $filesToExport += @{
            path = $pdfFilename
            name = $pdfFilename
        }
    }
    
    Write-Output-JSON @{
        xy = 1
        files = $filesToExport
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
