[CmdletBinding()]
param(
    [ValidateSet('Check', 'Worker', 'Coordinator', 'Token')]
    [string] $Mode = 'Check',

    [string] $BundleRoot,
    [string] $LocalAddress,
    [string] $CoordinatorAddress,
    [string] $WorkerProgram,
    [System.Security.SecureString] $ClusterToken
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw 'Unable to determine the script path for the default BundleRoot.'
    }
    $BundleRoot = Split-Path -Parent ([System.IO.Path]::GetFullPath($scriptPath))
}

$CoordinationPort = 50170
$WorkerPort = 50161
$RequiredFiles = @(
    'LICENSE',
    'README.md',
    'burn.exe',
    'lan_smoke.ps1',
    'scale_harness.exe',
    'sembazuru-worker.exe'
)

function Resolve-BundleRoot {
    param([string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'BundleRoot must not be empty.'
    }
    try {
        $resolved = [System.IO.Path]::GetFullPath($Path)
    } catch {
        throw "BundleRoot is not a valid path: $Path"
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "BundleRoot does not exist: $resolved"
    }
    return $resolved
}

function Test-ManifestRelativePath {
    param([string] $RelativePath)

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        return $false
    }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        return $false
    }
    if ($RelativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        return $false
    }
    return $true
}

function Test-BundleIntegrity {
    param([string] $Root)

    $manifestPath = Join-Path $Root 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Bundle manifest is missing: $manifestPath"
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    } catch {
        throw "Bundle manifest is not valid JSON: $manifestPath"
    }

    if ([string]$manifest.version -ne '0.0.3') {
        throw "Unsupported bundle version: $($manifest.version)"
    }
    if ([string]$manifest.kind -ne 'lan-smoke') {
        throw "Unsupported bundle kind: $($manifest.kind)"
    }

    $declared = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        $expected = ([string]$entry.sha256).ToLowerInvariant()
        if (-not (Test-ManifestRelativePath $relative) -or $expected -notmatch '^[0-9a-f]{64}$') {
            throw 'Bundle manifest contains an invalid file entry.'
        }

        $normalized = $relative.Replace('/', '\')
        $key = $normalized.ToLowerInvariant()
        if ($declared.ContainsKey($key)) {
            throw "Bundle manifest contains a duplicate file entry: $relative"
        }
        $declared[$key] = $true

        $filePath = Join-Path $Root $normalized
        $rootWithSeparator = ([System.IO.Path]::GetFullPath($Root)).TrimEnd('\') + '\'
        $fullPath = [System.IO.Path]::GetFullPath($filePath)
        if (-not $fullPath.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Bundle manifest file escapes BundleRoot: $relative"
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Bundle file is missing: $relative"
        }

        $actual = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "Bundle hash mismatch: $relative"
        }
        Write-Output ("Bundle file OK: {0}" -f $relative)
    }

    foreach ($required in $RequiredFiles) {
        if (-not $declared.ContainsKey($required.ToLowerInvariant())) {
            throw "Bundle manifest is missing required file: $required"
        }
    }
    Write-Output ('Bundle integrity: OK ({0} files)' -f $declared.Count)
}

function ConvertTo-LocalIPv4 {
    param(
        [string] $Address,
        [string] $ParameterName
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        throw "$ParameterName is required and must be an explicit IPv4 address."
    }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
        throw "$ParameterName is not a valid IPv4 address: $Address"
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$ParameterName must be an IPv4 address: $Address"
    }
    if ($parsed.Equals([System.Net.IPAddress]::Any)) {
        throw "$ParameterName must not be 0.0.0.0."
    }

    $canonical = $parsed.ToString()
    $isLocal = $false
    foreach ($networkInterface in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($networkInterface.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) {
            continue
        }
        foreach ($unicast in $networkInterface.GetIPProperties().UnicastAddresses) {
            if ($unicast.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                $unicast.Address.ToString() -eq $canonical) {
                $isLocal = $true
            }
        }
    }
    if (-not $isLocal) {
        throw "$ParameterName is not configured on this PC: $canonical"
    }
    return $canonical
}

function ConvertTo-IPv4Endpoint {
    param(
        [string] $Endpoint,
        [string] $ParameterName,
        [int] $RequiredPort
    )

    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        throw "$ParameterName is required as IPv4:port."
    }
    $separator = $Endpoint.LastIndexOf(':')
    if ($separator -le 0 -or $separator -eq ($Endpoint.Length - 1) -or $Endpoint.IndexOf(':') -ne $separator) {
        throw "$ParameterName must be an IPv4 endpoint:port."
    }
    $addressText = $Endpoint.Substring(0, $separator)
    $portText = $Endpoint.Substring($separator + 1)
    $address = $null
    $port = 0
    if (-not [System.Net.IPAddress]::TryParse($addressText, [ref]$address) -or
        $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $address.Equals([System.Net.IPAddress]::Any) -or
        -not [int]::TryParse($portText, [ref]$port) -or
        $port -lt 1 -or $port -gt 65535) {
        throw "$ParameterName must be an explicit IPv4 endpoint:port."
    }
    if ($port -ne $RequiredPort) {
        throw "$ParameterName must use TCP port $RequiredPort."
    }
    return [pscustomobject]@{
        Address = $address.ToString()
        Port = $port
        Text = ('{0}:{1}' -f $address.ToString(), $port)
    }
}

function Get-ClusterTokenText {
    param([System.Security.SecureString] $SecureToken)

    if ($null -eq $SecureToken) {
        $SecureToken = Read-Host -Prompt 'Cluster token' -AsSecureString
    }
    if ($null -eq $SecureToken) {
        throw 'Cluster token is required.'
    }
    $plain = (New-Object System.Net.NetworkCredential('', $SecureToken)).Password
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -lt 32) {
        throw 'Cluster token must contain at least 32 characters.'
    }
    return $plain
}

function Assert-NotReparsePoint {
    param([string] $Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to use a reparse point: $Path"
    }
}

function Get-ManifestExpectedHash {
    param(
        [string] $Root,
        [string] $RelativePath
    )

    $manifestPath = Join-Path $Root 'manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $wanted = $RelativePath.Replace('/', '\').ToLowerInvariant()
    $matches = @(
        foreach ($entry in @($manifest.files)) {
            if ([string]$entry.path.Replace('/', '\').ToLowerInvariant() -eq $wanted) {
                [string]$entry.sha256
            }
        }
    )
    if ($matches.Count -ne 1 -or $matches[0] -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Bundle manifest has no unique SHA256 for $RelativePath"
    }
    return $matches[0].ToLowerInvariant()
}

function New-WorkerBurnCopy {
    param(
        [string] $Root,
        [string] $RunRoot,
        [string] $RunDirectory
    )

    $runRootItem = Get-Item -LiteralPath $RunRoot -Force -ErrorAction SilentlyContinue
    if ($null -ne $runRootItem) {
        if (-not $runRootItem.PSIsContainer) {
            throw "Worker run root is not a directory: $RunRoot"
        }
        Assert-NotReparsePoint $RunRoot
    } else {
        New-Item -ItemType Directory -Path $RunRoot | Out-Null
    }

    $runDirectoryItem = Get-Item -LiteralPath $RunDirectory -Force -ErrorAction SilentlyContinue
    if ($null -ne $runDirectoryItem) {
        throw "Refusing to reuse an existing worker run directory: $RunDirectory"
    }
    New-Item -ItemType Directory -Path $RunDirectory | Out-Null
    Assert-NotReparsePoint $RunDirectory

    $burnSource = Join-Path $Root 'burn.exe'
    $burnCopy = Join-Path $RunDirectory 'burn.exe'
    if (Test-Path -LiteralPath $burnCopy) {
        throw "Refusing to replace an existing worker burn copy: $burnCopy"
    }
    $expectedHash = Get-ManifestExpectedHash $Root 'burn.exe'
    Copy-Item -LiteralPath $burnSource -Destination $burnCopy
    $copiedHash = (Get-FileHash -LiteralPath $burnCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($copiedHash -ne $expectedHash) {
        throw 'Worker burn copy does not match the bundle manifest SHA256.'
    }

    $acl = Get-Acl -LiteralPath $burnCopy
    $restrictedCode = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-12')
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $restrictedCode,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule) | Out-Null
    Set-Acl -LiteralPath $burnCopy -AclObject $acl

    $postAclHash = (Get-FileHash -LiteralPath $burnCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($postAclHash -ne $expectedHash) {
        throw 'Worker burn copy changed while applying its ACL.'
    }
    return [System.IO.Path]::GetFullPath($burnCopy)
}

function Invoke-NativeWithClusterToken {
    param(
        [string] $FilePath,
        [string[]] $Arguments,
        [string] $Token,
        [hashtable] $EnvironmentVariables = @{}
    )

    $saved = @{}
    $exitCode = 1
    try {
        $environment = [System.Environment]::GetEnvironmentVariables('Process')
        foreach ($entry in $environment.GetEnumerator()) {
            $name = [string]$entry.Key
            if ($name -like 'SEMBAZURU_*') {
                $saved[$name] = [string]$entry.Value
                [System.Environment]::SetEnvironmentVariable($name, $null, 'Process')
            }
        }
        [System.Environment]::SetEnvironmentVariable('SEMBAZURU_CLUSTER_TOKEN', $Token, 'Process')
        foreach ($environmentEntry in $EnvironmentVariables.GetEnumerator()) {
            [System.Environment]::SetEnvironmentVariable(
                [string]$environmentEntry.Key,
                [string]$environmentEntry.Value,
                'Process'
            )
        }
        & $FilePath @Arguments | ForEach-Object { Write-Host $_ }
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
    } finally {
        try {
            $current = [System.Environment]::GetEnvironmentVariables('Process')
            foreach ($entry in $current.GetEnumerator()) {
                $name = [string]$entry.Key
                if ($name -like 'SEMBAZURU_*') {
                    [System.Environment]::SetEnvironmentVariable($name, $null, 'Process')
                }
            }
        } finally {
            foreach ($entry in $saved.GetEnumerator()) {
                [System.Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, 'Process')
            }
        }
    }
    return $exitCode
}

function Invoke-Token {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    Write-Output ([System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant())
}

function Invoke-Check {
    param([string] $Root)

    $critical = New-Object System.Collections.Generic.List[string]
    Write-Output 'Sembazuru LAN smoke check'

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        Write-Output ("OS: {0} ({1})" -f $os.Caption, $os.Version)
        Write-Output ("OS architecture: {0}" -f [Environment]::Is64BitOperatingSystem)
        if (-not [Environment]::Is64BitOperatingSystem) {
            $critical.Add('64-bit Windows is required.')
        }
    } catch {
        $critical.Add('Unable to query Windows OS information.')
    }

    try {
        $processors = @(Get-CimInstance -ClassName Win32_Processor)
        $names = ($processors | ForEach-Object { $_.Name }) -join '; '
        Write-Output ("CPU: {0} logical processors; {1}" -f [Environment]::ProcessorCount, $names)
    } catch {
        $critical.Add('Unable to query CPU information.')
    }

    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem
        $memoryGb = [Math]::Round(([double]$computer.TotalPhysicalMemory / 1GB), 1)
        Write-Output ("Memory: {0} GB" -f $memoryGb)
        if ([double]$computer.TotalPhysicalMemory -lt 1GB) {
            $critical.Add('At least 1 GB of physical memory is required.')
        }
    } catch {
        $critical.Add('Unable to query physical memory.')
    }

    try {
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop)
        if ($adapters.Count -eq 0) {
            $critical.Add('No physical network adapter was found.')
        }
        foreach ($adapter in $adapters) {
            $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -ne '0.0.0.0' } |
                ForEach-Object { $_.IPAddress })
            $profiles = @(Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
                ForEach-Object { $_.NetworkCategory })
            $addressText = if ($addresses.Count -gt 0) { $addresses -join ', ' } else { '<none>' }
            $profileText = if ($profiles.Count -gt 0) { $profiles -join ', ' } else { '<unknown>' }
            Write-Output ("NIC: {0}; status={1}; link={2}; IPv4={3}; profile={4}" -f
                $adapter.Name, $adapter.Status, $adapter.LinkSpeed, $addressText, $profileText)
        }
    } catch {
        $critical.Add('Unable to query physical network adapters.')
    }

    $runtimePaths = @(
        (Join-Path $env:WINDIR 'System32\vcruntime140.dll'),
        (Join-Path $env:WINDIR 'System32\msvcp140.dll')
    )
    foreach ($runtimePath in $runtimePaths) {
        $exists = Test-Path -LiteralPath $runtimePath -PathType Leaf
        Write-Output ("VC++ runtime: {0} = {1}" -f $runtimePath, $exists)
        if (-not $exists -and $runtimePath.EndsWith('vcruntime140.dll')) {
            $critical.Add('Microsoft VC++ v14 x64 runtime is missing.')
        }
    }

    try {
        $connections = @(Get-NetTCPConnection -LocalPort $CoordinationPort, $WorkerPort -ErrorAction SilentlyContinue |
            Where-Object { $_.State -in @('Listen', 'Bound', 'Established', 'SynSent', 'SynReceived') })
        if ($connections.Count -eq 0) {
            Write-Output ("Dedicated ports: {0} and {1} are not occupied." -f $CoordinationPort, $WorkerPort)
        } else {
            foreach ($connection in $connections) {
                Write-Output ("Dedicated port conflict: local={0}; state={1}; pid={2}" -f
                    $connection.LocalPort, $connection.State, $connection.OwningProcess)
            }
            $critical.Add('A dedicated LAN smoke port is already occupied.')
        }
    } catch {
        $netstatLines = @(netstat.exe -ano -p tcp 2>$null)
        $conflicts = @($netstatLines | Where-Object {
            $_ -match '\sTCP\s+[^ ]+:(50170|50161)\s+[^ ]+\s+(LISTENING|ESTABLISHED|SYN_SENT|SYN_RECEIVED)\s+\d+'
        })
        if ($conflicts.Count -eq 0) {
            Write-Output ("Dedicated ports: {0} and {1} are not occupied." -f $CoordinationPort, $WorkerPort)
        } else {
            Write-Output 'Dedicated port conflict:'
            $conflicts | ForEach-Object { Write-Output $_ }
            $critical.Add('A dedicated LAN smoke port is already occupied.')
        }
    }

    try {
        Test-BundleIntegrity $Root
    } catch {
        Write-Output ("Bundle integrity: FAIL; {0}" -f $_.Exception.Message)
        $critical.Add('Bundle integrity verification failed.')
    }

    try {
        $services = @(Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*Sembazuru*' -or $_.DisplayName -like '*Sembazuru*' })
        if ($services.Count -eq 0) {
            Write-Output 'Sembazuru services: none found.'
        } else {
            foreach ($service in $services) {
                Write-Output ("Sembazuru service: {0}; status={1}" -f $service.Name, $service.Status)
            }
        }
    } catch {
        Write-Output 'Sembazuru services: unable to query service status.'
    }

    if ($critical.Count -gt 0) {
        Write-Output 'Check result: FAIL'
        throw ('Check failed: ' + ($critical -join '; '))
    }
    Write-Output 'Check result: PASS'
}

function Invoke-Worker {
    param([string] $Root)

    Test-BundleIntegrity $Root
    $local = ConvertTo-LocalIPv4 $LocalAddress '-LocalAddress'
    $coordinator = ConvertTo-IPv4Endpoint $CoordinatorAddress '-CoordinatorAddress' $CoordinationPort
    $token = Get-ClusterTokenText $ClusterToken
    $workerPath = Join-Path $Root 'sembazuru-worker.exe'
    if (-not (Test-Path -LiteralPath $workerPath -PathType Leaf)) {
        throw "Worker binary is missing: $workerPath"
    }

    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        throw 'LocalAppData is unavailable.'
    }
    $runRoot = Join-Path $localAppData 'SembazuruLan'
    $runDir = Join-Path $runRoot ([Guid]::NewGuid().ToString('N'))
    $burnCopy = New-WorkerBurnCopy $Root $runRoot $runDir
    $configPath = Join-Path $runDir 'worker.toml'
    $config = @"
capacity = 2
participation_mode = 'always'
action_timeout_secs = 30
unsafe_allow_insecure_execution_lan = true
listen_addr = '$local`:$WorkerPort'
advertise = 'http://$local`:$WorkerPort'
agent = 'http://$($coordinator.Text)'
"@
    [System.IO.File]::WriteAllText($configPath, $config, (New-Object System.Text.UTF8Encoding($false)))

    Write-Output ("Worker burn program: {0}" -f $burnCopy)
    Write-Output ("Worker listening on {0}:{1}; coordinator={2}" -f $local, $WorkerPort, $coordinator.Text)
    $arguments = @()
    $environmentVariables = @{ SEMBAZURU_WORKER_CONFIG = $configPath }
    $exitCode = Invoke-NativeWithClusterToken $workerPath $arguments $token $environmentVariables
    exit $exitCode
}

function Invoke-Coordinator {
    param([string] $Root)

    Test-BundleIntegrity $Root
    $local = ConvertTo-LocalIPv4 $LocalAddress '-LocalAddress'
    if ([string]::IsNullOrWhiteSpace($WorkerProgram)) {
        throw '-WorkerProgram is required for Coordinator mode.'
    }
    if (-not [System.IO.Path]::IsPathRooted($WorkerProgram)) {
        throw '-WorkerProgram must be an absolute path on the worker PC.'
    }
    $token = Get-ClusterTokenText $ClusterToken
    $harnessPath = Join-Path $Root 'scale_harness.exe'
    if (-not (Test-Path -LiteralPath $harnessPath -PathType Leaf)) {
        throw "Scale harness binary is missing: $harnessPath"
    }

    $coordEndpoint = '{0}:{1}' -f $local, $CoordinationPort
    Write-Output ("Coordinator listening on {0}; worker program={1}" -f $coordEndpoint, $WorkerProgram)
    $arguments = @($coordEndpoint, '1', '8', $WorkerProgram, '1000000')
    $exitCode = Invoke-NativeWithClusterToken $harnessPath $arguments $token
    exit $exitCode
}

try {
    if ($Mode -eq 'Token') {
        Invoke-Token
        exit 0
    }

    $resolvedRoot = Resolve-BundleRoot $BundleRoot
    switch ($Mode) {
        'Check' { Invoke-Check $resolvedRoot }
        'Worker' { Invoke-Worker $resolvedRoot }
        'Coordinator' { Invoke-Coordinator $resolvedRoot }
        default { throw "Unsupported mode: $Mode" }
    }
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
