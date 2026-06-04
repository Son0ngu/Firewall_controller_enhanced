param(
    [string]$ServerUrl = $env:SAINT_E2E_SERVER_URL,
    [string]$BootstrapAdminUsername = $env:SAINT_E2E_BOOTSTRAP_ADMIN_USERNAME,
    [string]$BootstrapAdminPassword = $env:SAINT_E2E_BOOTSTRAP_ADMIN_PASSWORD,
    [string]$OutputDir = "",
    [string]$RunId = "",
    [string]$CleanupResultJson = "",
    [switch]$RunRealFirewallPolicy,
    [switch]$KeepTestData,
    [switch]$SkipBuild,
    [switch]$SkipAgentExeLaunch,
    [switch]$DryRun,
    [switch]$Deep,
    [switch]$FirewallOnly,
    [ValidateSet("auto", "netsh", "netsecurity")]
    [string]$ReadProvider = "auto",
    [ValidateSet("netsh", "powershell", "netsecurity")]
    [string]$WriteBackend = "powershell",
    [int]$TimeoutSeconds = 20,
    [int]$BuildTimeoutSeconds = 900,
    [int]$AgentExeSmokeSeconds = 12,
    [string]$FirewallTestIp = "203.0.113.10",
    [string]$DeepAllowedIp = "151.101.1.69",
    [int]$DeepAllowedPort = 443,
    [string]$DeepBlockedCandidates = "151.101.1.69,104.16.132.229,142.250.190.14,93.184.216.34",
    [string]$DeepMutationIp = "203.0.113.10",
    [int]$DeepPacketTimeoutSeconds = 25,
    [int]$DeepClassroomAgentCount = 24,
    [double]$DeepSoakMinutes = 30,
    [int]$DeepSoakIntervalSeconds = 60,
    [int]$DeepGuiTimeoutSeconds = 180,
    [int]$DeepWebSocketTimeoutSeconds = 25,
    [switch]$VerboseSmoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Error "Run this script from an elevated PowerShell window (Run as Administrator)."
    exit 2
}

if (-not $BootstrapAdminUsername) {
    $BootstrapAdminUsername = Read-Host "Bootstrap admin username"
}
if (-not $BootstrapAdminPassword) {
    $SecurePassword = Read-Host "Bootstrap admin password" -AsSecureString
    $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    try {
        $BootstrapAdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
    }
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Runner = Join-Path $RepoRoot "tools\saint_full_system_e2e.py"
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    $Python = $VenvPython
} else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) {
        Write-Error "Python not found. Expected $VenvPython or python on PATH."
        exit 2
    }
    $Python = $PythonCommand.Source
}

$EnvDeep = $env:SAINT_E2E_DEEP -match '^(1|true|yes|on)$'
$DeepEnabled = [bool]$Deep -or [bool]$EnvDeep

$ArgsList = @(
    $Runner,
    "--server-url", $ServerUrl,
    "--bootstrap-admin-username", $BootstrapAdminUsername,
    "--bootstrap-admin-password", $BootstrapAdminPassword,
    "--read-provider", $ReadProvider,
    "--write-backend", $WriteBackend,
    "--timeout-seconds", "$TimeoutSeconds",
    "--build-timeout-seconds", "$BuildTimeoutSeconds",
    "--agent-exe-smoke-seconds", "$AgentExeSmokeSeconds",
    "--firewall-test-ip", $FirewallTestIp,
    "--deep-allowed-ip", $DeepAllowedIp,
    "--deep-allowed-port", "$DeepAllowedPort",
    "--deep-blocked-candidates", $DeepBlockedCandidates,
    "--deep-mutation-ip", $DeepMutationIp,
    "--deep-packet-timeout-seconds", "$DeepPacketTimeoutSeconds",
    "--deep-classroom-agent-count", "$DeepClassroomAgentCount",
    "--deep-soak-minutes", "$DeepSoakMinutes",
    "--deep-soak-interval-seconds", "$DeepSoakIntervalSeconds",
    "--deep-gui-timeout-seconds", "$DeepGuiTimeoutSeconds",
    "--deep-websocket-timeout-seconds", "$DeepWebSocketTimeoutSeconds"
)

if ($OutputDir) { $ArgsList += @("--output-dir", $OutputDir) }
if ($RunId) { $ArgsList += @("--run-id", $RunId) }
if ($CleanupResultJson) { $ArgsList += @("--cleanup-result-json", $CleanupResultJson) }
if ($RunRealFirewallPolicy) { $ArgsList += "--run-real-firewall-policy" }
if ($KeepTestData) { $ArgsList += "--keep-test-data" }
if ($SkipBuild) { $ArgsList += "--skip-build" }
if ($SkipAgentExeLaunch) { $ArgsList += "--skip-agent-exe-launch" }
if ($DryRun) { $ArgsList += "--dry-run" }
if ($DeepEnabled) { $ArgsList += "--deep" }
if ($FirewallOnly) { $ArgsList += "--firewall-only" }
if ($VerboseSmoke) { $ArgsList += "--verbose" }

Write-Host "Running SAINT full system E2E..."
Write-Host "Repo: $RepoRoot"
Write-Host "Python: $Python"
Write-Host "Server: $ServerUrl"
Write-Host "Real firewall policy: $RunRealFirewallPolicy"
Write-Host "Deep mode: $DeepEnabled"
Write-Host "Firewall only: $FirewallOnly"

& $Python @ArgsList
exit $LASTEXITCODE
