# ============================================================
#  Certificate Radar - IIS demo environment setup
#  Run ON THE VM (Windows Server 2019/2025) as Administrator:
#     powershell -ExecutionPolicy Bypass -File C:\Certs\iis_setup.ps1
#  Expects C:\Certs to contain: demo_ca.crt + 01..06 .pfx files
# ============================================================
param([string]$CertDir = "C:\Certs")
$ErrorActionPreference = "Stop"
$pfxPassword = ConvertTo-SecureString -String "demo" -Force -AsPlainText

Write-Host "== Certificate Radar IIS setup ==" -ForegroundColor Cyan

# ---- 1. IIS -------------------------------------------------
Write-Host "[1/6] Installing IIS (Web-Server role)..."
if (-not (Get-WindowsFeature Web-Server).Installed) {
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
}

# ---- 2. Demo CA into Trusted Root ---------------------------
Write-Host "[2/6] Installing demo CA into Trusted Root CAs..."
Import-Certificate -FilePath "$CertDir\demo_ca.crt" `
    -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

# ---- 3. Import all PFX into Personal store ------------------
Write-Host "[3/6] Importing PFX certificates (password: demo)..."
$certs = @{}
foreach ($f in (Get-ChildItem "$CertDir\*.pfx" | Sort-Object Name)) {
    $c = Import-PfxCertificate -FilePath $f.FullName `
        -CertStoreLocation Cert:\LocalMachine\My -Password $pfxPassword -Exportable
    $certs[$f.BaseName] = $c
    Write-Host ("   + {0,-20} thumbprint {1}" -f $f.Name, $c.Thumbprint)
}

# ---- 4. Create 6 sites with certificates --------------------
Import-Module WebAdministration
$plan = [ordered]@{
    "01_valid"      = 9441
    "02_expiring"   = 9442
    "03_expired"    = 9443
    "04_selfsigned" = 9444
    "05_brokenchain"= 9445
    "06_mismatch"   = 9446
}
Write-Host "[4/6] Creating HTTPS sites..."
foreach ($name in $plan.Keys) {
    $port = $plan[$name]
    $dir  = "C:\inetpub\$name"
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path "$dir\index.html" `
        -Value "<h1>Certificate Radar demo: $name</h1><p>port $port</p>"

    if (Get-Website | Where-Object Name -eq $name) { Remove-Website -Name $name }
    # placeholder binding, then replace with https
    New-Website -Name $name -PhysicalPath $dir -Port 80 -HostHeader "$name.radar" | Out-Null
    New-WebBinding -Name $name -Protocol https -Port $port
    (Get-WebBinding -Name $name -Protocol https).AddSslCertificate(
        $certs[$name].Thumbprint, "My")
    Get-WebBinding -Name $name |
        Where-Object { $_.protocol -eq "http" } | Remove-WebBinding
    Start-Website -Name $name
    Write-Host ("   + https://<vm-ip>:{0}  <- {1}" -f $port, $name)
}

# ---- 5. Firewall --------------------------------------------
Write-Host "[5/6] Opening firewall ports..."
foreach ($port in $plan.Values) {
    New-NetFirewallRule -DisplayName "CertRadar $port" -Direction Inbound `
        -Protocol TCP -LocalPort $port -Action Allow -ErrorAction SilentlyContinue | Out-Null
}

# ---- 6. Hosts file (for testing from the VM itself) ---------
Write-Host "[6/6] Adding hosts entries..."
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
foreach ($h in "iis-demo.local", "other-name.local") {
    if (-not (Select-String -Path $hostsPath -Pattern $h -Quiet)) {
        Add-Content $hostsPath "127.0.0.1 $h"
    }
}

# ---- summary ------------------------------------------------
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
       Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "DONE. VM IP address: $ip" -ForegroundColor Green
Write-Host "On the HOST (your Windows) add to C:\Windows\System32\drivers\etc\hosts:"
Write-Host "    $ip iis-demo.local"
Write-Host "Then scan targets (one per line):"
foreach ($port in $plan.Values) { Write-Host "    $ip`:$port" }
Write-Host "Test in VM browser: https://localhost:9443 (warning is EXPECTED)"
