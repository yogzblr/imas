# WinRM over HTTPS for a UAT Windows sprout (uat/tofu, run once by the
# CustomScriptExtension at create time).
#
# The certificate is self-signed and lives 30 days: clients reach 5986 only
# through an Azure Bastion tunnel on 127.0.0.1, where the name never matches,
# so UAT.4 turns certificate validation off. The HTTP listener is removed, Basic
# auth and unencrypted traffic stay off (NTLM/Negotiate over HTTPS works with
# the local admin account), and Windows Firewall opens 5986 only. The subnet's
# NSG admits 5986 only from AzureBastionSubnet.
$ErrorActionPreference = 'Stop'

Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation 'Cert:\LocalMachine\My' -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(30)

Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } | Remove-Item -Recurse -Force
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' } | Remove-Item -Recurse -Force

Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false

Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
Remove-NetFirewallRule -Name 'imas-uat-winrm-https' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'imas-uat-winrm-https' -DisplayName 'WinRM HTTPS (imas UAT)' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Any | Out-Null

Restart-Service -Name WinRM
