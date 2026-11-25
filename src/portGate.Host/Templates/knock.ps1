#Requires -Version 5.1
# Персональный пропуск portGate. Файл содержит секрет: передавайте только владельцу.
param([switch]$NoRdp)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
Write-Host '[2/4] Авторизация portGate...'
$server = '@@SERVER@@'
$port = @@PORT@@
$serverId = '@@SERVERID@@'
$clientId = '@@CLIENTID@@'
$key = [Convert]::FromBase64String('@@KEY@@')
$launchRdp = @@LAUNCH@@
function Get-Mac([string]$body) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try { $hmac.Key = $key; return ([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($body)))).Replace('-','').ToLowerInvariant() }
    finally { $hmac.Dispose() }
}
function Protect-Message([string]$body) { return $body + '|' + (Get-Mac $body) }
function Test-Message([string]$message) {
    $split = $message.LastIndexOf('|')
    if ($split -lt 0) { return $false }
    $expected = Get-Mac $message.Substring(0,$split)
    $received = $message.Substring($split+1)
    if ($received.Length -ne 64 -or $received -cnotmatch '^[0-9a-f]{64}$') { return $false }
    $difference = 0
    for ($i=0; $i -lt 64; $i++) { $difference = $difference -bor ([int][char]$expected[$i] -bxor [int][char]$received[$i]) }
    return $difference -eq 0
}
function Exchange([string]$message, [string]$expectedType, [string]$expectedNonce, [string]$expectedToken = '') {
    $bytes = [Text.Encoding]::UTF8.GetBytes($message)
    $prefix = "KG1|$expectedType|$serverId|$clientId|$expectedNonce|"
    if ($expectedToken) { $prefix += "$expectedToken|" }
    for ($attempt=0; $attempt -lt 3; $attempt++) {
        $deadline = [Math]::Min(30000L, $clock.ElapsedMilliseconds + 2000L)
        if ($clock.ElapsedMilliseconds -ge $deadline) { break }
        [void]$udp.Send($bytes,$bytes.Length)
        while (($remaining = $deadline - $clock.ElapsedMilliseconds) -gt 0) {
            $udp.Client.ReceiveTimeout = [int]$remaining
            try {
                $remote = New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
                if ($udp.Client.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $remote = New-Object Net.IPEndPoint([Net.IPAddress]::IPv6Any,0) }
                $response = $udp.Receive([ref]$remote)
                if ($response.Length -gt 1200) { continue }
                $text = [Text.Encoding]::UTF8.GetString($response)
                if ($text.StartsWith($prefix, [StringComparison]::Ordinal) -and (Test-Message $text)) { return $text }
            } catch [Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -ne [Net.Sockets.SocketError]::TimedOut) { throw }
                break
            }
        }
    }
    $stage = if ($expectedType -eq 'CHALLENGE') { 'первый ответ сервера' } else { 'подтверждение разрешения RDP' }
    throw ("Не получен " + $stage + " от " + $udp.Client.RemoteEndPoint + ". Порт авторизации UDP " + $port + ".")
}
$udp = $null
$clock = [Diagnostics.Stopwatch]::StartNew()
try {
    $lookup = [Net.Dns]::GetHostAddressesAsync($server)
    if (-not $lookup.Wait(5000)) { throw 'Истёк таймаут определения адреса сервера (5 секунд).' }
    $addresses = @($lookup.Result | Select-Object -First 8)
    if ($addresses.Length -eq 0) { throw 'Адрес сервера не найден.' }
    $lastFailure = 'Адрес сервера недоступен.'
    foreach ($address in $addresses) {
    if ($clock.Elapsed.TotalSeconds -ge 30) { throw 'Истёк общий таймаут авторизации (30 секунд).' }
    try {
    $udp = New-Object Net.Sockets.UdpClient($address.AddressFamily)
    $udp.Connect($address,$port)
    $udp.Client.ReceiveTimeout = 2000
    $random = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $nonce = ([BitConverter]::ToString($random)).Replace('-','').ToLowerInvariant()
    $challenge = (Exchange (Protect-Message "KG1|HELLO|$serverId|$clientId|0|$nonce") 'CHALLENGE' $nonce).Split('|')
    if ($challenge.Length -ne 9 -or $challenge[0] -cne 'KG1' -or $challenge[1] -cne 'CHALLENGE' -or $challenge[2] -cne $serverId -or $challenge[3] -cne $clientId -or $challenge[4] -cne $nonce -or $challenge[5] -cnotmatch '^[0-9a-f]{32}$') { throw 'Неверный контекст ответа сервера.' }
    $expires = [long]$challenge[6]
    if ($expires -le 0) { throw 'Некорректный срок запроса сервера.' }
    $token = $challenge[5]
    $result = (Exchange (Protect-Message "KG1|PROOF|$serverId|$clientId|$nonce|$token|$expires") 'RESULT' $nonce $token).Split('|')
    if ($result.Length -ne 9 -or $result[0] -cne 'KG1' -or $result[1] -cne 'RESULT' -or $result[2] -cne $serverId -or $result[3] -cne $clientId -or $result[4] -cne $nonce -or $result[5] -cne $token) { throw 'Неверное подтверждение доступа.' }
    $until = [DateTimeOffset]::FromUnixTimeSeconds([long]$result[6])
    $rdpPort = [int]$result[7]
    if ($until.ToUnixTimeSeconds() -le 0 -or $rdpPort -lt 1 -or $rdpPort -gt 65535) { throw 'Получено некорректное разрешение.' }
    Write-Host ('[3/4] Доступ RDP подтверждён до ' + $until.ToLocalTime().ToString('HH:mm:ss'))
    if ($launchRdp -and -not $NoRdp) {
        $target = $address.ToString()
        if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $target = '['+$target+']' }
        Write-Host '[4/4] Запуск удалённого рабочего стола...'
        Start-Process -FilePath "$env:SystemRoot\System32\mstsc.exe" -ArgumentList ('/v:'+$target+':'+$rdpPort)
    }
    else { Write-Host '[4/4] Автоматический запуск RDP отключён.' }
    exit 0
    } catch { $lastFailure = $_.Exception.Message }
    finally { if ($null -ne $udp) { $udp.Dispose(); $udp = $null } }
    }
    throw ('Не удалось авторизоваться ни по одному адресу сервера: ' + $lastFailure)
} catch { [Console]::Error.WriteLine('portGate: ' + $_.Exception.Message); exit 1 }
finally { if ($null -ne $udp) { $udp.Dispose() }; [Array]::Clear($key,0,$key.Length) }
