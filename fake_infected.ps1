# Имитация ЗАРАЖЁННОГО компьютера для демонстрации. Безопасно: никакого вредоносного кода,
# никаких атак на чужие компьютеры — только сетевые запросы, которые выглядят как поведение бота:
#
#   1) DGA: пачки DNS-запросов к случайным несуществующим доменам (бот ищет свой сервер);
#   2) маячок: каждые ~20 с соединение с одним и тем же адресом (бот выходит на связь);
#      адрес — безобидный example.com (зарезервирован для примеров);
#   3) резервный канал: прямые соединения с IP без DNS-запроса (публичные DNS-серверы
#      Google, Cloudflare, Quad9, OpenDNS — они спокойно принимают такие соединения).
#
# Запускать, пока идёт запись трафика (pktmon / Wireshark). Длится ~3,5 минуты.
#   powershell -ExecutionPolicy Bypass -File fake_infected.ps1

param(
    [int]$Beacons = 10,        # сколько раз «выйти на связь»
    [int]$Interval = 20,       # секунд между выходами на связь
    [int]$FirstBurst = 40,     # DGA-доменов в первой пачке
    [int]$PerBeacon = 6        # DGA-доменов между выходами на связь
)

$tlds = @("com", "net", "info", "biz", "ru", "org")

function New-DgaName {
    $len = Get-Random -Minimum 10 -Maximum 17
    $s = -join (1..$len | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) })
    return "$s." + ($tlds | Get-Random)
}

function Invoke-Dga([int]$n) {
    $nx = 0
    for ($k = 0; $k -lt $n; $k++) {
        $d = New-DgaName
        try { Resolve-DnsName $d -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null }
        catch { $nx++ }
        Start-Sleep -Milliseconds 150
    }
    return $nx
}

function Test-Tcp([string]$hostOrIp, [int]$port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ok = $c.ConnectAsync($hostOrIp, $port).Wait(3000)
        return $(if ($ok -and $c.Connected) { "соединение есть" } else { "нет ответа" })
    } catch { return "нет ответа" }
    finally { $c.Close() }
}

Write-Host "=== Имитация заражённого компьютера (безопасно) ===" -ForegroundColor Yellow

Write-Host "`n[1] Бот перебирает придуманные домены (DGA)..."
$nx = Invoke-Dga $FirstBurst
Write-Host "    запрошено $FirstBurst доменов, не существует: $nx"

Write-Host "`n[2] Соединения с «зашитыми» IP без DNS-запроса..."
foreach ($ip in @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220")) {
    Write-Host ("    {0,-16} {1}" -f $ip, (Test-Tcp $ip 443))
}

Write-Host "`n[3] Бот регулярно выходит на связь с сервером (каждые ~$Interval с) и продолжает перебор..."
$c2 = (Resolve-DnsName "example.com" -Type A -DnsOnly | Where-Object IPAddress | Select-Object -First 1).IPAddress
for ($i = 1; $i -le $Beacons; $i++) {
    $r = Test-Tcp $c2 443
    $nx = Invoke-Dga $PerBeacon
    Write-Host ("    выход на связь {0,2}/{1} -> {2}:443 ({3}); ещё {4} DGA-доменов" -f $i, $Beacons, $c2, $r, $PerBeacon)
    if ($i -lt $Beacons) {
        $pause = $Interval + (Get-Random -Minimum -2 -Maximum 3) - [math]::Round($PerBeacon * 0.2)
        Start-Sleep -Seconds ([math]::Max($pause, 1))
    }
}

Write-Host "`nГотово. Остановите запись (pktmon stop) и прогоните файл через программу." -ForegroundColor Green
