# Имитация обычного пользователя для демонстрационной записи трафика.
# Открывает нейтральные сайты (как браузер: DNS-запрос + HTTPS-запрос) со случайными паузами,
# чтобы в записи не было личной переписки и личных сайтов.
#
#   powershell -ExecutionPolicy Bypass -File fake_user.ps1              (3 минуты)
#   powershell -ExecutionPolicy Bypass -File fake_user.ps1 -Minutes 5

param([double]$Minutes = 3)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"

$sites = @(
    "www.google.com", "ru.wikipedia.org", "www.youtube.com", "github.com", "stackoverflow.com",
    "www.python.org", "docs.python.org", "www.microsoft.com", "www.bbc.com", "www.reuters.com",
    "kaspi.kz", "egov.kz", "iitu.edu.kz", "www.kinopoisk.ru", "translate.google.com",
    "www.wikipedia.org", "www.coursera.org", "habr.com", "www.weather.com", "www.apple.com",
    "www.mozilla.org", "www.wireshark.org", "attack.mitre.org", "www.kaggle.com", "pypi.org"
)

$end = (Get-Date).AddMinutes($Minutes)
$i = 0
Write-Host "Имитация пользователя: $Minutes мин. Сайты открываются по одному со случайной паузой."
while ((Get-Date) -lt $end) {
    $i++
    $site = $sites | Get-Random
    try {
        $r = Invoke-WebRequest -Uri "https://$site/" -UseBasicParsing -TimeoutSec 10 -MaximumRedirection 3
        $status = $r.StatusCode
    } catch {
        $status = "нет ответа"
    }
    Write-Host ("{0,3}  {1,-24} {2}" -f $i, $site, $status)
    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 12)
}
Write-Host "Готово: открыто $i сайтов. Остановите запись (pktmon stop) и запустите программу."
