# Безопасная имитация DGA-бота для демонстрации.
# Делает только DNS-запросы к случайным несуществующим доменам — как бот, перебирающий список DGA.
# Ничего не скачивает и не запускает. Запускать, пока идёт запись трафика (Wireshark / pktmon).
#
#   powershell -ExecutionPolicy Bypass -File fake_bot.ps1

param([int]$Count = 60)

$tlds = @("com", "net", "info", "biz", "ru")
Write-Host "Имитация DGA-бота: $Count запросов к случайным доменам..."
for ($i = 1; $i -le $Count; $i++) {
    $name = -join ((97..122) | Get-Random -Count (Get-Random -Minimum 10 -Maximum 16) | ForEach-Object { [char]$_ })
    $domain = "$name." + ($tlds | Get-Random)
    try { Resolve-DnsName $domain -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $r = "есть" }
    catch { $r = "NXDOMAIN" }
    Write-Host ("{0,3}  {1,-24} {2}" -f $i, $domain, $r)
    Start-Sleep -Milliseconds 300
}
Write-Host "Готово. Остановите запись и запустите: python main.py --pcap <файл> --out live.html"
