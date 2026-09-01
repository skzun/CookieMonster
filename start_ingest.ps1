$log = "D:\CookieMonster\ingest.log"
$pidFile = "D:\CookieMonster\ingest.pid"
if (Test-Path $pidFile) { Remove-Item $pidFile }
if (Test-Path $log) { Remove-Item $log }

# Start-process with redirected streams
$proc = Start-Process -FilePath "python" `
    -ArgumentList "-m","cookiemonster","ingest","--dir","D:\CookieMonster\Cookies","--db","D:\CookieMonster\store.db","--resume" `
    -WorkingDirectory "D:\CookieMonster" `
    -RedirectStandardOutput $log `
    -RedirectStandardError "$log.err" `
    -WindowStyle Hidden `
    -PassThru

Set-Content -Path $pidFile -Value $proc.Id -NoNewline
Write-Output "Ingest iniciado PID=$($proc.Id) log=$log"