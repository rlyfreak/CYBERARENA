<#
.SYNOPSIS
  Запуск CYBERARENA одной командой: .env, запуск стека и публикация трёх заданий.

.DESCRIPTION
  1. Проверяет, что Docker запущен.
  2. Если файла .env нет, создаёт его из .env.example: случайные SESSION_SECRET,
     WEB01_FLAG и пароль администратора (показывается один раз). Существующий .env
     не изменяется.
  3. Читает настройки так, как их видит Docker Compose (docker compose config):
     с учётом кавычек в .env и переменных окружения. Эти же значения получают
     контейнеры, поэтому лаборатория и карточка WEB-01 используют один флаг.
  4. Собирает и запускает стек и ждёт состояния healthy. С -NoBuild запускает
     ранее собранные образы без сборки и без обращения к интернету.
  5. Проверяет, что nginx отдаёт материалы заданий байт в байт и что лаборатория
     WEB-01 отвечает.
  6. Настраивает и публикует три задания. Уже настроенные карточки не меняются.
     Если карточка не совпадает с флагами или изменена вручную и скрыта,
     установка завершается с ошибкой и объясняет, что исправить.

  Запуск из корня репозитория: двойной клик по start.bat или
    .\start.bat              обычный запуск (нужен интернет при первой сборке)
    .\start.bat -NoBuild     запуск без сборки и без интернета (образы уже собраны)
    .\start.bat -ResetData   удалить данные прошлой установки и установить заново

  Флаги и секреты не выводятся на экран и не передаются аргументами команд.
#>
[CmdletBinding()]
param(
    # Удалить контейнеры и том с базой прошлой установки перед запуском.
    [switch]$ResetData,
    # Не собирать образы и не обращаться к интернету: запустить уже собранные.
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

# Имя проекта задано полем name в compose.yaml; том базы называется <проект>_db-data.
$ComposeProject = 'cyberarena'
$DataVolume = 'cyberarena_db-data'

# ----------------------------------------------------------------- генерация

function Get-RandomBytes([int]$Count) {
    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ,$bytes
}

function New-Password([int]$Length = 16) {
    # Без похожих символов (I, O, l, o, 0, 1) и без знаков, которые Compose
    # трактует особо (например, $ в .env).
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
    $limit = 256 - (256 % $alphabet.Length)
    $builder = New-Object System.Text.StringBuilder
    while ($builder.Length -lt $Length) {
        foreach ($byte in (Get-RandomBytes 32)) {
            if ($byte -lt $limit -and $builder.Length -lt $Length) {
                [void]$builder.Append($alphabet[$byte % $alphabet.Length])
            }
        }
    }
    return $builder.ToString()
}

function New-SessionSecret {
    return [Convert]::ToBase64String((Get-RandomBytes 48))
}

function New-Web01Flag {
    $bytes = Get-RandomBytes 12
    return 'CTF{' + (($bytes | ForEach-Object { $_.ToString('x2') }) -join '') + '}'
}

function New-EnvFile([string]$Root) {
    $example = Join-Path $Root '.env.example'
    if (-not (Test-Path -LiteralPath $example)) { throw "Не найден файл $example" }
    $password = New-Password 16
    $lines = foreach ($line in [System.IO.File]::ReadAllLines($example)) {
        if ($line -match '^ADMIN_PASSWORD=') { "ADMIN_PASSWORD=$password" }
        elseif ($line -match '^SESSION_SECRET=') { 'SESSION_SECRET=' + (New-SessionSecret) }
        elseif ($line -match '^WEB01_FLAG=') { 'WEB01_FLAG=' + (New-Web01Flag) }
        else { $line }
    }
    $text = ($lines -join "`n") + "`n"
    # UTF-8 без BOM: Docker Compose читает .env без сюрпризов.
    [System.IO.File]::WriteAllText((Join-Path $Root '.env'), $text, (New-Object System.Text.UTF8Encoding($false)))
    return $password
}

# ------------------------------------------- настройки глазами Docker Compose

# Те же правила, что у приложения (bootstrap_admin, main) и лаборатории (valid_flag).
function Test-CtfFlag([string]$Flag) {
    if (-not $Flag -or $Flag.Length -lt 6 -or $Flag.Length -gt 256) { return $false }
    if (-not $Flag.StartsWith('CTF{', [StringComparison]::Ordinal) -or -not $Flag.EndsWith('}', [StringComparison]::Ordinal)) {
        return $false
    }
    foreach ($char in $Flag.Substring(4, $Flag.Length - 5).ToCharArray()) {
        $code = [int]$char
        if ($code -lt 33 -or $code -gt 126 -or $char -eq [char]'{' -or $char -eq [char]'}') { return $false }
    }
    return $true
}

function Get-Settings($Config) {
    $app = $Config.services.app.environment
    $lab = $Config.services.'lab-web'.environment
    $hostIp = '127.0.0.1'
    $ports = @($Config.services.nginx.ports)
    if ($ports.Count -gt 0 -and $ports[0].host_ip) { $hostIp = [string]$ports[0].host_ip }
    $images = @($Config.services.PSObject.Properties |
        ForEach-Object { $_.Value.image } | Where-Object { $_ } | Sort-Object -Unique)
    return [pscustomobject]@{
        AdminUsername = ([string]$app.ADMIN_USERNAME).Trim().ToLowerInvariant()
        AdminPassword = [string]$app.ADMIN_PASSWORD
        SessionSecret = [string]$app.SESSION_SECRET
        Web01Flag     = [string]$lab.WEB01_FLAG
        HostIp        = $hostIp
        Images        = $images
    }
}

function Test-Settings($Settings) {
    $problems = @()
    if ($Settings.AdminUsername -cnotmatch '^[a-z0-9_]{3,32}$') {
        $problems += 'ADMIN_USERNAME: 3-32 символа, латинские буквы, цифры и _'
    }
    $password = $Settings.AdminPassword
    if ($password.Length -lt 12 -or $password.Length -gt 128 -or
        $password -ceq 'change-me' -or $password -ceq 'REPLACE_WITH_YOUR_PASSWORD') {
        $problems += 'ADMIN_PASSWORD: нужен пароль длиной 12-128 символов (не заглушка из шаблона)'
    }
    if ($Settings.SessionSecret.Length -lt 32) {
        $problems += 'SESSION_SECRET: нужна случайная строка не короче 32 символов'
    }
    if (-not (Test-CtfFlag $Settings.Web01Flag)) {
        $problems += 'WEB01_FLAG: нужен флаг формата CTF{...}: 6-256 печатных ASCII-символов без { и } внутри'
    }
    return ,$problems
}

# --------------------------------------------------------------------- флаги

function Get-Crypto01Flag([string]$Root) {
    $material = [System.IO.File]::ReadAllText((Join-Path $Root 'files/crypto-01/challenge.txt'), [System.Text.Encoding]::UTF8)
    $parts = $material -split 'Ciphertext \(hex\):', 2
    if ($parts.Count -ne 2) { throw 'CRYPTO-01: в challenge.txt нет строки Ciphertext (hex):' }
    $hex = $parts[1] -replace '\s', ''
    if ($hex.Length % 2 -ne 0) { throw 'CRYPTO-01: нечётная длина hex' }
    [byte[]]$cipher = for ($i = 0; $i -lt $hex.Length; $i += 2) {
        [Convert]::ToByte($hex.Substring($i, 2), 16)
    }
    [byte[]]$known = [Text.Encoding]::UTF8.GetBytes('CYBERARENA INCIDENT REPORT' + [char]10)
    [byte[]]$key = for ($i = 0; $i -lt 7; $i++) { $cipher[$i] -bxor $known[$i] }
    [byte[]]$plain = New-Object byte[] $cipher.Length
    for ($i = 0; $i -lt $cipher.Length; $i++) { $plain[$i] = $cipher[$i] -bxor $key[$i % 7] }
    $decoded = [Text.Encoding]::UTF8.GetString($plain)
    if (-not $decoded.StartsWith('CYBERARENA INCIDENT REPORT' + [char]10)) { throw 'CRYPTO-01: расшифровка не совпала с известным началом' }
    if ($decoded -notmatch '(?m)^Access token: (CTF\{[^}\r\n]+\})$') { throw 'CRYPTO-01: в записке нет строки Access token' }
    return $Matches[1]
}

function Get-Web02Flag([string]$Root) {
    $js = [System.IO.File]::ReadAllText((Join-Path $Root 'files/web-02/script.js'), [System.Text.Encoding]::UTF8)
    $found = [regex]::Matches($js, 'seq:\s*(\d+),\s*bytes:\s*\[([^\]]*)\]')
    if ($found.Count -eq 0) { throw 'WEB-02: в script.js не найдены пакеты' }
    $packets = foreach ($match in $found) {
        [pscustomobject]@{
            Seq   = [int]$match.Groups[1].Value
            Bytes = [int[]](($match.Groups[2].Value -split ',') | ForEach-Object { $_.Trim() })
        }
    }
    $data = foreach ($packet in ($packets | Sort-Object Seq)) { $packet.Bytes }
    $mask = 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x17
    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $data.Count; $i++) {
        [void]$builder.Append([char]($data[$i] -bxor $mask[$i % 7]))
    }
    $flag = $builder.ToString()
    if (-not (Test-CtfFlag $flag)) { throw 'WEB-02: восстановленный токен не в формате CTF{...}' }
    return $flag
}

# -------------------------------------------------------------------- docker

function Test-DockerReady {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $false }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        docker info *> $null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Invoke-Docker([string]$What, [scriptblock]$Command) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Command
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { throw "${What}: ошибка (код $code). Подробности выше." }
}

function Get-ComposeConfig {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $previousEncoding = $null
    try {
        # docker пишет UTF-8; без этого Windows PowerShell исказит не-ASCII символы.
        try { $previousEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { $previousEncoding = $null }
        $lines = docker compose config --format json 2>$null
        $code = $LASTEXITCODE
    } finally {
        if ($previousEncoding) { try { [Console]::OutputEncoding = $previousEncoding } catch { } }
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { throw 'Не удалось прочитать настройки docker compose.' }
    return (($lines | Out-String) | ConvertFrom-Json)
}

function Test-DataVolume {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        docker volume inspect $DataVolume *> $null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Remove-OldData {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $ids = @(docker ps -aq --filter "label=com.docker.compose.project=$ComposeProject")
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось получить список контейнеров прошлой установки (подробности выше).' }
        if ($ids.Count -gt 0) {
            docker rm -f $ids | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Не удалось удалить контейнеры прошлой установки (подробности выше). Установка остановлена, база не тронута.'
            }
        }
        if (Test-DataVolume) {
            docker volume rm $DataVolume | Out-Null
            if ($LASTEXITCODE -ne 0 -or (Test-DataVolume)) {
                throw ("Не удалось удалить том $DataVolume с данными прошлой установки (подробности выше). " +
                       "Установка остановлена, чтобы не продолжать со старой базой. Обычно том держит другой " +
                       "контейнер: найдите его командой docker ps -a --filter volume=$DataVolume, удалите и повторите.")
            }
        }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Find-MissingImage([string[]]$Images) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        foreach ($image in $Images) {
            docker image inspect $image *> $null
            if ($LASTEXITCODE -ne 0) { return $image }
        }
        return $null
    } finally {
        $ErrorActionPreference = $previous
    }
}

# ----------------------------------------------------------------- материалы

function Test-Materials([string]$Root, [string]$BaseUrl) {
    $client = New-Object System.Net.WebClient
    $client.Proxy = $null
    try {
        foreach ($relative in 'files/crypto-01/challenge.txt', 'files/web-02/index.html', 'files/web-02/script.js', 'files/web-02/style.css') {
            $local = [System.IO.File]::ReadAllBytes((Join-Path $Root $relative))
            try {
                $served = $client.DownloadData("$BaseUrl/$relative")
            } catch {
                throw "Материал /$relative не отдаётся через nginx ($BaseUrl)."
            }
            if ([Convert]::ToBase64String($served) -cne [Convert]::ToBase64String($local)) {
                throw "Материал /$relative через nginx отличается от файла в репозитории."
            }
        }
        try {
            [void]$client.DownloadData("$BaseUrl/lab/")
        } catch {
            throw "Лаборатория WEB-01 не отвечает по адресу $BaseUrl/lab/."
        }
    } finally {
        $client.Dispose()
    }
}

# ------------------------------------------------------------------- основной

function Start-Setup {
    $root = Split-Path -Parent $PSScriptRoot
    Set-Location -LiteralPath $root

    if (-not (Test-DockerReady)) {
        throw ('Docker не отвечает. Установите Docker Desktop, запустите его, дождитесь статуса ' +
               '"Engine running" (зелёный значок внизу слева) и запустите скрипт снова.')
    }

    $envExists = Test-Path -LiteralPath (Join-Path $root '.env')
    if ($ResetData) {
        Write-Host 'Удаляю данные прошлой установки...'
        Remove-OldData
    } elseif (-not $envExists -and (Test-DataVolume)) {
        throw ("Найдены данные прошлой установки, а файла .env нет. Новый .env к ним не подойдёт: " +
               "пароль администратора и флаг WEB-01 окажутся другими.`n" +
               "Верните прежний .env либо запустите скрипт с параметром -ResetData " +
               "(удалит всех пользователей, решения и рейтинг).")
    }

    $generatedPassword = $null
    if (-not $envExists) {
        $generatedPassword = New-EnvFile $root
        Write-Host 'Создан файл .env со случайными секретами.'
    } else {
        Write-Host 'Файл .env уже есть, он не изменяется.'
    }

    Invoke-Docker 'Проверка настроек docker compose' { docker compose config --quiet }
    $settings = Get-Settings (Get-ComposeConfig)
    $problems = Test-Settings $settings
    if ($problems.Count -gt 0) {
        throw ("Исправьте настройки и запустите скрипт снова. Значения берутся так же, как их видит " +
               "Docker Compose: из .env или из переменных окружения этого окна.`n  - " + ($problems -join "`n  - "))
    }

    if ($NoBuild) {
        $missing = Find-MissingImage $settings.Images
        if ($missing) {
            throw ("Нет собранного образа $missing. Режим -NoBuild запускает только уже собранные образы: " +
                   'сначала выполните обычный запуск с интернетом.')
        }
        Write-Host 'Запуск без сборки (ранее собранные образы)...'
        Invoke-Docker 'Запуск docker compose up' { docker compose up -d --no-build --pull never --wait --wait-timeout 600 }
    } else {
        Write-Host 'Сборка и запуск (первый раз это занимает несколько минут)...'
        try {
            Invoke-Docker 'Запуск docker compose up' { docker compose up -d --build --wait --wait-timeout 600 }
        } catch {
            throw ($_.Exception.Message + "`nЕсли нет интернета, а проект уже запускался на этом компьютере, " +
                   'запустите start.bat -NoBuild.')
        }
    }

    $checkHost = $settings.HostIp
    if ($checkHost -eq '0.0.0.0') { $checkHost = '127.0.0.1' }
    Write-Host 'Проверка материалов через nginx...'
    Test-Materials $root "http://${checkHost}:8080"

    Write-Host 'Настройка заданий...'
    $flags = [ordered]@{
        'WEB-01'    = $settings.Web01Flag
        'WEB-02'    = (Get-Web02Flag $root)
        'CRYPTO-01' = (Get-Crypto01Flag $root)
    }
    # Флаги передаются через stdin: не попадают в аргументы команд и в историю.
    $json = $flags | ConvertTo-Json -Compress
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $json | docker compose exec -T app python -m app.ctf.setup_case
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) { throw 'Установка не завершена: задания не готовы. Причины и что исправить — выше.' }

    $shownHost = $settings.HostIp
    if ($shownHost -eq '127.0.0.1') { $shownHost = 'localhost' }
    Write-Host ''
    Write-Host "Готово: платформа работает на http://${shownHost}:8080"
    Write-Host ('Администратор: ' + $settings.AdminUsername)
    if ($generatedPassword) {
        Write-Host "Пароль администратора: $generatedPassword"
        Write-Host 'Запишите его: повторно он не показывается. При первом входе приложение попросит сменить пароль.'
    } else {
        Write-Host 'Пароль администратора указан в вашем файле .env (если вы его уже меняли, используйте новый).'
    }
}

# Выполняется только при запуске файла; при подключении через точку ("dot-source") функции только загружаются.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Start-Setup
    } catch {
        Write-Host ''
        Write-Host ('ОШИБКА: ' + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}
