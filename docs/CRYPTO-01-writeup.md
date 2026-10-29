# CRYPTO-01 — Повторяющаяся маска

- **Категория:** Crypto
- **Сложность:** Easy
- **Стоимость:** 150 баллов
- **Ориентир по времени:** 10–20 минут

## Цель и исходные данные

Участник получает перехваченную служебную записку в
`files/crypto-01/challenge.txt`. После заголовка в файле находится
шестнадцатеричная запись зашифрованных байтов. Нужно восстановить сообщение
и отправить значение строки `Access token:` через карточку CRYPTO-01.

Условие сообщает три факта: использован XOR с повторяющимся ключом,
длина ключа равна семи байтам, а исходный текст начинается **точно** с
`CYBERARENA INCIDENT REPORT` и одного байта перевода строки (`\n`).
На Windows достаточно штатного PowerShell; ниже также есть вариант на Python.
Перебор ключей не нужен.

## Как работает шифрование

Для каждого байта исходного текста генератор вычисляет
`ciphertext[i] = plaintext[i] XOR key[i % 7]`. Операция XOR обратима:
`plaintext[i] = ciphertext[i] XOR key[i % 7]`.

Первые семь байтов открытого текста известны. Поэтому каждый байт ключа
восстанавливается напрямую: `key[i] = ciphertext[i] XOR known_prefix[i]`
при `i` от 0 до 6. Остальные известные байты префикса служат проверкой:
если расшифровка не начинается с полной ожидаемой строки и `\n`, значит
неверно прочитан hex, пропущен перевод строки или выбран неверный ключ.

## Пошаговое решение

1. Скачайте `challenge.txt` и найдите строку `Ciphertext (hex):`.
2. Соедините следующие строки hex и преобразуйте их в байты.
3. Преобразуйте известный префикс в байты UTF-8, включая завершающий `\n`.
4. Примените XOR к первым семи байтам шифртекста и префикса. Это ключ.
5. Повторяйте семь байтов ключа по всей длине шифртекста и выполните XOR.
6. Проверьте заголовок, строку `Ticket: CRYPTO-01` и возьмите значение
   `Access token:`. Оно имеет формат `CTF{...}`.

Необязательный вариант на Python, запускаемый из корня репозитория:

```python
from pathlib import Path

path = Path("files/crypto-01/challenge.txt")
material = path.read_text(encoding="utf-8")
hex_data = material.split("Ciphertext (hex):\n", 1)[1]
ciphertext = bytes.fromhex(hex_data)
known = b"CYBERARENA INCIDENT REPORT\n"
key = bytes(ciphertext[i] ^ known[i] for i in range(7))
message = bytes(byte ^ key[i % 7] for i, byte in enumerate(ciphertext))
assert message.startswith(known)
decoded = message.decode("utf-8")
assert "Ticket: CRYPTO-01\n" in decoded
flag = decoded.split("Access token: ", 1)[1].split("\n", 1)[0]
assert flag.startswith("CTF{") and flag.endswith("}")
print(flag)
```

Вариант для PowerShell, запускаемый из корня репозитория без установки Python:

```powershell
$material = Get-Content -Raw -Encoding UTF8 'files/crypto-01/challenge.txt'
$parts = $material -split 'Ciphertext \(hex\):', 2
if ($parts.Count -ne 2) { throw 'Ciphertext marker missing' }
$hex = $parts[1] -replace '\s', ''
if ($hex.Length % 2 -ne 0) { throw 'Odd hex length' }
[byte[]]$cipher = for ($i = 0; $i -lt $hex.Length; $i += 2) {
    [Convert]::ToByte($hex.Substring($i, 2), 16)
}
[byte[]]$known = [Text.Encoding]::UTF8.GetBytes(
    'CYBERARENA INCIDENT REPORT' + [char]10
)
[byte[]]$key = for ($i = 0; $i -lt 7; $i++) {
    $cipher[$i] -bxor $known[$i]
}
[byte[]]$plain = New-Object byte[] $cipher.Length
for ($i = 0; $i -lt $cipher.Length; $i++) {
    $plain[$i] = $cipher[$i] -bxor $key[$i % 7]
}
$decoded = [Text.Encoding]::UTF8.GetString($plain)
if (-not $decoded.StartsWith('CYBERARENA INCIDENT REPORT' + [char]10)) {
    throw 'Wrong plaintext prefix'
}
if (-not $decoded.Contains('Ticket: CRYPTO-01')) { throw 'Wrong ticket' }
if ($decoded -notmatch '(?m)^Access token: (CTF\{[^}\r\n]+\})$') {
    throw 'Flag line missing'
}
$Matches[1]
```

Полученное значение является правильным ответом. Его не следует добавлять
в исходный код, документацию, CI или логи. Ожидаемая расшифровка по смыслу:
служебный заголовок, номер задания, строка с токеном и `End of report.`.
Действительное значение токена намеренно не напечатано в этом write-up.

## Проверка ответа организатором

На новом стенде сначала проверьте
`http://localhost:8080/files/crypto-01/challenge.txt`. Создайте черновики
через `/admin`, откройте CRYPTO-01, укажите ресурс
`/files/crypto-01/challenge.txt`, сложность `easy` и стоимость 150.
Локально выполните пример выше из корня репозитория и введите полученный
флаг в закрытое поле карточки. Опубликуйте её после проверки материала.
CTF Core хранит Argon2id-хеш флага. Пробный участник должен получить
150 баллов за первый правильный ответ и не получить дополнительных баллов
за повторный. Проверьте рейтинг и сохранность после `docker compose restart`.

Не меняйте флаг в опубликованной карточке: это сделает файл и проверку
несогласованными. Если нужно переиздать задание, сначала согласуйте
перезапуск задания и судьбу уже полученных результатов.

## Типичные ошибки

- Применять XOR к символам hex, а не к байтам после преобразования hex.
- Взять семь символов строки hex вместо семи байтов шифртекста.
- Забыть, что `\n` — один байт `0A` в известном префиксе.
- Не повторять ключ, а использовать его только для первых семи байтов.
- Принять ключ или весь расшифрованный отчёт за флаг.
- Вставить пробел или перевод строки вместе с `CTF{...}` при отправке.

## Образовательный результат

Повторное использование короткого XOR-ключа раскрывает ключ при известном
фрагменте открытого текста. Участник учится различать hex-представление
и реальные байты, применять обратимость XOR и проверять гипотезу по
дополнительному известному тексту. Такой способ не подходит для защиты
настоящих секретов.

## Материалы и публикация

`scripts/generate_crypto_01.py` воспроизводимо создаёт файл из одного и
того же флага и семисимвольного ключа; ввод происходит скрыто. В Git хранится
только шифртекст. Порядок установки карточки описан в
[инструкции публикации](CRYPTO-01-publish.md). Авторское решение нельзя
передавать участникам до завершения турнира.
