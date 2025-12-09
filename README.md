# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в различных режимах работы, вычисления криптографических хешей и HMAC.

## Возможности

- **Поддержка 7 режимов шифрования**: ECB, CBC, CFB, OFB, CTR, GCM (аутентифицированный), ETM (Encrypt-then-MAC)
- **Криптографические хеш-функции**: SHA-256 и SHA3-256 для проверки целостности данных
- **HMAC (Hash-based Message Authentication Code)**: Аутентификация сообщений с использованием SHA-256
- **Аутентифицированное шифрование (AEAD)**: GCM и Encrypt-then-MAC режимы с поддержкой AAD
- **Безопасная генерация IV/Nonce**: Автоматическая генерация криптографически безопасных IV и nonce
- **Автоматическая генерация ключей**: Ключ опционален для шифрования
- **Гибкая работа с IV/Nonce**: Поддержка чтения из файла или указания через CLI
- **Интероперабельность**: Совместимость с OpenSSL для всех режимов, включая GCM
- **Поддержка различных типов данных**: Текст, бинарные файлы, Unicode, файлы с нуль-байтами
- **Проверка слабых ключей**: Предупреждения при использовании потенциально слабых ключей
- **Катастрофический отказ при аутентификации**: Защита от поддельных данных без утечки информации

## Инструкции по сборке

### Использование Cargo (рекомендуется):
```bash
# Отладочная сборка (быстрее для разработки)
cargo build

# Релизная сборка (оптимизированная)
cargo build --release
```

Исполняемый файл будет создан в:
- Отладочная: `target/debug/cryptocore` или `target/debug/cryptocore.exe`
- Релизная: `target/release/cryptocore` или `target/release/cryptocore.exe`

## Зависимости

- **Rust 1.70+** - [Установить Rust](https://rustup.rs/)
- **Библиотеки OpenSSL** (автоматически устанавливаются через vendored feature)
- **Cargo** менеджер пакетов (входит в состав Rust)

### Примечания для платформ:
- **Windows**: Дополнительная настройка не требуется (OpenSSL поставляется с проектом)
- **Linux**: Может потребоваться `pkg-config` и `libssl-dev`
- **macOS**: Дополнительная настройка не требуется

## Использование

### Команды CryptoCore:

Утилита поддерживает две основные команды:
- **`crypto`** - для шифрования и дешифрования файлов
- **`dgst`** - для вычисления хеш-сумм файлов и HMAC

---

### Шифрование с автоматической генерацией ключа:

**Bash/Linux:**
```bash
# Ключ генерируется автоматически и выводится в терминал
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --input plaintext.txt \
  --output ciphertext.bin
# Вывод: [INFO] Generated random key: 1a2b3c4d5e6f7890a1b2c3d4e5f67890
```

**PowerShell:**
```powershell
# Ключ генерируется автоматически и выводится в терминал
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt `
  --input plaintext.txt `
  --output ciphertext.bin
# Вывод: [INFO] Generated random key: 1a2b3c4d5e6f7890a1b2c3d4e5f67890
```

### Шифрование с указанием ключа:

**Bash/Linux:**
```bash
# Для режимов с IV (CBC, CFB, OFB, CTR) - IV генерируется автоматически
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.bin
```

**PowerShell:**
```powershell
# Для режимов с IV (CBC, CFB, OFB, CTR) - IV генерируется автоматически
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt `
  --key 00112233445566778899aabbccddeeff `
  --input plaintext.txt `
  --output ciphertext.bin

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin
```

### Дешифрование (чтение IV из файла):

**Bash/Linux:**
```bash
# IV автоматически читается из начала файла
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt
```

**PowerShell:**
```powershell
# IV автоматически читается из начала файла
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt `
  --key 00112233445566778899aabbccddeeff `
  --input ciphertext.bin `
  --output decrypted.txt

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt
```

### Дешифрование с указанием IV:

**Bash/Linux:**
```bash
# IV указывается явно через --iv
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext.bin \
  --output decrypted.txt
```

**PowerShell:**
```powershell
# IV указывается явно через --iv
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt `
  --key 00112233445566778899aabbccddeeff `
  --iv aabbccddeeff00112233445566778899 `
  --input ciphertext.bin `
  --output decrypted.txt

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

### ECB режим (без IV):

**Bash/Linux:**
```bash
# Шифрование
cryptocore crypto --algorithm aes --mode ecb --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.bin

# Дешифрование
cryptocore crypto --algorithm aes --mode ecb --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt
```

**PowerShell:**
```powershell
# Шифрование
.\cryptocore crypto --algorithm aes --mode ecb --operation encrypt `
  --key 00112233445566778899aabbccddeeff `
  --input plaintext.txt `
  --output ciphertext.bin

# Дешифрование
.\cryptocore crypto --algorithm aes --mode ecb --operation decrypt `
  --key 00112233445566778899aabbccddeeff `
  --input ciphertext.bin `
  --output decrypted.txt

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode ecb --operation encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin
.\cryptocore crypto --algorithm aes --mode ecb --operation decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt
```

### GCM (Galois/Counter Mode) Шифрование:

**Bash/Linux:**
```bash
# GCM шифрование с автоматической генерацией nonce и AAD
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output secret.gcm.bin \
  --aad aabbccddeeff001122334455

# Вывод включает сгенерированный nonce
# [INFO] Generated random nonce (hex): 1a2b3c4d5e6f7890a1b2c3d4
# [SUCCESS] GCM encryption completed successfully
```

**PowerShell:**
```powershell
# GCM шифрование с указанием nonce
.\cryptocore crypto --algorithm aes --mode gcm --operation encrypt `
  --key 00112233445566778899aabbccddeeff `
  --nonce 000000000000000000000000 `
  --input secret.txt `
  --output secret.gcm.bin `
  --aad aabbccddeeff
```

### GCM Дешифрование:

**Bash/Linux:**
```bash
# GCM дешифрование с правильным AAD
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.gcm.bin \
  --output decrypted.txt \
  --aad aabbccddeeff001122334455
# [SUCCESS] GCM decryption completed successfully

# GCM дешифрование с неправильным AAD (катастрофический отказ)
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.gcm.bin \
  --output should_fail.txt \
  --aad wrongaad1234567890abcdef
# [ERROR] Authentication failed: tag mismatch or ciphertext tampered
# [ERROR] No plaintext output will be produced
# Выходной файл не создан!
```

**PowerShell:**
```powershell
# GCM дешифрование
.\cryptocore crypto --algorithm aes --mode gcm --operation decrypt `
  --key 00112233445566778899aabbccddeeff `
  --input secret.gcm.bin `
  --output decrypted.txt `
  --aad aabbccddeeff
```

### ETM (Encrypt-then-MAC) Шифрование:

**Bash/Linux:**
```bash
# ETM с CBC как базовый режим
cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.txt \
  --output document.etm.bin \
  --aad metadata123456

# ETM с CTR как базовый режим (без padding)
cryptocore crypto --algorithm aes --mode etm --base-mode ctr --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input video.mp4 \
  --output video.etm.bin
```

**PowerShell:**
```powershell
# ETM шифрование
.\cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt `
  --key 00112233445566778899aabbccddeeff `
  --input document.txt `
  --output document.etm.bin `
  --aad metadata123456
```

### ETM Дешифрование:

**Bash/Linux:**
```bash
# ETM дешифрование
cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.etm.bin \
  --output decrypted.txt \
  --aad metadata123456

# ETM с неправильным AAD (катастрофический отказ)
cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.etm.bin \
  --output should_fail.txt \
  --aad wrongmetadata
# [ERROR] Authentication failed: MAC mismatch
# Выходной файл удален!
```

---

### Вычисление хеш-сумм файлов:

**Bash/Linux:**
```bash
# SHA-256 хеш файла
cryptocore dgst --algorithm sha256 --input document.pdf
# Вывод: 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b05 document.pdf

# SHA3-256 хеш файла
cryptocore dgst --algorithm sha3-256 --input backup.tar
# Вывод: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 backup.tar

# Хеш с выводом в файл
cryptocore dgst --algorithm sha256 --input important.dat --output important.sha256

# Хеширование из stdin
echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
# Вывод: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad -
```

**PowerShell:**
```powershell
# SHA-256 хеш файла
.\cryptocore dgst --algorithm sha256 --input document.pdf
# Вывод: 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b05 document.pdf

# SHA3-256 хеш файла
.\cryptocore dgst --algorithm sha3-256 --input backup.tar
# Вывод: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 backup.tar

# Хеш с выводом в файл
.\cryptocore dgst --algorithm sha256 --input important.dat --output important.sha256

# Хеширование из stdin
echo "abc" | .\cryptocore dgst --algorithm sha256 --input -
```

---

### HMAC (Hash-based Message Authentication Code):

**Bash/Linux:**
```bash
# Генерация HMAC-SHA256
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
# Вывод: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 message.txt

# Генерация HMAC с выводом в файл
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.bin --output document.hmac

# Верификация HMAC
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected.hmac
# Вывод: [OK] HMAC verification successful

# Ключи произвольной длины
cryptocore dgst --algorithm sha256 --hmac --key "my_secret_key" --input data.txt
cryptocore dgst --algorithm sha256 --hmac --key aabbcc --input data.txt
```

**PowerShell:**
```powershell
# Генерация HMAC-SHA256
.\cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
# Вывод: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 message.txt

# Генерация HMAC с выводом в файл
.\cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input document.bin --output document.hmac

# Верификация HMAC
.\cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected.hmac
# Вывод: [OK] HMAC verification successful

# Ключи произвольной длины
.\cryptocore dgst --algorithm sha256 --hmac --key "my_secret_key" --input data.txt
.\cryptocore dgst --algorithm sha256 --hmac --key aabbcc --input data.txt
```

## Аргументы командной строки

### Команда `crypto` (шифрование/дешифрование):

| Аргумент | Описание | Обязательный | Примечания |
|----------|-------------|----------|------------|
| `--algorithm` | Алгоритм шифрования (`aes`) | Да | Только AES-128 |
| `--mode` | Режим работы (`ecb`, `cbc`, `cfb`, `ofb`, `ctr`, `gcm`, `etm`) | Да | `gcm` и `etm` - новые AEAD режимы |
| `--operation` | Операция (`encrypt` или `decrypt`) | Да | |
| `--key` | 16-байтный ключ (32 hex символа) | Нет (для шифрования) | Для шифрования: опционально (генерируется случайный) |
| `--input` | Путь к входному файлу | Да | Используйте `-` для stdin |
| `--output` | Путь к выходному файлу | Нет | Если не указан, генерируется автоматически |
| `--iv` | Вектор инициализации (32 hex символа) | Нет | Для CBC, CFB, OFB, CTR, ETM режимов |
| `--nonce` | Nonce для GCM (24 hex символа) | Нет | Только для GCM режима |
| `--aad` | Additional Authenticated Data (hex строка) | Нет | Для GCM и ETM режимов |
| `--base-mode` | Базовый режим для ETM (`ecb`, `cbc`, `cfb`, `ofb`, `ctr`) | Нет | Только для `--mode etm` |

### Команда `dgst` (вычисление хешей и HMAC):

| Аргумент | Описание | Обязательный | Примечания |
|----------|-------------|----------|------------|
| `--algorithm` | Алгоритм хеширования (`sha256`, `sha3-256`) | Да | |
| `--input` | Путь к входному файлу (используйте `-` для stdin) | Да | |
| `--output` | Путь к выходному файлу | Нет | |
| `--hmac` | Включить режим HMAC | Нет | |
| `--key` | Ключ для HMAC (hex-строка произвольной длины) | Только с `--hmac` | |
| `--verify` | Файл с ожидаемым HMAC для верификации | Нет | Только с `--hmac` |

### Формат ключа для шифрования:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `00112233445566778899aabbccddeeff`
- Опциональный префикс `@`: `@00112233445566778899aabbccddeeff`
- **Для шифрования**: если не указан, генерируется случайный ключ

### Формат ключа для HMAC:
- Шестнадцатеричная строка произвольной длины
- Примеры: `001122`, `aabbccddeeff`, `my_secret_key` (будет преобразован в hex)
- **Обязателен** при использовании `--hmac`

### Формат IV:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `aabbccddeeff00112233445566778899`
- Только для дешифрования в режимах CBC, CFB, OFB, CTR, ETM

### Формат Nonce для GCM:
- 24 шестнадцатеричных символа (12 байт)
- Пример: `000000000000000000000000`
- Для шифрования: если не указан, генерируется случайный

### Формат AAD:
- Шестнадцатеричная строка произвольной длины
- Пример: `aabbccddeeff001122334455`
- Опциональный: если не указан, используется пустая строка

### Формат вывода хешей/HMAC:
- `HASH_VALUE INPUT_FILE_PATH` (совместим с форматом *sum инструментов)
- Хеш в lowercase hexadecimal
- Поддержка вывода в файл через `--output`

### Автоматическое именование выходных файлов:
Если `--output` не указан, утилита генерирует имена по умолчанию:
- **Шифрование**: `{имя_входного_файла}.enc`
- **Дешифрование**: `{имя_входного_файла}.dec`
- **Хеширование/HMAC**: вывод в stdout

### Режим GCM (Galois/Counter Mode)
GCM объединяет шифрование в режиме счетчика (CTR) с аутентификацией на основе умножения в поле Галуа GF(2^128).

#### Особенности:
- **Размер nonce**: 12 байт (рекомендуется)
- **Размер тега**: 16 байт (128 бит)
- **Формат вывода**: `nonce (12 байт) | ciphertext | tag (16 байт)`
- **AAD (Additional Authenticated Data)**: Опциональные данные для аутентификации
- **Катастрофический отказ**: При неудачной аутентификации данные не выводятся

#### Формат работы GCM:
```
TAG = GHASH(H, AAD, CT) ⊕ E(K, J0)
где:
  H = E(K, 0)
  J0 = nonce || 0x01 (для 12-байтного nonce)
```

### Encrypt-then-MAC
Реализована парадигма "Зашифровать-потом-MAC", которая комбинирует любой блочный режим шифрования с HMAC-SHA256.

#### Особенности:
- **Шифрование**: Любой режим (CBC, CTR, CFB и т.д.)
- **Аутентификация**: HMAC-SHA256 над ciphertext || AAD
- **Разделение ключей**: Разные ключи для шифрования и MAC
- **Формат вывода**: `IV | ciphertext | tag (32 байт)`
- **Гибкость**: Можно использовать любой базовый режим шифрования

#### Формула Encrypt-then-MAC:
```
C = E(K_e, P)
T = HMAC-SHA256(K_m, C || AAD)
Output = IV || C || T
```

### Умножение в поле Галуа GF(2^128)
Реализация GCM включает эффективное умножение в поле Галуа GF(2^128) с использованием неприводимого полинома:
```
P(x) = x^128 + x^7 + x^2 + x + 1
```

## HMAC (Hash-based Message Authentication Code)
HMAC обеспечивает аутентификацию сообщений и целостность данных с использованием криптографических хеш-функций. Реализация соответствует RFC 2104.

### Особенности реализации:
- **Алгоритм**: HMAC-SHA256
- **Стандарт**: RFC 2104
- **Размер блока**: 64 байта
- **Обработка ключей**:
    - Ключи длиннее 64 байт хешируются
    - Ключи короче 64 байт дополняются нулями
    - Поддержка ключей произвольной длины

### Формула HMAC:
```
HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))
```
где:
- `H` - SHA-256 хеш-функция
- `K` - ключ (после обработки)
- `m` - сообщение
- `ipad` - внутренний padding (0x36 повторенный 64 раза)
- `opad` - внешний padding (0x5c повторенный 64 раза)

### Использование:
```bash
# Генерация HMAC
cryptocore dgst --algorithm sha256 --hmac --key <ключ> --input <файл>

# Верификация HMAC
cryptocore dgst --algorithm sha256 --hmac --key <ключ> --input <файл> --verify <файл_с_hmac>
```

## Режимы шифрования

### ECB (Electronic Codebook)
- **Без IV**, каждый блок шифруется независимо
- **Требует padding** (PKCS#7)
- Подходит для случайных данных, не рекомендуется для текста с паттернами

### CBC (Cipher Block Chaining)
- **Требует IV**, блоки связываются через XOR
- **Требует padding** (PKCS#7)
- Рекомендуется для большинства случаев использования

### CFB (Cipher Feedback)
- **Потоковый режим**, не требует padding
- **Требует IV**, работает как самосинхронизирующийся потоковый шифр
- Подходит для сетевых протоколов

### OFB (Output Feedback)
- **Потоковый режим**, не требует padding
- **Требует IV**, генерирует независимый keystream
- Устойчив к ошибкам передачи

### CTR (Counter)
- **Потоковый режим**, не требует padding
- **Требует IV** (используется как начальное значение счетчика)
- Высокая производительность, возможность параллельной обработки

### GCM (Galois/Counter Mode) - НОВЫЙ
- **Аутентифицированное шифрование**, объединяет CTR с аутентификацией
- **Требует nonce** (12 байт), поддерживает AAD
- **Не требует padding**, потоковый режим
- Высокая производительность, стандарт для TLS 1.2+

### ETM (Encrypt-then-MAC) - НОВЫЙ
- **Комбинированный режим**, любая комбинация шифрования + HMAC
- **Гибкий**: можно использовать с любым базовым режимом
- **Поддерживает AAD**, разделение ключей
- Универсальное решение для аутентифицированного шифрования

## Хеш-алгоритмы

### SHA-256
- **Реализация**: С нуля, соответствует NIST FIPS 180-4
- **Размер хеша**: 256 бит (64 hex символа)
- **Структура**: Merkle-Damgård с обработкой 512-битных блоков
- **Использование**: Проверка целостности данных, цифровые подписи, HMAC

### SHA3-256
- **Реализация**: Через библиотеку sha3, соответствует NIST FIPS 202
- **Размер хеша**: 256 бит (64 hex символа)
- **Структура**: Sponge construction (губчатая конструкция Keccak)
- **Использование**: Современная альтернатива SHA-2, устойчивость к атакам

## Безопасность CSPRNG

Утилита использует криптографически безопасный генератор псевдослучайных чисел (CSPRNG) на основе OpenSSL `rand_bytes()`:

- **Источник энтропии**: Используются системные источники энтропии ОС
- **Криптографическая стойкость**: Подходит для генерации ключей и IV
- **Проверка уникальности**: Тесты подтверждают уникальность 1000 сгенерированных ключей
- **Статистическое распределение**: Биты распределены равномерно (50.00% ± 0.01%)
- **Проверенное качество**: Все статистические тесты пройдены успешно

### Результаты тестирования CSPRNG:
- **Битовое распределение**: 50.00% единиц (идеально)
- **Уникальность ключей**: 1000/1000 без коллизий
- **Уникальность IV**: 100/100 без коллизий
- **Уникальность nonce**: 1000/1000 без коллизий
- **Паттерны**: 0 повторяющихся последовательностей
- **Непредсказуемость**: Разные результаты при последовательных вызовах

### Пример генерации ключа:
```
[INFO] Generated random key: 5c02dca03af5d0cc48e9c8578ec25efb
[INFO] Remember to save the generated key for decryption!
```

### Пример генерации nonce для GCM:
```
[INFO] Generated random nonce (hex): 1a2b3c4d5e6f7890a1b2c3d4
[SUCCESS] GCM encryption completed successfully
```

## Проверка слабых ключей

Утилита обнаруживает и предупреждает о потенциально слабых ключах:

- **Все нули**: `00000000000000000000000000000000`
- **Последовательные байты**: `000102030405060708090a0b0c0d0e0f`
- **Все одинаковые байты**: `aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb`
- **Общие паттерны**: `0123456789abcdef0123456789abcdef`

При обнаружении слабого ключа выводится предупреждение, но операция выполняется.

## Тестирование

### Полное автоматическое тестирование (PowerShell - Windows):
```powershell
.\scripts\test.ps1
```

### NIST тестирование (PowerShell - Windows):
```powershell
.\scripts\test_nist.ps1
```

### Полное автоматическое тестирование (Bash - Linux/Mac):
```bash
chmod +x scripts/test.sh
./scripts/test.sh
```

### NIST тестирование (Bash - Linux/Mac):
```bash
chmod +x scripts/test_nist.sh
./scripts/test.sh
```

### Тестирование AEAD (новые режимы):
```bash
# Тестирование GCM
cargo test --test gcm

# Тестирование Encrypt-then-MAC
cargo test --test aead

# Тестирование совместимости с OpenSSL
cargo test --test openssl_compatibility

# Тестирование больших данных в GCM
cargo test --test gcm_large_data

# Тестирование уникальности nonce
cargo test --test gcm_nonce_uniqueness
```

### Тестирование хеш-функций и HMAC:
```bash
# Запуск всех тестов включая хеш-функции и HMAC
cargo test

# Тестирование только хеш-функций
cargo test --test hash

# Тестирование HMAC
cargo test --test hmac

# Интеграционные тесты с хешированием и HMAC
cargo test --test integration_tests
```

### Автоматическое тестирование NIST STS:
```bash
# Генерация тестовых данных и базовое тестирование CSPRNG
make test-nist

# Полное NIST тестирование (требует WSL или Linux)
make test-nist-full

# Быстрая проверка CSPRNG
make test-nist-quick
```

### Тестирование отдельных режимов через Make:
```bash
# Протестировать все режимы
make test-all

# Тестировать конкретный режим
make test-ecb
make test-cbc
make test-cfb
make test-ofb
make test-ctr
make test-gcm
make test-etm

# Тестирование хеш-функций
make test-hash

# Тестирование HMAC
make test-hmac

# Тестирование CSPRNG модуля
make test-csprng

# Тестирование автоматической генерации ключей
make test-auto-key

# Тестирование интероперабельности с OpenSSL
make test-openssl

# Тестирование безопасности AEAD
make test-aead-security

# Тестирование производительности
make test-performance
```

### Быстрая ручная проверка:

**Bash/Linux:**
```bash
# Создать тестовый файл
echo "Hello CryptoCore Multi-Mode" > test.txt

# Зашифровать с автоматической генерацией ключа
cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input test.txt --output test.cbc.enc

# Расшифровать с использованием сгенерированного ключа
cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key "СГЕНЕРИРОВАННЫЙ_КЛЮЧ" --input test.cbc.enc --output test.cbc.dec

# Проверить что файлы идентичны
diff test.txt test.cbc.dec && echo "УСПЕХ: Автоматическая генерация ключа работает"

# Тестирование GCM
echo "Testing GCM mode" > test_gcm.txt
cryptocore crypto --algorithm aes --mode gcm --operation encrypt --key 00112233445566778899aabbccddeeff --input test_gcm.txt --output test_gcm.enc --aad test123
cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key 00112233445566778899aabbccddeeff --input test_gcm.enc --output test_gcm.dec --aad test123
diff test_gcm.txt test_gcm.dec && echo "УСПЕХ: GCM работает правильно"

# Тестирование катастрофического отказа в GCM
cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key 00112233445566778899aabbccddeeff --input test_gcm.enc --output should_fail.txt --aad wrongaad 2>/dev/null || echo "УСПЕХ: Катастрофический отказ работает"

# Вычислить хеш файла
cryptocore dgst --algorithm sha256 --input test.txt
cryptocore dgst --algorithm sha3-256 --input test.txt

# Вычислить HMAC
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt

# Очистка
rm test.txt test.cbc.enc test.cbc.dec test_gcm.txt test_gcm.enc test_gcm.dec
```

**PowerShell:**
```powershell
# Создать тестовый файл
echo "Hello CryptoCore Multi-Mode" > test.txt

# Зашифровать с автоматической генерацией ключа
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input test.txt --output test.cbc.enc

# Расшифровать с использованием сгенерированного ключа
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key "СГЕНЕРИРОВАННЫЙ_КЛЮЧ" --input test.cbc.enc --output test.cbc.dec

# Проверить что файлы идентичны
fc test.txt test.cbc.dec

# Если файлы идентичны, вы увидите: "Сравнение файлов завершено. Различия не обнаружены."

# Тестирование GCM
echo "Testing GCM mode" > test_gcm.txt
.\cryptocore crypto --algorithm aes --mode gcm --operation encrypt --key 00112233445566778899aabbccddeeff --input test_gcm.txt --output test_gcm.enc --aad test123
.\cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key 00112233445566778899aabbccddeeff --input test_gcm.enc --output test_gcm.dec --aad test123
fc test_gcm.txt test_gcm.dec

# Тестирование катастрофического отказа
.\cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key 00112233445566778899aabbccddeeff --input test_gcm.enc --output should_fail.txt --aad wrongaad 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "УСПЕХ: Катастрофический отказ работает" }

# Вычислить хеш файла
.\cryptocore dgst --algorithm sha256 --input test.txt
.\cryptocore dgst --algorithm sha3-256 --input test.txt

# Вычислить HMAC
.\cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt

# Очистка
Remove-Item test.txt, test.cbc.enc, test.cbc.dec, test_gcm.txt, test_gcm.enc, test_gcm.dec -ErrorAction SilentlyContinue
```

### Модульные тесты:
```bash
cargo test
```

### Интеграционные тесты:
```bash
cargo test --test integration_tests
```

### Тесты CSPRNG:
```bash
cargo test --test csprng
```

### Тесты хеш-функций:
```bash
cargo test --test hash
```

### Тесты HMAC:
```bash
cargo test --test hmac
```

## Интероперабельность с OpenSSL

### Шифрование CryptoCore → Дешифрование OpenSSL:

**Bash/Linux:**
```bash
# Шифруем нашим инструментом
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.txt --output file.enc

# Извлекаем IV и шифротекст
dd if=file.enc of=iv.bin bs=16 count=1
dd if=file.enc of=ciphertext.bin bs=16 skip=1

# Дешифруем OpenSSL
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext.bin -out file.dec
```

**PowerShell:**
```powershell
# Шифруем нашим инструментом
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc

# Извлекаем IV и шифротекст с помощью PowerShell
$content = [System.IO.File]::ReadAllBytes("file.enc")
[System.IO.File]::WriteAllBytes("iv.bin", $content[0..15])
[System.IO.File]::WriteAllBytes("ciphertext.bin", $content[16..($content.Length-1)])

# Конвертируем IV в hex строку для OpenSSL
$ivHex = -join ($content[0..15] | ForEach-Object { $_.ToString("x2") })

# Дешифруем OpenSSL
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $ivHex -in ciphertext.bin -out file.dec

# Альтернативный упрощенный способ (OpenSSL сам читает IV из файла):
# openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -in file.enc -out file.dec
```

### Шифрование OpenSSL → Дешифрование CryptoCore:

**Bash/Linux:**
```bash
# Шифруем OpenSSL
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff \
  -iv aabbccddeeff00112233445566778899 \
  -in file.txt -out file.enc

# Дешифруем нашим инструментом
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input file.enc --output file.dec
```

**PowerShell:**
```powershell
# Шифруем OpenSSL
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv aabbccddeeff00112233445566778899 -in file.txt -out file.enc

# Дешифруем нашим инструментом
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input file.enc --output file.dec
```

### Интероперабельность GCM с OpenSSL:

**Bash/Linux:**
```bash
# Шифруем GCM с нашим инструментом
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00000000000000000000000000000000 \
  --nonce 000000000000000000000000 \
  --input plain.txt --output cipher.gcm \
  --aad ""

# Извлекаем компоненты для OpenSSL
# GCM формат: nonce (12) | ciphertext | tag (16)
dd if=cipher.gcm of=nonce.bin bs=1 count=12
dd if=cipher.gcm of=tag.bin bs=1 skip=$(( $(stat -c%s cipher.gcm) - 16 )) count=16
dd if=cipher.gcm of=ciphertext_only.bin bs=1 skip=12 count=$(( $(stat -c%s cipher.gcm) - 12 - 16 ))

# Дешифруем OpenSSL
openssl enc -aes-128-gcm -d \
  -K 00000000000000000000000000000000 \
  -iv $(xxd -p nonce.bin | tr -d '\n') \
  -aad "" \
  -in ciphertext_only.bin \
  -out decrypted.txt \
  -tag $(xxd -p tag.bin | tr -d '\n')
```

### Интероперабельность хеш-функций:

**Bash/Linux:**
```bash
# Сравнение с системными утилитами
cryptocore dgst --algorithm sha256 --input file.txt
sha256sum file.txt

cryptocore dgst --algorithm sha3-256 --input file.txt
sha3sum -a 256 file.txt
```

## Технические детали

- **Алгоритм**: AES-128 (Advanced Encryption Standard)
- **Размер ключа**: 128 бит (16 байт)
- **Режимы**: ECB, CBC, CFB, OFB, CTR, GCM, ETM
- **Размер блока**: 16 байт
- **Размер IV**: 16 байт (для CBC, CFB, OFB, CTR, ETM)
- **Размер Nonce**: 12 байт (для GCM)
- **Размер тега**: 16 байт (GCM), 32 байта (ETM/HMAC-SHA256)
- **Дополнение**: PKCS#7 (для ECB и CBC)
- **Хеш-алгоритмы**: SHA-256, SHA3-256
- **HMAC**: HMAC-SHA256 (RFC 2104)
- **GCM**: Реализация по NIST SP 800-38D
- **Генерация ключей**: Криптографически безопасный ГПСЧ (OpenSSL `rand_bytes()`)
- **Генерация IV/Nonce**: Криптографически безопасный генератор
- **Библиотека**: OpenSSL через Rust crate `openssl`
- **Формат файла**:
    - CBC/CFB/OFB/CTR: `<16-байт IV><шифротекст>`
    - GCM: `<12-байт nonce><шифротекст><16-байт тег>`
    - ETM: `<16-байт IV><шифротекст><32-байт тег>`

## Структура проекта

```
cryptocore/
├── src/
│   ├── main.rs              # Точка входа
│   ├── lib.rs               # Библиотечные компоненты
│   ├── csprng/              # Модуль CSPRNG
│   │   └── mod.rs           # Криптографически безопасный ГПСЧ
│   ├── cli/                 # Интерфейс командной строки
│   │   ├── mod.rs
│   │   └── parser.rs        # Парсинг аргументов CLI
│   ├── crypto/              # Криптографические операции
│   │   ├── mod.rs
│   │   ├── aead.rs          # Реализация AEAD (Encrypt-then-MAC)
│   │   └── modes/           # Реализации всех режимов
│   │       ├── mod.rs
│   │       ├── ecb.rs       # ECB режим
│   │       ├── cbc.rs       # CBC режим
│   │       ├── cfb.rs       # CFB режим
│   │       ├── ofb.rs       # OFB режим
│   │       ├── ctr.rs       # CTR режим
│   │       └── gcm.rs       # Реализация GCM режима
│   ├── file/                # Операции ввода-вывода файлов
│   │   ├── mod.rs
│   │   └── io.rs            # Функции работы с файлами и IV
│   ├── hash/                # Модуль хеш-функций
│   │   ├── mod.rs           # Интерфейс хеш-алгоритмов
│   │   ├── sha256.rs        # Реализация SHA-256 с нуля
│   │   └── sha3_256.rs      # Реализация SHA3-256 через библиотеку
│   └── mac/                 # Модуль MAC функции
│       ├── mod.rs           # Интерфейс MAC алгоритмов
│       └── hmac.rs          # Реализация HMAC-SHA256
├── tests/                   # Интеграционные тесты
│   ├── integration_tests.rs
│   ├── test_csprng.rs       # Тесты CSPRNG
│   ├── test_hash.rs         # Тесты хеш-функций
│   ├── test_hmac_vectors.rs # Тесты HMAC (RFC 4231)
│   ├── test_gcm_comprehensive.rs  # Тесты GCM
│   ├── test_aead.rs         # Тесты AEAD
│   ├── test_openssl_compatibility.rs # Тесты совместимости
│   ├── test_gcm_large_data.rs      # Тесты больших данных
│   └── test_gcm_nonce_uniqueness.rs # Тесты уникальности nonce
├── scripts/                 # Скрипты автоматического тестирования
│   ├── test.ps1             # Полные тесты для PowerShell
│   ├── test.sh              # Полные тесты для Linux/Mac
│   ├── test_nist.ps1        # NIST тестирование для Windows
│   └── test_nist.sh         # NIST тестирование для Linux
├── Makefile                # Команды для тестирования
├── Cargo.toml              # Конфигурация проекта
└── README.md               # Этот файл
```

## Примеры использования

### Зашифровать документ с автоматической генерацией ключа:

**Bash/Linux:**
```bash
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --input document.pdf \
  --output document.pdf.enc
# Запомните сгенерированный ключ для дешифрования!
```

**PowerShell:**
```powershell
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt `
  --input document.pdf `
  --output document.pdf.enc
# Запомните сгенерированный ключ для дешифрования!

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input document.pdf --output document.pdf.enc
```

### Зашифровать в потоковом режиме (без padding):

**Bash/Linux:**
```bash
cryptocore crypto --algorithm aes --mode ctr --operation encrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input video.mp4 \
  --output video.mp4.enc
```

**PowerShell:**
```powershell
.\cryptocore crypto --algorithm aes --mode ctr --operation encrypt `
  --key 2b7e151628aed2a6abf7158809cf4f3c `
  --input video.mp4 `
  --output video.mp4.enc

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode ctr --operation encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input video.mp4 --output video.mp4.enc
```

### Зашифровать с аутентификацией (GCM):

**Bash/Linux:**
```bash
# Шифрование конфиденциального файла с контекстом
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key $(openssl rand -hex 16) \
  --input financial_report.pdf \
  --output report.enc \
  --aad $(echo -n "context:Q4_2023_financials" | xxd -p)

# Шифрование с автоматической генерацией nonce
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input medical_record.txt \
  --output record.enc \
  --aad aabbccddeeff
```

### Расшифровать с автоматическим именем выходного файла:

**Bash/Linux:**
```bash
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input document.pdf.enc
# Создаст: document.pdf.enc.dec
```

**PowerShell:**
```powershell
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt `
  --key 2b7e151628aed2a6abf7158809cf4f3c `
  --input document.pdf.enc
# Создаст: document.pdf.enc.dec

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input document.pdf.enc
```

### Расшифровать с проверкой аутентификации (GCM):

**Bash/Linux:**
```bash
# Успешное дешифрование с правильным контекстом
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key KEY_FROM_ENCRYPTION \
  --input report.enc \
  --output report_decrypted.pdf \
  --aad $(echo -n "context:Q4_2023_financials" | xxd -p)
# [SUCCESS] GCM decryption completed successfully

# Попытка доступа с неправильным контекстом (провалится)
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key KEY_FROM_ENCRYPTION \
  --input report.enc \
  --output /dev/null \
  --aad $(echo -n "context:hacker_attempt" | xxd -p)
# [ERROR] Authentication failed: tag mismatch or ciphertext tampered
# [ERROR] No plaintext output will be produced
```

### Проверить целостность файлов с помощью хешей:

**Bash/Linux:**
```bash
# Вычислить хеш файла
cryptocore dgst --algorithm sha256 --input software.iso
# Вывод: 5d5b09f6dcb2d53a5fffc60c4ac0d55fb052072fa2fe5d95f011b5d5d5b0b05 software.iso

# Сохранить хеш в файл
cryptocore dgst --algorithm sha256 --input software.iso --output software.sha256

# Проверить целостность позже
cryptocore dgst --algorithm sha256 --input software.iso
# Сравнить с содержимым software.sha256

# Использовать SHA3-256 для дополнительной безопасности
cryptocore dgst --algorithm sha3-256 --input critical_data.db --output checksum.sha3
```

**PowerShell:**
```powershell
# Вычислить хеш файла
.\cryptocore dgst --algorithm sha256 --input software.iso

# Сохранить хеш в файл
.\cryptocore dgst --algorithm sha256 --input software.iso --output software.sha256

# Использовать SHA3-256
.\cryptocore dgst --algorithm sha3-256 --input critical_data.db --output checksum.sha3
```

### Аутентификация данных с помощью HMAC:

**Bash/Linux:**
```bash
# Создать HMAC для файла
cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat
# Вывод: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 important.dat

# Сохранить HMAC в файл
cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat --output important.hmac

# Проверить аутентичность и целостность файла
cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat --verify important.hmac
# Вывод: [OK] HMAC verification successful

# Проверить с измененным файлом (должно завершиться с ошибкой)
echo "tampered" >> important.dat
cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat --verify important.hmac
# Вывод: [ERROR] HMAC verification failed
```

**PowerShell:**
```powershell
# Создать HMAC для файла
.\cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat

# Сохранить HMAC в файл
.\cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat --output important.hmac

# Проверить аутентичность и целостность файла
.\cryptocore dgst --algorithm sha256 --hmac --key my_secret_key --input important.dat --verify important.hmac
# Вывод: [OK] HMAC verification successful
```

### Работа с бинарными данными:

**Bash/Linux:**
```bash
# Шифрование бинарного файла
cryptocore crypto --algorithm aes --mode cfb --operation encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input database.bin --output database.enc

# Дешифрование с указанием IV
cryptocore crypto --algorithm aes --mode cfb --operation decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv 1234567890abcdef1234567890abcdef \
  --input database.enc --output database.dec

# Проверить целостность бинарного файла
cryptocore dgst --algorithm sha256 --input database.bin

# Создать HMAC для бинарного файла
cryptocore dgst --algorithm sha256 --hmac --key 0011223344556677 --input database.bin --output database.hmac
```

**PowerShell:**
```powershell
# Шифрование бинарного файла
.\cryptocore crypto --algorithm aes --mode cfb --operation encrypt `
  --key 000102030405060708090a0b0c0d0e0f `
  --input database.bin --output database.enc

# Дешифрование с указанием IV
.\cryptocore crypto --algorithm aes --mode cfb --operation decrypt `
  --key 000102030405060708090a0b0c0d0e0f `
  --iv 1234567890abcdef1234567890abcdef `
  --input database.enc --output database.dec

# Проверить целостность бинарного файла
.\cryptocore dgst --algorithm sha256 --input database.bin

# Создать HMAC для бинарного файла
.\cryptocore dgst --algorithm sha256 --hmac --key 0011223344556677 --input database.bin --output database.hmac

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cfb --operation encrypt --key 000102030405060708090a0b0c0d0e0f --input database.bin --output database.enc
.\cryptocore crypto --algorithm aes --mode cfb --operation decrypt --key 000102030405060708090a0b0c0d0e0f --iv 1234567890abcdef1234567890abcdef --input database.enc --output database.dec
.\cryptocore dgst --algorithm sha256 --input database.bin
.\cryptocore dgst --algorithm sha256 --hmac --key 0011223344556677 --input database.bin --output database.hmac
```

### Продвинутые сценарии использования AEAD:

**Bash/Linux:**
```bash
# 1. Зашифровать файл с метаданными (AAD)
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key $(openssl rand -hex 16) \
  --input sensitive_data.csv \
  --output encrypted.csv.gcm \
  --aad $(echo -n "user:alice|department:finance|date:2024-01-15" | xxd -p)

# 2. Проверить доступ только для финансового отдела
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key KEY_FROM_STEP_1 \
  --input encrypted.csv.gcm \
  --output decrypted_finance.csv \
  --aad $(echo -n "user:alice|department:finance|date:2024-01-15" | xxd -p)
# Успешно: у Alice есть доступ к финансовым данным

# 3. Попытка доступа из другого отдела (провалится)
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key KEY_FROM_STEP_1 \
  --input encrypted.csv.gcm \
  --output /dev/null \
  --aad $(echo -n "user:bob|department:engineering|date:2024-01-15" | xxd -p)
# Ошибка: Bob из инженерного отдела не имеет доступа

# 4. ETM для архивов с разными базовыми режимами
cryptocore crypto --algorithm aes --mode etm --base-mode ctr --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input archive.tar.gz \
  --output archive.enc \
  --aad $(echo -n "compression:gzip|type:backup|version:2" | xxd -p)

# 5. Проверка целостности архива при распаковке
cryptocore crypto --algorithm aes --mode etm --base-mode ctr --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input archive.enc \
  --output archive_decrypted.tar.gz \
  --aad $(echo -n "compression:gzip|type:backup|version:2" | xxd -p)
```

## Обработка ошибок

Утилита предоставляет понятные сообщения об ошибках:

- **Неверный ключ**: "Key must be 32 hex characters"
- **Неверный IV**: "IV must be 32 hex characters"
- **Неверный nonce**: "Nonce must be 24 hex characters (12 bytes) for GCM"
- **IV при шифровании**: "IV should not be provided for encryption"
- **Отсутствует IV при дешифровании**: "IV is required for decryption in this mode"
- **Несуществующий входной файл**: "Input file does not exist"
- **Файл слишком короткий для IV/nonce**: "File too short to contain IV/nonce"
- **Неверный hex-формат**: "Key must be a valid hexadecimal string"
- **Неверный алгоритм хеширования**: "Unsupported hash algorithm"
- **Слабый ключ**: "WARNING: The provided key appears to be weak. Consider using a stronger key."
- **HMAC без ключа**: "Key is required when --hmac is specified"
- **HMAC верификация не удалась**: "[ERROR] HMAC verification failed"
- **Аутентификация GCM не удалась**: "[ERROR] Authentication failed: tag mismatch or ciphertext tampered"
- **Аутентификация ETM не удалась**: "[ERROR] Authentication failed: MAC mismatch"
- **Катастрофический отказ**: "[ERROR] No plaintext output will be produced"

## Примечания по безопасности

- Использует промышленный стандарт шифрования AES-128
- Криптографически безопасная генерация ключей через OpenSSL `rand_bytes()`
- Криптографически безопасная генерация IV/Nonce через CSPRNG модуль
- Использует проверенную реализацию криптографии от OpenSSL
- Правильная обработка дополнения PKCS#7 для ECB и CBC режимов
- Безопасное управление памятью для чувствительных данных
- Потоковые режимы (CFB, OFB, CTR) не используют padding, сохраняя точный размер данных
- **SHA-256 реализован с нуля** по стандарту NIST FIPS 180-4
- **SHA3-256** использует проверенную библиотечную реализацию
- **HMAC-SHA256** реализован по RFC 2104 для аутентификации сообщений
- Проверка слабых ключей с предупреждениями
- **Проверенное качество CSPRNG**: все статистические тесты пройдены успешно
- **Проверенные хеш-функции**: проходят NIST тестовые векторы и тест лавинного эффекта
- **Проверенный HMAC**: проходит тестовые векторы RFC 4231

## Лицензия

Этот проект лицензирован на условиях:
- Лицензия Apache, версия 2.0
- Лицензия MIT

## Вклад в проект

1. Сделайте форк репозитория
2. Создайте ветку для новой функциональности
3. Внесите свои изменения
4. Добавьте тесты для новой функциональности
5. Запустите полный набор тестов
6. Отправьте pull request

## Поддержка

При возникновении проблем и вопросов:

1. **Проверьте сообщения об ошибках** - они содержат детальную информацию
2. **Для автоматической генерации ключа** - сохраните сгенерированный ключ для дешифрования
3. **Для дешифрования в режимах с IV**:
    - Либо не указывайте `--iv` (IV будет прочитан из файла)
    - Либо укажите правильный IV через `--iv` (32 hex символа)
4. **Для дешифрования GCM** - nonce автоматически читается из файла
5. **Для шифрования в режимах с IV** - не указывайте `--iv` (генерируется автоматически)
6. **Для вычисления хешей** используйте команду `dgst` с указанием алгоритма
7. **Для HMAC** используйте флаг `--hmac` с обязательным ключом `--key`
8. **Для AEAD режимов** - используйте `--aad` для дополнительных аутентифицированных данных
9. **В PowerShell используйте `.\` и `powershell -ExecutionPolicy Bypass -File .\` перед cryptocore или измените политику выполнения для текущей сессии `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` ** - это требование безопасности PowerShell для запуска локальных исполняемых файлов
10. **При вызове в Powershell может потребоваться добавлять .exe  конце вызова `./cryptopro.exe`, если утилита не прописана в переменной окружения PATH **