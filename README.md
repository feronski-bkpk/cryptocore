# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в различных режимах работы, а также вычисления криптографических хешей.

## Возможности

- **Поддержка 5 режимов шифрования**: ECB, CBC, CFB, OFB, CTR
- **Криптографические хеш-функции**: SHA-256 и SHA3-256 для проверки целостности данных
- **Безопасная генерация IV**: Автоматическая генерация криптографически безопасных IV
- **Автоматическая генерация ключей**: Ключ опционален для шифрования
- **Гибкая работа с IV**: Поддержка чтения IV из файла или указания через CLI
- **Интероперабельность**: Совместимость с OpenSSL для всех режимов
- **Поддержка различных типов данных**: Текст, бинарные файлы, Unicode, файлы с нуль-байтами
- **Проверка слабых ключей**: Предупреждения при использовании потенциально слабых ключей

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
- **`dgst`** - для вычисления хеш-сумм файлов

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

## Аргументы командной строки

### Команда `crypto` (шифрование/дешифрование):

| Аргумент | Описание | Обязательный |
|----------|-------------|----------|
| `--algorithm` | Алгоритм шифрования (в настоящее время только `aes`) | Да |
| `--mode` | Режим работы (`ecb`, `cbc`, `cfb`, `ofb`, `ctr`) | Да |
| `--operation` | Операция (`encrypt` или `decrypt`) | Да |
| `--key` | 16-байтный ключ в виде 32-символьной hex-строки. **Опционально для шифрования** - если не указан, генерируется случайный ключ | Нет (для шифрования) |
| `--input` | Путь к входному файлу | Да |
| `--output` | Путь к выходному файлу (опционально) | Нет |
| `--iv` | Вектор инициализации для дешифрования (32 hex символа) | Нет |

### Команда `dgst` (вычисление хешей):

| Аргумент | Описание | Обязательный |
|----------|-------------|----------|
| `--algorithm` | Алгоритм хеширования (`sha256`, `sha3-256`) | Да |
| `--input` | Путь к входному файлу (используйте `-` для stdin) | Да |
| `--output` | Путь к выходному файлу (опционально) | Нет |

### Формат ключа:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `00112233445566778899aabbccddeeff`
- Опциональный префикс `@`: `@00112233445566778899aabbccddeeff`
- **Для шифрования**: если не указан, генерируется случайный ключ

### Формат IV:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `aabbccddeeff00112233445566778899`
- Только для дешифрования в режимах CBC, CFB, OFB, CTR

### Формат вывода хешей:
- `HASH_VALUE INPUT_FILE_PATH` (совместим с форматом *sum инструментов)
- Хеш в lowercase hexadecimal
- Поддержка вывода в файл через `--output`

### Автоматическое именование выходных файлов:
Если `--output` не указан, утилита генерирует имена по умолчанию:
- **Шифрование**: `{имя_входного_файла}.enc`
- **Дешифрование**: `{имя_входного_файла}.dec`
- **Хеширование**: вывод в stdout

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

## Хеш-алгоритмы

### SHA-256
- **Реализация**: С нуля, соответствует NIST FIPS 180-4
- **Размер хеша**: 256 бит (64 hex символа)
- **Структура**: Merkle-Damgård с обработкой 512-битных блоков
- **Использование**: Проверка целостности данных, цифровые подписи

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
- **Паттерны**: 0 повторяющихся последовательностей
- **Непредсказуемость**: Разные результаты при последовательных вызовах

### Пример генерации ключа:
```
[INFO] Generated random key: 5c02dca03af5d0cc48e9c8578ec25efb
[INFO] Remember to save the generated key for decryption!
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

### Тестирование хеш-функций:
```bash
# Запуск всех тестов включая хеш-функции
cargo test

# Тестирование только хеш-функций
cargo test --test hash

# Интеграционные тесты с хешированием
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

# Тестирование хеш-функций
make test-hash

# Тестирование CSPRNG модуля
make test-csprng

# Тестирование автоматической генерации ключей
make test-auto-key

# Тестирование интероперабельности с OpenSSL
make test-openssl

# Тестирование безопасности
make test-security

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

# Вычислить хеш файла
cryptocore dgst --algorithm sha256 --input test.txt
cryptocore dgst --algorithm sha3-256 --input test.txt

# Очистка
rm test.txt test.cbc.enc test.cbc.dec
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

# Вычислить хеш файла
.\cryptocore dgst --algorithm sha256 --input test.txt
.\cryptocore dgst --algorithm sha3-256 --input test.txt

# Очистка
Remove-Item test.txt, test.cbc.enc, test.cbc.dec
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
- **Режимы**: ECB, CBC, CFB, OFB, CTR
- **Размер блока**: 16 байт
- **Размер IV**: 16 байт
- **Дополнение**: PKCS#7 (для ECB и CBC)
- **Хеш-алгоритмы**: SHA-256, SHA3-256
- **Генерация ключей**: Криптографически безопасный ГПСЧ (OpenSSL `rand_bytes()`)
- **Генерация IV**: Криптографически безопасный генератор (`Csprng::generate_iv()`)
- **Библиотека**: OpenSSL через Rust crate `openssl`
- **Формат файла**: Для режимов с IV - `<16-байт IV><шифротекст>`

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
│   │   └── modes/           # Реализации всех режимов
│   │       ├── mod.rs
│   │       ├── ecb.rs       # ECB режим
│   │       ├── cbc.rs       # CBC режим
│   │       ├── cfb.rs       # CFB режим
│   │       ├── ofb.rs       # OFB режим
│   │       └── ctr.rs       # CTR режим
│   ├── file/                # Операции ввода-вывода файлов
│   │   ├── mod.rs
│   │   └── io.rs            # Функции работы с файлами и IV
│   └── hash/                # НОВЫЙ МОДУЛЬ: Хеш-функции
│       ├── mod.rs           # Интерфейс хеш-алгоритмов
│       ├── sha256.rs        # Реализация SHA-256 с нуля
│       └── sha3_256.rs      # Реализация SHA3-256 через библиотеку
├── tests/                   # Интеграционные тесты
│   ├── integration_tests.rs
│   ├── test_csprng.rs       # Тесты CSPRNG
│   └── test_hash.rs         # Тесты хеш-функции
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

# Или в одну строку:
.\cryptocore crypto --algorithm aes --mode cfb --operation encrypt --key 000102030405060708090a0b0c0d0e0f --input database.bin --output database.enc
.\cryptocore crypto --algorithm aes --mode cfb --operation decrypt --key 000102030405060708090a0b0c0d0e0f --iv 1234567890abcdef1234567890abcdef --input database.enc --output database.dec
.\cryptocore dgst --algorithm sha256 --input database.bin
```

## Обработка ошибок

Утилита предоставляет понятные сообщения об ошибках:

- **Неверный ключ**: "Key must be 32 hex characters"
- **Неверный IV**: "IV must be 32 hex characters"
- **IV при шифровании**: "IV should not be provided for encryption"
- **Отсутствует IV при дешифровании**: "IV is required for decryption in this mode"
- **Несуществующий входной файл**: "Input file does not exist"
- **Файл слишком короткий для IV**: "File too short to contain IV"
- **Неверный hex-формат**: "Key must be a valid hexadecimal string"
- **Неверный алгоритм хеширования**: "Unsupported hash algorithm"
- **Слабый ключ**: "WARNING: The provided key appears to be weak. Consider using a stronger key."

## Примечания по безопасности

- Использует промышленный стандарт шифрования AES-128
- Криптографически безопасная генерация ключей через OpenSSL `rand_bytes()`
- Криптографически безопасная генерация IV через CSPRNG модуль
- Использует проверенную реализацию криптографии от OpenSSL
- Правильная обработка дополнения PKCS#7 для ECB и CBC режимов
- Безопасное управление памятью для чувствительных данных
- Потоковые режимы (CFB, OFB, CTR) не используют padding, сохраняя точный размер данных
- **SHA-256 реализован с нуля** по стандарту NIST FIPS 180-4
- **SHA3-256** использует проверенную библиотечную реализацию
- Проверка слабых ключей с предупреждениями
- **Проверенное качество CSPRNG**: все статистические тесты пройдены успешно
- **Проверенные хеш-функции**: проходят NIST тестовые векторы и тест лавинного эффекта

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
4. **Для шифрования в режимах с IV** - не указывайте `--iv` (генерируется автоматически)
5. **Для вычисления хешей** используйте команду `dgst` с указанием алгоритма
6. **Формат вывода хешей** совместим с системными утилитами (*sum)
7. **Убедитесь что входной файл** существует и доступен для чтения
8. **Проверьте доступное место на диске** для выходных файлов
9. **В PowerShell используйте `.\` перед cryptocore** - это требование безопасности PowerShell для запуска локальных исполняемых файлов
10. **При использовании слабых ключей** - обратите внимание на предупреждения