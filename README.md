# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в различных режимах работы.

## Возможности

- **Поддержка 5 режимов шифрования**: ECB, CBC, CFB, OFB, CTR
- **Безопасная генерация IV**: Автоматическая генерация криптографически безопасных IV
- **Гибкая работа с IV**: Поддержка чтения IV из файла или указания через CLI
- **Интероперабельность**: Совместимость с OpenSSL для всех режимов
- **Поддержка различных типов данных**: Текст, бинарные файлы, Unicode, файлы с нуль-байтами

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

### Шифрование (с автоматической генерацией IV):
```bash
# Для режимов с IV (CBC, CFB, OFB, CTR) - IV генерируется автоматически
cryptocore --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.bin
```

### Дешифрование (чтение IV из файла):
```bash
# IV автоматически читается из начала файла
cryptocore --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt
```

### Дешифрование с указанием IV:
```bash
# IV указывается явно через --iv
cryptocore --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext.bin \
  --output decrypted.txt
```

### ECB режим (без IV):
```bash
# Шифрование
cryptocore --algorithm aes --mode ecb --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.bin

# Дешифрование
cryptocore --algorithm aes --mode ecb --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt
```

## Аргументы командной строки

| Аргумент | Описание | Обязательный |
|----------|-------------|----------|
| `--algorithm` | Алгоритм шифрования (в настоящее время только `aes`) | Да |
| `--mode` | Режим работы (`ecb`, `cbc`, `cfb`, `ofb`, `ctr`) | Да |
| `--operation` | Операция (`encrypt` или `decrypt`) | Да |
| `--key` | 16-байтный ключ в виде 32-символьной hex-строки | Да |
| `--input` | Путь к входному файлу | Да |
| `--output` | Путь к выходному файлу (опционально) | Нет |
| `--iv` | Вектор инициализации для дешифрования (32 hex символа) | Нет |

### Формат ключа:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `00112233445566778899aabbccddeeff`
- Опциональный префикс `@`: `@00112233445566778899aabbccddeeff`

### Формат IV:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `aabbccddeeff00112233445566778899`
- Только для дешифрования в режимах CBC, CFB, OFB, CTR

### Автоматическое именование выходных файлов:
Если `--output` не указан, утилита генерирует имена по умолчанию:
- Шифрование: `{имя_входного_файла}.enc`
- Дешифрование: `{имя_входного_файла}.dec`

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

## Тестирование

### Полное автоматическое тестирование (PowerShell - Windows):
```powershell
.\scripts\test.ps1
```

### Полное автоматическое тестирование (Bash - Linux/Mac):
```bash
chmod +x scripts/test.sh
./scripts/test.sh
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

# Тестирование интероперабельности с OpenSSL
make test-openssl
```

### Быстрая ручная проверка:
```bash
# Создать тестовый файл
echo "Hello CryptoCore Multi-Mode" > test.txt

# Зашифровать в CBC режиме
cryptocore --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.cbc.enc

# Расшифровать
cryptocore --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.cbc.enc --output test.cbc.dec

# Проверить что файлы идентичны
diff test.txt test.cbc.dec && echo "УСПЕХ: CBC режим работает корректно"

# Очистка
rm test.txt test.cbc.enc test.cbc.dec
```

### Модульные тесты:
```bash
cargo test
```

### Интеграционные тесты:
```bash
cargo test --test integration_tests
```

## Интероперабельность с OpenSSL

### Шифрование CryptoCore → Дешифрование OpenSSL:
```bash
# Шифруем нашим инструментом
cryptocore --algorithm aes --mode cbc --operation encrypt \
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

### Шифрование OpenSSL → Дешифрование CryptoCore:
```bash
# Шифруем OpenSSL
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff \
  -iv aabbccddeeff00112233445566778899 \
  -in file.txt -out file.enc

# Дешифруем нашим инструментом
cryptocore --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input file.enc --output file.dec
```

## Технические детали

- **Алгоритм**: AES-128 (Advanced Encryption Standard)
- **Размер ключа**: 128 бит (16 байт)
- **Режимы**: ECB, CBC, CFB, OFB, CTR
- **Размер блока**: 16 байт
- **Размер IV**: 16 байт
- **Дополнение**: PKCS#7 (для ECB и CBC)
- **Генерация IV**: Криптографически безопасный генератор (`rand::thread_rng()`)
- **Библиотека**: OpenSSL через Rust crate `openssl`
- **Формат файла**: Для режимов с IV - `<16-байт IV><шифротекст>`

## Структура проекта

```
cryptocore/
├── src/
│   ├── main.rs              # Точка входа
│   ├── lib.rs               # Библиотечные компоненты
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
│   └── file/                # Операции ввода-вывода файлов
│       ├── mod.rs
│       └── io.rs            # Функции работы с файлами и IV
├── tests/                   # Интеграционные тесты
│   └── integration_tests.rs
├── scripts/                 # Скрипты автоматического тестирования
│   ├── test.ps1             # Полные тесты для PowerShell
│   └── test.sh              # Полные тесты для Linux/Mac
├── Makefile                # Команды для тестирования
├── Cargo.toml              # Конфигурация проекта
└── README.md               # Этот файл
```

## Примеры использования

### Зашифровать документ в CBC режиме:
```bash
cryptocore --algorithm aes --mode cbc --operation encrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input document.pdf \
  --output document.pdf.enc
```

### Зашифровать в потоковом режиме (без padding):
```bash
cryptocore --algorithm aes --mode ctr --operation encrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input video.mp4 \
  --output video.mp4.enc
```

### Расшифровать с автоматическим именем выходного файла:
```bash
cryptocore --algorithm aes --mode cbc --operation decrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input document.pdf.enc
# Создаст: document.pdf.enc.dec
```

### Работа с бинарными данными:
```bash
# Шифрование бинарного файла
cryptocore --algorithm aes --mode cfb --operation encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input database.bin --output database.enc

# Дешифрование с указанием IV
cryptocore --algorithm aes --mode cfb --operation decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv 1234567890abcdef1234567890abcdef \
  --input database.enc --output database.dec
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

## Примечания по безопасности

- Использует промышленный стандарт шифрования AES-128
- Криптографически безопасная генерация IV через `rand::thread_rng()`
- Использует проверенную реализацию криптографии от OpenSSL
- Правильная обработка дополнения PKCS#7 для ECB и CBC режимов
- Безопасное управление памятью для чувствительных данных
- Потоковые режимы (CFB, OFB, CTR) не используют padding, сохраняя точный размер данных

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
2. **Убедитесь что ваш ключ** состоит из 32 шестнадцатеричных символов
3. **Для дешифрования в режимах с IV**:
    - Либо не указывайте `--iv` (IV будет прочитан из файла)
    - Либо укажите правильный IV через `--iv` (32 hex символа)
4. **Для шифрования в режимах с IV** - не указывайте `--iv` (генерируется автоматически)
5. **Убедитесь что входной файл** существует и доступен для чтения
6. **Проверьте доступное место на диске** для выходных файлов