# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в режиме ECB.

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

### Шифрование:
```bash
cryptocore --algorithm aes --mode ecb --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt \
  --output ciphertext.bin
```

### Дешифрование:
```bash
cryptocore --algorithm aes --mode ecb --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin \
  --output decrypted.txt
```

### Аргументы командной строки:

| Аргумент | Описание | Обязательный |
|----------|-------------|----------|
| `--algorithm` | Алгоритм шифрования (в настоящее время только `aes`) | Да |
| `--mode` | Режим работы (в настоящее время только `ecb`) | Да |
| `--operation` | Операция (`encrypt` или `decrypt`) | Да |
| `--key` | 16-байтный ключ в виде 32-символьной hex-строки | Да |
| `--input` | Путь к входному файлу | Да |
| `--output` | Путь к выходному файлу (опционально) | Нет |

### Формат ключа:
- 32 шестнадцатеричных символа (16 байт)
- Пример: `00112233445566778899aabbccddeeff`
- Опциональный префикс `@`: `@00112233445566778899aabbccddeeff`

### Автоматическое именование выходных файлов:
Если `--output` не указан, утилита генерирует имена по умолчанию:
- Шифрование: `{имя_входного_файла}.enc`
- Дешифрование: `{имя_входного_файла}.dec`

## Тестирование

### Автоматические тесты (PowerShell - Windows):
```powershell
.\scripts\test.ps1
```

### Автоматические тесты (Bash - Linux/Mac):
```bash
chmod +x scripts/test.sh
./scripts/test.sh
```

### Быстрая ручная проверка:
```bash
# Создать тестовый файл
echo "Hello CryptoCore" > test.txt

# Зашифровать
cryptocore --algorithm aes --mode ecb --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.enc

# Расшифровать
cryptocore --algorithm aes --mode ecb --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.enc --output test.dec

# Проверить что файлы идентичны
diff test.txt test.dec && echo "УСПЕХ: Файлы идентичны"

# Очистка
rm test.txt test.enc test.dec
```

### Модульные тесты:
```bash
cargo test
```

### Интеграционные тесты:
```bash
cargo test --test integration_tests
```

## Технические детали

- **Алгоритм**: AES-128 (Advanced Encryption Standard)
- **Размер ключа**: 128 бит (16 байт)
- **Режим**: ECB (Electronic Codebook)
- **Дополнение**: PKCS#7 (обрабатывается OpenSSL)
- **Библиотека**: OpenSSL через Rust crate `openssl`
- **Формат ключа**: Шестнадцатеричная строка (32 символа)

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
│   │   └── aes_ecb.rs       # Реализация AES-128 ECB
│   └── file/                # Операции ввода-вывода файлов
│       ├── mod.rs
│       └── io.rs
├── tests/                   # Интеграционные тесты
│   └── integration_tests.rs
├── scripts/                 # Скрипты автоматического тестирования
│   ├── test.ps1             # Тесты для PowerShell
│   └── test.sh              # Тесты для Linux/Mac
├── Cargo.toml              # Конфигурация проекта
└── README.md               # Этот файл
```

## Примеры использования

### Зашифровать документ:
```bash
cryptocore --algorithm aes --mode ecb --operation encrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input document.pdf \
  --output document.pdf.enc
```

### Расшифровать с автоматическим именем выходного файла:
```bash
cryptocore --algorithm aes --mode ecb --operation decrypt \
  --key 2b7e151628aed2a6abf7158809cf4f3c \
  --input document.pdf.enc
# Создаст: document.pdf.enc.dec
```

### Тестирование с разными типами файлов:
```bash
# Текстовый файл
cryptocore --algorithm aes --mode ecb --operation encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input data.txt --output data.enc

# Бинарный файл
cryptocore --algorithm aes --mode ecb --operation encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input image.jpg --output image.enc
```

## Обработка ошибок

Утилита предоставляет понятные сообщения об ошибках для частых проблем:

- **Неверный ключ**: "Key must be 32 hex characters"
- **Несуществующий входной файл**: "Input file does not exist"
- **Неверный hex-формат**: "Key must be a valid hexadecimal string"
- **Отсутствующие аргументы**: Соответствующая информация об использовании

## Примечания по безопасности

- Использует промышленный стандарт шифрования AES-128
- Использует проверенную реализацию криптографии от OpenSSL
- Правильная обработка дополнения PKCS#7
- Безопасное управление памятью для чувствительных данных

## Лицензия

Этот проект лицензирован на условиях:
- Лицензия Apache, версия 2.0
- Лицензия MIT

## Вклад в проект

1. Сделайте форк репозитория
2. Создайте ветку для новой функциональности
3. Внесите свои изменения
4. Добавьте тесты
5. Запустите набор тестов
6. Отправьте pull request

## Поддержка

При возникновении проблем и вопросов:
1. Проверьте сообщения об ошибках
2. Убедитесь что ваш ключ состоит из 32 шестнадцатеричных символов
3. Убедитесь что входной файл существует и доступен для чтения
4. Проверьте доступное место на диске для выходных файлов