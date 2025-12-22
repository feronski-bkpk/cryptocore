# Руководство пользователя CryptoCore CLI

## Обзор

CryptoCore — это командная утилита для криптографических операций с файлами, поддерживающая шифрование AES-128 в различных режимах, вычисление хеш-сумм, HMAC и безопасное выведение ключей.

**Основные возможности:**
- 7 режимов шифрования AES-128: ECB, CBC, CFB, OFB, CTR, GCM, ETM
- Хеш-функции: SHA-256 и SHA3-256
- HMAC-SHA256 для аутентификации сообщений
- Аутентифицированное шифрование (AEAD) через GCM и Encrypt-then-MAC
- Безопасное выведение ключей через PBKDF2-HMAC-SHA256
- Интероперабельность с OpenSSL

## Установка

### Требования
- Rust 1.70+ и Cargo (менеджер пакетов Rust)
- Для Linux: `pkg-config` и `libssl-dev` (или их эквиваленты)

### Установка из исходного кода

#### Windows (PowerShell)
```powershell
# Скачайте или клонируйте репозиторий
git clone <repository-url>
cd cryptocore

# Сборка релизной версии
cargo build --release

# Добавьте в PATH (опционально)
$env:Path += ";$pwd\target\release"
```

#### Linux/macOS (Bash)
```bash
# Клонирование и сборка
git clone <repository-url>
cd cryptocore
cargo build --release

# Установка в системный путь
sudo cp target/release/cryptocore /usr/local/bin/

# Проверка установки
cryptocore --help
```

### Проверка установки
```bash
cryptocore --version
cryptocore --help
```

## Быстрый старт

### Шифрование файла с автоматической генерацией ключа
```bash
# Ключ будет сгенерирован и показан в терминале
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --input secret.txt \
  --output secret.enc

# Запомните выведенный ключ для дешифрования!
```

### Дешифрование файла
```bash
# IV автоматически читается из файла
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key <сгенерированный-ключ> \
  --input secret.enc \
  --output decrypted.txt
```

### Вычисление хеша файла
```bash
cryptocore dgst --algorithm sha256 --input file.txt
```

## Шифрование и дешифрование

### Поддерживаемые режимы
| Режим | IV/Nonce | Padding | Аутентификация | Рекомендации |
|-------|----------|---------|----------------|--------------|
| ECB | Нет | PKCS#7 | Нет | Только для случайных данных |
| CBC | 16 байт | PKCS#7 | Нет | Основной режим для файлов |
| CFB | 16 байт | Нет | Нет | Потоковый режим |
| OFB | 16 байт | Нет | Нет | Потоковый, устойчив к ошибкам |
| CTR | 16 байт | Нет | Нет | Высокая производительность |
| GCM | 12 байт | Нет | Да | Рекомендуемый AEAD режим |
| ETM | 16 байт | Зависит | Да | Гибкое аутентифицированное шифрование |

### Основные сценарии

#### 1. Шифрование с автоматической генерацией ключа и IV
```bash
# Ключ и IV генерируются автоматически
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --input document.pdf \
  --output document.enc
# Сохраните выведенный ключ!
```

#### 2. Шифрование с указанием ключа
```bash
# IV генерируется автоматически
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt \
  --output data.enc
```

#### 3. Дешифрование (автоматическое чтение IV из файла)
```bash
# IV читается из начала файла
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.enc \
  --output data.dec
```

#### 4. Дешифрование с указанием IV
```bash
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input data.enc \
  --output data.dec
```

### GCM (аутентифицированное шифрование)

#### Шифрование с AAD
```bash
# С автоматической генерацией nonce
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input confidential.txt \
  --output confidential.enc \
  --aad "context:Q4_report|user:alice"
```

#### Дешифрование с проверкой AAD
```bash
# Успешное дешифрование
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input confidential.enc \
  --output decrypted.txt \
  --aad "context:Q4_report|user:alice"
# [SUCCESS] GCM decryption completed successfully

# Неудачное дешифрование (неверный AAD)
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input confidential.enc \
  --output should_fail.txt \
  --aad "context:hacker_attempt"
# [ERROR] Authentication failed: tag mismatch or ciphertext tampered
```

#### Шифрование с указанием nonce
```bash
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --nonce 000000000000000000000000 \
  --input file.txt \
  --output file.enc \
  --aad metadata123
```

### Encrypt-then-MAC (ETM)

#### Шифрование с CBC как базовым режимом
```bash
cryptocore crypto --algorithm aes --mode etm --base-mode cbc \
  --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.txt \
  --output document.etm \
  --aad "version:1.0|timestamp:$(date +%s)"
```

#### Дешифрование ETM
```bash
cryptocore crypto --algorithm aes --mode etm --base-mode cbc \
  --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.etm \
  --output document.dec \
  --aad "version:1.0|timestamp:1672531200"
```

### Потоковые режимы (без padding)

#### CTR режим для бинарных файлов
```bash
# Шифрование
cryptocore crypto --algorithm aes --mode ctr --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input video.mp4 \
  --output video.enc

# Дешифрование
cryptocore crypto --algorithm aes --mode ctr --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input video.enc \
  --output video.dec
```

#### CFB режим
```bash
cryptocore crypto --algorithm aes --mode cfb --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.bin \
  --output data.cfb.enc
```

### Работа с stdin/stdout

#### Шифрование из stdin в stdout
```bash
echo "Secret data" | cryptocore crypto --algorithm aes --mode cbc \
  --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input - \
  --output - > encrypted.bin
```

#### Дешифрование в stdout
```bash
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin \
  --output - > decrypted.txt
```

## Хеширование и HMAC

### Вычисление хеш-сумм

#### SHA-256
```bash
# Базовое хеширование
cryptocore dgst --algorithm sha256 --input file.txt

# Сохранение хеша в файл
cryptocore dgst --algorithm sha256 --input important.dat \
  --output important.sha256

# Хеширование из stdin
echo -n "data to hash" | cryptocore dgst --algorithm sha256 --input -
```

#### SHA3-256
```bash
cryptocore dgst --algorithm sha3-256 --input file.txt
```

#### Проверка целостности нескольких файлов
```bash
# Создание хешей
for file in *.iso; do
  cryptocore dgst --algorithm sha256 --input "$file" > "${file}.sha256"
done

# Проверка хешей
for file in *.iso; do
  cryptocore dgst --algorithm sha256 --input "$file" | \
    diff - "${file}.sha256" && echo "$file: OK" || echo "$file: FAILED"
done
```

### HMAC (аутентификация сообщений)

#### Создание HMAC
```bash
# С hex ключом
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt

# С текстовым ключом
cryptocore dgst --algorithm sha256 --hmac \
  --key "MySecretKey123" \
  --input document.pdf

# Сохранение HMAC в файл
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input data.bin \
  --output data.hmac
```

#### Верификация HMAC
```bash
# Успешная верификация
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt \
  --verify expected.hmac
# [OK] HMAC verification successful

# Неудачная верификация (измененный файл)
echo "tampered" >> message.txt
cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt \
  --verify expected.hmac
# [ERROR] HMAC verification failed
```

#### Использование HMAC в скриптах
```bash
#!/bin/bash
# Скрипт для безопасной передачи файлов

FILE="backup.tar.gz"
KEY="shared_secret_123"

# Отправитель создает HMAC
HMAC=$(cryptocore dgst --algorithm sha256 --hmac --key "$KEY" --input "$FILE")
echo "$HMAC" > "${FILE}.hmac"

# Получатель проверяет
cryptocore dgst --algorithm sha256 --hmac --key "$KEY" \
  --input "$FILE" --verify "${FILE}.hmac" && \
  echo "File integrity verified" || \
  echo "File integrity check failed"
```

## Выведение ключей

### PBKDF2: Выведение ключей из паролей

#### Базовое использование
```bash
# С указанием соли
cryptocore derive --password "MySecurePassword" \
  --salt a1b2c3d4e5f67890a1b2c3d4e5f67890 \
  --iterations 100000 \
  --length 32

# С автоматической генерацией соли
cryptocore derive --password "AnotherPassword" \
  --iterations 500000 \
  --length 16
# Сохраните вывод (ключ И соль)!
```

#### Сохранение ключа в файл
```bash
# Ключ сохраняется в бинарном формате
cryptocore derive --password "application_key" \
  --salt fixedappsalt123456 \
  --iterations 100000 \
  --length 32 \
  --output app.key.derived
```

#### Использование в конвейере
```bash
# Создание ключа и немедленное использование для шифрования
cryptocore derive --password "$(cat password.txt)" \
  --salt "$(cat salt.txt)" \
  --iterations 100000 \
  --length 32 | \
  cut -d' ' -f1 | \
  xargs -I {} cryptocore crypto --algorithm aes --mode cbc \
    --operation encrypt --key {} --input data.txt --output data.enc
```

#### Тестовые векторы RFC 6070
```bash
# Проверка корректности реализации
cryptocore derive --password "password" --salt 73616c74 \
  --iterations 1 --length 20
# Должно вывести: 0c60c80f961f0e71f3a9b524af6012062fe037a6 73616c74

cryptocore derive --password "password" --salt 73616c74 \
  --iterations 2 --length 20
# Должно вывести: ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957 73616c74
```

### Полный рабочий процесс с PBKDF2

#### Шаг 1: Создание ключа
```bash
# Генерация ключа с сохранением параметров
PASSWORD="MyDatabasePassword"
SALT=$(openssl rand -hex 16)
ITERATIONS=100000
KEY_LENGTH=32

# Сохраняем параметры в конфигурационный файл
cat > kdf_config.txt << EOF
password_env=DB_PASSWORD
salt=$SALT
iterations=$ITERATIONS
key_length=$KEY_LENGTH
EOF

# Выводим ключ
cryptocore derive --password "$PASSWORD" \
  --salt "$SALT" \
  --iterations "$ITERATIONS" \
  --length "$KEY_LENGTH" \
  --output database.key
```

#### Шаг 2: Шифрование данных
```bash
# Использование выведенного ключа
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$(xxd -p database.key | tr -d '\n')" \
  --input sensitive_data.csv \
  --output encrypted_data.gcm \
  --aad "$(echo -n 'table:transactions|date:2024-01-15' | xxd -p)"
```

#### Шаг 3: Дешифрование данных
```bash
# Воссоздание ключа при необходимости
cryptocore derive --password "$PASSWORD" \
  --salt "$SALT" \
  --iterations "$ITERATIONS" \
  --length "$KEY_LENGTH" \
  --output database.key.new

# Дешифрование
cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
  --key "$(xxd -p database.key.new | tr -d '\n')" \
  --input encrypted_data.gcm \
  --output decrypted_data.csv \
  --aad "$(echo -n 'table:transactions|date:2024-01-15' | xxd -p)"
```

### HKDF: Иерархическое выведение ключей

Хотя HKDF в основном используется через API, вот пример использования в коде:

```rust
// Пример использования HKDF в Rust коде
use cryptocore::kdf::derive_key;

let master_key = b"0123456789abcdef0123456789abcdef";

// Выведение ключей для разных целей
let encryption_key = derive_key(master_key, "database:users:encryption", 32)?;
let auth_key = derive_key(master_key, "api:authentication", 32)?;
let backup_key = derive_key(master_key, "backup:2024-01", 32)?;
```

## Устранение неполадок

### Распространенные ошибки и решения

#### Ошибка: "Key must be 32 hex characters"
**Причина:** Ключ не в hex-формате или неправильной длины.
**Решение:**
```bash
# Убедитесь, что ключ — 32 hex символа (16 байт)
# Правильно:
cryptocore crypto --key 00112233445566778899aabbccddeeff ...

# Неправильно:
cryptocore crypto --key "my password" ...  # Не hex
cryptocore crypto --key 001122...          # Слишком короткий
```

#### Ошибка: "IV is required for decryption in this mode"
**Причина:** Для дешифрования в режимах CBC/CFB/OFB/CTR требуется IV.
**Решение:**
```bash
# Способ 1: Не указывайте IV — он будет прочитан из файла
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.enc \
  --output file.dec

# Способ 2: Укажите правильный IV
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input file.enc \
  --output file.dec
```

#### Ошибка: "Input file does not exist"
**Причина:** Указан несуществующий файл.
**Решение:**
```bash
# Проверьте путь к файлу
ls -la input_file.txt
cryptocore crypto --input input_file.txt ...
```

#### Ошибка: "File too short to contain IV/nonce"
**Причина:** Файл поврежден или не является корректным зашифрованным файлом.
**Решение:**
```bash
# Проверьте размер файла
stat -c%s file.enc
# Для CBC/CFB/OFB/CTR: минимум 16 байт (IV) + хотя бы 1 байт данных
# Для GCM: минимум 12 байт (nonce) + 16 байт (tag) + хотя бы 1 байт данных
```

#### Ошибка: "Authentication failed: tag mismatch"
**Причина в GCM/ETM:**
1. Неверный ключ
2. Неверный AAD (Additional Authenticated Data)
3. Измененный шифротекст
4. Неверный nonce (GCM)

**Решение:**
```bash
# Убедитесь, что используете те же параметры, что и при шифровании:
# 1. Тот же ключ
# 2. Тот же AAD (если использовался)
# 3. Тот же nonce (если указывали явно)

# Для GCM с автоматической генерацией nonce:
# Nonce хранится в файле, убедитесь, что файл не поврежден
```

#### Ошибка: "WARNING: The provided key appears to be weak"
**Причина:** Используется ключ с паттерном (все нули, последовательности и т.д.)
**Решение:**
```bash
# Сгенерируйте безопасный ключ
openssl rand -hex 16
# Или позвольте CryptoCore сгенерировать ключ автоматически
cryptocore crypto ...  # без --key
```

#### Ошибка в PowerShell: "Cannot be loaded because running scripts is disabled"
**Решение:**
```powershell
# Временное разрешение для текущей сессии
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Или используйте прямой вызов
.\target\release\cryptocore.exe --help
```

#### Ошибка: "No plaintext output will be produced" (GCM/ETM)
**Причина:** Катастрофический отказ при аутентификации. Это функция безопасности.
**Решение:** Убедитесь в правильности всех параметров аутентификации.

### Проблемы с производительностью

#### Медленное выведение ключей PBKDF2
**Причина:** Большое количество итераций (это особенность безопасности).
**Решение:**
```bash
# Для тестирования используйте меньше итераций
cryptocore derive --password "test" --iterations 1000 ...

# Для продакшена выбирайте баланс безопасности/производительности
# Рекомендуется: 100,000-600,000 итераций
```

#### Большие файлы медленно обрабатываются
**Решение:** Используйте потоковые режимы (CTR, CFB, OFB, GCM):
```bash
# CTR обычно быстрее всего
cryptocore crypto --algorithm aes --mode ctr --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input large_file.iso \
  --output large_file.enc
```

### Проблемы совместимости

#### Несовпадение с OpenSSL
**Проверка совместимости:**
```bash
# 1. Шифрование CryptoCore -> Дешифрование OpenSSL
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.enc

# Извлечение IV и шифротекста
dd if=test.enc of=iv.bin bs=16 count=1
dd if=test.enc of=ciphertext.bin bs=16 skip=1

# Дешифрование OpenSSL
openssl enc -aes-128-cbc -d \
  -K 00112233445566778899aabbccddeeff \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext.bin -out openssl_decrypted.txt

# 2. Шифрование OpenSSL -> Дешифрование CryptoCore
openssl enc -aes-128-cbc \
  -K 00112233445566778899aabbccddeeff \
  -iv 000102030405060708090a0b0c0d0e0f \
  -in test.txt -out openssl_encrypted.bin

cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv 000102030405060708090a0b0c0d0e0f \
  --input openssl_encrypted.bin \
  --output cryptocore_decrypted.txt
```

### Отладка

#### Включение дополнительной информации
```bash
# Некоторые команды показывают дополнительную информацию
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt \
  --output test.enc \
  --aad test123
# Вывод включает сгенерированный nonce
```

#### Проверка корректности операций
```bash
# Простой тест "зашифровать-расшифровать"
echo "Test data" > test.txt
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.txt --output test.enc

cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input test.enc --output test.dec

diff test.txt test.dec && echo "SUCCESS" || echo "FAILURE"
```

## Рекомендации по безопасности

### Управление ключами

#### Генерация ключей
```bash
# Всегда используйте криптографически безопасную генерацию
# Способ 1: Автоматическая генерация CryptoCore
cryptocore crypto ...  # без --key

# Способ 2: OpenSSL
openssl rand -hex 16

# Способ 3: PBKDF2 с надежным паролем
cryptocore derive --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n1)" \
  --iterations 100000 \
  --length 32
```

#### Хранение ключей
- **Никогда не храните ключи в коде или репозитории**
- Используйте менеджеры паролей (Bitwarden, 1Password)
- Используйте переменные окружения в продакшене:
```bash
# Установка ключа как переменной окружения
export ENCRYPTION_KEY="00112233445566778899aabbccddeeff"

# Использование
cryptocore crypto --key "$ENCRYPTION_KEY" ...
```

- Для контейнеров используйте Docker secrets или Kubernetes secrets
- Регулярно ротируйте ключи (каждые 90 дней для критичных систем)

### Выбор режима шифрования

#### Рекомендации по выбору режима
| Сценарий использования | Рекомендуемый режим | Причина |
|------------------------|---------------------|---------|
| Файлы с текстом/документы | CBC или GCM | Надежная защита, аутентификация (GCM) |
| Бинарные файлы (изображения, видео) | CTR или GCM | Без padding, высокая производительность |
| Сетевые протоколы | GCM | Аутентификация + шифрование, стандарт для TLS |
| Устаревшие системы | CBC | Широкая совместимость |
| Базы данных, бэкапы | GCM с AAD | Аутентификация контекста |
| **Избегайте:** | **ECB** | Небезопасен для данных с паттернами |

#### Использование аутентифицированного шифрования
```bash
# Всегда используйте GCM или ETM для важных данных
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$(openssl rand -hex 16)" \
  --input sensitive_data.txt \
  --output protected.enc \
  --aad "$(echo -n 'purpose:medical_records|date:2024-01' | xxd -p)"
```

### Работа с паролями

#### Создание надежных паролей для PBKDF2
```bash
# Генерация надежного пароля
PASSWORD=$(openssl rand -base64 32)
echo "Generated password: $PASSWORD"

# Использование в PBKDF2
cryptocore derive --password "$PASSWORD" \
  --iterations 600000 \
  --length 32 \
  --output master.key
```

#### Безопасная передача паролей
- Используйте инструменты типа `sshpass` или `gpg` для передачи
- Никогда не передавайте пароли через аргументы командной строки (видны в `ps`)
- Используйте pipes или файлы:
```bash
# Безопасное чтение пароля
read -s -p "Enter password: " PASSWORD
echo
cryptocore derive --password "$PASSWORD" ...

# Или из файла с ограниченными правами
chmod 600 password.txt
cryptocore derive --password "$(cat password.txt)" ...
```

### Дополнительные меры безопасности

#### Уникальность IV/Nonce
- **Никогда не повторяйте IV/nonce с одним ключом**
- Для GCM: 12-байтный nonce рекомендуется для случайной генерации
- CryptoCore автоматически генерирует уникальные IV/nonce при шифровании

#### Защита AAD (Additional Authenticated Data)
```bash
# Используйте AAD для контекстуальной аутентификации
AAD_CONTEXT="user:$USER|host:$HOSTNAME|timestamp:$(date +%s)|file:$(basename $FILE)"
AAD_HEX=$(echo -n "$AAD_CONTEXT" | xxd -p)

cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$KEY" \
  --input "$FILE" \
  --output "${FILE}.enc" \
  --aad "$AAD_HEX"
```

#### Мониторинг и аудит
```bash
# Логирование использования (пример)
log_encryption() {
  local operation=$1
  local file=$2
  local user=$(whoami)
  local timestamp=$(date -Iseconds)
  
  echo "$timestamp | $user | $operation | $file | $(stat -c%s "$file") bytes" \
    >> /var/log/cryptocore_audit.log
}

# Использование
log_encryption "encrypt" "sensitive.pdf"
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$KEY" --input sensitive.pdf --output sensitive.pdf.enc
```

### Рекомендуемые настройки для различных случаев

#### Для персонального использования
```bash
# Средний уровень безопасности
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$(openssl rand -hex 16)" \
  --input personal_file.txt \
  --output personal_file.enc
```

#### Для корпоративного использования
```bash
# Высокий уровень безопасности
# 1. Генерация ключа через PBKDF2
cryptocore derive --password "$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n1)" \
  --iterations 600000 \
  --length 32 \
  --output master.key

# 2. Шифрование с полным контекстом
AAD="dept:finance|project:budget_2024|classification:confidential|owner:$USER"
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$(xxd -p master.key | tr -d '\n')" \
  --input financial_report.docx \
  --output financial_report.enc \
  --aad "$(echo -n "$AAD" | xxd -p)"
```

#### Для долгосрочного хранения (архивы)
```bash
# Максимальная безопасность + метаданные
# 1. Создание ключа с высокой энтропией
KEY=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | xxd -p)
echo "$KEY" > archive_key_$(date +%Y%m%d).txt
chmod 400 archive_key_*.txt

# 2. Шифрование с подробным AAD
METADATA="archive_id:$(uuidgen)|created:$(date -Iseconds)|\
retention:10y|description:Quarterly financial records"
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$KEY" \
  --input archive_2024_Q1.tar \
  --output archive_2024_Q1.tar.enc \
  --aad "$(echo -n "$METADATA" | xxd -p)"
```

## Шпаргалка

### Быстрые команды

#### Шифрование
```bash
# Быстрое шифрование файла
cryptocore crypto -a aes -m cbc -o encrypt -i file.txt -o file.enc

# Шифрование с автоматическим ключом (запомните вывод!)
cryptocore crypto -a aes -m gcm -o encrypt -i secret.txt

# Шифрование потока
cat data.txt | cryptocore crypto -a aes -m ctr -o encrypt -i - -o data.enc
```

#### Дешифрование
```bash
# Быстрое дешифрование
cryptocore crypto -a aes -m cbc -o decrypt -i file.enc -k KEY

# Дешифрование GCM
cryptocore crypto -a aes -m gcm -o decrypt -i file.gcm.enc -k KEY -a AAD
```

#### Хеширование
```bash
# SHA-256 файла
cryptocore dgst -a sha256 -i file.txt

# HMAC
cryptocore dgst -a sha256 --hmac -k KEY -i file.txt
```

#### Выведение ключей
```bash
# Простое выведение ключа
cryptocore derive -p "password" -i 100000 -l 32

# С сохранением
cryptocore derive -p "$(cat pass.txt)" -s $(cat salt.txt) -o key.bin
```

### Форматы данных

| Параметр | Формат | Пример | Примечания |
|----------|--------|--------|------------|
| Ключ | 32 hex символа | `00112233445566778899aabbccddeeff` | 16 байт |
| IV | 32 hex символа | `aabbccddeeff00112233445566778899` | 16 байт |
| Nonce (GCM) | 24 hex символа | `000000000000000000000000` | 12 байт |
| AAD | Любая hex строка | `aabbccddeeff001122334455` | Произвольной длины |
| Соль | Hex строка | `a1b2c3d4e5f67890a1b2c3d4e5f67890` | Рекомендуется 16+ байт |

### Полезные сочетания команд

#### Шифрование каталога
```bash
# Архивировать и зашифровать каталог
tar czf - directory/ | cryptocore crypto -a aes -m ctr -o encrypt -i - -o backup.tar.enc -k KEY
```

#### Проверка и расшифровка
```bash
# Проверить HMAC и расшифровать
cryptocore dgst -a sha256 --hmac -k KEY -i data.enc -v expected.hmac && \
cryptocore crypto -a aes -m cbc -o decrypt -i data.enc -k KEY -o data.dec
```

#### Ротация ключей
```bash
# Перешифрование с новым ключом
cryptocore crypto -a aes -m cbc -o decrypt -i old.enc -k OLD_KEY -o temp.txt
cryptocore crypto -a aes -m gcm -o encrypt -i temp.txt -k NEW_KEY -o new.enc
rm temp.txt
```

### Сценарии использования одним командой

#### 1. Безопасная передача файла
```bash
# Отправитель
KEY=$(openssl rand -hex 16)
cryptocore crypto -a aes -m gcm -o encrypt -i file.txt -k $KEY -o file.enc
echo "Key: $KEY" | gpg --encrypt --recipient recipient@example.com > key.gpg

# Получатель
KEY=$(gpg --decrypt key.gpg)
cryptocore crypto -a aes -m gcm -o decrypt -i file.enc -k $KEY -o file.txt
```

#### 2. Ежедневное резервное копирование
```bash
#!/bin/bash
# backup_encrypt.sh
KEY="$(cat /etc/backup_key)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
AAD="backup:${TIMESTAMP}:$(hostname)"

tar czf - /important/data | \
cryptocore crypto -a aes -m gcm -o encrypt -i - -k "$KEY" \
  -a "$(echo -n "$AAD" | xxd -p)" \
  -o /backup/backup_${TIMESTAMP}.tar.enc
```

#### 3. Проверка целостности системы
```bash
#!/bin/bash
# integrity_check.sh
KEY="$(cat /etc/integrity_key)"

# Создание HMAC для всех важных файлов
for file in /etc/passwd /etc/shadow /etc/nginx/nginx.conf; do
  if [ -f "$file" ]; then
    cryptocore dgst -a sha256 --hmac -k "$KEY" -i "$file" \
      > "${file}.hmac"
  fi
done

# Проверка (запускать регулярно)
for file in /etc/passwd /etc/shadow /etc/nginx/nginx.conf; do
  if [ -f "$file" ] && [ -f "${file}.hmac" ]; then
    cryptocore dgst -a sha256 --hmac -k "$KEY" \
      -i "$file" -v "${file}.hmac" || \
      echo "ALERT: $file modified!"
  fi
done
```

## Сравнение с OpenSSL/GPG

### CryptoCore vs OpenSSL

| Возможность | CryptoCore | OpenSSL | Примечания |
|-------------|------------|---------|------------|
| **Простота использования** | Выше | Ниже | CryptoCore имеет более понятный CLI |
| **Режимы шифрования** | 7 режимов AES | Все режимы | CryptoCore фокусируется на AES-128 |
| **Аутентифицированное шифрование** | GCM, ETM | GCM, CCM | Обе поддерживают GCM |
| **Формат файлов** | Стандартизирован | Вариативный | CryptoCore всегда включает IV/nonce |
| **Автоматическая генерация** | Ключей, IV, nonce | Требует флагов | CryptoCore генерирует автоматически |
| **Хеш-функции** | SHA-256, SHA3-256 | Все алгоритмы | CryptoCore имеет ограниченный набор |
| **HMAC** | HMAC-SHA256 | Любой алгоритм | CryptoCore только SHA-256 |
| **Выведение ключей** | PBKDF2, HKDF | PBKDF2, scrypt | CryptoCore имеет HKDF для иерархии ключей |
| **Интероперабельность** | Высокая | Эталон | Полная совместимость с OpenSSL форматами |

#### Примеры эквивалентных команд

##### Шифрование CBC
```bash
# CryptoCore
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.txt --output file.enc

# OpenSSL
openssl enc -aes-128-cbc \
  -K 00112233445566778899aabbccddeeff \
  -iv $(openssl rand -hex 16) \
  -in file.txt -out file.enc
```

##### Дешифрование CBC
```bash
# CryptoCore (автоматическое чтение IV)
cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.enc --output file.dec

# OpenSSL (требует отдельного указания IV)
openssl enc -aes-128-cbc -d \
  -K 00112233445566778899aabbccddeeff \
  -iv $(dd if=file.enc bs=16 count=1 2>/dev/null | xxd -p) \
  -in <(dd if=file.enc bs=16 skip=1 2>/dev/null) \
  -out file.dec
```

##### GCM шифрование
```bash
# CryptoCore
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.txt --output file.gcm \
  --aad aabbccddeeff

# OpenSSL
openssl enc -aes-128-gcm \
  -K 00112233445566778899aabbccddeeff \
  -iv $(openssl rand -hex 12) \
  -aad aabbccddeeff \
  -in file.txt -out file.gcm
```

### CryptoCore vs GPG

| Возможность | CryptoCore | GPG | Примечания |
|-------------|------------|-----|------------|
| **Тип** | Утилита шифрования | Полный PGP пакет | Разные цели использования |
| **Ключевая модель** | Симметричная | Асимметричная/симметричная | CryptoCore только симметричная |
| **Управление ключами** | Простое | Комплексное (ключи, сертификаты) | CryptoCore проще для новичков |
| **Цифровые подписи** | Нет | Да | GPG включает подписи |
| **Шифрование файлов** | Да | Да | Обе утилиты поддерживают |
| **Интеграция с почтой** | Нет | Да | GPG для email, CryptoCore для файлов |
| **Шифрование для нескольких получателей** | Нет | Да | GPG поддерживает |
| **Простота автоматизации** | Выше | Ниже | CryptoCore проще в скриптах |

#### Когда использовать CryptoCore вместо GPG

1. **Автоматизация скриптов** - более простой и предсказуемый интерфейс
2. **Шифрование больших файлов** - оптимизированная работа с потоками
3. **Встроенные приложения** - легче интегрировать как библиотеку
4. **Обучение криптографии** - понятная структура команд
5. **Интероперабельность** - простой обмен с другими системами

#### Когда использовать GPG вместо CryptoCore

1. **Шифрование email** - встроенная поддержка в почтовые клиенты
2. **Цифровые подписи** - требуется аутентификация отправителя
3. **Работа с людьми** - веб траст, ключевые серверы
4. **Стандартная совместимость** - требуется OpenPGP совместимость
5. **Шифрование для нескольких получателей** - один файл, много ключей

### Преимущества CryptoCore

1. **Единообразный интерфейс** - все команды следуют одной логике
2. **Автоматизация** - минимум required флагов, максимум defaults
3. **Безопасность по умолчанию** - всегда используются безопасные настройки
4. **Подробные сообщения об ошибках** - понятные даже новичкам
5. **Интероперабельность** - можно обмениваться файлами с OpenSSL пользователями
6. **Современные алгоритмы** - GCM, SHA3, PBKDF2 с большим числом итераций
7. **Катастрофический отказ** - защита от атак на аутентификацию

### Миграция с OpenSSL/GPG

#### Конвертация OpenSSL -> CryptoCore
```bash
# Если у вас есть OpenSSL-зашифрованный файл
# 1. Узнайте параметры (ключ, IV, режим)
# 2. Дешифруйте OpenSSL
openssl enc -aes-128-cbc -d \
  -K KEY -iv IV \
  -in openssl_encrypted.bin \
  -out temp_plain.txt

# 3. Зашифруйте CryptoCore
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key KEY \
  --input temp_plain.txt \
  --output cryptocore_encrypted.bin
```

#### Конвертация GPG -> CryptoCore
```bash
# 1. Дешифруйте GPG
gpg --decrypt --output temp_plain.txt encrypted_file.gpg

# 2. Зашифруйте CryptoCore
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$(openssl rand -hex 16)" \
  --input temp_plain.txt \
  --output new_encrypted.bin

# 3. Безопасно удалите временные файлы
shred -u temp_plain.txt
```

### Совместное использование

#### Создание файлов, совместимых с OpenSSL
```bash
# CryptoCore создает файлы, которые можно прочитать OpenSSL
cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input file.txt --output file.enc

# OpenSSL может прочитать (с извлечением IV)
dd if=file.enc of=iv.bin bs=16 count=1
dd if=file.enc of=ciphertext.bin bs=16 skip=1
openssl enc -aes-128-cbc -d \
  -K 00112233445566778899aabbccddeeff \
  -iv $(xxd -p iv.bin | tr -d '\n') \
  -in ciphertext.bin -out file_decr.txt
```

#### Использование в существующих системах
```bash
# Интеграция CryptoCore в pipeline с OpenSSL
# 1. Генерация ключа через PBKDF2
cryptocore derive --password "$PASSWORD" \
  --iterations 100000 --length 32 --output key.bin

# 2. Шифрование данных
cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
  --key "$(xxd -p key.bin | tr -d '\n')" \
  --input sensitive_data.csv \
  --output encrypted.gcm
```

Это руководство покрывает все основные аспекты использования CryptoCore CLI. Для дополнительной информации обратитесь к встроенной справке (`cryptocore --help`) или документации API.