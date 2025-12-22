# CryptoCore API Documentation

## Общая информация
**Версия:** 0.8.0  
**Описание:** Криптографическая библиотека для шифрования, хеширования и управления ключами с поддержкой AES-128 и AEAD.  
**Совместимость:** Rust 2021 edition или новее. Зависит от OpenSSL для базовых криптографических операций.

## Структура модулей

```
cryptocore::                # Корневой модуль
├── crypto::               # Криптографические операции
│   ├── aead              # Authenticated Encryption with Associated Data
│   └── modes             # Режимы блочного шифрования
│       ├── cbc           # Cipher Block Chaining
│       ├── cfb           # Cipher Feedback
│       ├── ctr           # Counter
│       ├── ecb           # Electronic Codebook
│       ├── ofb           # Output Feedback
│       └── gcm           # Galois/Counter Mode
├── csprng::               # Криптографически безопасный ГПСЧ
├── hash::                 # Хеш-функции
│   ├── sha256            # SHA-256
│   └── sha3_256          # SHA3-256
├── mac::                  # Message Authentication Codes
│   └── hmac              # HMAC-SHA256
└── kdf::                  # Key Derivation Functions
    ├── pbkdf2            # PBKDF2-HMAC-SHA256
    └── hkdf              # HKDF для иерархии ключей
```

## Диаграмма зависимостей

```
    A[cryptocore::crypto] --> B[cryptocore::modes]
    A --> C[cryptocore::aead]
    C --> D[cryptocore::mac::hmac]
    C --> B
    D --> E[cryptocore::hash]
    F[cryptocore::kdf] --> D
    G[cryptocore::cli] --> A
    G --> F
    G --> H[cryptocore::csprng]
    
    B --> I[openssl::symm]
    H --> J[openssl::rand]
    E --> K[sha3::Digest]
```

## Модуль cryptocore (корневой)

### Константы

```rust
pub const BLOCK_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;
pub const KEY_SIZE: usize = 16;
```

**Назначение:** Основные размеры блоков, используемые во всей библиотеке.

### Функции

#### `hex_to_key`

```rust
pub fn hex_to_key(hex_str: &str) -> Result<[u8; KEY_SIZE], anyhow::Error>
```

**Назначение:** Преобразует шестнадцатеричную строку в ключ фиксированного размера.

**Параметры:**
- `hex_str`: &str - Шестнадцатеричная строка (может начинаться с '@')

**Возвращаемое значение:**
- `Ok([u8; KEY_SIZE])` - Ключ фиксированного размера
- `Err(anyhow::Error)` - Ошибка при неверной длине или некорректных символах

**Возможные ошибки:**
- `anyhow::Error` - Если длина строки не равна 32 символам или содержатся некорректные шестнадцатеричные символы

**Пример использования:**
```rust
use cryptocore::hex_to_key;

let key = hex_to_key("00112233445566778899aabbccddeeff")?;
let key_with_prefix = hex_to_key("@00112233445566778899aabbccddeeff")?;
```

#### `key_to_hex`

```rust
pub fn key_to_hex(key: &[u8; KEY_SIZE]) -> String
```

**Назначение:** Преобразует ключ в шестнадцатеричную строку.

**Параметры:**
- `key`: &[u8; KEY_SIZE] - Ключ для преобразования

**Возвращаемое значение:**
- `String` - Шестнадцатеричное представление ключа

**Пример использования:**
```rust
use cryptocore::key_to_hex;

let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
let hex = key_to_hex(&key);
assert_eq!(hex, "00112233445566778899aabbccddeeff");
```

## Модуль cryptocore::csprng

### Структура `Csprng`

```rust
pub struct Csprng;
```

**Назначение:** Предоставляет криптографически безопасные функции генерации случайных данных.

**Константы модуля:**
- `KEY_SIZE: usize = 16`
- `IV_SIZE: usize = 16`
- `SALT_SIZE: usize = 16`

### Методы

#### `generate_key`

```rust
pub fn generate_key() -> Result<[u8; KEY_SIZE]>
```

**Назначение:** Генерирует криптографически безопасный ключ AES-128.

**Возвращаемое значение:**
- `Ok([u8; KEY_SIZE])` - Сгенерированный ключ
- `Err(anyhow::Error)` - Ошибка генерации случайных чисел

**Безопасность:** Использует OpenSSL RAND_bytes, который является криптографически безопасным.

**Пример использования:**
```rust
use cryptocore::csprng::Csprng;

let key = Csprng::generate_key()?;
```

#### `generate_iv`

```rust
pub fn generate_iv() -> Result<[u8; IV_SIZE]>
```

**Назначение:** Генерирует случайный вектор инициализации (IV).

**Возвращаемое значение:**
- `Ok([u8; IV_SIZE])` - Сгенерированный IV
- `Err(anyhow::Error)` - Ошибка генерации случайных чисел

**Рекомендации по безопасности:**
- IV должен быть уникальным для каждого шифрования с одним ключом
- Не используйте один и тот же IV с одним ключом

**Пример использования:**
```rust
use cryptocore::csprng::Csprng;

let iv = Csprng::generate_iv()?;
```

#### `generate_salt`

```rust
pub fn generate_salt() -> Result<[u8; SALT_SIZE]>
```

**Назначение:** Генерирует случайную соль для KDF.

**Возвращаемое значение:**
- `Ok([u8; SALT_SIZE])` - Сгенерированная соль
- `Err(anyhow::Error)` - Ошибка генерации случайных чисел

**Рекомендации по безопасности:**
- Соль должна быть уникальной для каждого пользователя/пароля
- Храните соль вместе с производным ключом

**Пример использования:**
```rust
use cryptocore::csprng::Csprng;

let salt = Csprng::generate_salt()?;
```

#### `generate_random_bytes`

```rust
pub fn generate_random_bytes(size: usize) -> Result<Vec<u8>>
```

**Назначение:** Генерирует криптографически безопасные случайные байты произвольной длины.

**Параметры:**
- `size`: usize - Количество байт для генерации

**Возвращаемое значение:**
- `Ok(Vec<u8>)` - Вектор случайных байтов
- `Err(anyhow::Error)` - Ошибка генерации случайных чисел

**Пример использования:**
```rust
use cryptocore::csprng::Csprng;

let random_data = Csprng::generate_random_bytes(100)?;
```

#### `test_randomness`

```rust
pub fn test_randomness() -> Result<()>
```

**Назначение:** Тестирует уникальность сгенерированных ключей, IV и солей.

**Возвращаемое значение:**
- `Ok(())` - Все 1000 наборов уникальны
- `Err(anyhow::Error)` - Обнаружены дубликаты

**Пример использования:**
```rust
use cryptocore::csprng::Csprng;

Csprng::test_randomness()?;
```

## Модуль cryptocore::crypto::modes

### Трейт `BlockMode`

```rust
pub trait BlockMode {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
}
```

**Назначение:** Базовый трейт для всех режимов блочного шифрования.

### Трейт `FromKeyBytes`

```rust
pub trait FromKeyBytes {
    fn from_key_bytes(key: &[u8; 16]) -> Result<Self> where Self: Sized;
}
```

**Назначение:** Создание режима шифрования из массива байтов ключа.

### Структуры режимов

Все структуры реализуют трейты `BlockMode` и `FromKeyBytes`.

#### `Cbc`

```rust
pub struct Cbc {
    key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация режима Cipher Block Chaining (CBC).

**Методы конструктора:**
- `new(key_hex: &str) -> Result<Self>` - Создает из шестнадцатеричной строки
- `new_from_bytes(key: &[u8; BLOCK_SIZE]) -> Result<Self>` - Создает из массива байтов
- `new_from_key_bytes(key_bytes: &[u8]) -> Result<Self>` - Создает из среза байтов

**Безопасность:**
- Использует PKCS#7 padding
- Требует уникального IV для каждого шифрования

**Пример использования:**
```rust
use cryptocore::crypto::modes::Cbc;

let cbc = Cbc::new("00112233445566778899aabbccddeeff")?;
let ciphertext = cbc.encrypt(plaintext, iv)?;
let decrypted = cbc.decrypt(&ciphertext, iv)?;
```

#### `Cfb`

```rust
pub struct Cfb {
    key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация режима Cipher Feedback (CFB).

**Особенности:**
- Не требует дополнения (padding)
- Может работать с данными произвольной длины
- Самосинхронизирующийся потоковый шифр

**Пример использования:**
```rust
use cryptocore::crypto::modes::Cfb;

let cfb = Cfb::new("00112233445566778899aabbccddeeff")?;
let ciphertext = cfb.encrypt(plaintext, iv)?;
let decrypted = cfb.decrypt(&ciphertext, iv)?;
```

#### `Ctr`

```rust
pub struct Ctr {
    key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация режима Counter (CTR).

**Особенности:**
- Превращает блочный шифр в потоковый
- Не требует дополнения
- Поддерживает параллельную обработку

**Пример использования:**
```rust
use cryptocore::crypto::modes::Ctr;

let ctr = Ctr::new("00112233445566778899aabbccddeeff")?;
let ciphertext = ctr.encrypt(plaintext, iv)?;
let decrypted = ctr.decrypt(&ciphertext, iv)?;
```

#### `Ecb`

```rust
pub struct Ecb {
    key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация режима Electronic Codebook (ECB).

**Внимание по безопасности:**
- **Не рекомендуется для использования** с повторяющимися данными
- Не скрывает паттерны в данных
- Используется только в образовательных целях

**Пример использования:**
```rust
use cryptocore::crypto::modes::Ecb;

let ecb = Ecb::new("00112233445566778899aabbccddeeff")?;
let ciphertext = ecb.encrypt(plaintext, &[])?;
let decrypted = ecb.decrypt(&ciphertext, &[])?;
```

#### `Ofb`

```rust
pub struct Ofb {
    key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация режима Output Feedback (OFB).

**Особенности:**
- Превращает блочный шифр в потоковый
- Синхронный потоковый шифр
- Нет распространения ошибок

**Пример использования:**
```rust
use cryptocore::crypto::modes::Ofb;

let ofb = Ofb::new("00112233445566778899aabbccddeeff")?;
let ciphertext = ofb.encrypt(plaintext, iv)?;
let decrypted = ofb.decrypt(&ciphertext, iv)?;
```

#### `Gcm`

```rust
pub struct Gcm {
    key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация режима Galois/Counter Mode (GCM).

**Особенности:**
- Аутентифицированное шифрование
- Поддерживает дополнительные аутентифицированные данные (AAD)
- Высокая производительность

**Константы:**
- `TAG_SIZE: usize = 16`
- `NONCE_SIZE: usize = 12`

**Методы:**
- `encrypt_with_aad(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>>`
- `decrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>>`
- `generate_nonce() -> [u8; NONCE_SIZE]`

**Пример использования:**
```rust
use cryptocore::crypto::modes::Gcm;

let gcm = Gcm::new("00112233445566778899aabbccddeeff")?;
let nonce = Gcm::generate_nonce();
let ciphertext = gcm.encrypt_with_aad(plaintext, &nonce, aad)?;
let decrypted = gcm.decrypt_with_aad(&ciphertext, aad)?;
```

## Модуль cryptocore::crypto::aead

### Структура `EncryptThenMac`

```rust
pub struct EncryptThenMac {
    encryption_key: [u8; BLOCK_SIZE],
    mac_key: [u8; BLOCK_SIZE],
}
```

**Назначение:** Реализация паттерна Encrypt-then-MAC для аутентифицированного шифрования.

**Принцип работы:**
1. Из общего ключа выводятся два отдельных ключа: для шифрования и для MAC
2. Данные шифруются
3. На зашифрованные данные вычисляется MAC
4. При проверке сначала проверяется MAC, затем расшифровываются данные

### Методы

#### `new`

```rust
pub fn new(key_hex: &str) -> Result<Self>
```

**Назначение:** Создает AEAD-объект из шестнадцатеричного ключа.

**Параметры:**
- `key_hex`: &str - Мастер-ключ в шестнадцатеричном формате

**Возвращаемое значение:**
- `Ok(Self)` - Успешно созданный AEAD-объект
- `Err(anyhow::Error)` - Неверный формат ключа

**Пример использования:**
```rust
use cryptocore::crypto::aead::EncryptThenMac;

let aead = EncryptThenMac::new("00112233445566778899aabbccddeeff")?;
```

#### `encrypt`

```rust
pub fn encrypt<M: BlockMode + FromKeyBytes>(
    &self,
    plaintext: &[u8],
    iv: &[u8],
    aad: &[u8]
) -> Result<Vec<u8>>
```

**Назначение:** Шифрует данные с использованием указанного режима.

**Параметры:**
- `plaintext`: &[u8] - Открытый текст для шифрования
- `iv`: &[u8] - Вектор инициализации
- `aad`: &[u8] - Дополнительные аутентифицированные данные

**Возвращаемое значение:**
- `Ok(Vec<u8>)` - Зашифрованные данные в формате: IV || ciphertext || MAC
- `Err(anyhow::Error)` - Ошибка шифрования

**Пример использования:**
```rust
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::modes::Cbc;

let ciphertext = aead.encrypt::<Cbc>(plaintext, iv, aad)?;
```

#### `decrypt`

```rust
pub fn decrypt<M: BlockMode + FromKeyBytes>(
    &self,
    data: &[u8],
    aad: &[u8]
) -> Result<Vec<u8>>
```

**Назначение:** Расшифровывает и проверяет аутентичность данных.

**Параметры:**
- `data`: &[u8] - Данные в формате: IV || ciphertext || MAC
- `aad`: &[u8] - Дополнительные аутентифицированные данные

**Возвращаемое значение:**
- `Ok(Vec<u8>)` - Расшифрованный текст
- `Err(anyhow::Error)` - Ошибка аутентификации или расшифрования

**Пример использования:**
```rust
use cryptocore::crypto::aead::EncryptThenMac;
use cryptocore::crypto::modes::Cbc;

let plaintext = aead.decrypt::<Cbc>(&ciphertext, aad)?;
```

## Модуль cryptocore::hash

### Перечисление `HashType`

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    Sha256,
    Sha3_256,
}
```

**Назначение:** Определяет тип хеш-функции.

**Методы:**
- `from_str(s: &str) -> Option<Self>` - Создает из строки
- `create_hasher(&self) -> Box<dyn HashAlgorithm>` - Создает соответствующий хешер

### Трейт `HashAlgorithm`

```rust
pub trait HashAlgorithm {
    fn hash_file(&self, file_path: &Path) -> Result<String>;
    fn hash_data(&self, data: &[u8]) -> Result<String>;
}
```

**Назначение:** Базовый трейт для всех хеш-алгоритмов.

### Структура `Sha256`

```rust
pub struct Sha256;
```

**Назначение:** Реализация SHA-256 с нуля.

**Методы:**
- `new() -> Self` - Создает новый экземпляр
- Реализует `HashAlgorithm`

**Пример использования:**
```rust
use cryptocore::hash::Sha256;

let sha256 = Sha256::new();
let hash = sha256.hash_data(b"Hello, world!")?;
println!("SHA-256 hash: {}", hash);
```

### Структура `Sha3_256`

```rust
pub struct Sha3_256;
```

**Назначение:** Реализация SHA3-256 через библиотеку sha3.

**Методы:**
- `new() -> Self` - Создает новый экземпляр
- Реализует `HashAlgorithm`

**Пример использования:**
```rust
use cryptocore::hash::Sha3_256;

let sha3_256 = Sha3_256::new();
let hash = sha3_256.hash_data(b"Hello, world!")?;
println!("SHA3-256 hash: {}", hash);
```

## Модуль cryptocore::mac

### Структура `HMAC`

```rust
pub struct HMAC {
    key: Vec<u8>,
    hash_function: HashType,
    block_size: usize,
}
```

**Назначение:** Реализация HMAC (Hash-based Message Authentication Code) согласно RFC 2104.

### Методы

#### `new`

```rust
pub fn new(key: &[u8], hash_function: HashType) -> Self
```

**Назначение:** Создает HMAC с указанным ключом и хеш-функцией.

**Параметры:**
- `key`: &[u8] - Секретный ключ
- `hash_function`: `HashType` - Тип хеш-функции (только Sha256 поддерживается)

**Пример использования:**
```rust
use cryptocore::mac::hmac::HMAC;
use cryptocore::hash::HashType;

let key = b"secret_key";
let hmac = HMAC::new(key, HashType::Sha256);
```

#### `compute`

```rust
pub fn compute(&self, message: &[u8]) -> Result<String>
```

**Назначение:** Вычисляет HMAC для сообщения.

**Параметры:**
- `message`: &[u8] - Сообщение для аутентификации

**Возвращаемое значение:**
- `Ok(String)` - HMAC в шестнадцатеричном формате
- `Err(anyhow::Error)` - Ошибка вычисления

**Пример использования:**
```rust
use cryptocore::mac::hmac::HMAC;
use cryptocore::hash::HashType;

let hmac = HMAC::new(b"key", HashType::Sha256);
let mac = hmac.compute(b"message")?;
```

#### `compute_bytes`

```rust
pub fn compute_bytes(&self, message: &[u8]) -> Result<Vec<u8>>
```

**Назначение:** Вычисляет HMAC и возвращает сырые байты.

**Параметры:**
- `message`: &[u8] - Сообщение для аутентификации

**Возвращаемое значение:**
- `Ok(Vec<u8>)` - HMAC в виде байтов
- `Err(anyhow::Error)` - Ошибка вычисления

#### `compute_file`

```rust
pub fn compute_file(&self, file_path: &Path) -> Result<String>
```

**Назначение:** Вычисляет HMAC для содержимого файла.

**Параметры:**
- `file_path`: &Path - Путь к файлу

**Возвращаемое значение:**
- `Ok(String)` - HMAC в шестнадцатеричном формате
- `Err(anyhow::Error)` - Ошибка чтения файла или вычисления

## Модуль cryptocore::kdf

### Функция `pbkdf2_hmac_sha256`

```rust
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dklen: usize
) -> Result<Vec<u8>>
```

**Назначение:** Реализация PBKDF2 с HMAC-SHA256.

**Параметры:**
- `password`: &[u8] - Пароль для усиления
- `salt`: &[u8] - Соль
- `iterations`: u32 - Количество итераций
- `dklen`: usize - Длина производного ключа

**Возвращаемое значение:**
- `Ok(Vec<u8>)` - Производный ключ
- `Err(anyhow::Error)` - Ошибка параметров или вычисления

**Рекомендации по безопасности:**
- Используйте не менее 100,000 итераций
- Используйте уникальную соль для каждого пароля
- Храните соль вместе с производным ключом

**Пример использования:**
```rust
use cryptocore::kdf::pbkdf2_hmac_sha256;

let password = b"my_password";
let salt = b"unique_salt";
let iterations = 100_000;
let dklen = 32;

let derived_key = pbkdf2_hmac_sha256(password, salt, iterations, dklen)?;
```

## Зависимости между модулями

1. **cryptocore::aead** зависит от:
    - `cryptocore::modes` для шифрования
    - `cryptocore::mac` для аутентификации
    - `cryptocore::hash` для хеширования

2. **cryptocore::kdf** зависит от:
    - `cryptocore::mac` для HMAC
    - `cryptocore::hash` для хеш-функций

3. **cryptocore::mac** зависит от:
    - `cryptocore::hash` для базовых хеш-функций

4. **Все криптографические операции** используют:
    - `cryptocore::csprng` для генерации случайных значений
    - OpenSSL для низкоуровневых операций

## Рекомендации по безопасности

### Ключевые моменты:

1. **Используйте AEAD режимы** (GCM или EncryptThenMac) для шифрования с аутентификацией
2. **Никогда не используйте ECB** для реальных приложений
3. **Всегда используйте уникальные IV/nonce** с одним ключом
4. **Проверяйте MAC перед расшифрованием** для предотвращения атак на заполнение
5. **Используйте KDF** для усиления паролей
6. **Генерируйте ключи с помощью Csprng**

### Минимальные параметры безопасности:

- Ключ AES: 128 бит (16 байт)
- IV: 128 бит (16 байт)
- Соль для PBKDF2: 128 бит (16 байт)
- Количество итераций PBKDF2: ≥ 100,000
- MAC размер: ≥ 256 бит

## Примеры использования

### Полный пример: Шифрование файла с AEAD

```rust
use cryptocore::{
    csprng::Csprng,
    crypto::aead::EncryptThenMac,
    crypto::modes::Gcm,
};

fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key_hex: &str
) -> Result<(), anyhow::Error> {
    // Создаем AEAD объект
    let aead = EncryptThenMac::new(key_hex)?;
    
    // Читаем файл
    let plaintext = std::fs::read(input_path)?;
    
    // Генерируем IV
    let iv = Csprng::generate_iv()?;
    
    // Шифруем с дополнительными данными
    let aad = b"file_metadata";
    let ciphertext = aead.encrypt::<Gcm>(&plaintext, &iv, aad)?;
    
    // Сохраняем зашифрованный файл
    std::fs::write(output_path, ciphertext)?;
    
    Ok(())
}
```

### Пример: Проверка целостности файла с HMAC

```rust
use cryptocore::{
    mac::hmac::HMAC,
    hash::HashType,
};

fn verify_file_integrity(
    file_path: &str,
    key: &[u8],
    expected_mac: &str
) -> Result<bool, anyhow::Error> {
    let hmac = HMAC::new(key, HashType::Sha256);
    let actual_mac = hmac.compute_file(file_path.as_ref())?;
    
    Ok(actual_mac == expected_mac)
}
```

## Совместимость

Библиотека совместима с:
- Rust 2021 edition или новее
- OpenSSL 1.1.1 или новее
- Windows, Linux, macOS

Для проверки совместимости с OpenSSL используйте тесты в `tests/test_openssl_compatibility.rs`.