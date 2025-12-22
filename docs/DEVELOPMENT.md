# Руководство разработчика CryptoCore

## Архитектура

### Обзор архитектуры
CryptoCore построен по модульной архитектуре с четким разделением ответственности:

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
├─────────────────────────────────────────────────────────────┤
│                     Command Parser                          │
├─────────────────────────────────────────────────────────────┤
│  Crypto Module    Hash Module    MAC Module    KDF Module   │
│  ┌──────────┐    ┌──────────┐   ┌─────────┐   ┌─────────┐   │
│  │ AES Modes│    │SHA-256   │   │ HMAC    │   │ PBKDF2  │   │
│  │ GCM      │    │SHA3-256  │   │         │   │ HKDF    │   │
│  │ ETM      │    └──────────┘   └─────────┘   └─────────┘   │
│  └──────────┘                                               │
├─────────────────────────────────────────────────────────────┤
│                 File I/O & CSPRNG                           │
├─────────────────────────────────────────────────────────────┤
│                OpenSSL Bindings                             │
└─────────────────────────────────────────────────────────────┘
```

### Ключевые компоненты

#### 1. Основные модули
- **`src/main.rs`** - Точка входа CLI
- **`src/lib.rs`** - Публичное API библиотеки
- **`src/cli/`** - Парсинг аргументов командной строки
- **`src/crypto/`** - Реализация криптографических алгоритмов
- **`src/hash/`** - Хеш-функции (SHA-256, SHA3-256)
- **`src/mac/`** - HMAC реализация
- **`src/kdf/`** - Функции выведения ключей (PBKDF2, HKDF)
- **`src/file/`** - Операции ввода-вывода файлов
- **`src/csprng/`** - Криптографически безопасный ГПСЧ

#### 2. Режимы шифрования в `src/crypto/modes/`
```
modes/
├── mod.rs           # Реестр и фабрика режимов
├── ecb.rs           # Electronic Codebook
├── cbc.rs           # Cipher Block Chaining
├── cfb.rs           # Cipher Feedback
├── ofb.rs           # Output Feedback
├── ctr.rs           # Counter Mode
├── gcm.rs           # Galois/Counter Mode
└── aead.rs          # Encrypt-then-MAC
```

#### 3. Тесты
```
tests/
├── integration_tests.rs          # Интеграционные тесты
├── test_csprng.rs               # Тесты CSPRNG
├── test_hash.rs                 # Тесты хеш-функций
├── test_hmac_vectors.rs         # Тесты HMAC (RFC 4231)
├── test_gcm_comprehensive.rs    # Тесты GCM
├── test_aead.rs                 # Тесты AEAD
├── test_openssl_compatibility.rs # Тесты совместимости
├── test_gcm_large_data.rs       # Тесты больших данных
├── test_gcm_nonce_uniqueness.rs # Тесты уникальности nonce
└── test_kdf.rs                  # Тесты KDF
```

### Потоки данных

#### Шифрование файла
```rust
// 1. Парсинг аргументов CLI
let args = Cli::parse();

// 2. Загрузка данных
let data = file::read_input(&args.input)?;

// 3. Выбор и инициализация режима
let mode = crypto::create_mode(args.mode, args.base_mode)?;

// 4. Выполнение операции
let result = match args.operation {
    Operation::Encrypt => mode.encrypt(&data, &key, iv, aad)?,
    Operation::Decrypt => mode.decrypt(&data, &key, iv, aad)?,
};

// 5. Сохранение результата
file::write_output(&args.output, &result)?;
```

#### Вычисление HMAC
```rust
// 1. Загрузка данных
let data = file::read_input(&input)?;

// 2. Создание HMAC-ключа
let key = mac::prepare_hmac_key(raw_key)?;

// 3. Вычисление HMAC
let hmac = mac::hmac_sha256(&key, &data)?;

// 4. Верификация или вывод
if let Some(expected) = verify_file {
    mac::verify_hmac(&hmac, &expected)?
} else {
    print_result(&hmac, &input)
}
```

## Сборка проекта

### Требования к окружению

#### Обязательные зависимости
```bash
# Rust и Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update

# Для Linux/macOS
sudo apt-get install pkg-config libssl-dev  # Debian/Ubuntu
brew install openssl pkg-config             # macOS

# Для Windows
# Установите Visual Studio Build Tools
# или используйте MSYS2: pacman -S mingw-w64-x86_64-openssl
```

#### Проверка установки
```bash
rustc --version      # ≥ 1.70.0
cargo --version      # ≥ 1.70.0
openssl version      # ≥ 1.1.1
```

### Сборка из исходного кода

#### Отладочная сборка
```bash
# Быстрая сборка для разработки
cargo build

# Или с выводом подробной информации
cargo build --verbose

# Расположение бинарного файла
# Linux/macOS: target/debug/cryptocore
# Windows: target\debug\cryptocore.exe
```

#### Релизная сборка
```bash
# Оптимизированная сборка
cargo build --release

# С дополнительными оптимизациями
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Расположение: target/release/cryptocore
```

#### Сборка с различными флагами
```bash
# Сборка с включенными всех фич
cargo build --release --all-features

# Сборка только библиотеки
cargo build --lib

# Сборка для проверки зависимостей
cargo check

# Сборка с генерацией документации
cargo doc --no-deps --open
```

### Конфигурация Cargo.toml

#### Основные секции
```toml
[package]
name = "cryptocore"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <email@example.com>"]
description = "Cryptographic CLI utility with multiple AES modes"
license = "Apache-2.0 OR MIT"

[dependencies]
openssl = { version = "0.10", features = ["vendored"] }
hex = "0.4"
clap = { version = "4.0", features = ["derive"] }
sha3 = "0.10"
anyhow = "1.0"

[dev-dependencies]
tempfile = "3.3"

[features]
default = []
vendored-openssl = ["openssl/vendored"]

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = 'abort'
```

### Кросс-компиляция

#### Для Windows из Linux/macOS
```bash
# Установка целевой архитектуры
rustup target add x86_64-pc-windows-gnu

# Установка инструментов (Ubuntu)
sudo apt-get install mingw-w64

# Компиляция
cargo build --release --target x86_64-pc-windows-gnu
```

#### Для Linux из Windows (WSL)
```bash
# В WSL
rustup target add x86_64-unknown-linux-gnu

# Компиляция
cargo build --release --target x86_64-unknown-linux-gnu
```

### Docker сборка

#### Dockerfile
```dockerfile
FROM rust:1.70-slim as builder

WORKDIR /usr/src/cryptocore
COPY . .

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/cryptocore/target/release/cryptocore /usr/local/bin/

ENTRYPOINT ["cryptocore"]
```

#### Сборка и запуск
```bash
# Сборка образа
docker build -t cryptocore .

# Запуск контейнера
docker run --rm -v $(pwd):/data cryptocore \
    crypto --algorithm aes --mode cbc --operation encrypt \
    --input /data/secret.txt \
    --output /data/secret.enc
```

## Тестирование

### Типы тестов

#### 1. Модульные тесты (Unit Tests)
```rust
// Внутри файлов с кодом
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = generate_key();
        assert_eq!(key.len(), 16);
    }

    #[test]
    #[should_panic(expected = "Invalid key length")]
    fn test_invalid_key() {
        validate_key(&[0; 15]).unwrap();
    }
}
```

#### 2. Интеграционные тесты
```rust
// tests/integration_tests.rs
#[test]
fn test_full_encryption_workflow() {
    let plaintext = b"Test data";
    let key = [0x00; 16];
    
    let ciphertext = encrypt_cbc(&plaintext, &key);
    let decrypted = decrypt_cbc(&ciphertext, &key);
    
    assert_eq!(plaintext, &decrypted[..]);
}
```

#### 3. Функциональные тесты CLI
```bash
# Тестирование команд CLI
cargo test --test integration_tests -- --nocapture

# Тестирование отдельных компонентов
cargo test --test test_hash
cargo test --test test_kdf
```

### Запуск тестов

#### Полный набор тестов
```bash
# Все тесты
cargo test

# С подробным выводом
cargo test -- --nocapture

# С фильтрацией по имени
cargo test test_encryption
```

#### Тестирование конкретных модулей
```bash
# Тесты CSPRNG
cargo test --test test_csprng

# Тесты хеш-функций
cargo test --test test_hash

# Тесты HMAC
cargo test --test test_hmac_vectors

# Тесты GCM
cargo test --test gcm

# Тесты KDF
cargo test --test kdf
```

#### Интеграционные тесты
```bash
# Тестирование совместимости с OpenSSL
cargo test --test test_openssl_compatibility

# Тестирование больших данных
cargo test --test test_gcm_large_data

# Тестирование AEAD
cargo test --test test_aead
```

### Автоматическое тестирование через Make

#### Основные команды
```bash
# Полный тестовый прогон
make test-all

# Тестирование всех режимов шифрования
make test-modes

# Тестирование AEAD режимов
make test-aead

# Тестирование KDF функций
make test-kdf

# Тестирование CSPRNG
make test-csprng

# Тестирование совместимости с OpenSSL
make test-openssl
```

#### Тестирование отдельных режимов
```bash
make test-ecb
make test-cbc
make test-cfb
make test-ofb
make test-ctr
make test-gcm
make test-etm
```

### NIST тестирование CSPRNG

#### Генерация тестовых данных
```bash
# Генерация данных для NIST STS
make test-nist
# Создает файл: nist_test_data.bin (1MB данных)

# Быстрая проверка
make test-nist-quick

# Полный NIST тест (требует установленного NIST STS)
make test-nist-full
```

#### Скрипты автоматического тестирования
```bash
# PowerShell (Windows)
.\scripts\test.ps1

# Bash (Linux/macOS)
chmod +x scripts/test.sh
./scripts/test.sh

# NIST тестирование (Windows)
.\scripts\test_nist.ps1
```

### Тестовые векторы

#### HMAC тестовые векторы (RFC 4231)
```rust
// tests/test_hmac_vectors.rs
#[test]
fn test_hmac_sha256_test_cases() {
    let test_cases = vec![
        (
            b"Hi There",
            &[0x0b; 20],
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        ),
        // ... больше тестовых случаев
    ];
    
    for (data, key, expected) in test_cases {
        let hmac = hmac_sha256(key, data);
        assert_eq!(hex::encode(hmac), expected);
    }
}
```

#### PBKDF2 тестовые векторы (RFC 6070)
```rust
// tests/test_kdf.rs
#[test]
fn test_pbkdf2_hmac_sha256_test_vectors() {
    let test_cases = vec![
        (
            "password",
            "73616c74",
            1,
            20,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        ),
        // ... RFC 6070 векторы
    ];
}
```

#### Тестирование граничных случаев
```rust
#[test]
fn test_edge_cases() {
    // Пустые данные
    test_encryption(&[], &[0; 16]);
    
    // Данные меньше блока
    test_encryption(&[1, 2, 3], &[0; 16]);
    
    // Данные точно кратные блоку
    test_encryption(&[0; 16], &[0; 16]);
    
    // Очень большие данные
    let large_data = vec![0; 1024 * 1024]; // 1MB
    test_encryption(&large_data, &[0; 16]);
}
```

### Тестирование производительности

#### Бенчмарки
```rust
// benchmarks/encryption_benchmark.rs
#[bench]
fn bench_aes_cbc_encryption(b: &mut Bencher) {
    let data = vec![0u8; 1024 * 1024]; // 1MB
    let key = [0u8; 16];
    
    b.iter(|| {
        encrypt_cbc(&data, &key)
    });
    
    b.bytes = data.len() as u64;
}
```

#### Запуск бенчмарков
```bash
cargo bench

# Конкретный бенчмарк
cargo bench --bench encryption_benchmark
```

### Покрытие кода

#### Установка инструментов
```bash
# Установка tarpaulin для покрытия кода
cargo install cargo-tarpaulin
```

#### Генерация отчета
```bash
# Измерение покрытия кода
cargo tarpaulin --out Html

# Только для библиотеки
cargo tarpaulin --lib --out Xml

# Сохранение в файл
cargo tarpaulin --out Html --output-dir ./coverage
```

#### Просмотр отчета
```bash
# Открыть HTML отчет
open ./coverage/tarpaulin-report.html

# Или в консоли
cargo tarpaulin --out Line
```

## Структура кода

### Основные модули

#### src/crypto/modes/mod.rs - Фабрика режимов
```rust
pub enum EncryptionMode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
    Gcm,
    Etm(Box<dyn BlockCipherMode>), // ETM использует базовый режим
}

pub trait BlockCipherMode {
    fn encrypt(&self, data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>>;
}

pub fn create_mode(mode: Mode, base_mode: Option<Mode>) -> Result<Box<dyn BlockCipherMode>> {
    match mode {
        Mode::Ecb => Ok(Box::new(EcbMode::new())),
        Mode::Cbc => Ok(Box::new(CbcMode::new())),
        Mode::Gcm => Ok(Box::new(GcmMode::new())),
        Mode::Etm => {
            let base = create_base_mode(base_mode.unwrap())?;
            Ok(Box::new(EtmMode::new(base)))
        }
        // ... другие режимы
    }
}
```

#### src/crypto/modes/gcm.rs - Реализация GCM
```rust
pub struct GcmMode {
    // Поля для хранения состояния GCM
}

impl GcmMode {
    pub fn new() -> Self {
        GcmMode {
            // Инициализация
        }
    }
    
    fn ghash(&self, h: &[u8; 16], data: &[u8]) -> [u8; 16] {
        // Реализация умножения в GF(2^128)
    }
    
    fn gctr(&self, key: &[u8; 16], icb: [u8; 16], data: &[u8]) -> Vec<u8> {
        // Режим счетчика
    }
}

impl BlockCipherMode for GcmMode {
    fn encrypt(&self, data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
        // GCM шифрование с аутентификацией
    }
    
    fn decrypt(&self, data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
        // GCM дешифрование с проверкой тега
    }
}
```

#### src/hash/sha256.rs - SHA-256 реализация
```rust
pub struct Sha256 {
    state: [u32; 8],
    len: u64,
    buffer: [u8; 64],
    buffer_len: usize,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: SHA256_INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            buffer_len: 0,
        }
    }
    
    fn process_block(&mut self, block: &[u8; 64]) {
        // Обработка 512-битного блока
        let mut w = [0u32; 64];
        
        // Подготовка расписания сообщений
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        
        // Вычисление расписания
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        
        // Сжатие
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        // Обновление состояния
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
```

### Паттерны проектирования

#### 1. Стратегия (Strategy) - Режимы шифрования
```rust
// Трейт определяет общий интерфейс
pub trait EncryptionStrategy {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>>;
}

// Конкретные реализации
struct CbcStrategy;
struct GcmStrategy;
struct CtrStrategy;

// Использование
let strategy: Box<dyn EncryptionStrategy> = match mode {
    Mode::Cbc => Box::new(CbcStrategy),
    Mode::Gcm => Box::new(GcmStrategy),
    // ...
};
```

#### 2. Фабрика (Factory) - Создание режимов
```rust
pub struct ModeFactory;

impl ModeFactory {
    pub fn create(mode: Mode) -> Result<Box<dyn EncryptionStrategy>> {
        match mode {
            Mode::Cbc => Ok(Box::new(CbcMode::new())),
            Mode::Gcm => Ok(Box::new(GcmMode::new())),
            Mode::Etm => Ok(Box::new(EtmMode::new(
                ModeFactory::create(base_mode)?
            ))),
            _ => Err(anyhow!("Unsupported mode")),
        }
    }
}
```

#### 3. Строитель (Builder) - Конфигурация CLI
```rust
pub struct CryptoConfigBuilder {
    algorithm: Algorithm,
    mode: Mode,
    operation: Operation,
    key: Option<Vec<u8>>,
    input: String,
    output: Option<String>,
}

impl CryptoConfigBuilder {
    pub fn new() -> Self {
        CryptoConfigBuilder::default()
    }
    
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
    
    pub fn build(self) -> Result<CryptoConfig> {
        // Валидация и создание конфигурации
        Ok(CryptoConfig { ... })
    }
}
```

### Обработка ошибок

#### Иерархия ошибок
```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid IV length: expected {expected}, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },
    
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("OpenSSL error: {0}")]
    Openssl(String),
}

// Использование
fn validate_key(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 16,
            actual: key.len(),
        });
    }
    Ok(())
}
```

#### Комбинирование с anyhow
```rust
use anyhow::{Context, Result};

fn load_and_encrypt(path: &str, key: &[u8]) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .context(format!("Failed to read file: {}", path))?;
    
    encrypt_cbc(&data, key)
        .context("Encryption failed")
}
```

## Добавление новых функций

### Процесс разработки

#### 1. Создание ветки
```bash
git checkout -b feature/new-encryption-mode
```

#### 2. Добавление нового режима шифрования

**Шаг 1: Создание файла реализации**
```rust
// src/crypto/modes/new_mode.rs
pub struct NewMode {
    // Конфигурация режима
}

impl NewMode {
    pub fn new() -> Self {
        NewMode {
            // Инициализация
        }
    }
}

impl BlockCipherMode for NewMode {
    fn encrypt(&self, data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
        // Реализация шифрования
    }
    
    fn decrypt(&self, data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
        // Реализация дешифрования
    }
}
```

**Шаг 2: Регистрация в mod.rs**
```rust
// src/crypto/modes/mod.rs
mod new_mode;
pub use new_mode::NewMode;

pub fn create_mode(mode: Mode, base_mode: Option<Mode>) -> Result<Box<dyn BlockCipherMode>> {
    match mode {
        Mode::New => Ok(Box::new(NewMode::new())),
        // ...
    }
}
```

**Шаг 3: Добавление в перечисление Mode**
```rust
// src/cli/parser.rs
#[derive(ValueEnum, Clone, Debug)]
pub enum Mode {
    #[clap(name = "ecb")]
    Ecb,
    #[clap(name = "new")]
    New,
    // ...
}
```

**Шаг 4: Добавление тестов**
```rust
// tests/test_new_mode.rs
#[test]
fn test_new_mode_encryption() {
    let mode = NewMode::new();
    let key = [0u8; 16];
    let data = b"Test data";
    
    let encrypted = mode.encrypt(data, &key, None).unwrap();
    let decrypted = mode.decrypt(&encrypted, &key, None).unwrap();
    
    assert_eq!(data, &decrypted[..]);
}
```

#### 3. Добавление новой хеш-функции

**Шаг 1: Создание реализации**
```rust
// src/hash/new_hash.rs
pub struct NewHash {
    // Состояние хеш-функции
}

impl NewHash {
    pub fn new() -> Self {
        NewHash {
            // Инициализация
        }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        // Обработка данных
    }
    
    pub fn finalize(self) -> [u8; 32] {
        // Финальный хеш
    }
}
```

**Шаг 2: Интеграция в систему хеширования**
```rust
// src/hash/mod.rs
mod new_hash;
pub use new_hash::NewHash;

pub enum HashAlgorithm {
    Sha256,
    Sha3_256,
    NewHash,
}

pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::NewHash => {
            let mut hasher = NewHash::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        // ...
    }
}
```

### Руководства по стилю кода

#### Форматирование кода
```bash
# Автоматическое форматирование
cargo fmt

# Проверка стиля
cargo clippy -- -D warnings

# Проверка безопасности
cargo audit
```

#### Коммиты
```bash
# Соблюдение Conventional Commits
git commit -m "feat: add new encryption mode"
git commit -m "fix: correct IV handling in CBC mode"
git commit -m "docs: update API documentation"
git commit -m "test: add tests for edge cases"
```

### Документация

#### Документирование кода
```rust
/// Реализация нового режима шифрования.
///
/// # Примеры
/// ```
/// use cryptocore::crypto::NewMode;
///
/// let mode = NewMode::new();
/// let key = [0u8; 16];
/// let data = b"Hello, world!";
///
/// let encrypted = mode.encrypt(data, &key, None).unwrap();
/// let decrypted = mode.decrypt(&encrypted, &key, None).unwrap();
///
/// assert_eq!(data, &decrypted[..]);
/// ```
pub struct NewMode {
    // ...
}
```

#### Генерация документации
```bash
# Генерация и открытие документации
cargo doc --open

# Документация с приватными элементами
cargo doc --document-private-items

# Документация только для библиотеки
cargo doc --lib
```

## Отладка

### Инструменты отладки

#### Встроенный отладчик
```bash
# Сборка с отладочной информацией
cargo build

# Запуск через rust-gdb
rust-gdb target/debug/cryptocore

# В gdb:
(gdb) break main
(gdb) run --algorithm aes --mode cbc --operation encrypt --input test.txt
```

#### Вывод отладочной информации
```rust
// Использование log crate
use log::{debug, info, warn, error};

fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    debug!("Encrypting {} bytes with key: {:?}", data.len(), key);
    
    if key.iter().all(|&b| b == 0) {
        warn!("Using all-zero key, consider generating a secure key");
    }
    
    // Шифрование...
    
    info!("Encryption completed successfully");
    Ok(encrypted)
}
```

#### Настройка логирования
```rust
// В main.rs
fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    // Остальной код...
}
```

### Тестирование отладки

#### Тестирование ошибок
```rust
#[test]
fn test_error_conditions() {
    // Тестирование неверного ключа
    assert!(encrypt_cbc(b"data", &[0; 15]).is_err());
    
    // Тестирование неверного IV
    assert!(decrypt_cbc(b"data", &[0; 16], Some(&[0; 15])).is_err());
    
    // Тестирование поврежденных данных
    let mut corrupted = vec![0; 32];
    corrupted[10] = corrupted[10].wrapping_add(1);
    assert!(decrypt_cbc(&corrupted, &[0; 16], None).is_err());
}
```

#### Фаззинг-тесты
```rust
// tests/fuzz_tests.rs
#[test]
fn fuzz_encryption() {
    let mut rng = rand::thread_rng();
    
    for _ in 0..1000 {
        let data_len = rng.gen_range(0..1024);
        let data: Vec<u8> = (0..data_len).map(|_| rng.gen()).collect();
        let key: [u8; 16] = rng.gen();
        
        let encrypted = encrypt_cbc(&data, &key).unwrap();
        let decrypted = decrypt_cbc(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted);
    }
}
```

### Профилирование

#### CPU профилирование
```bash
# Установка инструментов
cargo install flamegraph

# Генерация flamegraph
cargo flamegraph --bin cryptocore -- crypto --algorithm aes --mode cbc --operation encrypt --input large_file.txt

# Альтернатива: perf (Linux)
perf record ./target/release/cryptocore crypto ...
perf report
```

#### Профилирование памяти
```bash
# Установка valgrind (Linux)
sudo apt-get install valgrind

# Проверка утечек памяти
valgrind --leak-check=full ./target/debug/cryptocore ...

# Massif для анализа использования памяти
valgrind --tool=massif ./target/debug/cryptocore ...
```

#### Бенчмаркинг
```rust
// benches/benchmark.rs
#[bench]
fn bench_encryption(b: &mut Bencher) {
    let data = vec![0u8; 1024 * 1024]; // 1MB
    let key = [0u8; 16];
    
    b.iter(|| {
        encrypt_cbc(&data, &key)
    });
}

// Запуск
cargo bench
```

## Производительность

### Оптимизации

#### Оптимизация компиляции
```toml
# Cargo.toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = 'abort'

# Дополнительные флаги
[profile.release.build-override]
opt-level = 3

[profile.bench]
opt-level = 3
lto = true
```

#### Оптимизации во время выполнения

**Буферизация ввода-вывода:**
```rust
use std::io::{BufReader, BufWriter};

fn process_large_file(input: &str, output: &str) -> Result<()> {
    let input_file = File::open(input)?;
    let output_file = File::create(output)?;
    
    let reader = BufReader::new(input_file);
    let writer = BufWriter::new(output_file);
    
    // Обработка с буферизацией
    process_stream(reader, writer)
}
```

**Избегание лишних копий:**
```rust
// Плохо: лишнее копирование
fn process_data(data: Vec<u8>) -> Vec<u8> {
    let mut result = data.clone(); // Ненужное копирование
    // Обработка result
    result
}

// Хорошо: работа на месте
fn process_data_in_place(mut data: Vec<u8>) -> Vec<u8> {
    // Обработка data на месте
    data
}

// Или использование срезов
fn process_slice(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    // Заполнение result
    result
}
```

### Мониторинг производительности

#### Метрики
```rust
use std::time::Instant;

fn benchmark_operation() {
    let start = Instant::now();
    
    // Операция для бенчмарка
    let result = expensive_operation();
    
    let duration = start.elapsed();
    println!("Operation took: {:?}", duration);
    println!("Throughput: {:.2} MB/s", 
        result.len() as f64 / duration.as_secs_f64() / 1_000_000.0);
}
```

#### Профилировщики
- **perf** (Linux) - низкоуровневое профилирование
- **dtrace** (macOS/BSD) - динамическое трассирование
- **Instruments** (macOS) - графический профилировщик
- **VTune** (Windows/Linux) - коммерческий профилировщик Intel

### Работа с большими файлами

#### Потоковая обработка
```rust
use std::io::{Read, Write};

fn stream_encrypt<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8; 16],
) -> Result<()> {
    let mut buffer = [0u8; 8192]; // 8KB буфер
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        let encrypted = encrypt_chunk(&buffer[..bytes_read], key)?;
        writer.write_all(&encrypted)?;
    }
    
    Ok(())
}
```

#### Параллельная обработка
```rust
use rayon::prelude::*;

fn parallel_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let chunk_size = 1024 * 1024; // 1MB chunks
    
    data.par_chunks(chunk_size)
        .flat_map(|chunk| {
            encrypt_chunk(chunk, key).unwrap()
        })
        .collect()
}
```

## Безопасность разработки

### Практики безопасного программирования

#### Обработка чувствительных данных
```rust
use zeroize::Zeroize;

struct SensitiveData {
    key: [u8; 32],
    iv: [u8; 16],
}

impl Drop for SensitiveData {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl SensitiveData {
    fn new() -> Self {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        
        // Безопасная генерация
        openssl::rand::rand_bytes(&mut key).unwrap();
        openssl::rand::rand_bytes(&mut iv).unwrap();
        
        SensitiveData { key, iv }
    }
}
```

#### Защита от тайминговых атак
```rust
use constant_time_eq::constant_time_eq;

fn verify_hmac(expected: &[u8], actual: &[u8]) -> Result<()> {
    if !constant_time_eq(expected, actual) {
        return Err(anyhow!("HMAC verification failed"));
    }
    Ok(())
}

fn verify_tag(expected: &[u8; 16], actual: &[u8; 16]) -> bool {
    // Использование постоянного времени для сравнения тегов
    let mut result = 0u8;
    for (a, b) in expected.iter().zip(actual.iter()) {
        result |= a ^ b;
    }
    result == 0
}
```

### Анализ безопасности

#### Статический анализ
```bash
# Проверка уязвимостей в зависимостях
cargo audit

# Статический анализ кода
cargo clippy -- -D warnings

# Проверка небезопасного кода
cargo geiger

# Анализ сложности кода
cargo tally
```

#### Динамический анализ
```bash
# Фаззинг-тесты
cargo install cargo-fuzz
cargo fuzz run encryption_fuzz

# Тестирование на утечки памяти
valgrind --leak-check=full ./target/debug/cryptocore ...

# ASAN для обнаружения ошибок памяти
RUSTFLAGS="-Z sanitizer=address" cargo run --target x86_64-unknown-linux-gnu
```

### Тестирование безопасности

#### Тестирование граничных случаев
```rust
#[test]
fn test_security_edge_cases() {
    // Тестирование с максимальными размерами
    test_encryption_with_size(usize::MAX - 100);
    
    // Тестирование с нулевыми данными
    test_encryption_with_size(0);
    
    // Тестирование с повторяющимися паттернами
    let repeating_pattern = vec![0xAA; 1024 * 1024];
    test_encryption(&repeating_pattern, &[0; 16]);
    
    // Тестирование на утечки информации
    test_information_leakage();
}
```

#### Тестирование устойчивости к ошибкам
```rust
#[test]
fn test_error_resilience() {
    // Тестирование поврежденных данных
    for i in 0..100 {
        let mut data = vec![0u8; 1024];
        data[i] = data[i].wrapping_add(1); // Изменение одного байта
        
        // Убедиться, что ошибка обрабатывается корректно
        let result = decrypt_cbc(&data, &[0; 16], Some(&[0; 16]));
        assert!(result.is_err() || {
            // Если дешифрование прошло, убедиться, что результат отличается
            let decrypted = result.unwrap();
            decrypted != vec![0u8; 1024 - 16] // Учитываем padding
        });
    }
}
```

## CI/CD

### GitHub Actions

#### Конфигурация CI
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y pkg-config libssl-dev
        
    - name: Check format
      run: cargo fmt -- --check
      
    - name: Clippy
      run: cargo clippy -- -D warnings
      
    - name: Run tests
      run: cargo test --verbose
      
    - name: Build release
      run: cargo build --release
      
    - name: Run integration tests
      run: make test-all
      
    - name: Security audit
      run: cargo audit
```

#### Конфигурация CD
```yaml
# .github/workflows/cd.yml
name: CD

on:
  release:
    types: [published]

jobs:
  build-and-release:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target: [x86_64-unknown-linux-gnu, x86_64-pc-windows-gnu, x86_64-apple-darwin]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        target: ${{ matrix.target }}
        override: true
    
    - name: Build
      run: cargo build --release --target ${{ matrix.target }}
      
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: cryptocore-${{ matrix.target }}
        path: target/${{ matrix.target }}/release/cryptocore*
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

variables:
  CARGO_HOME: $CI_PROJECT_DIR/cargo

test:
  stage: test
  image: rust:latest
  before_script:
    - apt-get update && apt-get install -y pkg-config libssl-dev
  script:
    - cargo test --verbose
    - cargo clippy -- -D warnings
    - cargo fmt -- --check

build-linux:
  stage: build
  image: rust:latest
  script:
    - cargo build --release
  artifacts:
    paths:
      - target/release/cryptocore

build-windows:
  stage: build
  image: rust:latest
  before_script:
    - rustup target add x86_64-pc-windows-gnu
    - apt-get update && apt-get install -y mingw-w64
  script:
    - cargo build --release --target x86_64-pc-windows-gnu
  artifacts:
    paths:
      - target/x86_64-pc-windows-gnu/release/cryptocore.exe
```

Для дополнительных вопросов обращайтесь к исходному коду или создавайте issue в репозитории проекта.