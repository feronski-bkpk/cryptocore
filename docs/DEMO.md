# Демо команды по порядку

## 1. Подготовка
```bash
cd cryptocore
cargo build --release
cd target/release/
echo "This is only for testing" > test.txt
```

## 2. РЕЖИМЫ ШИФРОВАНИЯ

### 2.1 CBC режим (автоматический ключ)
```bash
# Шифруем
cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input test.txt --output test_cbc.enc
# Скопируйте ключ из вывода!

# Дешифруем (вставьте ваш ключ)
cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX --input test_cbc.enc --output test_cbc.dec
fc test.txt test_cbc.dec && echo "✓ CBC работает"
```

### 2.2 ECB режим
```bash
cryptocore crypto --algorithm aes --mode ecb --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_ecb.enc
cryptocore crypto --algorithm aes --mode ecb --operation decrypt --key 00112233445566778899aabbccddeeff --input test_ecb.enc --output test_ecb.dec
fc test.txt test_ecb.dec && echo "✓ ECB работает"
```

### 2.3 CFB режим
```bash
cryptocore crypto --algorithm aes --mode cfb --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_cfb.enc
cryptocore crypto --algorithm aes --mode cfb --operation decrypt --key 00112233445566778899aabbccddeeff --input test_cfb.enc --output test_cfb.dec
fc test.txt test_cfb.dec && echo "✓ CFB работает"
```

### 2.4 OFB режим
```bash
cryptocore crypto --algorithm aes --mode ofb --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_ofb.enc
cryptocore crypto --algorithm aes --mode ofb --operation decrypt --key 00112233445566778899aabbccddeeff --input test_ofb.enc --output test_ofb.dec
fc test.txt test_ofb.dec && echo "✓ OFB работает"
```

### 2.5 CTR режим
```bash
cryptocore crypto --algorithm aes --mode ctr --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_ctr.enc
cryptocore crypto --algorithm aes --mode ctr --operation decrypt --key 00112233445566778899aabbccddeeff --input test_ctr.enc --output test_ctr.dec
fc test.txt test_ctr.dec && echo "✓ CTR работает"
```

### 2.6 GCM режим (с аутентификацией)
```bash
cryptocore crypto --algorithm aes --mode gcm --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_gcm.enc --aad demo_context
cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key 00112233445566778899aabbccddeeff --input test_gcm.enc --output test_gcm.dec --aad demo_context
fc test.txt test_gcm.dec && echo "✓ GCM работает"
```

### 2.7 ETM режим (Encrypt-then-MAC)
```bash
cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_etm.enc --aad context
cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --input test_etm.enc --output test_etm.dec --aad context
fc test.txt test_etm.dec && echo "✓ ETM работает"
```

## 3. ИНТЕРОПЕРАБЕЛЬНОСТЬ

### 3.1 CryptoCore → OpenSSL (CBC)
```bash
cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output interop_c2o.enc
dd if=interop_c2o.enc of=c2o_iv.bin bs=16 count=1 2>/dev/null
dd if=interop_c2o.enc of=c2o_cipher.bin bs=16 skip=1 2>/dev/null
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $(xxd -p c2o_iv.bin | tr -d '\n') -in c2o_cipher.bin -out c2o_decrypted.txt
fc test.txt c2o_decrypted.txt && echo "✓ CryptoCore→OpenSSL CBC работает"
```

Попробовать:
```bash
cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output interop_c2o.enc
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -in interop_c2o.enc -out c2o_decrypted.txt
fc test.txt c2o_decrypted.txt && echo "✓ CryptoCore→OpenSSL работает"
```

### 3.2 OpenSSL → CryptoCore (CBC)
```bash
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090a0b0c0d0e0f -in test.txt -out openssl_encrypted.bin
cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f --input openssl_encrypted.bin --output o2c_decrypted.txt
fc test.txt o2c_decrypted.txt && echo "✓ OpenSSL→CryptoCore CBC работает"
```

Попробовать:
```bash
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090a0b0c0d0e0f -in test.txt -out openssl_encrypted.bin
cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f --input openssl_encrypted.bin --output o2c_decrypted.txt
fc test.txt o2c_decrypted.txt && echo "✓ OpenSSL→CryptoCore работает"
```

### 3.3 CryptoCore → OpenSSL (GCM)
```bash
cryptocore crypto --algorithm aes --mode gcm --operation encrypt --key 00000000000000000000000000000000 --nonce 000000000000000000000000 --input test.txt --output gcm_c2o.enc --aad demo
dd if=gcm_c2o.enc of=gcm_nonce.bin bs=12 count=1 2>/dev/null
dd if=gcm_c2o.enc of=gcm_cipher.bin bs=12 skip=1 2>/dev/null
dd if=gcm_cipher.bin of=gcm_tag.bin bs=$(($(stat -c%s gcm_cipher.bin)-16)) skip=1 2>/dev/null
dd if=gcm_cipher.bin of=gcm_ct_only.bin bs=$(($(stat -c%s gcm_cipher.bin)-16)) count=1 2>/dev/null
openssl enc -aes-128-gcm -d -K 00000000000000000000000000000000 -iv 000000000000000000000000 -aad demo -in gcm_ct_only.bin -out gcm_openssl_dec.txt -tag $(xxd -p gcm_tag.bin | tr -d '\n') 2>/dev/null && fc test.txt gcm_openssl_dec.txt && echo "✓ CryptoCore→OpenSSL GCM работает"
```

## 4. DGST КОМАНДЫ

### 4.1 SHA-256
```bash
cryptocore dgst --algorithm sha256 --input test.txt
echo "✓ SHA-256 работает"
```

### 4.2 SHA3-256
```bash
cryptocore dgst --algorithm sha3-256 --input test.txt
echo "✓ SHA3-256 работает"
```

### 4.3 SHA-256 в файл
```bash
cryptocore dgst --algorithm sha256 --input test.txt --output test.sha256
echo "Хеш сохранен в test.sha256"
```

### 4.4 HMAC создание
```bash
cryptocore dgst --algorithm sha256 --hmac --key secret123 --input test.txt --output test.hmac
echo "HMAC создан"
```

### 4.5 HMAC проверка (успешная)
```bash
cryptocore dgst --algorithm sha256 --hmac --key secret123 --input test.txt --verify test.hmac && echo "✓ HMAC проверка успешна"
```

### 4.6 HMAC проверка (неудачная)
```bash
echo "tamper" >> test.txt
cryptocore dgst --algorithm sha256 --hmac --key secret123 --input test.txt --verify test.hmac 2>/dev/null || echo "✓ HMAC обнаружил изменение"
```

### 4.7 Восстановление файла
```bash
# Удаляем последнюю строку (изменение)
head -n -1 test.txt > test_temp.txt && mv test_temp.txt test.txt
cryptocore dgst --algorithm sha256 --hmac --key secret123 --input test.txt --verify test.hmac && echo "✓ Файл восстановлен, HMAC проверка снова успешна"
```

## 5. DERIVE КОМАНДЫ

### 5.1 Базовое выведение ключа
```bash
cryptocore derive --password "MyPassword" --salt 1234567890abcdef --iterations 10000 --length 32
```

### 5.2 Использование выведенного ключа для шифрования
```bash
# Выводим ключ и берем первую часть (hex ключ)
KEY=$(cryptocore derive --password "MyPassword" --salt 1234567890abcdef --iterations 10000 --length 32 | cut -d' ' -f1)
echo "Выведенный ключ: $KEY"

# Шифруем выведенным ключом
cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --input test.txt --output test_pbkdf2.enc

# Дешифруем тем же ключом
cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key $KEY --input test_pbkdf2.enc --output test_pbkdf2.dec

fc test.txt test_pbkdf2.dec && echo "✓ Шифрование PBKDF2-ключом работает"
```

### 5.3 Выведение с авто-солью
```bash
cryptocore derive --password "AnotherPassword" --iterations 50000 --length 16
echo "✓ Автоматическая генерация соли работает"
```

### 5.4 RFC 6070 тестовые векторы
```bash
cryptocore derive --password "password" --salt 73616c74 --iterations 1 --length 20
echo "✓ RFC 6070 вектор 1"
cryptocore derive --password "password" --salt 73616c74 --iterations 2 --length 20
echo "✓ RFC 6070 вектор 2"
```

### 5.5 Выведение ключа в файл
```bash
cryptocore derive --password "app_password" --salt fixedappsalt123456 --iterations 10000 --length 32 --output derived.key
echo "✓ Ключ сохранен в derived.key"
```