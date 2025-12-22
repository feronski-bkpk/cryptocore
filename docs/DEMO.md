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
./cryptocore crypto --algorithm aes --mode cbc --operation encrypt --input test.txt --output test_cbc.enc
# Скопируйте ключ из вывода!
```
```
# Дешифруем (вставьте ваш ключ)
./cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX --input test_cbc.enc --output test_cbc.dec
```
```
diff test.txt test_cbc.dec
```

### 2.2 ECB режим
```bash
./cryptocore crypto --algorithm aes --mode ecb --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_ecb.enc
```
```
./cryptocore crypto --algorithm aes --mode ecb --operation decrypt --key 00112233445566778899aabbccddeeff --input test_ecb.enc --output test_ecb.dec
```
```
diff test.txt test_ecb.dec
```

### 2.3 CFB режим
```bash
./cryptocore crypto --algorithm aes --mode cfb --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_cfb.enc
```
```
./cryptocore crypto --algorithm aes --mode cfb --operation decrypt --key 00112233445566778899aabbccddeeff --input test_cfb.enc --output test_cfb.dec
```
```
diff test.txt test_cfb.dec
```

### 2.4 OFB режим
```bash
./cryptocore crypto --algorithm aes --mode ofb --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_ofb.enc
```
```
./cryptocore crypto --algorithm aes --mode ofb --operation decrypt --key 00112233445566778899aabbccddeeff --input test_ofb.enc --output test_ofb.dec
```
```
diff test.txt test_ofb.dec
```

### 2.5 CTR режим
```bash
./cryptocore crypto --algorithm aes --mode ctr --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_ctr.enc
```
```
./cryptocore crypto --algorithm aes --mode ctr --operation decrypt --key 00112233445566778899aabbccddeeff --input test_ctr.enc --output test_ctr.dec
```
```
diff test.txt test_ctr.dec
```

### 2.6 GCM режим (с аутентификацией)
```bash
./cryptocore crypto --algorithm aes --mode gcm --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_gcm.enc
```
```
./cryptocore crypto --algorithm aes --mode gcm --operation decrypt --key 00112233445566778899aabbccddeeff --input test_gcm.enc --output test_gcm.dec
```
```
diff test.txt test_gcm.dec
```

### 2.7 ETM режим (Encrypt-then-MAC)
```bash
./cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test_etm.enc --aad 636f6e74657874
```
```
./cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --input test_etm.enc --output test_etm.dec --aad 636f6e74657874
```
```
diff test.txt test_etm.dec
```

## 3. ИНТЕРОПЕРАБЕЛЬНОСТЬ

### 3.1 CryptoCore -- OpenSSL (CBC)
```bash
./cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output interop_c2o.enc
```
```
dd if=interop_c2o.enc of=c2o_iv.bin bs=16 count=1 2>/dev/null
dd if=interop_c2o.enc of=c2o_cipher.bin bs=16 skip=1 2>/dev/null
```
```
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $(xxd -p c2o_iv.bin | tr -d '\n') -in c2o_cipher.bin -out c2o_decrypted.txt
diff test.txt c2o_decrypted.txt
```

### 3.2 OpenSSL -- CryptoCore (CBC)
```bash
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090a0b0c0d0e0f -in test.txt -out openssl_encrypted.bin
```
```
./cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key 00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f --input openssl_encrypted.bin --output o2c_decrypted.txt
```
```
diff test.txt o2c_decrypted.txt
```

## 4. DGST КОМАНДЫ

### 4.1 SHA-256
```bash
./cryptocore dgst --algorithm sha256 --input test.txt
```

### 4.2 SHA3-256
```bash
./cryptocore dgst --algorithm sha3-256 --input test.txt
```

### 4.3 SHA-256 в файл
```bash
./cryptocore dgst --algorithm sha256 --input test.txt --output test.sha256
```

### 4.4 HMAC создание
```bash
./cryptocore dgst --algorithm sha256 --hmac --key secret123 --input test.txt --output test.hmac
```

### 4.5 HMAC проверка (успешная)
```bash
./cryptocore dgst --algorithm sha256 --hmac --key 736563726574313233 --input test.txt --verify test.hmac && echo "✓ HMAC проверка успешна"
```

### 4.6 HMAC проверка (неудачная)
```bash
echo "tamper" >> test.txt
```
```
./cryptocore dgst --algorithm sha256 --hmac --key 736563726574313233 --input test.txt --verify test.hmac 2>/dev/null || echo "✓ HMAC обнаружил изменение"
```

### 4.7 Восстановление файла
```bash
# Удаляем последнюю строку (изменение)
head -n -1 test.txt > test_temp.txt && mv test_temp.txt test.txt
```
```
./cryptocore dgst --algorithm sha256 --hmac --key 736563726574313233 --input test.txt --verify test.hmac
```

## 5. DERIVE КОМАНДЫ

### 5.1 Базовое выведение ключа
```bash
./cryptocore derive --password "MyPassword" --salt 1234567890abcdef --iterations 10000 --length 32
```

### 5.2 Использование выведенного ключа для шифрования
```bash
# Выводим ключ и берем первую часть (hex ключ)
KEY=$(./cryptocore derive --password "MyPassword" --salt 1234567890abcdef --iterations 10000 --length 32 2>&1 | grep -E '^[0-9a-f]{64}$' | head -1)
echo "Выведенный ключ: $KEY"
```
```
# Шифруем выведенным ключом
./cryptocore crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --input test.txt --output test_pbkdf2.enc
```
```
# Дешифруем тем же ключом
./cryptocore crypto --algorithm aes --mode cbc --operation decrypt --key $KEY --input test_pbkdf2.enc --output test_pbkdf2.dec
```
```
diff test.txt test_pbkdf2.dec
```

### 5.3 Выведение с авто-солью
```bash
./cryptocore derive --password "AnotherPassword" --iterations 50000 --length 16
```

### 5.4 Выведение ключа в файл
```bash
SALT_HEX=$(echo -n "fixedappsalt123456" | xxd -p)
./cryptocore derive --password "app_password" --salt $SALT_HEX --iterations 10000 --length 32 --output derived.key
```
