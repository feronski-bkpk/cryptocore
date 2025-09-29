#!/bin/bash

set -e

echo "Starting CryptoCore Automated Tests..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}SUCCESS: $2${NC}"
    else
        echo -e "${RED}FAILED: $2${NC}"
    fi
}

# Step 1: Build project
echo -e "${YELLOW}Building project...${NC}"
cargo build --release
print_status $? "Build completed"

# Step 2: Test help command
echo -e "${YELLOW}Testing help command...${NC}"
./target/release/cryptocore --help
print_status $? "Help command works"

# Step 3: Create test files
echo -e "${YELLOW}Creating test files...${NC}"
declare -A testFiles=(
    ["short.txt"]="Short test"
    ["medium.txt"]="This is a medium length test file for encryption"
    ["long.txt"]="This is a much longer test file that contains more data to ensure encryption works properly with different data sizes and padding."
    ["empty.txt"]=""
)

for filename in "${!testFiles[@]}"; do
    echo "${testFiles[$filename]}" > "$filename"
    echo "Created $filename"
done

# Create binary test file
echo -n -e "Binary data test!\x001\x002\x003" > binary.bin

# Step 4: Test encryption/decryption
KEY="00112233445566778899aabbccddeeff"
echo -e "${YELLOW}Testing encryption/decryption...${NC}"

all_tests_passed=true
test_results=()

for filename in "${!testFiles[@]}"; do
    echo -n "Testing $filename..."

    encrypted_file="$filename.enc"
    decrypted_file="$filename.dec"

    # Encrypt
    if ! ./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "$filename" --output "$encrypted_file"; then
        echo -e "${RED} Encryption failed${NC}"
        test_results+=("FAILED: $filename - Encryption failed")
        all_tests_passed=false
        continue
    fi

    # Decrypt
    if ! ./target/release/cryptocore --algorithm aes --mode ecb --operation decrypt --key "$KEY" --input "$encrypted_file" --output "$decrypted_file"; then
        echo -e "${RED} Decryption failed${NC}"
        test_results+=("FAILED: $filename - Decryption failed")
        all_tests_passed=false
        continue
    fi

    # Compare
    if diff "$filename" "$decrypted_file" >/dev/null; then
        echo -e "${GREEN} Success${NC}"
        test_results+=("PASSED: $filename - Round-trip successful")
    else
        echo -e "${RED} Files don't match${NC}"
        test_results+=("FAILED: $filename - Files don't match")
        all_tests_passed=false
    fi

    # Cleanup
    rm -f "$encrypted_file" "$decrypted_file"
done

# Test binary file
echo -n "Testing binary.bin..."
if ./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input binary.bin --output binary.enc && \
   ./target/release/cryptocore --algorithm aes --mode ecb --operation decrypt --key "$KEY" --input binary.enc --output binary.dec && \
   cmp -s binary.bin binary.dec; then
    echo -e "${GREEN} Success${NC}"
    test_results+=("PASSED: binary.bin - Round-trip successful")
else
    echo -e "${RED} Failed${NC}"
    test_results+=("FAILED: binary.bin - Round-trip failed")
    all_tests_passed=false
fi
rm -f binary.enc binary.dec

# Step 5: Test validation
echo -e "${YELLOW}Testing argument validation...${NC}"

# Test invalid key
if ./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "test.txt" --output "test.enc" 2>/dev/null; then
    echo -e "${RED}Should reject invalid key${NC}"
    test_results+=("FAILED: Validation - Invalid key accepted")
    all_tests_passed=false
else
    echo -e "${GREEN}Invalid key rejected${NC}"
    test_results+=("PASSED: Validation - Invalid key rejected")
fi

# Test nonexistent file
if ./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "nonexistent_file_12345.txt" --output "test.enc" 2>/dev/null; then
    echo -e "${RED}Should reject nonexistent file${NC}"
    test_results+=("FAILED: Validation - Nonexistent file accepted")
    all_tests_passed=false
else
    echo -e "${GREEN}Nonexistent file rejected${NC}"
    test_results+=("PASSED: Validation - Nonexistent file rejected")
fi

# Step 6: Test automatic output naming
echo -e "${YELLOW}Testing automatic output naming...${NC}"
echo "Auto name test" > auto_test.txt

./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input auto_test.txt
if [ $? -eq 0 ] && [ -f "auto_test.txt.enc" ]; then
    echo -e "${GREEN}Automatic encryption naming works${NC}"
    test_results+=("PASSED: Auto naming - Encryption works")
else
    echo -e "${RED}Automatic encryption naming failed${NC}"
    test_results+=("FAILED: Auto naming - Encryption failed")
    all_tests_passed=false
fi

./target/release/cryptocore --algorithm aes --mode ecb --operation decrypt --key "$KEY" --input auto_test.txt.enc
if [ $? -eq 0 ] && [ -f "auto_test.txt.enc.dec" ]; then
    echo -e "${GREEN}Automatic decryption naming works${NC}"
    test_results+=("PASSED: Auto naming - Decryption works")
else
    echo -e "${RED}Automatic decryption naming failed${NC}"
    test_results+=("FAILED: Auto naming - Decryption failed")
    all_tests_passed=false
fi

rm -f auto_test.txt auto_test.txt.enc auto_test.txt.enc.dec

# Step 7: Cleanup test files
echo -e "${YELLOW}Cleaning up...${NC}"
for filename in "${!testFiles[@]}"; do
    rm -f "$filename"
done
rm -f binary.bin

# Step 8: Print results
echo -e "${YELLOW}Test Results:${NC}"
for result in "${test_results[@]}"; do
    if [[ $result == PASSED:* ]]; then
        echo -e "${GREEN}  $result${NC}"
    else
        echo -e "${RED}  $result${NC}"
    fi
done

echo
echo "=================================================="
if $all_tests_passed; then
    echo -e "${GREEN}ALL TESTS PASSED! CryptoCore is working correctly!${NC}"
    echo -e "${GREEN}All requirements from M1 document are satisfied${NC}"
else
    echo -e "${RED}SOME TESTS FAILED! Please check the errors above.${NC}"
    exit 1
fi
echo "=================================================="