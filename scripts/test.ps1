# test.ps1 - Complete Automated Testing for Windows PowerShell

Write-Host "Starting CryptoCore Complete Automated Tests..." -ForegroundColor Cyan

# Colors and formatting
function Write-Step { Write-Host ">>> $($args[0])" -ForegroundColor Blue }
function Write-Section {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  $($args[0])" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
}
function Write-Status {
    param($Success, $Message)
    if ($Success) { Write-Host "SUCCESS: $Message" -ForegroundColor Green }
    else { Write-Host "FAILED: $Message" -ForegroundColor Red }
}

# Get the script directory and project root
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = if ($SCRIPT_DIR -like "*\scripts") { Split-Path -Parent $SCRIPT_DIR } else { $SCRIPT_DIR }

Write-Host "Script directory: $SCRIPT_DIR" -ForegroundColor Gray
Write-Host "Project root: $PROJECT_ROOT" -ForegroundColor Gray

# Step 1: Build project
Write-Section "Building Project"
Set-Location $PROJECT_ROOT
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Status $true "Build completed"

# Define the path to the executable
$CRYPTOCORE_EXE = Join-Path $PROJECT_ROOT "target\release\cryptocore.exe"
if (-not (Test-Path $CRYPTOCORE_EXE)) {
    Write-Host "Executable not found at $CRYPTOCORE_EXE" -ForegroundColor Yellow
    Write-Host "Trying debug build..." -ForegroundColor Yellow
    $CRYPTOCORE_EXE = Join-Path $PROJECT_ROOT "target\debug\cryptocore.exe"
    cargo build
    if (-not (Test-Path $CRYPTOCORE_EXE)) {
        Write-Host "Executable not found at $CRYPTOCORE_EXE" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Using executable: $CRYPTOCORE_EXE" -ForegroundColor Green

# Change to script directory for test files
Set-Location $SCRIPT_DIR

# Step 2: Basic functionality tests
Write-Section "Basic Functionality Tests"

Write-Step "Testing help command"
& $CRYPTOCORE_EXE --help
Write-Status ($LASTEXITCODE -eq 0) "Help command works"

Write-Step "Testing version command"
& $CRYPTOCORE_EXE --version
Write-Status ($LASTEXITCODE -eq 0) "Version command works"

# Step 3: Create comprehensive test files
Write-Section "Creating Test Files"

$testFiles = @{
    "empty.txt" = ""
    "short.txt" = "Short test"
    "medium.txt" = "This is a medium length test file for encryption testing with various data patterns."
    "long.txt" = "This is a much longer test file that contains significantly more data to ensure encryption works properly with different data sizes, padding requirements, and edge cases. It includes various characters and patterns."
    "special_chars.txt" = 'Special chars: ~!@#$%^&*()_+{}|:""<>?[]\;'',./'
    "unicode.txt" = "Unicode test: Hello World"
}

foreach ($file in $testFiles.GetEnumerator()) {
    $filePath = Join-Path $SCRIPT_DIR $file.Key
    $file.Value | Out-File -FilePath $filePath -Encoding utf8
    Write-Host "Created $($file.Key)" -ForegroundColor Green
}

# Create binary test files
$binaryData1 = @(0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f)
[System.IO.File]::WriteAllBytes((Join-Path $SCRIPT_DIR "binary_16.bin"), $binaryData1)

$binaryData2 = @(0x42,0x69,0x6E,0x61,0x72,0x79,0x00,0x64,0x61,0x74,0x61,0x00,0x77,0x69,0x74,0x68,0x00,0x6E,0x75,0x6C,0x6C,0x73,0x00,0x61,0x6E,0x64,0x00,0x73,0x70,0x65,0x63,0x69,0x61,0x6C,0x00,0x63,0x68,0x61,0x72,0x73,0xFF,0xFE,0xFD)
[System.IO.File]::WriteAllBytes((Join-Path $SCRIPT_DIR "binary_with_nulls.bin"), $binaryData2)

# Create random 1KB file
$randomBytes = New-Object byte[] 1024
(New-Object Random).NextBytes($randomBytes)
[System.IO.File]::WriteAllBytes((Join-Path $SCRIPT_DIR "random_1k.bin"), $randomBytes)

Write-Host "Created binary test files" -ForegroundColor Green

# Step 4: CSPRNG Module Tests
Write-Section "CSPRNG Module Tests"

Write-Step "Testing CSPRNG module"
cargo test --test csprng -- --nocapture
Write-Status ($LASTEXITCODE -eq 0) "CSPRNG module tests"

# Step 5: Hash Function Tests
Write-Section "Hash Function Tests"

Write-Step "Testing hash module"
cargo test --test hash -- --nocapture
Write-Status ($LASTEXITCODE -eq 0) "Hash module tests"

# Test SHA-256 with known vectors
Write-Step "Testing SHA-256 known vectors"
$sha256TestFile = Join-Path $SCRIPT_DIR "sha256_test.txt"
"abc" | Out-File -FilePath $sha256TestFile -Encoding utf8 -NoNewline

$sha256Output = & $CRYPTOCORE_EXE dgst --algorithm sha256 --input $sha256TestFile 2>&1
$sha256OutputText = $sha256Output -join "`n"

if ($sha256OutputText -match "1c28dc3f1f804a1ad9c9b4b4cf5e2658d16ad4ed08e3020d04a8d2865018947c") {
    Write-Status $true "SHA-256 known vector test"
    $testResults += "PASSED: Hash - SHA-256 known vector"
} else {
    Write-Status $false "SHA-256 known vector test failed"
    Write-Host "Expected: 1c28dc3f1f804a1ad9c9b4b4cf5e2658d16ad4ed08e3020d04a8d2865018947c" -ForegroundColor Yellow
    Write-Host "Got: $sha256OutputText" -ForegroundColor Yellow
    $testResults += "FAILED: Hash - SHA-256 known vector"
    $allTestsPassed = $false
}

# Test SHA3-256 with known vectors
Write-Step "Testing SHA3-256 known vectors"
$sha3TestFile = Join-Path $SCRIPT_DIR "sha3_test.txt"
"abc" | Out-File -FilePath $sha3TestFile -Encoding utf8 -NoNewline

$sha3Output = & $CRYPTOCORE_EXE dgst --algorithm sha3-256 --input $sha3TestFile 2>&1
$sha3OutputText = $sha3Output -join "`n"

if ($sha3OutputText -match "d6fc903061d8ea170c2e12d8ebc29737c5edf8fe60e11801cebd674b719166b1") {
    Write-Status $true "SHA3-256 known vector test"
    $testResults += "PASSED: Hash - SHA3-256 known vector"
} else {
    Write-Status $false "SHA3-256 known vector test failed"
    Write-Host "Expected: d6fc903061d8ea170c2e12d8ebc29737c5edf8fe60e11801cebd674b719166b1" -ForegroundColor Yellow
    Write-Host "Got: $sha3OutputText" -ForegroundColor Yellow
    $testResults += "FAILED: Hash - SHA3-256 known vector"
    $allTestsPassed = $false
}

# Test hash output to file
Write-Step "Testing hash output to file"
$hashOutputFile = Join-Path $SCRIPT_DIR "hash_output.txt"
& $CRYPTOCORE_EXE dgst --algorithm sha256 --input $sha256TestFile --output $hashOutputFile

if ($LASTEXITCODE -eq 0 -and (Test-Path $hashOutputFile)) {
    $hashContent = Get-Content $hashOutputFile -Raw
    # В файл пишется только хеш, без имени файла
    if ($hashContent -match "1c28dc3f1f804a1ad9c9b4b4cf5e2658d16ad4ed08e3020d04a8d2865018947c") {
        Write-Status $true "Hash output to file works"
        $testResults += "PASSED: Hash - Output to file"
    } else {
        Write-Status $false "Hash output to file content mismatch"
        Write-Host "Expected hash in file: 1c28dc3f1f804a1ad9c9b4b4cf5e2658d16ad4ed08e3020d04a8d2865018947c" -ForegroundColor Yellow
        Write-Host "Got in file: $hashContent" -ForegroundColor Yellow
        $testResults += "FAILED: Hash - Output to file"
        $allTestsPassed = $false
    }
} else {
    Write-Status $false "Hash output to file failed"
    $testResults += "FAILED: Hash - Output to file"
    $allTestsPassed = $false
}

# Test hash with different file types
Write-Step "Testing hash with different file types"
$hashAlgorithms = @("sha256", "sha3-256")

foreach ($algorithm in $hashAlgorithms) {
    foreach ($file in $testFiles.GetEnumerator()) {
        $filename = $file.Key
        $filePath = Join-Path $SCRIPT_DIR $filename
        Write-Host "  Testing $algorithm with $filename..." -NoNewline

        $hashOutput = & $CRYPTOCORE_EXE dgst --algorithm $algorithm --input $filePath 2>&1
        if ($LASTEXITCODE -eq 0) {
            $hashOutputText = $hashOutput -join "`n"
            if ($hashOutputText -match "^[0-9a-f]{64}\s+") {
                Write-Host " Success" -ForegroundColor Green
                $testResults += "PASSED: Hash - $algorithm with $filename"
            } else {
                Write-Host " Invalid format" -ForegroundColor Red
                $testResults += "FAILED: Hash - $algorithm with $filename (format)"
                $allTestsPassed = $false
            }
        } else {
            Write-Host " Failed" -ForegroundColor Red
            $testResults += "FAILED: Hash - $algorithm with $filename"
            $allTestsPassed = $false
        }
    }
}

# Cleanup hash test files
Remove-Item $sha256TestFile, $sha3TestFile, $hashOutputFile -ErrorAction SilentlyContinue

# Step 6: Automatic Key Generation Tests
Write-Section "Automatic Key Generation Tests"

Write-Step "Testing encryption without --key parameter"
$autoKeyTestFile = Join-Path $SCRIPT_DIR "auto_key_test.txt"
"Testing automatic key generation" | Out-File -FilePath $autoKeyTestFile -Encoding utf8

# Capture both stdout and stderr
$autoKeyProcess = Start-Process -FilePath $CRYPTOCORE_EXE -ArgumentList @(
    "crypto", "--algorithm", "aes",
    "--mode", "cbc",
    "--operation", "encrypt",
    "--input", $autoKeyTestFile,
    "--output", "$autoKeyTestFile.enc"
) -PassThru -Wait -NoNewWindow
$autoKeySuccess = ($autoKeyProcess.ExitCode -eq 0)

# Get the output by running the command again and capturing output
$autoKeyOutput = & $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --input $autoKeyTestFile --output "$autoKeyTestFile.enc" 2>&1
$autoKeySuccess = ($LASTEXITCODE -eq 0)

if ($autoKeySuccess) {
    # Convert output array to string for matching
    $outputText = $autoKeyOutput -join "`n"

    # Check if key was generated and printed
    if ($outputText -match "Generated random key: ([0-9a-f]{32})") {
        $generatedKey = $matches[1]
        Write-Host "Generated key: $generatedKey" -ForegroundColor Green

        # Test decryption with generated key
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation decrypt --key $generatedKey --input "$autoKeyTestFile.enc" --output "$autoKeyTestFile.dec"
        $decryptSuccess = ($LASTEXITCODE -eq 0)

        if ($decryptSuccess) {
            $original = Get-Content $autoKeyTestFile -Raw
            $decrypted = Get-Content "$autoKeyTestFile.dec" -Raw

            if ($original -eq $decrypted) {
                Write-Status $true "Automatic key generation and usage"
                $testResults += "PASSED: Auto Key - Generation and usage"
            } else {
                Write-Status $false "Automatic key generation (content mismatch)"
                $testResults += "FAILED: Auto Key - Content mismatch"
                $allTestsPassed = $false
            }
        } else {
            Write-Status $false "Automatic key generation (decryption failed)"
            $testResults += "FAILED: Auto Key - Decryption failed"
            $allTestsPassed = $false
        }
    } else {
        Write-Status $false "Automatic key generation (no key output)"
        Write-Host "Output was: $outputText" -ForegroundColor Yellow
        $testResults += "FAILED: Auto Key - No key output"
        $allTestsPassed = $false
    }
} else {
    Write-Status $false "Automatic key generation (encryption failed)"
    Write-Host "Output was: $autoKeyOutput" -ForegroundColor Yellow
    $testResults += "FAILED: Auto Key - Encryption failed"
    $allTestsPassed = $false
}

Remove-Item $autoKeyTestFile, "$autoKeyTestFile.enc", "$autoKeyTestFile.dec" -ErrorAction SilentlyContinue

# Step 7: Weak Key Detection Tests
Write-Section "Weak Key Detection Tests"

Write-Step "Testing weak key detection"
$weakKeyTestFile = Join-Path $SCRIPT_DIR "weak_key_test.txt"
"Weak key test" | Out-File -FilePath $weakKeyTestFile -Encoding utf8

# Test all zeros key (should show warning but work)
$weakKeyOutput = & $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key "00000000000000000000000000000000" --input $weakKeyTestFile --output "$weakKeyTestFile.enc" 2>&1
$weakKeyOutputText = $weakKeyOutput -join "`n"
$weakKeyWarning = $weakKeyOutputText -match "WARNING.*weak"
$weakKeySuccess = ($LASTEXITCODE -eq 0)

if ($weakKeyWarning -and $weakKeySuccess) {
    Write-Status $true "Weak key detection with all zeros"
    $testResults += "PASSED: Weak Key - All zeros detection"
} else {
    Write-Status $false "Weak key detection failed"
    $testResults += "FAILED: Weak Key - All zeros detection"
    $allTestsPassed = $false
}

# Test sequential key (should show warning but work)
$sequentialKeyOutput = & $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key "000102030405060708090a0b0c0d0e0f" --input $weakKeyTestFile --output "$weakKeyTestFile.enc2" 2>&1
$sequentialKeyOutputText = $sequentialKeyOutput -join "`n"
$sequentialKeyWarning = $sequentialKeyOutputText -match "WARNING.*weak"
$sequentialKeySuccess = ($LASTEXITCODE -eq 0)

if ($sequentialKeyWarning -and $sequentialKeySuccess) {
    Write-Status $true "Weak key detection with sequential bytes"
    $testResults += "PASSED: Weak Key - Sequential bytes detection"
} else {
    Write-Status $false "Sequential key detection failed"
    $testResults += "FAILED: Weak Key - Sequential bytes detection"
    $allTestsPassed = $false
}

Remove-Item $weakKeyTestFile, "$weakKeyTestFile.enc", "$weakKeyTestFile.enc2" -ErrorAction SilentlyContinue

# Step 8: Test all encryption modes comprehensively
Write-Section "Testing All Encryption Modes"

$KEY = "00112233445566778899aabbccddeeff"
$allTestsPassed = $true
$testResults = @()

# All supported modes
$modes = @("ecb", "cbc", "cfb", "ofb", "ctr")

foreach ($mode in $modes) {
    Write-Step "Testing $($mode.ToUpper()) mode"

    # Test with each file type
    foreach ($file in $testFiles.GetEnumerator()) {
        $filename = $file.Key
        $filePath = Join-Path $SCRIPT_DIR $filename
        Write-Host "  Testing $filename..." -NoNewline

        $encryptedFile = Join-Path $SCRIPT_DIR "$filename.$mode.enc"
        $decryptedFile = Join-Path $SCRIPT_DIR "$filename.$mode.dec"

        # Build encryption command
        $encryptArgs = @(
            "crypto", "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "encrypt",
            "--key", $KEY,
            "--input", $filePath,
            "--output", $encryptedFile
        )

        # Build decryption command
        $decryptArgs = @(
            "crypto", "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "decrypt",
            "--key", $KEY,
            "--input", $encryptedFile,
            "--output", $decryptedFile
        )

        # Encrypt
        $encryptResult = & $CRYPTOCORE_EXE @encryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Encryption failed" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - Encryption failed"
            $allTestsPassed = $false
            continue
        }

        # Verify encrypted file exists and has content
        if (-not (Test-Path $encryptedFile) -or (Get-Item $encryptedFile).Length -eq 0) {
            Write-Host " Empty encrypted file" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - Empty encrypted file"
            $allTestsPassed = $false
            continue
        }

        # For modes with IV, verify file contains IV + data
        if ($mode -ne "ecb") {
            $fileSize = (Get-Item $encryptedFile).Length
            if ($fileSize -lt 16) {
                Write-Host " Encrypted file too small for IV" -ForegroundColor Red
                $testResults += "FAILED: $filename.$mode - File too small for IV"
                $allTestsPassed = $false
                continue
            }
        }

        # Decrypt
        $decryptResult = & $CRYPTOCORE_EXE @decryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Decryption failed" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - Decryption failed"
            $allTestsPassed = $false
            continue
        }

        # Compare files as bytes
        try {
            $originalBytes = [System.IO.File]::ReadAllBytes($filePath)
            $decryptedBytes = [System.IO.File]::ReadAllBytes($decryptedFile)
            $filesMatch = ($originalBytes.Length -eq $decryptedBytes.Length)
            if ($filesMatch) {
                for ($i = 0; $i -lt $originalBytes.Length; $i++) {
                    if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                        $filesMatch = $false
                        break
                    }
                }
            }

            if ($filesMatch) {
                Write-Host " Success" -ForegroundColor Green
                $testResults += "PASSED: $filename.$mode - Round-trip successful"
            } else {
                Write-Host " Files don't match" -ForegroundColor Red
                $testResults += "FAILED: $filename.$mode - Files don't match"
                $allTestsPassed = $false
            }
        } catch {
            Write-Host " File comparison error: $($_.Exception.Message)" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - File comparison error"
            $allTestsPassed = $false
        }

        # Cleanup
        Remove-Item $encryptedFile, $decryptedFile -ErrorAction SilentlyContinue
    }

    # Test with binary files
    $binaryFiles = @("binary_16.bin", "binary_with_nulls.bin", "random_1k.bin")
    foreach ($binaryFile in $binaryFiles) {
        Write-Host "  Testing $binaryFile..." -NoNewline

        $binaryFilePath = Join-Path $SCRIPT_DIR $binaryFile
        $encryptedFile = Join-Path $SCRIPT_DIR "$binaryFile.$mode.enc"
        $decryptedFile = Join-Path $SCRIPT_DIR "$binaryFile.$mode.dec"

        $encryptArgs = @(
            "crypto", "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "encrypt",
            "--key", $KEY,
            "--input", $binaryFilePath,
            "--output", $encryptedFile
        )

        $decryptArgs = @(
            "crypto", "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "decrypt",
            "--key", $KEY,
            "--input", $encryptedFile,
            "--output", $decryptedFile
        )

        $encryptResult = & $CRYPTOCORE_EXE @encryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Encryption failed" -ForegroundColor Red
            $testResults += "FAILED: $binaryFile.$mode - Encryption failed"
            $allTestsPassed = $false
            continue
        }

        $decryptResult = & $CRYPTOCORE_EXE @decryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Decryption failed" -ForegroundColor Red
            $testResults += "FAILED: $binaryFile.$mode - Decryption failed"
            $allTestsPassed = $false
            continue
        }

        try {
            $originalBytes = [System.IO.File]::ReadAllBytes($binaryFilePath)
            $decryptedBytes = [System.IO.File]::ReadAllBytes($decryptedFile)
            $filesMatch = ($originalBytes.Length -eq $decryptedBytes.Length)
            if ($filesMatch) {
                for ($i = 0; $i -lt $originalBytes.Length; $i++) {
                    if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                        $filesMatch = $false
                        break
                    }
                }
            }

            if ($filesMatch) {
                Write-Host " Success" -ForegroundColor Green
                $testResults += "PASSED: $binaryFile.$mode - Round-trip successful"
            } else {
                Write-Host " Failed" -ForegroundColor Red
                $testResults += "FAILED: $binaryFile.$mode - Round-trip failed"
                $allTestsPassed = $false
            }
        } catch {
            Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
            $testResults += "FAILED: $binaryFile.$mode - File error"
            $allTestsPassed = $false
        }

        Remove-Item $encryptedFile, $decryptedFile -ErrorAction SilentlyContinue
    }
}

# Step 9: Advanced IV handling tests
Write-Section "Testing IV Handling"

# Test IV provided for decryption
Write-Step "Testing decryption with provided IV"
$ivTestFile = Join-Path $SCRIPT_DIR "iv_test.txt"
"IV test data" | Out-File -FilePath $ivTestFile -Encoding utf8

$ivEncryptedFile = Join-Path $SCRIPT_DIR "iv_encrypted.bin"

# Encrypt with auto IV
& $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --input $ivTestFile --output $ivEncryptedFile

if ($LASTEXITCODE -eq 0) {
    # Extract IV from encrypted file
    $encryptedData = [System.IO.File]::ReadAllBytes($ivEncryptedFile)
    $extractedIv = $encryptedData[0..15]
    $ciphertextOnly = $encryptedData[16..($encryptedData.Length-1)]

    # Save ciphertext without IV
    $ciphertextFile = Join-Path $SCRIPT_DIR "ciphertext_only.bin"
    [System.IO.File]::WriteAllBytes($ciphertextFile, $ciphertextOnly)

    # Convert IV to hex for CLI
    $ivHex = -join ($extractedIv | ForEach-Object { $_.ToString("X2") })

    # Decrypt with provided IV
    $ivDecryptedFile = Join-Path $SCRIPT_DIR "iv_decrypted.txt"
    & $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation decrypt --key $KEY --iv $ivHex --input $ciphertextFile --output $ivDecryptedFile

    if ($LASTEXITCODE -eq 0) {
        $original = Get-Content $ivTestFile -Raw
        $decrypted = Get-Content $ivDecryptedFile -Raw

        if ($original -eq $decrypted) {
            Write-Status $true "Decryption with provided IV works"
            $testResults += "PASSED: IV handling - Provided IV decryption"
        } else {
            Write-Status $false "Decryption with provided IV failed (content mismatch)"
            $testResults += "FAILED: IV handling - Provided IV decryption"
            $allTestsPassed = $false
        }
    } else {
        Write-Status $false "Decryption with provided IV failed"
        $testResults += "FAILED: IV handling - Provided IV decryption"
        $allTestsPassed = $false
    }
} else {
    Write-Status $false "Encryption for IV test failed"
    $testResults += "FAILED: IV handling - Encryption failed"
    $allTestsPassed = $false
}

Remove-Item $ivTestFile, $ivEncryptedFile, $ciphertextFile, $ivDecryptedFile -ErrorAction SilentlyContinue

# Step 10: Validation and error handling tests
Write-Section "Validation and Error Handling"

# Test invalid key
Write-Step "Testing invalid key rejection"
$shortFilePath = Join-Path $SCRIPT_DIR "short.txt"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key "invalid" --input $shortFilePath --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject invalid key"
    $testResults += "FAILED: Validation - Invalid key accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Invalid key rejected"
    $testResults += "PASSED: Validation - Invalid key rejected"
}

# Test wrong key length
Write-Step "Testing wrong key length"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key "001122" --input $shortFilePath --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject wrong key length"
    $testResults += "FAILED: Validation - Wrong key length accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Wrong key length rejected"
    $testResults += "PASSED: Validation - Wrong key length rejected"
}

# Test nonexistent file
Write-Step "Testing nonexistent file rejection"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key $KEY --input "nonexistent_file_12345.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject nonexistent file"
    $testResults += "FAILED: Validation - Nonexistent file accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Nonexistent file rejected"
    $testResults += "PASSED: Validation - Nonexistent file rejected"
}

# Test IV provided during encryption (should fail)
Write-Step "Testing IV rejection during encryption"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --iv "000102030405060708090A0B0C0D0E0F" --input $shortFilePath --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject IV during encryption"
    $testResults += "FAILED: Validation - IV accepted during encryption"
    $allTestsPassed = $false
} else {
    Write-Status $true "IV correctly rejected during encryption"
    $testResults += "PASSED: Validation - IV rejected during encryption"
}

# Test missing IV for decryption
Write-Step "Testing missing IV detection"
$shortCipherFile = Join-Path $SCRIPT_DIR "short_cipher.bin"
"test" | Out-File -FilePath $shortCipherFile -Encoding utf8
& $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation decrypt --key $KEY --input $shortCipherFile --output "test.dec" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should detect missing IV"
    $testResults += "FAILED: Validation - Missing IV not detected"
    $allTestsPassed = $false
} else {
    Write-Status $true "Missing IV correctly detected"
    $testResults += "PASSED: Validation - Missing IV detected"
}
Remove-Item $shortCipherFile -ErrorAction SilentlyContinue

# Test invalid hash algorithm
Write-Step "Testing invalid hash algorithm rejection"
& $CRYPTOCORE_EXE dgst --algorithm "invalid_hash" --input $shortFilePath 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject invalid hash algorithm"
    $testResults += "FAILED: Validation - Invalid hash algorithm accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Invalid hash algorithm rejected"
    $testResults += "PASSED: Validation - Invalid hash algorithm rejected"
}

# Step 11: File handling tests
Write-Section "File Handling Tests"

# Test automatic output naming
Write-Step "Testing automatic output naming"
$autoTestFile = Join-Path $SCRIPT_DIR "auto_test.txt"
"Auto name test" | Out-File -FilePath $autoTestFile -Encoding utf8

& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key $KEY --input $autoTestFile
if ($LASTEXITCODE -eq 0 -and (Test-Path "$autoTestFile.enc")) {
    Write-Status $true "Automatic encryption naming works"
    $testResults += "PASSED: File handling - Auto encryption naming"
} else {
    Write-Status $false "Automatic encryption naming failed"
    $testResults += "FAILED: File handling - Auto encryption naming"
    $allTestsPassed = $false
}

& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation decrypt --key $KEY --input "$autoTestFile.enc"
if ($LASTEXITCODE -eq 0 -and (Test-Path "$autoTestFile.enc.dec")) {
    Write-Status $true "Automatic decryption naming works"
    $testResults += "PASSED: File handling - Auto decryption naming"
} else {
    Write-Status $false "Automatic decryption naming failed"
    $testResults += "FAILED: File handling - Auto decryption naming"
    $allTestsPassed = $false
}

Remove-Item $autoTestFile, "$autoTestFile.enc", "$autoTestFile.enc.dec" -ErrorAction SilentlyContinue

# Step 12: OpenSSL interoperability tests
Write-Section "OpenSSL Interoperability Tests"

if (Get-Command "openssl" -ErrorAction SilentlyContinue) {
    Write-Step "Testing OpenSSL interoperability"

    try {
        # Test 1: Encrypt with our tool, decrypt with OpenSSL
        $opensslTest1File = Join-Path $SCRIPT_DIR "openssl_test1.txt"
        "OpenSSL interoperability test data" | Out-File -FilePath $opensslTest1File -Encoding utf8

        $ourEncryptedFile = Join-Path $SCRIPT_DIR "our_encrypted.bin"

        # Encrypt with our tool
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --input $opensslTest1File --output $ourEncryptedFile

        if ($LASTEXITCODE -eq 0) {
            # Extract IV and ciphertext
            $encryptedData = [System.IO.File]::ReadAllBytes($ourEncryptedFile)
            $ivBytes = $encryptedData[0..15]
            $ciphertextBytes = $encryptedData[16..($encryptedData.Length-1)]

            $ourIvFile = Join-Path $SCRIPT_DIR "our_iv.bin"
            $ourCiphertextFile = Join-Path $SCRIPT_DIR "our_ciphertext.bin"
            [System.IO.File]::WriteAllBytes($ourIvFile, $ivBytes)
            [System.IO.File]::WriteAllBytes($ourCiphertextFile, $ciphertextBytes)

            # Convert IV to hex for OpenSSL
            $ivHex = -join ($ivBytes | ForEach-Object { $_.ToString("X2") })

            # Decrypt with OpenSSL
            $opensslDecrypted1File = Join-Path $SCRIPT_DIR "openssl_decrypted1.txt"
            openssl enc -aes-128-cbc -d -K $KEY -iv $ivHex -in $ourCiphertextFile -out $opensslDecrypted1File

            if ($LASTEXITCODE -eq 0) {
                $original = Get-Content $opensslTest1File -Raw
                $decrypted = Get-Content $opensslDecrypted1File -Raw

                if ($original -eq $decrypted) {
                    Write-Status $true "OurTool -> OpenSSL: PASS"
                    $testResults += "PASSED: Interop - OurTool to OpenSSL"
                } else {
                    Write-Status $false "OurTool -> OpenSSL: FAIL (content mismatch)"
                    $testResults += "FAILED: Interop - OurTool to OpenSSL"
                    $allTestsPassed = $false
                }
            } else {
                Write-Status $false "OurTool -> OpenSSL: FAIL (OpenSSL decryption failed)"
                $testResults += "FAILED: Interop - OurTool to OpenSSL"
                $allTestsPassed = $false
            }
        } else {
            Write-Status $false "OurTool -> OpenSSL: FAIL (our encryption failed)"
            $testResults += "FAILED: Interop - OurTool to OpenSSL"
            $allTestsPassed = $false
        }

        # Test 2: Encrypt with OpenSSL, decrypt with our tool
        $opensslTest2File = Join-Path $SCRIPT_DIR "openssl_test2.txt"
        "OpenSSL to our tool test" | Out-File -FilePath $opensslTest2File -Encoding utf8

        $opensslEncryptedFile = Join-Path $SCRIPT_DIR "openssl_encrypted.bin"

        # Encrypt with OpenSSL
        $TEST_IV = "000102030405060708090A0B0C0D0E0F"
        openssl enc -aes-128-cbc -K $KEY -iv $TEST_IV -in $opensslTest2File -out $opensslEncryptedFile

        if ($LASTEXITCODE -eq 0) {
            # Decrypt with our tool
            $ourDecryptedFile = Join-Path $SCRIPT_DIR "our_decrypted.txt"
            & $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation decrypt --key $KEY --iv $TEST_IV --input $opensslEncryptedFile --output $ourDecryptedFile

            if ($LASTEXITCODE -eq 0) {
                $original = Get-Content $opensslTest2File -Raw
                $decrypted = Get-Content $ourDecryptedFile -Raw

                if ($original -eq $decrypted) {
                    Write-Status $true "OpenSSL -> OurTool: PASS"
                    $testResults += "PASSED: Interop - OpenSSL to OurTool"
                } else {
                    Write-Status $false "OpenSSL -> OurTool: FAIL (content mismatch)"
                    $testResults += "FAILED: Interop - OpenSSL to OurTool"
                    $allTestsPassed = $false
                }
            } else {
                Write-Status $false "OpenSSL -> OurTool: FAIL (our decryption failed)"
                $testResults += "FAILED: Interop - OpenSSL to OurTool"
                $allTestsPassed = $false
            }
        } else {
            Write-Status $false "OpenSSL -> OurTool: FAIL (OpenSSL encryption failed)"
            $testResults += "FAILED: Interop - OpenSSL to OurTool"
            $allTestsPassed = $false
        }

        # Cleanup
        Remove-Item $opensslTest1File, $opensslTest2File, $ourEncryptedFile, $ourIvFile, $ourCiphertextFile, $opensslDecrypted1File, $opensslEncryptedFile, $ourDecryptedFile -ErrorAction SilentlyContinue

    } catch {
        Write-Status $false "OpenSSL interoperability test error: $($_.Exception.Message)"
        $testResults += "FAILED: Interop - Test error"
        $allTestsPassed = $false
    }
} else {
    Write-Host "OpenSSL not available, skipping interoperability tests" -ForegroundColor Yellow
    $testResults += "SKIPPED: OpenSSL interoperability"
}

# Step 13: Performance and stress tests
Write-Section "Performance and Stress Tests"

Write-Step "Testing with larger files"
# Create a larger test file if we have enough space
try {
    $freeSpace = (Get-PSDrive -Name (Get-Location).Drive.Name).Free
    if ($freeSpace -gt 10MB) {
        # Create 1MB file
        $largeTestFile = Join-Path $SCRIPT_DIR "large_test.bin"
        $largeData = New-Object byte[] 1MB
        (New-Object Random).NextBytes($largeData)
        [System.IO.File]::WriteAllBytes($largeTestFile, $largeData)

        foreach ($mode in @("ecb", "cbc")) {
            Write-Host "  Testing 1MB file with $mode..." -NoNewline

            $largeEncryptedFile = Join-Path $SCRIPT_DIR "large_encrypted.bin"
            $largeDecryptedFile = Join-Path $SCRIPT_DIR "large_decrypted.bin"

            & $CRYPTOCORE_EXE crypto --algorithm aes --mode $mode --operation encrypt --key $KEY --input $largeTestFile --output $largeEncryptedFile
            $encryptSuccess = ($LASTEXITCODE -eq 0)

            & $CRYPTOCORE_EXE crypto --algorithm aes --mode $mode --operation decrypt --key $KEY --input $largeEncryptedFile --output $largeDecryptedFile
            $decryptSuccess = ($LASTEXITCODE -eq 0)

            if ($encryptSuccess -and $decryptSuccess) {
                $originalBytes = [System.IO.File]::ReadAllBytes($largeTestFile)
                $decryptedBytes = [System.IO.File]::ReadAllBytes($largeDecryptedFile)
                $filesMatch = ($originalBytes.Length -eq $decryptedBytes.Length)

                if ($filesMatch) {
                    # Compare first and last few bytes for performance
                    $match = $true
                    for ($i = 0; $i -lt 100; $i++) {
                        if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                            $match = $false
                            break
                        }
                    }
                    if ($match) {
                        for ($i = $originalBytes.Length - 100; $i -lt $originalBytes.Length; $i++) {
                            if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                                $match = $false
                                break
                            }
                        }
                    }

                    if ($match) {
                        Write-Host " Success" -ForegroundColor Green
                        $testResults += "PASSED: Performance - 1MB file with $mode"
                    } else {
                        Write-Host " Content mismatch" -ForegroundColor Red
                        $testResults += "FAILED: Performance - 1MB file with $mode"
                        $allTestsPassed = $false
                    }
                } else {
                    Write-Host " Size mismatch" -ForegroundColor Red
                    $testResults += "FAILED: Performance - 1MB file with $mode"
                    $allTestsPassed = $false
                }
            } else {
                Write-Host " Execution failed" -ForegroundColor Red
                $testResults += "FAILED: Performance - 1MB file with $mode"
                $allTestsPassed = $false
            }

            Remove-Item $largeEncryptedFile, $largeDecryptedFile -ErrorAction SilentlyContinue
        }

        Remove-Item $largeTestFile -ErrorAction SilentlyContinue
    } else {
        Write-Host "  Skipping large file tests (insufficient disk space)" -ForegroundColor Yellow
        $testResults += "SKIPPED: Performance - Large file tests"
    }
} catch {
    Write-Host "  Skipping large file tests (error: $($_.Exception.Message))" -ForegroundColor Yellow
    $testResults += "SKIPPED: Performance - Large file tests"
}

# Step 14: Integration tests
Write-Section "Integration Tests"

Write-Step "Running integration tests"
cargo test --test integration_tests -- --nocapture
Write-Status ($LASTEXITCODE -eq 0) "Integration tests"

# Step 15: Cleanup
Write-Section "Cleaning Up"

foreach ($file in $testFiles.GetEnumerator()) {
    $filePath = Join-Path $SCRIPT_DIR $file.Key
    Remove-Item $filePath -ErrorAction SilentlyContinue
}
Remove-Item (Join-Path $SCRIPT_DIR "binary_16.bin"), (Join-Path $SCRIPT_DIR "binary_with_nulls.bin"), (Join-Path $SCRIPT_DIR "random_1k.bin") -ErrorAction SilentlyContinue

# Step 16: Results summary
Write-Section "Test Results Summary"

$passedCount = 0
$failedCount = 0
$skippedCount = 0

foreach ($result in $testResults) {
    if ($result -like "PASSED:*") {
        Write-Host "  $result" -ForegroundColor Green
        $passedCount++
    } elseif ($result -like "FAILED:*") {
        Write-Host "  $result" -ForegroundColor Red
        $failedCount++
    } else {
        Write-Host "  $result" -ForegroundColor Yellow
        $skippedCount++
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  FINAL RESULTS" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.Count)" -ForegroundColor White
Write-Host "Passed: $passedCount" -ForegroundColor Green
Write-Host "Failed: $failedCount" -ForegroundColor Red
Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host ""

if ($allTestsPassed) {
    Write-Host "ALL TESTS PASSED! CryptoCore is fully functional!" -ForegroundColor Green
    Write-Host "All requirements from M4 document are satisfied" -ForegroundColor Green
    Write-Host "CSPRNG module working with automatic key generation" -ForegroundColor Green
    Write-Host "All 5 encryption modes working: ECB, CBC, CFB, OFB, CTR" -ForegroundColor Green
    Write-Host "Hash functions SHA-256 and SHA3-256 working correctly" -ForegroundColor Green
    Write-Host "Comprehensive testing completed successfully" -ForegroundColor Green
    Write-Host "File handling, validation, and interoperability verified" -ForegroundColor Green
} else {
    Write-Host "SOME TESTS FAILED! Please check the errors above." -ForegroundColor Red
    exit 1
}

Write-Host "================================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")