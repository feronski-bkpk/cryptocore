# test.ps1 - Automated testing for Windows PowerShell

Write-Host "Starting CryptoCore Automated Tests..." -ForegroundColor Cyan

# Step 1: Build project
Write-Host "Building project..." -ForegroundColor Yellow
cargo build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "Build successful!" -ForegroundColor Green

# Step 2: Test help command
Write-Host "Testing help command..." -ForegroundColor Yellow
.\target\debug\cryptocore.exe --help
if ($LASTEXITCODE -eq 0) {
    Write-Host "Help command works" -ForegroundColor Green
} else {
    Write-Host "Help command failed" -ForegroundColor Red
}

# Step 3: Create test files
Write-Host "Creating test files..." -ForegroundColor Yellow
$testFiles = @{
    "short.txt" = "Short test"
    "medium.txt" = "This is a medium length test file for encryption"
    "long.txt" = "This is a much longer test file that contains more data to ensure encryption works properly with different data sizes and padding."
    "empty.txt" = ""
}

foreach ($file in $testFiles.GetEnumerator()) {
    $file.Value | Out-File -FilePath $file.Key -Encoding utf8
    Write-Host "Created $($file.Key)" -ForegroundColor Gray
}

# Step 4: Test encryption/decryption
$KEY = "00112233445566778899aabbccddeeff"
Write-Host "Testing encryption/decryption..." -ForegroundColor Yellow

$allTestsPassed = $true
$testResults = @()

foreach ($file in $testFiles.GetEnumerator()) {
    $filename = $file.Key
    $originalContent = $file.Value

    Write-Host "Testing $filename..." -NoNewline

    $encryptedFile = "$filename.enc"
    $decryptedFile = "$filename.dec"

    # Encrypt
    $encryptResult = .\target\debug\cryptocore.exe --algorithm aes --mode ecb --operation encrypt --key $KEY --input $filename --output $encryptedFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host " Encryption failed" -ForegroundColor Red
        $testResults += "FAILED: $filename - Encryption failed"
        $allTestsPassed = $false
        continue
    }

    # Decrypt
    $decryptResult = .\target\debug\cryptocore.exe --algorithm aes --mode ecb --operation decrypt --key $KEY --input $encryptedFile --output $decryptedFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host " Decryption failed" -ForegroundColor Red
        $testResults += "FAILED: $filename - Decryption failed"
        $allTestsPassed = $false
        continue
    }

    # Compare files
    $originalContent = Get-Content $filename -Raw
    $decryptedContent = Get-Content $decryptedFile -Raw
    $filesMatch = ($originalContent -eq $decryptedContent)

    if ($filesMatch) {
        Write-Host " Success" -ForegroundColor Green
        $testResults += "PASSED: $filename - Round-trip successful"
    } else {
        Write-Host " Files don't match" -ForegroundColor Red
        $testResults += "FAILED: $filename - Files don't match"
        $allTestsPassed = $false
    }

    # Cleanup
    Remove-Item $encryptedFile, $decryptedFile -ErrorAction SilentlyContinue
}

# Step 5: Test validation
Write-Host "Testing argument validation..." -ForegroundColor Yellow

# Test invalid key
.\target\debug\cryptocore.exe --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "test.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Should reject invalid key" -ForegroundColor Red
    $testResults += "FAILED: Validation - Invalid key accepted"
    $allTestsPassed = $false
} else {
    Write-Host "Invalid key rejected" -ForegroundColor Green
    $testResults += "PASSED: Validation - Invalid key rejected"
}

# Test nonexistent file
.\target\debug\cryptocore.exe --algorithm aes --mode ecb --operation encrypt --key $KEY --input "nonexistent_file_12345.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Should reject nonexistent file" -ForegroundColor Red
    $testResults += "FAILED: Validation - Nonexistent file accepted"
    $allTestsPassed = $false
} else {
    Write-Host "Nonexistent file rejected" -ForegroundColor Green
    $testResults += "PASSED: Validation - Nonexistent file rejected"
}

# Step 6: Test automatic output naming
Write-Host "Testing automatic output naming..." -ForegroundColor Yellow
"Auto name test" | Out-File -FilePath auto_test.txt -Encoding utf8

.\target\debug\cryptocore.exe --algorithm aes --mode ecb --operation encrypt --key $KEY --input auto_test.txt
if ($LASTEXITCODE -eq 0 -and (Test-Path "auto_test.txt.enc")) {
    Write-Host "Automatic encryption naming works" -ForegroundColor Green
    $testResults += "PASSED: Auto naming - Encryption works"
} else {
    Write-Host "Automatic encryption naming failed" -ForegroundColor Red
    $testResults += "FAILED: Auto naming - Encryption failed"
    $allTestsPassed = $false
}

.\target\debug\cryptocore.exe --algorithm aes --mode ecb --operation decrypt --key $KEY --input auto_test.txt.enc
if ($LASTEXITCODE -eq 0 -and (Test-Path "auto_test.txt.enc.dec")) {
    Write-Host "Automatic decryption naming works" -ForegroundColor Green
    $testResults += "PASSED: Auto naming - Decryption works"
} else {
    Write-Host "Automatic decryption naming failed" -ForegroundColor Red
    $testResults += "FAILED: Auto naming - Decryption failed"
    $allTestsPassed = $false
}

Remove-Item auto_test.txt, auto_test.txt.enc, auto_test.txt.enc.dec -ErrorAction SilentlyContinue

# Step 7: Cleanup test files
Write-Host "Cleaning up..." -ForegroundColor Yellow
foreach ($file in $testFiles.GetEnumerator()) {
    Remove-Item $file.Key -ErrorAction SilentlyContinue
}

# Step 8: Print detailed results
Write-Host "Test Results:" -ForegroundColor Cyan
foreach ($result in $testResults) {
    if ($result -like "PASSED:*") {
        Write-Host "  $result" -ForegroundColor Green
    } else {
        Write-Host "  $result" -ForegroundColor Red
    }
}

# Final result
Write-Host "==================================================" -ForegroundColor Cyan
if ($allTestsPassed) {
    Write-Host "ALL TESTS PASSED! CryptoCore is working correctly!" -ForegroundColor Green
    Write-Host "All requirements from M1 document are satisfied" -ForegroundColor Green
} else {
    Write-Host "SOME TESTS FAILED! Please check the errors above." -ForegroundColor Red
    exit 1
}
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")