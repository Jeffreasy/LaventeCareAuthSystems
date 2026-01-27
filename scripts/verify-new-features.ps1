# LaventeCare Auth Systems - New Features Verification Script
# Tests all 6 newly added endpoints on production

$BASE_URL = "https://laventecareauthsystems.onrender.com/api/v1"
$TENANT_ID = "550e8400-e29b-41d4-a716-446655440000"  # Replace with your actual tenant ID

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "LaventeCare Auth - Feature Verification" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Colors for output
$Success = "Green"
$Warning = "Yellow"
$Error = "Red"
$Info = "Cyan"

# Test counter
$testsPassed = 0
$testsFailed = 0

# Helper function to test endpoint
function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Url,
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$ExpectedStatus = 200
    )
    
    Write-Host "Testing: $Name" -ForegroundColor $Info
    Write-Host "  $Method $Url" -ForegroundColor Gray
    
    try {
        $params = @{
            Uri         = $Url
            Method      = $Method
            Headers     = $Headers
            ContentType = "application/json"
        }
        
        if ($Body) {
            $params.Body = $Body
        }
        
        $response = Invoke-WebRequest @params -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq $ExpectedStatus) {
            Write-Host "  ✅ PASS - Status: $($response.StatusCode)" -ForegroundColor $Success
            $script:testsPassed++
            
            # Show response preview
            if ($response.Content) {
                $preview = ($response.Content | ConvertFrom-Json | ConvertTo-Json -Compress).Substring(0, [Math]::Min(100, $response.Content.Length))
                Write-Host "  Response: $preview..." -ForegroundColor Gray
            }
            return $true
        }
        else {
            Write-Host "  ❌ FAIL - Expected $ExpectedStatus, got $($response.StatusCode)" -ForegroundColor $Error
            $script:testsFailed++
            return $false
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq $ExpectedStatus) {
            Write-Host "  ✅ PASS - Status: $statusCode (expected)" -ForegroundColor $Success
            $script:testsPassed++
            
            # Try to show error message
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                $preview = $responseBody.Substring(0, [Math]::Min(100, $responseBody.Length))
                Write-Host "  Response: $preview..." -ForegroundColor Gray
            }
            catch {}
            
            return $true
        }
        else {
            Write-Host "  ❌ FAIL - Expected $ExpectedStatus, got $statusCode" -ForegroundColor $Error
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor $Error
            $script:testsFailed++
            return $false
        }
    }
    
    Write-Host ""
}

# ============================================
# TEST 1: Password Reset - Request
# ============================================
Write-Host "`n[1/6] Password Reset - Request Email" -ForegroundColor Yellow
Test-Endpoint `
    -Name "POST /auth/password/forgot" `
    -Method "POST" `
    -Url "$BASE_URL/auth/password/forgot" `
    -Headers @{
    "X-Tenant-ID" = $TENANT_ID
} `
    -Body '{"email":"test@example.com"}' `
    -ExpectedStatus 200

# ============================================
# TEST 2: Password Reset - Complete (should fail without valid token)
# ============================================
Write-Host "`n[2/6] Password Reset - Complete (Invalid Token)" -ForegroundColor Yellow
Test-Endpoint `
    -Name "POST /auth/password/reset" `
    -Method "POST" `
    -Url "$BASE_URL/auth/password/reset" `
    -Body '{"token":"invalid-token-12345","new_password":"TestPass123!"}' `
    -ExpectedStatus 401

# ============================================
# TEST 3: Email Verification - Resend
# ============================================
Write-Host "`n[3/6] Email Verification - Resend" -ForegroundColor Yellow
Test-Endpoint `
    -Name "POST /auth/email/resend" `
    -Method "POST" `
    -Url "$BASE_URL/auth/email/resend" `
    -Headers @{
    "X-Tenant-ID" = $TENANT_ID
} `
    -Body '{"email":"test@example.com"}' `
    -ExpectedStatus 200

# ============================================
# TEST 4: Email Verification - Verify (should fail without valid token)
# ============================================
Write-Host "`n[4/6] Email Verification - Verify (Invalid Token)" -ForegroundColor Yellow
Test-Endpoint `
    -Name "POST /auth/email/verify" `
    -Method "POST" `
    -Url "$BASE_URL/auth/email/verify" `
    -Body '{"token":"invalid-token-12345"}' `
    -ExpectedStatus 401

# ============================================
# TEST 5: Existing Endpoint - Token Refresh (should fail without cookie)
# ============================================
Write-Host "`n[5/6] Token Refresh (No Cookie - Should Fail)" -ForegroundColor Yellow
Test-Endpoint `
    -Name "POST /auth/refresh" `
    -Method "POST" `
    -Url "$BASE_URL/auth/refresh" `
    -ExpectedStatus 401

# ============================================
# TEST 6: Audit Logs (should fail - no auth)
# ============================================
Write-Host "`n[6/6] Audit Logs - Unauthorized Access" -ForegroundColor Yellow
Test-Endpoint `
    -Name "GET /admin/audit-logs (No Auth)" `
    -Method "GET" `
    -Url "$BASE_URL/admin/audit-logs?page=1&limit=10" `
    -Headers @{
    "X-Tenant-ID" = $TENANT_ID
} `
    -ExpectedStatus 401

# ============================================
# SUMMARY
# ============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($testsPassed + $testsFailed)" -ForegroundColor White
Write-Host "Passed: $testsPassed" -ForegroundColor $Success
Write-Host "Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -eq 0) { $Success } else { $Error })

if ($testsFailed -eq 0) {
    Write-Host "`n✅ All endpoints operational!" -ForegroundColor $Success
    Write-Host "All new features successfully deployed and responding correctly.`n" -ForegroundColor $Success
    exit 0
}
else {
    Write-Host "`n⚠️ Some tests failed" -ForegroundColor $Warning
    Write-Host "Check the output above for details.`n" -ForegroundColor $Warning
    exit 1
}
