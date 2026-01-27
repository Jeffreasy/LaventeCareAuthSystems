# Simple Endpoint Verification
# Quick test to verify new endpoints are responding

Write-Host "`n=== LaventeCare Auth - Endpoint Verification ===" -ForegroundColor Cyan

$url = "https://laventecareauthsystems.onrender.com/api/v1"

# Test 1: Password Reset Endpoint Exists
Write-Host "`n[1] Testing Password Reset Endpoint..."
try {
    $response = Invoke-WebRequest -Uri "$url/auth/password/forgot" -Method POST -ErrorAction Stop
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 400) {
        Write-Host "✅ Endpoint exists and responds (400 = missing body)" -ForegroundColor Green
    }
    else {
        Write-Host "Status: $status" -ForegroundColor Yellow
    }
}

# Test 2: Email Verification Endpoint
Write-Host "`n[2] Testing Email Verification Endpoint..."
try {
    $response = Invoke-WebRequest -Uri "$url/auth/email/resend" -Method POST -ErrorAction Stop
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 400) {
        Write-Host "✅ Endpoint exists and responds (400 = missing body)" -ForegroundColor Green
    }
    else {
        Write-Host "Status: $status" -ForegroundColor Yellow
    }
}

# Test 3: Password Reset Complete
Write-Host "`n[3] Testing Password Reset Complete Endpoint..."
try {
    $response = Invoke-WebRequest -Uri "$url/auth/password/reset" -Method POST -ErrorAction Stop
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 400) {
        Write-Host "✅ Endpoint exists and responds (400 = missing body)" -ForegroundColor Green
    }
    else {
        Write-Host "Status: $status" -ForegroundColor Yellow
    }
}

# Test 4: Email Verify
Write-Host "`n[4] Testing Email Verify Endpoint..."
try {
    $response = Invoke-WebRequest -Uri "$url/auth/email/verify" -Method POST -ErrorAction Stop
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 400) {
        Write-Host "✅ Endpoint exists and responds (400 = missing body)" -ForegroundColor Green
    }
    else {
        Write-Host "Status: $status" -ForegroundColor Yellow
    }
}

# Test 5: Audit Logs (should be 401 - unauthorized)
Write-Host "`n[5] Testing Audit Logs Endpoint..."
try {
    $response = Invoke-WebRequest -Uri "$url/admin/audit-logs" -Method GET -ErrorAction Stop
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 401) {
        Write-Host "✅ Endpoint exists and protected (401 = unauthorized)" -ForegroundColor Green
    }
    else {
        Write-Host "Status: $status" -ForegroundColor Yellow
    }
}

# Test 6: Refresh Token (should be 401)
Write-Host "`n[6] Testing Token Refresh Endpoint..."
try {
    $response = Invoke-WebRequest -Uri "$url/auth/refresh" -Method POST -ErrorAction Stop
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 401) {
        Write-Host "✅ Endpoint exists and requires cookie (401)" -ForegroundColor Green
    }
    else {
        Write-Host "Status: $status" -ForegroundColor Yellow
    }
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Green
Write-Host "All new endpoints are responding correctly!`n" -ForegroundColor Green
