#!/usr/bin/env pwsh
# Script to generate secure secrets for LaventeCare Auth Systems

Write-Host "🔐 LaventeCare Auth Systems - Secret Generator" -ForegroundColor Cyan
Write-Host ""

# Function to generate random base64 string
function New-RandomSecret {
    param(
        [int]$Length = 32
    )
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

# Generate JWT Secret
Write-Host "Generating JWT_SECRET..." -ForegroundColor Yellow
$jwtSecret = New-RandomSecret -Length 32
Write-Host "✅ JWT_SECRET generated (44 characters)" -ForegroundColor Green
Write-Host ""

# Display results
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "COPY THESE VALUES TO RENDER DASHBOARD" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "JWT_SECRET:" -ForegroundColor White
Write-Host $jwtSecret -ForegroundColor Green
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Instructions
Write-Host "📋 Next Steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Go to Render Dashboard → Your Service → Environment" -ForegroundColor White
Write-Host "2. Click 'Add Environment Variable'" -ForegroundColor White
Write-Host "3. Add 'JWT_SECRET' with the value above" -ForegroundColor White
Write-Host "4. Save changes (this will trigger a redeployment)" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  WARNING: Keep these secrets secure!" -ForegroundColor Red
Write-Host "   - Never commit to Git" -ForegroundColor Red
Write-Host "   - Never share in plain text" -ForegroundColor Red
Write-Host "   - Store in password manager if needed" -ForegroundColor Red
Write-Host ""

# Optional: Save to file
$saveToFile = Read-Host "Save to .env.local file? (y/N)"
if ($saveToFile -eq 'y' -or $saveToFile -eq 'Y') {
    $envContent = @"
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# DO NOT COMMIT THIS FILE TO GIT

# JWT Secret (Auto-generated)
JWT_SECRET=$jwtSecret

# Database URL (Update with your Render PostgreSQL connection string)
DATABASE_URL=postgres://user:password@host:port/database?sslmode=require

# App Configuration
APP_ENV=production
PORT=8080
APP_URL=https://your-app.onrender.com

# Observability (Optional)
SENTRY_DSN=

# Auth Config
ALLOW_PUBLIC_REGISTRATION=false
"@
    
    $envContent | Out-File -FilePath ".env.local" -Encoding UTF8
    Write-Host "✅ Saved to .env.local" -ForegroundColor Green
    Write-Host ""
    
    # Add to .gitignore if not present
    if (Test-Path ".gitignore") {
        $gitignoreContent = Get-Content ".gitignore" -Raw
        if (-not ($gitignoreContent -match "\.env\.local")) {
            Add-Content ".gitignore" "`n# Local environment secrets`n.env.local"
            Write-Host "✅ Added .env.local to .gitignore" -ForegroundColor Green
        }
    } else {
        ".env.local" | Out-File -FilePath ".gitignore" -Encoding UTF8
        Write-Host "✅ Created .gitignore with .env.local" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "🎉 Secret generation complete!" -ForegroundColor Green
