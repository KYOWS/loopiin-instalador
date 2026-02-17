# --- Configurações de Cores ---
$Cyan = "Cyan"
$Yellow = "Yellow"
$Green = "Green"
$Red = "Red"
$White = "White"

Write-Host "==========================================" -ForegroundColor $Cyan
Write-Host "   GERADOR DE ACESSO SSH (WINDOWS)        " -ForegroundColor $Cyan
Write-Host "==========================================" -ForegroundColor $Cyan
Write-Host ""

# 1. Coleta de Dados
Write-Host "Responda as perguntas abaixo:" -ForegroundColor $Yellow

$KeyName = Read-Host "1. Nome do arquivo da chave (ex: id_hostinger)"
if ([string]::IsNullOrWhiteSpace($KeyName)) { Write-Host "Erro: Nome inválido!" -ForegroundColor $Red; exit }

$KeyComment = Read-Host "2. Seu Email ou Comentário (ex: email@email)"
$HostAlias = Read-Host "3. Apelido do Servidor (ex: kvm4)"
$HostIP = Read-Host "4. IP do Servidor (ex: xxx.xxx.xxx.xx)"
$HostUser = Read-Host "5. Usuário Remoto (ex: root)"

$UserHome = $env:USERPROFILE
$SshDir = "$UserHome\.ssh"
$KeyPath = "$SshDir\$KeyName"
$ConfigFile = "$SshDir\config"

# 2. Verifica/Cria pasta .ssh
if (-not (Test-Path -Path $SshDir)) {
    New-Item -ItemType Directory -Force -Path $SshDir | Out-Null
    Write-Host "Pasta .ssh criada." -ForegroundColor $Green
}

# 3. Gera a Chave SSH
if (Test-Path -Path $KeyPath) {
    Write-Host "⚠️  A chave '$KeyName' já existe!" -ForegroundColor $Red
    $Overwrite = Read-Host "Deseja sobrescrever? (s/n)"
    if ($Overwrite -eq 's') {
        Remove-Item "$KeyPath"
        Remove-Item "$KeyPath.pub"
        # Gera chave nova
        ssh-keygen -t ed25519 -f "$KeyPath" -C "$KeyComment" -N "" -q
        Write-Host "✅ Nova chave gerada." -ForegroundColor $Green
    } else {
        Write-Host "Mantendo a chave existente." -ForegroundColor $Yellow
    }
} else {
    ssh-keygen -t ed25519 -f "$KeyPath" -C "$KeyComment" -N "" -q
    Write-Host "✅ Chave criada com sucesso." -ForegroundColor $Green
}

# 4. Configura o arquivo config
if (-not (Test-Path -Path $ConfigFile)) {
    New-Item -ItemType File -Force -Path $ConfigFile | Out-Null
}

$ConfigContent = Get-Content $ConfigFile -Raw -ErrorAction SilentlyContinue

# --- [NOVO] Configurações Globais (Agente e Compatibilidade) ---
# Verifica se já existe a config global para não duplicar
if ($ConfigContent -notmatch "IgnoreUnknown AddKeysToAgent") {
    Write-Host "⚙️ Adicionando configurações globais de compatibilidade..." -ForegroundColor $Yellow
    $GlobalBlock = @"
Host *
    IgnoreUnknown AddKeysToAgent,UseKeychain
    AddKeysToAgent yes
    # UseKeychain yes <-- somente habilitar se usar o Mac
"@
    # Adiciona no início ou fim. Aqui adicionamos antes do bloco novo.
    Add-Content -Path $ConfigFile -Value $GlobalBlock
}

# --- Configuração do Servidor Específico ---
if ($ConfigContent -match "Host $HostAlias") {
    Write-Host "⚠️  Já existe configuração para '$HostAlias'." -ForegroundColor $Red
} else {
    Write-Host "📝 Atualizando arquivo config..." -ForegroundColor $Yellow
    $NewBlock = @"

# --- Gerado automaticamente para $KeyComment ---
Host $HostAlias
    HostName $HostIP
    User $HostUser
    Port 22
    IdentityFile $KeyPath
    IdentitiesOnly yes
"@
    Add-Content -Path $ConfigFile -Value $NewBlock
    Write-Host "✅ Configuração salva!" -ForegroundColor $Green
}

# 5. Exibe a chave pública
Write-Host ""
Write-Host "==============================================" -ForegroundColor $Cyan
Write-Host "🎉 TUDO PRONTO!" -ForegroundColor $Green
Write-Host "Para conectar, abra o PowerShell e digite: ssh $HostAlias" -ForegroundColor $Yellow
Write-Host ""
Write-Host "Copie a linha abaixo para colar na VPS:" -ForegroundColor $White
Write-Host "---------------------------------------------------" -ForegroundColor $Cyan
Get-Content "$KeyPath.pub"
Write-Host "---------------------------------------------------" -ForegroundColor $Cyan
Write-Host ""
Pause
