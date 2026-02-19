# ==========================================
#      GERADOR DE ACESSO SSH (WINDOWS)
#           Versão Robusta
# ==========================================

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

# --- FUNÇÃO: Verifica se é Admin ---
function Test-IsAdmin {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- FUNÇÃO: Verifica se OpenSSH está instalado ---
function Test-OpenSSHInstalled {
    $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'
    return ($capability.State -eq "Installed")
}

# --- INSTALAÇÃO AUTOMÁTICA ---
if (-not (Get-Command "ssh-keygen" -ErrorAction SilentlyContinue)) {

    Write-Host "🔍 OpenSSH não detectado." -ForegroundColor $Yellow

    if (-not (Test-IsAdmin)) {
        Write-Host "❌ Execute o PowerShell como ADMINISTRADOR." -ForegroundColor $Red
        Pause
        exit
    }

    try {
        Write-Host "⏳ Tentando instalar via Add-WindowsCapability..." -ForegroundColor $Cyan
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction Stop
    }
    catch {
        Write-Host "⚠️ Falha no método padrão. Tentando via DISM..." -ForegroundColor $Yellow
        dism.exe /Online /Add-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0
    }

# Validação real do estado
$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'

if ($cap.State -eq "InstallPending") {
    Write-Host "⚠️ Instalação pendente. Reinicie o Windows para concluir." -ForegroundColor $Yellow
    Pause
    exit
}

if ($cap.State -ne "Installed") {
    Write-Host "❌ OpenSSH não foi instalado corretamente." -ForegroundColor $Red
    Pause
    exit
}

Write-Host "✅ OpenSSH instalado com sucesso!" -ForegroundColor $Green

}

# --- Coleta de Dados ---
Write-Host ""
Write-Host "Responda as perguntas abaixo:" -ForegroundColor $Yellow

$KeyName = Read-Host "1. Nome do arquivo da chave (ex: id_hostinger)"
if ([string]::IsNullOrWhiteSpace($KeyName)) {
    Write-Host "Erro: Nome inválido!" -ForegroundColor $Red
    exit
}
$KeyComment = Read-Host "2. Seu Email ou Comentário (ex: email@email)"
$HostAlias = Read-Host "3. Apelido do Servidor (ex: kmv)"
if ([string]::IsNullOrWhiteSpace($HostAlias)) {
    Write-Host "Erro: Apelido inválido!" -ForegroundColor $Red
    exit
}
$HostIP = Read-Host "4. IP do Servidor (ex: xxx.xxx.xxx.xx)"
if (-not ([System.Net.IPAddress]::TryParse($HostIP, [ref]$null))) {
    Write-Host "❌ IP inválido!" -ForegroundColor $Red
    exit
}
$HostUser = Read-Host "5. Usuário Remoto (ex: root)"
if ([string]::IsNullOrWhiteSpace($HostUser)) {
    Write-Host "Erro: Usuário inválido!" -ForegroundColor $Red
    exit
}

# --- Escolha de senha para a chave ---

$UsePassphrase = Read-Host "6. Deseja proteger a chave com senha? (s/n)"

$Passphrase = ""

if ($UsePassphrase -eq "s") {
    Write-Host "Digite a senha da chave:" -ForegroundColor $Yellow
    $SecurePass1 = Read-Host -AsSecureString
    Write-Host "Confirme a senha:" -ForegroundColor $Yellow
    $SecurePass2 = Read-Host -AsSecureString

    $Plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass1)
    )

    $Plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass2)
    )

    if ($Plain1 -ne $Plain2) {
        Write-Host "❌ As senhas não coincidem." -ForegroundColor $Red
        exit
    }

    $Passphrase = $Plain1
}


$UserHome = $env:USERPROFILE
$SshDir = "$UserHome\.ssh"
$KeyPath = "$SshDir\$KeyName"
$ConfigFile = "$SshDir\config"

# --- Cria pasta .ssh se necessário ---
if (-not (Test-Path $SshDir)) {
    New-Item -ItemType Directory -Path $SshDir | Out-Null
    Write-Host "📁 Pasta .ssh criada." -ForegroundColor $Green
}

# --- Geração de Chave ---
try {
    if (Test-Path $KeyPath) {
        Write-Host "⚠️ A chave já existe!" -ForegroundColor $Yellow
        $Overwrite = Read-Host "Sobrescrever? (s/n)"
        if ($Overwrite -ne "s") {
            Write-Host "Mantendo chave existente." -ForegroundColor $Yellow
        } else {
            Remove-Item "$KeyPath*" -Force
            ssh-keygen -t ed25519 -f "$KeyPath" -C "$KeyComment" -N "$Passphrase" -q
            Write-Host "✅ Nova chave criada." -ForegroundColor $Green
        }
    }
    else {
        ssh-keygen -t ed25519 -f "$KeyPath" -C "$KeyComment" -N "$Passphrase" -q
        Write-Host "✅ Chave criada com sucesso." -ForegroundColor $Green
    }
}
catch {
    Write-Host "❌ Erro ao gerar chave: $($_.Exception.Message)" -ForegroundColor $Red
    exit
}

# --- Configuração SSH config ---
if (-not (Test-Path $ConfigFile)) {
    New-Item -ItemType File -Path $ConfigFile | Out-Null
}

$ConfigContent = ""
if (Test-Path $ConfigFile) {
    $ConfigContent = Get-Content $ConfigFile -Raw -ErrorAction SilentlyContinue
}

# Bloco global (evita duplicação)
if ($ConfigContent -notmatch "IgnoreUnknown AddKeysToAgent") {

@"
Host *
    IgnoreUnknown AddKeysToAgent,UseKeychain
    AddKeysToAgent yes
"@ | Add-Content $ConfigFile

    Write-Host "⚙️ Configuração global adicionada." -ForegroundColor $Green
}

# Bloco específico
if ($ConfigContent -match "Host $HostAlias") {
    Write-Host "⚠️ Host já existe no config." -ForegroundColor $Yellow
}
else {

@"

# --- Gerado automaticamente ---
Host $HostAlias
    HostName $HostIP
    User $HostUser
    Port 22
    IdentityFile $KeyPath
    IdentitiesOnly yes
"@ | Add-Content $ConfigFile

    Write-Host "✅ Configuração adicionada ao config." -ForegroundColor $Green
}

# --- Finalização ---
Write-Host ""
Write-Host "==============================================" -ForegroundColor $Cyan
Write-Host "🎉 TUDO PRONTO!" -ForegroundColor $Green
Write-Host "Use: ssh $HostAlias" -ForegroundColor $Yellow
Write-Host ""
Write-Host "Chave pública para colar na VPS:" -ForegroundColor $White
Write-Host "---------------------------------------------------" -ForegroundColor $Cyan
Get-Content "$KeyPath.pub"
Write-Host "---------------------------------------------------" -ForegroundColor $Cyan
Write-Host ""

Pause
