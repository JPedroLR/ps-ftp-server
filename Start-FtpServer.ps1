<#
.SYNOPSIS
    Servidor FTP propio (TcpListener/TcpClient en C# embebido). Sin Internet, sin instalaciones, sin IIS.
    Usuarios definidos en un CSV que se recarga en caliente. FTPS (TLS explicito) opcional.

.DESCRIPTION
    CSV de usuarios (columnas):
      Usuario         Nombre de login. Para AD: usuario, DOMINIO\usuario o usuario@dominio.local
      Activo          SI / NO  (baja logica: no hace falta borrar la fila)
      Tipo            AD    = credenciales de Active Directory (la columna Password se ignora)
                      LOCAL = usuario y password definidos en el propio CSV (texto plano o hash, ver -GenerarHash)
      Password        Solo para Tipo=LOCAL
      Ruta            Carpeta unica a la que tiene acceso (C:\... o \\servidor\recurso). Debe existir.
      Permisos        LECTURA, ESCRITURA, ELIMINAR combinados con +  (ej. LECTURA+ESCRITURA)
                        LECTURA   : listar (LIST/NLST), descargar (RETR), SIZE
                        ESCRITURA : subir archivos NUEVOS (STOR), crear carpetas (MKD), renombrar (RNFR/RNTO)
                        ELIMINAR  : borrar archivos/carpetas vacias (DELE/RMD) y sobrescribir archivos existentes
      InactividadSeg  Segundos sin actividad antes de cerrar la sesion (vacio = -InactividadDefecto)

    - El CSV se vigila cada ~0.7 s: al guardarlo, los cambios aplican en ~1-2 s sin reiniciar:
      altas, bajas, cambios de ruta, permisos e inactividad. Si un usuario se da de baja, se elimina,
      cambia su password/tipo, su sesion activa se cierra en ese momento.
    - Si el CSV queda invalido (columna obligatoria faltante, etc.) se conserva la configuracion anterior.
    - Al detener el servidor (Ctrl+C, cerrar la ventana, cerrar sesion de Windows) se cierran TODAS las sesiones.
    - Sin -Tls el FTP es plano: las credenciales viajan en claro. Usar solo en red de confianza.
    - Tras -MaxIntentosFallidos logins fallidos seguidos, la IP queda bloqueada -BloqueoMin minutos
      (con AD evita que alguien bloquee cuentas del dominio adivinando passwords).

.EXAMPLE
    .\Start-FtpServer.ps1 -CrearPlantilla          # genera config\users.csv de ejemplo
    .\Start-FtpServer.ps1 -GenerarHash             # pide un password y escribe el hash para el CSV
    powershell -ExecutionPolicy Bypass -File .\Start-FtpServer.ps1 -AbrirFirewall
    powershell -ExecutionPolicy Bypass -File .\Start-FtpServer.ps1 -Tls -ExigirTls
#>
[CmdletBinding()]
param(
    [int]    $Puerto             = 21,
    [string] $ArchivoUsuarios    = '',      # Por defecto: .\config\users.csv junto al script
    [string] $Dominio            = $env:USERDOMAIN,   # Dominio por defecto para usuarios Tipo=AD escritos sin dominio
    [int]    $PuertoPasivoMin    = 50000,
    [int]    $PuertoPasivoMax    = 50100,
    [string] $IpPasiva           = '',      # Solo si el servidor esta detras de NAT
    [int]    $InactividadDefecto = 300,     # Segundos, para usuarios sin InactividadSeg
    [int]    $MaxIntentosFallidos = 5,      # 0 = no bloquear IPs
    [int]    $BloqueoMin         = 15,
    [switch] $Tls,                          # Activa FTPS explicito (AUTH TLS) con certificado autofirmado
    [string] $CertThumbprint     = '',      # Usar un certificado ya instalado (huella) en vez del autofirmado
    [switch] $ExigirTls,                    # Rechaza logins y transferencias sin cifrar (implica -Tls)
    [switch] $CrearPlantilla,               # Crea users.csv de ejemplo y termina
    [switch] $GenerarHash,                  # Genera un hash de password para el CSV y termina
    [switch] $AbrirFirewall,                # Crea regla de firewall (requiere admin)
    [string] $ArchivoLog         = ''       # Por defecto: .\ftpserver.log
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 0. Rutas por defecto
# ---------------------------------------------------------------------------
$base = $PSScriptRoot
if ([string]::IsNullOrEmpty($base)) { $base = (Get-Location).Path }
if ([string]::IsNullOrEmpty($ArchivoUsuarios)) { $ArchivoUsuarios = Join-Path $base 'config\users.csv' }
if ([string]::IsNullOrEmpty($ArchivoLog))      { $ArchivoLog      = Join-Path $base 'ftpserver.log' }

function Salir-ConError([string]$mensaje) {
    Write-Host ''
    Write-Host "[ERROR] $mensaje" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Plantilla de CSV (opcional)
# ---------------------------------------------------------------------------
if ($CrearPlantilla) {
    if (Test-Path -LiteralPath $ArchivoUsuarios) {
        Salir-ConError "Ya existe $ArchivoUsuarios ; no se sobrescribe."
    }
    $plantilla = @'
# Usuarios del servidor FTP. Las lineas que empiezan con # se ignoran.
# Activo: SI / NO (baja logica; no hace falta borrar la fila)
# Tipo: AD (credenciales de dominio, Password se ignora) | LOCAL (usuario y Password de esta fila)
# Password (LOCAL): texto plano o un hash generado con  .\Start-FtpServer.ps1 -GenerarHash
# Ruta: carpeta unica de acceso (C:\... o \\servidor\recurso). Debe existir.
# Permisos: LECTURA, ESCRITURA, ELIMINAR combinados con +  (ej. LECTURA+ESCRITURA)
# InactividadSeg: segundos sin actividad antes de cerrar la sesion (vacio = valor por defecto del script)
Usuario,Activo,Tipo,Password,Ruta,Permisos,InactividadSeg
jperez,NO,AD,,C:\FTP\jperez,LECTURA+ESCRITURA+ELIMINAR,600
reportes,NO,LOCAL,CambiaEsta1,C:\FTP\reportes,LECTURA,120
'@
    try {
        $carpetaCfg = Split-Path -Parent $ArchivoUsuarios
        if (-not (Test-Path -LiteralPath $carpetaCfg)) { New-Item -ItemType Directory -Path $carpetaCfg | Out-Null }
        Set-Content -LiteralPath $ArchivoUsuarios -Value $plantilla -Encoding UTF8
        Write-Host "Plantilla creada: $ArchivoUsuarios (usuarios de ejemplo con Activo=NO)" -ForegroundColor Green
        exit 0
    } catch {
        Salir-ConError "No se pudo crear la plantilla: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 2. Codigo C# (src\FtpServerCore.cs; si no esta ahi, se busca junto al script). Sintaxis C# 5.
# ---------------------------------------------------------------------------
$rutaCSharp = Join-Path $base 'src\FtpServerCore.cs'
if (-not (Test-Path -LiteralPath $rutaCSharp)) { $rutaCSharp = Join-Path $base 'FtpServerCore.cs' }
if (-not (Test-Path -LiteralPath $rutaCSharp)) {
    Salir-ConError "No se encuentra el codigo fuente del motor (src\FtpServerCore.cs) en: $base"
}

$codigoCSharp = Get-Content -LiteralPath $rutaCSharp -Raw -Encoding UTF8

# ---------------------------------------------------------------------------
# 3. Compilar el C# (solo ensamblados propios de .NET/Windows)
# ---------------------------------------------------------------------------
$tipoCargado = 'PsFtp.FtpServer' -as [type]
if ($tipoCargado) {
    # Ya hay un servidor cargado en ESTA sesion de PowerShell (p. ej. de una ejecucion anterior)
    $ver = $null
    try { $ver = [PsFtp.BuildInfo]::Version } catch { }
    if ($ver -ne '3') {
        Salir-ConError ("Hay una version anterior del servidor FTP cargada en esta sesion de PowerShell.`n" +
                        "Cierre esta ventana y abra una nueva (o ejecute con: powershell -File .\Start-FtpServer.ps1).")
    }
} else {
    try {
        Add-Type -TypeDefinition $codigoCSharp -Language CSharp -ErrorAction Stop
    } catch {
        Salir-ConError "Fallo la compilacion del codigo C#: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 3b. Generar hash de password (opcional)
# ---------------------------------------------------------------------------
function Leer-Password([string]$pregunta) {
    $seguro = Read-Host $pregunta -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($seguro)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if ($GenerarHash) {
    $p1 = Leer-Password 'Password'
    $p2 = Leer-Password 'Repita el password'
    if ($p1 -ne $p2)     { Salir-ConError 'Los passwords no coinciden.' }
    if ($p1.Length -eq 0) { Salir-ConError 'El password no puede estar vacio.' }
    Write-Host ''
    Write-Host 'Pegue esto en la columna Password (Tipo=LOCAL) del CSV:'
    Write-Host ([PsFtp.PasswordHasher]::Hash($p1)) -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# 4. Validaciones previas
# ---------------------------------------------------------------------------
if ($Puerto -lt 1 -or $Puerto -gt 65535) { Salir-ConError "Puerto invalido: $Puerto" }
if ($PuertoPasivoMin -lt 1024 -or $PuertoPasivoMax -gt 65535 -or $PuertoPasivoMin -ge $PuertoPasivoMax) {
    Salir-ConError "Rango pasivo invalido ($PuertoPasivoMin-$PuertoPasivoMax). Use puertos >= 1024 con Min < Max."
}
if ($InactividadDefecto -lt 5) { Salir-ConError "InactividadDefecto debe ser >= 5 segundos." }
if ($MaxIntentosFallidos -lt 0) { Salir-ConError "MaxIntentosFallidos no puede ser negativo (0 = sin bloqueo)." }
if ($BloqueoMin -lt 1) { Salir-ConError "BloqueoMin debe ser >= 1." }
if ($IpPasiva -ne '') {
    $ipTmp = $null
    if (-not [System.Net.IPAddress]::TryParse($IpPasiva, [ref]$ipTmp)) { Salir-ConError "IpPasiva invalida: $IpPasiva" }
}
if (-not (Test-Path -LiteralPath $ArchivoUsuarios -PathType Leaf)) {
    Salir-ConError ("No existe el archivo de usuarios: $ArchivoUsuarios`n" +
                    "Puede generar uno de ejemplo con:  .\Start-FtpServer.ps1 -CrearPlantilla")
}
$ArchivoUsuarios = (Resolve-Path -LiteralPath $ArchivoUsuarios).ProviderPath

if ([string]::IsNullOrEmpty($Dominio)) {
    Write-Host '[AVISO] No hay dominio por defecto: los usuarios AD deberan escribir DOMINIO\usuario o usuario@dominio.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 5. Firewall opcional
# ---------------------------------------------------------------------------
if ($AbrirFirewall) {
    $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $esAdmin) {
        Write-Host '[AVISO] -AbrirFirewall requiere ejecutar como Administrador; se omite.' -ForegroundColor Yellow
    } else {
        try {
            $nombreRegla = 'PS-FTP-Server'
            if (-not (Get-NetFirewallRule -DisplayName $nombreRegla -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $nombreRegla -Direction Inbound -Protocol TCP -Action Allow `
                    -LocalPort @("$Puerto", "$PuertoPasivoMin-$PuertoPasivoMax") | Out-Null
                Write-Host "Regla de firewall '$nombreRegla' creada."
            }
        } catch {
            Write-Host "[AVISO] No se pudo crear la regla de firewall: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# 5b. Certificado para FTPS (opcional)
# ---------------------------------------------------------------------------
function Obtener-Certificado([string]$huella) {
    $almacenes = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')

    if ($huella -ne '') {
        $huella = ($huella -replace '\s', '').ToUpper()
        foreach ($a in $almacenes) {
            $c = Get-ChildItem -Path $a -ErrorAction SilentlyContinue |
                 Where-Object { $_.Thumbprint -eq $huella -and $_.HasPrivateKey } | Select-Object -First 1
            if ($c) { return $c }
        }
        Salir-ConError "No se encontro un certificado con llave privada y huella $huella (CurrentUser\My o LocalMachine\My)."
    }

    # Sin huella: reutilizar el autofirmado de este servidor, o crearlo la primera vez
    $c = Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
         Where-Object { $_.Subject -eq 'CN=PS-FTP-Server' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
         Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($c) { return $c }

    try {
        $c = New-SelfSignedCertificate -Subject 'CN=PS-FTP-Server' -DnsName @($env:COMPUTERNAME, 'localhost') `
                -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(5) `
                -KeyAlgorithm RSA -KeyLength 2048
        Write-Host 'Certificado autofirmado creado en Cert:\CurrentUser\My (CN=PS-FTP-Server, 5 anios).' -ForegroundColor Green
        return $c
    } catch {
        Salir-ConError "No se pudo crear el certificado autofirmado: $($_.Exception.Message)"
    }
}

$usaTls = ($Tls -or $ExigirTls -or ($CertThumbprint -ne ''))
$certificado = $null
$huellaSha256 = ''
if ($usaTls) {
    $certificado = Obtener-Certificado $CertThumbprint
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $huellaSha256 = (($sha.ComputeHash($certificado.RawData) | ForEach-Object { $_.ToString('X2') }) -join ':')
}

# ---------------------------------------------------------------------------
# 6. Vaciado del log del servidor a pantalla y archivo
# ---------------------------------------------------------------------------
function Vaciar-Log {
    $linea = $null
    $lote  = New-Object System.Text.StringBuilder
    while ([PsFtp.FtpLog]::Queue.TryDequeue([ref]$linea)) {
        Write-Host $linea
        [void]$lote.AppendLine($linea)
    }
    if ($lote.Length -gt 0) {
        try {
            # rotacion simple: al pasar de 10 MB el log actual queda como .old
            $fi = New-Object System.IO.FileInfo($ArchivoLog)
            if ($fi.Exists -and $fi.Length -gt 10MB) { Move-Item -LiteralPath $ArchivoLog -Destination ($ArchivoLog + '.old') -Force }
            [System.IO.File]::AppendAllText($ArchivoLog, $lote.ToString(), [System.Text.Encoding]::UTF8)
        }
        catch { }   # el log en disco es opcional; no detener el servidor
    }
}

# ---------------------------------------------------------------------------
# 7. Configurar y arrancar
# ---------------------------------------------------------------------------
$cfg = New-Object PsFtp.FtpConfig
$cfg.Port           = $Puerto
$cfg.UsersFile      = $ArchivoUsuarios
$cfg.Domain         = $Dominio
$cfg.PassiveMin     = $PuertoPasivoMin
$cfg.PassiveMax     = $PuertoPasivoMax
$cfg.PassiveIp      = $IpPasiva
$cfg.DefaultIdleSec = $InactividadDefecto
$cfg.MaxFailedLogins = $MaxIntentosFallidos
$cfg.BlockMinutes   = $BloqueoMin
if ($usaTls) {
    $cfg.Certificate = $certificado
    $cfg.RequireTls  = [bool]$ExigirTls
}

$servidor = New-Object PsFtp.FtpServer($cfg)
try {
    $servidor.Start()
} catch {
    $ex = $_.Exception
    if ($ex.InnerException) { $ex = $ex.InnerException }
    Vaciar-Log      # muestra los errores de filas del CSV, si los hubo
    if ($ex -is [System.InvalidOperationException]) {
        Salir-ConError "CSV de usuarios invalido: $($ex.Message)"
    } elseif ($ex -is [System.Net.Sockets.SocketException] -and $ex.SocketErrorCode -eq 'AddressAlreadyInUse') {
        Salir-ConError ("El puerto $Puerto ya esta en uso. Averigue quien lo usa con:`n" +
                        "    Get-NetTCPConnection -LocalPort $Puerto -State Listen`n" +
                        "o ejecute este script con otro puerto: -Puerto 2121")
    } elseif ($ex -is [System.Net.Sockets.SocketException] -and $ex.SocketErrorCode -eq 'AccessDenied') {
        Salir-ConError "Acceso denegado al puerto $Puerto. Pruebe como Administrador o con otro puerto."
    } else {
        Salir-ConError "No se pudo iniciar el servidor: $($ex.Message)"
    }
}

# Red de seguridad extra: si el host de PowerShell sale con normalidad, detener el servidor
try {
    $null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) `
        -MessageData $servidor -Action { $Event.MessageData.Stop() }
} catch { }

Write-Host ''
Write-Host '=== Servidor FTP en ejecucion ===' -ForegroundColor Green
Write-Host "Puerto control : $Puerto"
Write-Host "Puertos pasivos: $PuertoPasivoMin-$PuertoPasivoMax"
Write-Host "Usuarios (CSV) : $ArchivoUsuarios  (se recarga solo al guardar)"
Write-Host "Dominio defecto: $Dominio"
Write-Host "Inactividad def: $InactividadDefecto s"
if ($MaxIntentosFallidos -gt 0) { Write-Host "Bloqueo por IP : $MaxIntentosFallidos fallos -> $BloqueoMin min" }
else                            { Write-Host 'Bloqueo por IP : desactivado' }
Write-Host "Log            : $ArchivoLog"
if ($usaTls) {
    $modo = if ($ExigirTls) { 'obligatorio' } else { 'opcional' }
    Write-Host "TLS (FTPS)     : $modo - cert $($certificado.Thumbprint)"
    Write-Host "SHA-256 cert   : $huellaSha256"
} else {
    Write-Host 'TLS (FTPS)     : desactivado (credenciales en claro, usar -Tls)' -ForegroundColor Yellow
}
Write-Host 'Ctrl+C o cerrar la ventana detiene el servidor y cierra TODAS las sesiones.' -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------------------
# 8. Bucle principal
# ---------------------------------------------------------------------------
try {
    while ($true) {
        Vaciar-Log
        Start-Sleep -Milliseconds 300
    }
}
finally {
    $servidor.Stop()          # cierra el listener y TODAS las sesiones abiertas
    Vaciar-Log
    try { Unregister-Event -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -ErrorAction SilentlyContinue } catch { }
    Write-Host 'Servidor detenido. Todas las sesiones cerradas.' -ForegroundColor Yellow
}
