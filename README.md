# PS-FTP-Server

Un servidor FTP ligero y autónomo desarrollado en PowerShell con un motor de red embebido en C#. Diseñado para despliegues rápidos en entornos locales donde no es viable instalar servicios pesados como IIS o software de terceros.

## Características Principales

* **Cero dependencias:** Utiliza `TcpListener` de .NET compilando código C# al vuelo. No requiere módulos externos ni paquetes NuGet.
* **Recarga en caliente (Hot-Reload):** Los usuarios y permisos se gestionan desde un archivo CSV. El servidor detecta los cambios y los aplica en tiempo real sin necesidad de reiniciar el servicio ni interrumpir conexiones activas ajenas a la modificación.
* **Doble motor de autenticación:**
  * **Local:** Credenciales gestionadas directamente en el CSV (en texto plano o como hash PBKDF2).
  * **Active Directory (AD):** Validación contra el dominio de Windows utilizando llamadas nativas (`advapi32.dll`).
* **Control granular:** Asignación de permisos de Lectura, Escritura y Eliminación independientes, además de configuración de timeouts por inactividad a nivel de usuario.
* **Aislamiento básico (Chroot):** Restringe el acceso de cada usuario estrictamente al directorio asignado en su configuración.
* **FTPS opcional:** TLS explícito (`AUTH TLS`) con certificado autofirmado o uno ya instalado en Windows.
* **Bloqueo por IP:** Después de varios logins fallidos seguidos la IP queda bloqueada unos minutos. Con usuarios AD esto evita que alguien te bloquee cuentas del dominio probando passwords.

## Requisitos

* Windows OS (hace uso de P/Invoke para el control del ciclo de vida y validación contra AD).
* PowerShell 5.1 o superior.
* Permisos de Administrador (únicamente si se utiliza el flag `-AbrirFirewall`).

## Instalación y Configuración

1. Clona este repositorio:
   ```powershell
   git clone https://github.com/JPedroLR/ps-ftp-server.git
   cd ps-ftp-server
   ```

2. Genera el CSV de usuarios de ejemplo (queda en `config\users.csv`, con los usuarios dados de baja):
   ```powershell
   .\Start-FtpServer.ps1 -CrearPlantilla
   ```

3. Edita `config\users.csv`: pon `Activo=SI` a los usuarios que quieras habilitar y revisa que la carpeta de cada uno exista.

4. Arranca el servidor:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Start-FtpServer.ps1 -AbrirFirewall
   ```

Mientras el servidor corre puedes seguir editando el CSV; al guardarlo los cambios se aplican solos en un par de segundos. `Ctrl+C` o cerrar la ventana detiene el servidor y cierra todas las sesiones.

## Formato del CSV

```
Usuario,Activo,Tipo,Password,Ruta,Permisos,InactividadSeg
jperez,SI,AD,,C:\FTP\jperez,LECTURA+ESCRITURA+ELIMINAR,600
reportes,SI,LOCAL,PBKDF2$100000$...,C:\FTP\reportes,LECTURA,120
```

| Columna | Descripción |
|---|---|
| `Usuario` | Login. Para AD sirve `usuario`, `DOMINIO\usuario` o `usuario@dominio.local`. |
| `Activo` | `SI` / `NO`. Es una baja lógica, no hace falta borrar la fila. |
| `Tipo` | `AD` o `LOCAL`. |
| `Password` | Solo para `LOCAL`. Texto plano o hash (ver más abajo). Con `AD` se ignora. |
| `Ruta` | Carpeta única del usuario (`C:\...` o `\\servidor\recurso`). Tiene que existir. |
| `Permisos` | `LECTURA`, `ESCRITURA`, `ELIMINAR` combinados con `+`. Vacío = solo lectura. |
| `InactividadSeg` | Segundos sin actividad antes de cerrar la sesión. Vacío = `-InactividadDefecto`. |

Las líneas que empiezan con `#` se ignoran. El separador puede ser coma, punto y coma o tabulador (lo detecta solo, para que Excel no estorbe).

Qué permite cada permiso:

* `LECTURA`: listar, descargar y consultar tamaños.
* `ESCRITURA`: subir archivos **nuevos**, crear carpetas y renombrar.
* `ELIMINAR`: borrar archivos y carpetas vacías, y también sobrescribir archivos que ya existen.

### Passwords con hash

Para no dejar passwords en texto plano en el CSV:

```powershell
.\Start-FtpServer.ps1 -GenerarHash
```

Te pide el password dos veces y escribe una línea `PBKDF2$100000$...`; la pegas en la columna `Password` del usuario `LOCAL`. Si la columna no empieza con `PBKDF2$` se compara como texto plano, así que puedes mezclar ambos.

## Parámetros

| Parámetro | Por defecto | Para qué sirve |
|---|---|---|
| `-Puerto` | `21` | Puerto de control. |
| `-ArchivoUsuarios` | `config\users.csv` | Ruta del CSV. |
| `-Dominio` | `$env:USERDOMAIN` | Dominio para usuarios AD escritos sin dominio. |
| `-PuertoPasivoMin` / `-PuertoPasivoMax` | `50000` / `50100` | Rango de puertos para el modo pasivo. |
| `-IpPasiva` | (vacío) | Solo si el servidor está detrás de NAT. |
| `-InactividadDefecto` | `300` | Segundos de inactividad para usuarios sin valor propio. |
| `-MaxIntentosFallidos` | `5` | Fallos seguidos antes de bloquear la IP (`0` = nunca bloquear). |
| `-BloqueoMin` | `15` | Minutos que dura el bloqueo. |
| `-Tls` | | Activa FTPS explícito. |
| `-CertThumbprint` | (vacío) | Usa un certificado ya instalado en lugar del autofirmado. |
| `-ExigirTls` | | Rechaza logins y transferencias sin cifrar (implica `-Tls`). |
| `-CrearPlantilla` | | Crea `config\users.csv` de ejemplo y termina. |
| `-GenerarHash` | | Genera un hash de password y termina. |
| `-AbrirFirewall` | | Crea la regla de firewall (requiere admin). |
| `-ArchivoLog` | `ftpserver.log` | Log en disco. Al pasar de 10 MB se guarda como `.old`. |

## FTPS (TLS)

```powershell
.\Start-FtpServer.ps1 -Tls              # el cliente puede elegir cifrar o no
.\Start-FtpServer.ps1 -Tls -ExigirTls   # sin TLS no entra nadie
```

La primera vez se crea un certificado autofirmado (`CN=PS-FTP-Server`, 5 años) en el almacén del usuario actual y se reutiliza en los siguientes arranques. Al conectar, el cliente (FileZilla, WinSCP...) va a avisar de que no conoce el certificado; compara la huella SHA-256 con la que imprime el servidor al arrancar antes de aceptarlo.

Es FTPS explícito (`AUTH TLS` + `PROT P`), **no** SFTP. SFTP es otro protocolo (va sobre SSH) y no se puede hacer solo con lo que trae Windows.

## Comandos soportados

`USER`, `PASS`, `QUIT`, `NOOP`, `SYST`, `FEAT`, `OPTS`, `AUTH`, `PBSZ`, `PROT`, `PWD`, `CWD`, `CDUP`, `TYPE`, `MODE`, `STRU`, `PASV`, `EPSV`, `PORT`, `LIST`, `NLST`, `RETR`, `STOR`, `SIZE`, `DELE`, `MKD`, `RMD`, `RNFR`, `RNTO`.

## Estructura del repo

```
Start-FtpServer.ps1       script de arranque (parámetros, firewall, certificado, log)
src/FtpServerCore.cs      motor FTP en C# (se compila con Add-Type al iniciar)
config/users.csv.example  ejemplo de CSV de usuarios
config/users.csv          tu CSV real (no se sube a git)
```

## Limitaciones conocidas

* Sin `-Tls` las credenciales y los archivos viajan en claro. Úsalo así solo en una red de confianza.
* Un usuario `LOCAL` con password en texto plano en el CSV es tan seguro como los permisos de ese archivo. Usa hash o restringe el acceso a la carpeta `config`.
* La "jaula" por usuario se valida por ruta; no sigue enlaces simbólicos ni junctions dentro de la carpeta del usuario. No crees ese tipo de enlaces hacia fuera de la ruta asignada.
* No hay `REST` (reanudar transferencias) ni `MLSD`.
* Máximo 50 sesiones simultáneas.
