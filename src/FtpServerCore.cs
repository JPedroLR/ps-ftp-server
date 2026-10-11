using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace PsFtp
{
    public static class BuildInfo { public const string Version = "3"; }

    public class FtpConfig
    {
        public int Port = 21;
        public string UsersFile;
        public string Domain;
        public int PassiveMin = 50000;
        public int PassiveMax = 50100;
        public string PassiveIp;
        public int DefaultIdleSec = 300;
        public int MaxSessions = 50;
        public int MaxFailedLogins = 5;     // 0 = sin bloqueo por IP
        public int BlockMinutes = 15;
        public X509Certificate2 Certificate;   // null = sin TLS (FTP plano)
        public bool RequireTls;
    }

    // Log en cola: PowerShell la vacia y la muestra/guarda
    public static class FtpLog
    {
        public static readonly ConcurrentQueue<string> Queue = new ConcurrentQueue<string>();

        public static void Write(string msg)
        {
            Queue.Enqueue(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "  " + msg);
            string dummy;
            while (Queue.Count > 5000) { Queue.TryDequeue(out dummy); }
        }
    }

    // ------------------------------------------------------------------
    // Passwords LOCAL: texto plano o hash PBKDF2-HMAC-SHA256 ("PBKDF2$iter$sal$hash")
    // ------------------------------------------------------------------
    public static class PasswordHasher
    {
        private const string Prefix = "PBKDF2$";
        private const int Iterations = 100000;

        public static bool IsHash(string s)
        {
            return s != null && s.StartsWith(Prefix, StringComparison.Ordinal);
        }

        public static string Hash(string password)
        {
            byte[] salt = new byte[16];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            byte[] h = Derive(password, salt, Iterations);
            return Prefix + Iterations + "$" + Convert.ToBase64String(salt) + "$" + Convert.ToBase64String(h);
        }

        public static bool Verify(string password, string stored)
        {
            if (!IsHash(stored))
            {
                return FixedTimeEquals(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(stored));
            }
            string[] p = stored.Split('$');
            int it;
            if (p.Length != 4 || !int.TryParse(p[1], out it) || it < 1000) { return false; }
            byte[] salt, expected;
            try { salt = Convert.FromBase64String(p[2]); expected = Convert.FromBase64String(p[3]); }
            catch (FormatException) { return false; }
            return FixedTimeEquals(Derive(password, salt, it), expected);
        }

        // PBKDF2 a mano: Rfc2898DeriveBytes con SHA256 solo existe desde .NET 4.7.2
        private static byte[] Derive(string password, byte[] salt, int iterations)
        {
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password)))
            {
                byte[] block = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, block, 0, salt.Length);
                block[salt.Length + 3] = 1;                 // bloque 1 (los 32 bytes de SHA256 alcanzan)
                byte[] u = hmac.ComputeHash(block);
                byte[] t = (byte[])u.Clone();
                for (int i = 1; i < iterations; i++)
                {
                    u = hmac.ComputeHash(u);
                    for (int j = 0; j < t.Length; j++) { t[j] ^= u[j]; }
                }
                return t;
            }
        }

        // Comparacion en tiempo constante
        private static bool FixedTimeEquals(byte[] x, byte[] y)
        {
            int diff = x.Length ^ y.Length;
            int n = Math.Max(x.Length, y.Length);
            for (int i = 0; i < n; i++)
            {
                byte bx = i < x.Length ? x[i] : (byte)0;
                byte by = i < y.Length ? y[i] : (byte)0;
                diff |= bx ^ by;
            }
            return diff == 0;
        }
    }

    // ------------------------------------------------------------------
    // Bloqueo temporal por IP tras varios logins fallidos
    // (importante con AD: cada intento fallido cuenta para el bloqueo de la cuenta del dominio)
    // ------------------------------------------------------------------
    internal class LoginGuard
    {
        private class Rec
        {
            public int Fails;
            public DateTime First;
            public DateTime BlockedUntil;
        }

        private readonly Dictionary<string, Rec> recs = new Dictionary<string, Rec>();
        private readonly int maxFails;
        private readonly TimeSpan window = TimeSpan.FromMinutes(10);
        private readonly TimeSpan blockTime;

        public LoginGuard(int max, int blockMinutes)
        {
            maxFails = max;
            blockTime = TimeSpan.FromMinutes(blockMinutes < 1 ? 1 : blockMinutes);
        }

        public bool IsBlocked(string ip)
        {
            if (maxFails <= 0) { return false; }
            lock (recs)
            {
                Rec r;
                return recs.TryGetValue(ip, out r) && r.BlockedUntil > DateTime.UtcNow;
            }
        }

        // Devuelve true si con este fallo la IP queda bloqueada
        public bool Fail(string ip)
        {
            if (maxFails <= 0) { return false; }
            DateTime now = DateTime.UtcNow;
            lock (recs)
            {
                Rec r;
                if (!recs.TryGetValue(ip, out r)) { r = new Rec(); recs[ip] = r; }
                if (r.Fails == 0 || now - r.First > window) { r.Fails = 0; r.First = now; }
                r.Fails++;
                if (r.Fails >= maxFails)
                {
                    r.BlockedUntil = now + blockTime;
                    r.Fails = 0;
                    return true;
                }
                return false;
            }
        }

        public void Ok(string ip)
        {
            lock (recs) { recs.Remove(ip); }
        }

        public void Cleanup()
        {
            DateTime now = DateTime.UtcNow;
            lock (recs)
            {
                List<string> old = new List<string>();
                foreach (KeyValuePair<string, Rec> kv in recs)
                {
                    if (kv.Value.BlockedUntil < now && now - kv.Value.First > window) { old.Add(kv.Key); }
                }
                foreach (string k in old) { recs.Remove(k); }
            }
        }
    }

    // ------------------------------------------------------------------
    // Validacion de credenciales de Windows / Active Directory
    // ------------------------------------------------------------------
    internal static class NativeAuth
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
                                             int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static bool Validate(string user, string domain, string password, out int win32Error)
        {
            IntPtr token = IntPtr.Zero;
            win32Error = 0;
            try
            {
                bool ok = LogonUser(user, domain, password, 3 /* NETWORK */, 0 /* DEFAULT */, out token);
                if (!ok) { win32Error = Marshal.GetLastWin32Error(); }
                return ok;
            }
            finally { if (token != IntPtr.Zero) { CloseHandle(token); } }
        }

        public static string Describe(int err)
        {
            switch (err)
            {
                case 1326: return "usuario o contrasena incorrectos";
                case 1327: return "restriccion de cuenta";
                case 1328: return "fuera del horario permitido";
                case 1329: return "restriccion de estacion de trabajo";
                case 1330: return "contrasena expirada";
                case 1331: return "cuenta deshabilitada";
                case 1385: return "sin derecho 'Obtener acceso a este equipo desde la red'";
                case 1909: return "cuenta bloqueada";
                case 1311: return "no hay controlador de dominio disponible";
                case 1355: return "dominio no encontrado";
                default:   return "error de Windows";
            }
        }
    }

    // ------------------------------------------------------------------
    // Cierra el servidor (y todas sus sesiones) al pulsar Ctrl+C, cerrar la
    // ventana de consola, cerrar sesion o apagar Windows.
    // ------------------------------------------------------------------
    internal static class ConsoleCtrl
    {
        private delegate bool HandlerRoutine(int ctrlType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(HandlerRoutine handler, bool add);

        private static HandlerRoutine handler;                       // referencia fuerte: evita que el GC lo libere
        private static readonly List<FtpServer> servers = new List<FtpServer>();

        public static void Register(FtpServer s)
        {
            lock (servers)
            {
                servers.Add(s);
                if (handler == null)
                {
                    handler = new HandlerRoutine(OnCtrl);
                    try { SetConsoleCtrlHandler(handler, true); } catch (Exception) { }
                }
            }
        }

        public static void Unregister(FtpServer s)
        {
            lock (servers) { servers.Remove(s); }
        }

        private static bool OnCtrl(int ctrlType)
        {
            // 0=Ctrl+C 1=Ctrl+Break 2=cerrar ventana 5=cerrar sesion 6=apagado
            FtpServer[] arr;
            lock (servers) { arr = servers.ToArray(); }
            foreach (FtpServer s in arr)
            {
                try { s.Stop(); } catch (Exception) { }
            }
            return false;   // continuar con el manejo normal (terminar el proceso / script)
        }
    }

    // ------------------------------------------------------------------
    // Usuarios (CSV) con recarga en caliente
    // ------------------------------------------------------------------
    internal class UserEntry
    {
        public string Name;
        public bool Active;
        public bool IsAd;
        public string Password;
        public string RootFull;
        public bool CanRead;
        public bool CanWrite;
        public bool CanDelete;
        public int IdleSec;

        // Si cambia, las sesiones abiertas de ese usuario se cierran
        public string AuthKey { get { return IsAd ? "AD" : ("PL|" + Password); } }

        public string PermText
        {
            get
            {
                List<string> p = new List<string>();
                if (CanRead) { p.Add("LECTURA"); }
                if (CanWrite) { p.Add("ESCRITURA"); }
                if (CanDelete) { p.Add("ELIMINAR"); }
                return p.Count == 0 ? "(ninguno)" : string.Join("+", p.ToArray());
            }
        }
    }

    internal class UserStore
    {
        private readonly string file;
        private readonly int defaultIdle;
        private volatile Dictionary<string, UserEntry> users =
            new Dictionary<string, UserEntry>(StringComparer.OrdinalIgnoreCase);

        private DateTime loadedWrite = DateTime.MinValue;
        private long loadedLen = -1;
        private DateTime seenWrite = DateTime.MinValue;
        private long seenLen = -1;
        private bool missingLogged;
        private bool ioWarned;

        public UserStore(string path, int idle) { file = path; defaultIdle = idle; }

        public UserEntry Get(string name)
        {
            if (name == null) { return null; }
            UserEntry e;
            return users.TryGetValue(name, out e) ? e : null;
        }

        // Carga inicial: lanza InvalidOperationException si no se puede
        public void LoadInitial()
        {
            DateTime w = DateTime.MinValue;
            long len = -1;
            try { FileInfo fi = new FileInfo(file); if (fi.Exists) { w = fi.LastWriteTimeUtc; len = fi.Length; } }
            catch (Exception) { }

            string err;
            if (TryLoad(out err) != 0) { throw new InvalidOperationException(err); }
            loadedWrite = w; loadedLen = len; seenWrite = w; seenLen = len;
        }

        // Se llama periodicamente. Devuelve true si se cargo una configuracion nueva.
        public bool Poll()
        {
            FileInfo fi = new FileInfo(file);
            if (!fi.Exists)
            {
                if (!missingLogged)
                {
                    FtpLog.Write("[CSV] AVISO: no se encuentra " + file + ". Se conserva la configuracion actual.");
                    missingLogged = true;
                }
                return false;
            }
            missingLogged = false;

            DateTime w = fi.LastWriteTimeUtc;
            long len = fi.Length;
            if (w == loadedWrite && len == loadedLen) { seenWrite = w; seenLen = len; return false; }

            // Cambio detectado: esperar a que el archivo este estable entre dos revisiones
            // (los editores escriben por etapas)
            if (w != seenWrite || len != seenLen) { seenWrite = w; seenLen = len; return false; }

            string err;
            int r = TryLoad(out err);
            if (r == 0)
            {
                loadedWrite = w; loadedLen = len; ioWarned = false;
                return true;
            }
            if (r == 1)
            {
                // No se pudo leer (bloqueado): reintentar en la siguiente revision
                if (!ioWarned) { FtpLog.Write("[CSV] " + err + " (reintentando)"); ioWarned = true; }
                return false;
            }
            // Invalido: conservar la anterior y no repetir el aviso hasta que cambie de nuevo
            loadedWrite = w; loadedLen = len; ioWarned = false;
            FtpLog.Write("[CSV] ERROR: " + err + " -> se CONSERVA la configuracion anterior.");
            return false;
        }

        // 0 = ok, 1 = error de lectura (reintentar), 2 = contenido invalido
        private int TryLoad(out string err)
        {
            err = null;
            byte[] raw;
            try
            {
                if (!File.Exists(file)) { err = "No existe el archivo de usuarios: " + file; return 1; }
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                                                      FileShare.ReadWrite | FileShare.Delete))
                {
                    raw = new byte[fs.Length];
                    int off = 0;
                    while (off < raw.Length)
                    {
                        int n = fs.Read(raw, off, raw.Length - off);
                        if (n <= 0) { break; }
                        off += n;
                    }
                }
            }
            catch (Exception ex) { err = "No se pudo leer " + file + ": " + ex.Message; return 1; }

            try
            {
                Dictionary<string, UserEntry> d = Parse(DecodeText(raw));
                users = d;
                int act = 0;
                foreach (UserEntry e in d.Values) { if (e.Active) { act++; } }
                FtpLog.Write("[CSV] Configuracion cargada: " + d.Count + " usuarios (" + act + " activos).");
                return 0;
            }
            catch (FormatException ex) { err = ex.Message; return 2; }
        }

        private static string DecodeText(byte[] raw)
        {
            string text;
            try { text = new UTF8Encoding(false, true).GetString(raw); }       // UTF-8 estricto
            catch (Exception)
            {
                try { text = Encoding.GetEncoding(1252).GetString(raw); }      // CSV "ANSI" de Excel
                catch (Exception) { text = Encoding.GetEncoding("iso-8859-1").GetString(raw); }
            }
            if (text.Length > 0 && text[0] == '\uFEFF') { text = text.Substring(1); }
            return text;
        }

        private static int CountChar(string s, char c)
        {
            int n = 0;
            foreach (char x in s) { if (x == c) { n++; } }
            return n;
        }

        private static char DetectDelimiter(string text)
        {
            foreach (string line in text.Split('\n'))
            {
                string t = line.Trim();
                if (t.Length == 0 || t.StartsWith("#")) { continue; }
                int semi = CountChar(t, ';');
                int comma = CountChar(t, ',');
                int tab = CountChar(t, '\t');
                if (tab > semi && tab > comma) { return '\t'; }
                return semi > comma ? ';' : ',';
            }
            return ',';
        }

        private static List<List<string>> ParseCsv(string text, char delim)
        {
            List<List<string>> rows = new List<List<string>>();
            List<string> cur = new List<string>();
            StringBuilder sb = new StringBuilder();
            bool inQ = false;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (inQ)
                {
                    if (c == '"')
                    {
                        if (i + 1 < text.Length && text[i + 1] == '"') { sb.Append('"'); i++; }
                        else { inQ = false; }
                    }
                    else { sb.Append(c); }
                }
                else
                {
                    if (c == '"') { inQ = true; }
                    else if (c == delim) { cur.Add(sb.ToString()); sb.Length = 0; }
                    else if (c == '\r') { }
                    else if (c == '\n')
                    {
                        cur.Add(sb.ToString()); sb.Length = 0;
                        rows.Add(cur); cur = new List<string>();
                    }
                    else { sb.Append(c); }
                }
            }
            if (sb.Length > 0 || cur.Count > 0) { cur.Add(sb.ToString()); rows.Add(cur); }
            return rows;
        }

        private static bool IsSkippable(List<string> r)
        {
            if (r.Count == 0) { return true; }
            if (r[0].Trim().StartsWith("#")) { return true; }
            foreach (string s in r) { if (s.Trim().Length > 0) { return false; } }
            return true;
        }

        private static string Cell(List<string> f, int idx)
        {
            return (idx >= 0 && idx < f.Count) ? f[idx] : "";
        }

        private static int Idx(Dictionary<string, int> col, string a, string b)
        {
            int i;
            if (col.TryGetValue(a, out i)) { return i; }
            if (b != null && col.TryGetValue(b, out i)) { return i; }
            return -1;
        }

        private static bool ParseBool(string s, out bool value)
        {
            value = false;
            switch (s.Trim().ToUpperInvariant())
            {
                case "SI": case "S": case "1": case "TRUE": case "YES": case "Y": case "ACTIVO": case "ALTA":
                    value = true; return true;
                case "NO": case "N": case "0": case "FALSE": case "INACTIVO": case "BAJA":
                    value = false; return true;
            }
            return false;
        }

        private static bool ParsePerms(string s, out bool r, out bool w, out bool d)
        {
            r = false; w = false; d = false;
            if (s.Trim().Length == 0) { r = true; return true; }     // por defecto: solo lectura
            string[] tokens = s.Split(new char[] { '+', '|', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string tk in tokens)
            {
                switch (tk.ToUpperInvariant())
                {
                    case "LECTURA": case "READ": case "R": case "L": case "SOLOLECTURA": case "RO":
                        r = true; break;
                    case "ESCRITURA": case "WRITE": case "W": case "E": case "ESCRIBIR": case "SUBIR":
                        w = true; break;
                    case "ELIMINAR": case "DELETE": case "D": case "BORRAR":
                        d = true; break;
                    case "TODO": case "FULL": case "ALL":
                        r = true; w = true; d = true; break;
                    default:
                        return false;
                }
            }
            return true;
        }

        private Dictionary<string, UserEntry> Parse(string text)
        {
            char delim = DetectDelimiter(text);
            List<List<string>> rows = ParseCsv(text, delim);

            int h = -1;
            for (int i = 0; i < rows.Count; i++) { if (!IsSkippable(rows[i])) { h = i; break; } }
            if (h < 0) { throw new FormatException("El CSV esta vacio o no tiene encabezado."); }

            Dictionary<string, int> col = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            List<string> head = rows[h];
            for (int i = 0; i < head.Count; i++)
            {
                string n = head[i].Trim().Trim('\uFEFF');
                if (n.Length > 0 && !col.ContainsKey(n)) { col[n] = i; }
            }
            string[] required = new string[] { "Usuario", "Activo", "Tipo", "Ruta" };
            foreach (string rq in required)
            {
                if (!col.ContainsKey(rq))
                {
                    throw new FormatException("Falta la columna obligatoria '" + rq + "' en el encabezado del CSV.");
                }
            }
            int cUser = col["Usuario"], cAct = col["Activo"], cTipo = col["Tipo"], cRuta = col["Ruta"];
            int cPass = Idx(col, "Password", "Contrasena");
            int cPerm = Idx(col, "Permisos", null);
            int cIdle = Idx(col, "InactividadSeg", "Inactividad");

            Dictionary<string, UserEntry> d = new Dictionary<string, UserEntry>(StringComparer.OrdinalIgnoreCase);

            for (int i = h + 1; i < rows.Count; i++)
            {
                List<string> f = rows[i];
                if (IsSkippable(f)) { continue; }
                string name = Cell(f, cUser).Trim();
                if (name.Length == 0) { continue; }
                string tag = "[CSV] fila " + (i + 1) + " (" + name + "): ";

                if (d.ContainsKey(name)) { FtpLog.Write(tag + "usuario duplicado, se ignora esta fila."); continue; }

                bool active;
                if (!ParseBool(Cell(f, cAct), out active))
                {
                    FtpLog.Write(tag + "Activo invalido '" + Cell(f, cAct).Trim() + "' -> se trata como NO.");
                    active = false;
                }

                UserEntry e = new UserEntry();
                e.Name = name;
                e.Active = active;

                if (!active) { d[name] = e; continue; }       // dado de baja: no se valida nada mas

                string tipo = Cell(f, cTipo).Trim().ToUpperInvariant();
                if (tipo == "AD" || tipo == "DOMINIO") { e.IsAd = true; }
                else if (tipo == "LOCAL" || tipo == "PLANO" || tipo == "PLAIN") { e.IsAd = false; }
                else { FtpLog.Write(tag + "Tipo invalido '" + tipo + "' (use AD o LOCAL). Usuario NO disponible."); continue; }

                if (!e.IsAd)
                {
                    e.Password = Cell(f, cPass);
                    if (e.Password.Length == 0) { FtpLog.Write(tag + "Tipo LOCAL requiere Password. Usuario NO disponible."); continue; }
                }

                string ruta = Cell(f, cRuta).Trim().Trim('"');
                bool absoluta = (ruta.Length >= 3 && ruta[1] == ':' && (ruta[2] == '\\' || ruta[2] == '/')) ||
                                ruta.StartsWith("\\\\");
                if (!absoluta)
                {
                    FtpLog.Write(tag + "Ruta debe ser absoluta (C:\\carpeta o \\\\servidor\\recurso). Usuario NO disponible.");
                    continue;
                }
                try
                {
                    string full = Path.GetFullPath(ruta);
                    if (full.Length > 3) { full = full.TrimEnd('\\'); }
                    e.RootFull = full;
                }
                catch (Exception ex) { FtpLog.Write(tag + "Ruta invalida: " + ex.Message); continue; }

                bool pr, pw, pd;
                if (!ParsePerms(Cell(f, cPerm), out pr, out pw, out pd))
                {
                    FtpLog.Write(tag + "Permisos invalidos '" + Cell(f, cPerm).Trim() +
                                 "' (use LECTURA, ESCRITURA, ELIMINAR con +). Usuario NO disponible.");
                    continue;
                }
                e.CanRead = pr; e.CanWrite = pw; e.CanDelete = pd;

                int idle = defaultIdle;
                string its = Cell(f, cIdle).Trim();
                if (its.Length > 0)
                {
                    int v;
                    if (int.TryParse(its, NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) { idle = v; }
                    else { FtpLog.Write(tag + "InactividadSeg invalido '" + its + "', se usa el valor por defecto."); }
                }
                if (idle < 5) { idle = 5; }
                if (idle > 86400) { idle = 86400; }
                e.IdleSec = idle;

                d[name] = e;
                FtpLog.Write("[CSV] usuario " + name + ": " + (e.IsAd ? "AD" : "LOCAL") + ", ruta " + e.RootFull +
                             ", permisos " + e.PermText + ", inactividad " + idle + "s");
            }
            return d;
        }
    }

    // ------------------------------------------------------------------
    // Servidor: acepta conexiones, mantiene el registro de sesiones,
    // recarga el CSV y vigila inactividad
    // ------------------------------------------------------------------
    public class FtpServer
    {
        private readonly FtpConfig cfg;
        private readonly UserStore store;
        private readonly LoginGuard guard;
        private TcpListener listener;
        private Thread acceptThread;
        private Thread maintThread;
        private volatile bool running;
        private int stopped;
        private int nextId;
        private readonly ConcurrentDictionary<int, FtpSession> active = new ConcurrentDictionary<int, FtpSession>();
        private readonly Random rnd = new Random();
        private readonly object rndLock = new object();

        public FtpServer(FtpConfig config)
        {
            cfg = config;
            store = new UserStore(config.UsersFile, config.DefaultIdleSec);
            guard = new LoginGuard(config.MaxFailedLogins, config.BlockMinutes);
        }

        public int ActiveSessions { get { return active.Count; } }

        internal LoginGuard Guard { get { return guard; } }

        public void Start()
        {
            store.LoadInitial();                          // InvalidOperationException si el CSV es invalido

            listener = new TcpListener(IPAddress.Any, cfg.Port);   // SocketException si el puerto esta ocupado
            listener.ExclusiveAddressUse = true;
            listener.Start(50);
            running = true;

            ConsoleCtrl.Register(this);

            acceptThread = new Thread(AcceptLoop);
            acceptThread.IsBackground = true;
            acceptThread.Name = "FTP-Accept";
            acceptThread.Start();

            maintThread = new Thread(MaintenanceLoop);
            maintThread.IsBackground = true;
            maintThread.Name = "FTP-Maintenance";
            maintThread.Start();
        }

        // Detiene el servidor Y cierra todas las sesiones. Es seguro llamarlo varias veces.
        public void Stop()
        {
            if (Interlocked.Exchange(ref stopped, 1) == 1) { return; }
            running = false;
            ConsoleCtrl.Unregister(this);
            try { if (listener != null) { listener.Stop(); } } catch (Exception) { }

            foreach (FtpSession s in active.Values)
            {
                try { s.Kill(null, false); } catch (Exception) { }
            }
            int waited = 0;
            while (active.Count > 0 && waited < 30) { Thread.Sleep(100); waited++; }
            FtpLog.Write("Servidor detenido. Sesiones abiertas restantes: " + active.Count);
        }

        internal void Remove(int id)
        {
            FtpSession s;
            active.TryRemove(id, out s);
        }

        private void AcceptLoop()
        {
            while (running)
            {
                TcpClient client = null;
                try { client = listener.AcceptTcpClient(); }
                catch (SocketException) { if (!running) { break; } continue; }
                catch (ObjectDisposedException) { break; }
                catch (InvalidOperationException) { break; }

                if (!running) { try { client.Close(); } catch (Exception) { } break; }

                string ipText = "";
                try { ipText = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString(); } catch (Exception) { }
                if (ipText.Length > 0 && guard.IsBlocked(ipText))
                {
                    FtpLog.Write("[" + ipText + "] conexion rechazada: IP bloqueada por intentos fallidos");
                    try
                    {
                        byte[] bmsg = Encoding.ASCII.GetBytes("421 Too many failed logins, try later.\r\n");
                        client.GetStream().Write(bmsg, 0, bmsg.Length);
                        client.Close();
                    }
                    catch (Exception) { }
                    continue;
                }

                if (active.Count >= cfg.MaxSessions)
                {
                    try
                    {
                        byte[] msg = Encoding.ASCII.GetBytes("421 Too many connections.\r\n");
                        client.GetStream().Write(msg, 0, msg.Length);
                        client.Close();
                    }
                    catch (Exception) { }
                    continue;
                }

                int id = Interlocked.Increment(ref nextId);
                FtpSession session = new FtpSession(cfg, this, store, client, id);
                active[id] = session;
                if (!running) { session.Kill(null, false); }     // el servidor se detuvo justo ahora

                Thread t = new Thread(delegate()
                {
                    try { session.Run(); }
                    catch (Exception ex) { FtpLog.Write("Error de sesion: " + ex.Message); }
                });
                t.IsBackground = true;
                t.Name = "FTP-Session";
                t.Start();
            }
        }

        // Cada ~0.7 s: detecta cambios del CSV, revalida sesiones y aplica inactividad
        private void MaintenanceLoop()
        {
            while (running)
            {
                try
                {
                    guard.Cleanup();
                    if (store.Poll())
                    {
                        foreach (FtpSession s in active.Values) { s.Revalidate(); }
                    }
                    foreach (FtpSession s in active.Values) { s.CheckIdle(); }
                }
                catch (Exception ex) { FtpLog.Write("Error en mantenimiento: " + ex.Message); }
                Thread.Sleep(700);
            }
        }

        // Abre un listener en un puerto libre del rango pasivo
        internal TcpListener OpenPassive()
        {
            int range = cfg.PassiveMax - cfg.PassiveMin + 1;
            int start;
            lock (rndLock) { start = rnd.Next(range); }
            for (int i = 0; i < range; i++)
            {
                int port = cfg.PassiveMin + ((start + i) % range);
                try
                {
                    TcpListener l = new TcpListener(IPAddress.Any, port);
                    l.ExclusiveAddressUse = true;
                    l.Start(1);
                    return l;
                }
                catch (SocketException) { }
            }
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Una sesion FTP
    // ------------------------------------------------------------------
    internal class FtpSession
    {
        private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        private const int PreLoginIdleSec = 60;
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

        private readonly FtpConfig cfg;
        private readonly FtpServer server;
        private readonly UserStore store;
        private readonly TcpClient ctrl;
        private readonly int id;
        private readonly IPAddress clientAddr;
        private readonly string clientTag;
        private readonly object writeLock = new object();

        private StreamReader reader;
        private StreamWriter writer;

        private volatile bool authed;
        private volatile bool killed;
        private volatile bool busy;
        private volatile int lastActivity;
        private volatile UserEntry user;
        private volatile string userRoot;
        private volatile string cwd = "/";
        private volatile TcpListener pasv;
        private volatile TcpClient dataClient;
        private IPEndPoint activeEp;
        private string pendingUser;
        private string loginName;
        private string renameFrom;
        private int failures;
        private NetworkStream rawStream;        // flujo sin cifrar (base para AUTH TLS)
        private volatile bool tlsOn;
        private volatile bool protP;            // canal de datos cifrado (PROT P)

        public FtpSession(FtpConfig config, FtpServer srv, UserStore st, TcpClient client, int sessionId)
        {
            cfg = config;
            server = srv;
            store = st;
            ctrl = client;
            id = sessionId;
            IPEndPoint remote = (IPEndPoint)client.Client.RemoteEndPoint;
            clientAddr = remote.Address;
            clientTag = "[" + remote.Address + ":" + remote.Port + "]";
            lastActivity = Environment.TickCount;
        }

        // ---------------- Ciclo de vida ----------------
        public void Run()
        {
            try
            {
                if (killed) { return; }
                ctrl.SendTimeout = 30000;
                NetworkStream ns = ctrl.GetStream();
                rawStream = ns;
                UTF8Encoding utf8 = new UTF8Encoding(false);
                reader = new StreamReader(ns, utf8);
                writer = new StreamWriter(ns, utf8);
                writer.AutoFlush = true;

                FtpLog.Write(clientTag + " conexion abierta");
                Reply(220, "PowerShell FTP Server ready.");

                string line;
                while (!killed && (line = reader.ReadLine()) != null)
                {
                    lastActivity = Environment.TickCount;
                    if (line.Length > 2048) { Reply(500, "Line too long."); break; }
                    if (line.Length == 0) { continue; }
                    if (!Dispatch(line)) { break; }
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex) { FtpLog.Write(clientTag + " error: " + ex.Message); }
            finally
            {
                killed = true;
                CloseData();
                try { ctrl.Close(); } catch (Exception) { }
                server.Remove(id);
                FtpLog.Write(clientTag + " conexion cerrada" + (loginName != null ? " (usuario " + loginName + ")" : ""));
            }
        }

        // Cierra la sesion desde otro hilo (baja de usuario, inactividad, apagado)
        internal void Kill(string msg, bool notify)
        {
            if (killed) { return; }
            killed = true;
            FtpLog.Write(clientTag + " sesion cerrada por el servidor" + (msg != null ? ": " + msg : ""));

            if (notify && msg != null && writer != null)
            {
                bool got = false;
                try
                {
                    got = Monitor.TryEnter(writeLock, 500);
                    if (got) { ctrl.SendTimeout = 1000; writer.Write("421 " + msg + "\r\n"); }
                }
                catch (Exception) { }
                finally { if (got) { Monitor.Exit(writeLock); } }
            }
            CloseData();
            try { ctrl.Close(); } catch (Exception) { }
        }

        // Inactividad: por usuario (CSV). Antes del login: 60 s.
        internal void CheckIdle()
        {
            if (killed || busy) { return; }
            UserEntry u = user;
            int limit = (authed && u != null) ? u.IdleSec : PreLoginIdleSec;
            long idleMs = unchecked(Environment.TickCount - lastActivity);
            if (idleMs >= limit * 1000L)
            {
                Kill("Idle timeout (" + limit + "s).", true);
            }
        }

        // Aplica cambios del CSV a una sesion ya abierta
        internal void Revalidate()
        {
            if (killed || !authed) { return; }
            UserEntry cur = store.Get(loginName);
            UserEntry old = user;
            if (cur == null) { Kill("Account removed.", true); return; }
            if (!cur.Active) { Kill("Account disabled.", true); return; }
            if (old != null && cur.AuthKey != old.AuthKey) { Kill("Credentials changed, please reconnect.", true); return; }

            if (old != null && !string.Equals(cur.RootFull, old.RootFull, StringComparison.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(cur.RootFull)) { Kill("Home directory unavailable.", true); return; }
                userRoot = cur.RootFull;
                cwd = "/";
                FtpLog.Write(clientTag + " ruta de " + loginName + " actualizada: " + cur.RootFull);
            }
            if (old != null && (old.PermText != cur.PermText || old.IdleSec != cur.IdleSec))
            {
                FtpLog.Write(clientTag + " permisos/inactividad de " + loginName + " actualizados: " +
                             cur.PermText + ", " + cur.IdleSec + "s");
            }
            user = cur;
        }

        private void Reply(int code, string text)
        {
            lock (writeLock) { writer.Write(code.ToString(Inv) + " " + text + "\r\n"); }
        }

        private void WriteRaw(string s)
        {
            lock (writeLock) { writer.Write(s); }
        }

        private bool Deny(string what)
        {
            Reply(550, "Permission denied: " + what);
            return false;
        }

        // ---------------- Despachador ----------------
        private bool Dispatch(string line)
        {
            string cmd = line;
            string arg = "";
            int sp = line.IndexOf(' ');
            if (sp >= 0) { cmd = line.Substring(0, sp); arg = line.Substring(sp + 1); }
            cmd = cmd.ToUpperInvariant();

            FtpLog.Write(clientTag + " << " + (cmd == "PASS" ? "PASS ****" : line));

            switch (cmd)
            {
                case "USER":
                    if (authed) { Reply(503, "Already logged in."); return true; }
                    if (cfg.RequireTls && !tlsOn) { Reply(530, "Login requires AUTH TLS first."); return true; }
                    pendingUser = arg;
                    Reply(331, "Password required.");
                    return true;
                case "PASS":
                    return HandlePass(arg);
                case "QUIT":
                    Reply(221, "Goodbye.");
                    return false;
                case "NOOP":
                    Reply(200, "OK.");
                    return true;
                case "SYST":
                    Reply(215, "UNIX Type: L8");
                    return true;
                case "FEAT":
                    if (cfg.Certificate != null) { WriteRaw("211-Features:\r\n UTF8\r\n SIZE\r\n EPSV\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n"); }
                    else { WriteRaw("211-Features:\r\n UTF8\r\n SIZE\r\n EPSV\r\n211 End\r\n"); }
                    return true;
                case "OPTS":
                    if (arg.ToUpperInvariant().StartsWith("UTF8")) { Reply(200, "UTF8 mode enabled."); }
                    else { Reply(501, "Option not supported."); }
                    return true;
                case "AUTH":
                    DoAuth(arg);
                    return true;
                case "PBSZ":
                    if (!tlsOn) { Reply(503, "Send AUTH TLS first."); } else { Reply(200, "PBSZ=0"); }
                    return true;
                case "PROT":
                    DoProt(arg);
                    return true;
            }

            if (!authed) { Reply(530, "Please login with USER and PASS."); return true; }

            switch (cmd)
            {
                case "PWD":
                case "XPWD":
                    Reply(257, "\"" + cwd.Replace("\"", "\"\"") + "\" is the current directory.");
                    return true;
                case "CWD":
                case "XCWD":
                    DoCwd(arg);
                    return true;
                case "CDUP":
                case "XCUP":
                    DoCwd("..");
                    return true;
                case "TYPE":
                    Reply(200, "Type set.");
                    return true;
                case "MODE":
                    if (arg.ToUpperInvariant() == "S") { Reply(200, "Mode S."); } else { Reply(504, "Only stream mode."); }
                    return true;
                case "STRU":
                    if (arg.ToUpperInvariant() == "F") { Reply(200, "Structure F."); } else { Reply(504, "Only file structure."); }
                    return true;
                case "PASV": DoPasv(false); return true;
                case "EPSV": DoPasv(true); return true;
                case "PORT": DoPort(arg); return true;
                case "LIST": DoList(arg, false); return true;
                case "NLST": DoList(arg, true); return true;
                case "RETR": DoRetr(arg); return true;
                case "STOR": DoStor(arg); return true;
                case "SIZE": DoSize(arg); return true;
                case "DELE": DoDele(arg); return true;
                case "MKD":
                case "XMKD": DoMkd(arg); return true;
                case "RMD":
                case "XRMD": DoRmd(arg); return true;
                case "RNFR": DoRnfr(arg); return true;
                case "RNTO": DoRnto(arg); return true;
                default:
                    Reply(502, "Command not implemented.");
                    return true;
            }
        }

        // ---------------- TLS explicito (FTPS) ----------------
        private void DoAuth(string arg)
        {
            string a = arg.Trim().ToUpperInvariant();
            if (cfg.Certificate == null) { Reply(502, "TLS not supported."); return; }
            if (a != "TLS" && a != "TLS-C") { Reply(504, "Only AUTH TLS is supported."); return; }
            if (tlsOn || authed) { Reply(503, "TLS not allowed now."); return; }

            Reply(234, "Proceed with TLS negotiation.");
            try
            {
                SslStream ssl = new SslStream(rawStream, false);
                ssl.AuthenticateAsServer(cfg.Certificate, false, SslProtocols.Tls12, false);
                lock (writeLock)
                {
                    reader = new StreamReader(ssl, Utf8);
                    writer = new StreamWriter(ssl, Utf8);
                    writer.AutoFlush = true;
                }
                tlsOn = true;
                FtpLog.Write(clientTag + " TLS activado (" + ssl.SslProtocol + ")");
            }
            catch (Exception ex)
            {
                FtpLog.Write(clientTag + " fallo el handshake TLS: " + ex.Message);
                Kill("TLS handshake failed.", false);
            }
        }

        private void DoProt(string arg)
        {
            if (!tlsOn) { Reply(503, "Send AUTH TLS first."); return; }
            string a = arg.Trim().ToUpperInvariant();
            if (a == "P") { protP = true; Reply(200, "Data channel protection: private."); }
            else if (a == "C")
            {
                if (cfg.RequireTls) { Reply(534, "Server policy requires PROT P."); return; }
                protP = false;
                Reply(200, "Data channel protection: clear.");
            }
            else { Reply(536, "Protection level not supported."); }
        }

        // ---------------- Login ----------------
        private bool HandlePass(string pass)
        {
            if (pendingUser == null) { Reply(503, "Send USER first."); return true; }
            string typed = pendingUser;
            pendingUser = null;

            if (server.Guard.IsBlocked(clientAddr.ToString()))
            {
                Reply(421, "Too many failed logins, try later.");
                return false;
            }

            UserEntry entry;
            string reason;
            if (Authenticate(typed, pass, out entry, out reason))
            {
                if (!Directory.Exists(entry.RootFull))
                {
                    FtpLog.Write(clientTag + " LOGIN RECHAZADO (" + typed + "): la ruta no existe: " + entry.RootFull);
                    Reply(550, "Home directory unavailable.");
                    return false;
                }
                user = entry;
                userRoot = entry.RootFull;
                cwd = "/";
                loginName = entry.Name;
                authed = true;
                server.Guard.Ok(clientAddr.ToString());
                FtpLog.Write(clientTag + " LOGIN OK: " + typed + " [" + (entry.IsAd ? "AD" : "LOCAL") + ", " +
                             entry.PermText + ", inactividad " + entry.IdleSec + "s]");
                Reply(230, "User logged in.");
                Revalidate();                    // por si el CSV cambio justo durante el login
                return !killed;
            }

            failures++;
            FtpLog.Write(clientTag + " LOGIN FALLIDO (" + typed + "): " + reason);
            bool locked = server.Guard.Fail(clientAddr.ToString());
            if (locked) { FtpLog.Write(clientTag + " IP BLOQUEADA " + cfg.BlockMinutes + " min por intentos fallidos"); }
            Thread.Sleep(1500);
            Reply(530, "Login incorrect.");      // mensaje generico: no revela el motivo real
            return failures < 3 && !locked;
        }

        private bool Authenticate(string typed, string pass, out UserEntry entry, out string reason)
        {
            entry = null;
            reason = "";

            if (string.IsNullOrEmpty(typed) || string.IsNullOrEmpty(pass))
            {
                reason = "usuario o contrasena vacios";
                return false;
            }

            string domain = cfg.Domain;
            string logonUser = typed;
            string bare = typed;
            bool isUpn = false;

            int bs = typed.IndexOf('\\');
            int at = typed.IndexOf('@');
            if (bs >= 0)
            {
                string dm = typed.Substring(0, bs);
                bare = typed.Substring(bs + 1);
                logonUser = bare;
                if (!string.IsNullOrEmpty(cfg.Domain) && !dm.Equals(cfg.Domain, StringComparison.OrdinalIgnoreCase))
                {
                    reason = "dominio no permitido: " + dm;
                    return false;
                }
                domain = dm;
            }
            else if (at > 0)
            {
                isUpn = true;
                domain = null;
                logonUser = typed;
                bare = typed.Substring(0, at);
            }
            string canonical = (!isUpn && !string.IsNullOrEmpty(domain)) ? (domain + "\\" + bare) : typed;

            // 1) Busqueda en el CSV: nombre tal cual; si no, (solo AD) DOMINIO\usuario o usuario
            UserEntry e = store.Get(typed);
            if (e == null && !isUpn)
            {
                UserEntry c = store.Get(canonical);
                if (c == null || !c.IsAd) { c = store.Get(bare); }
                if (c != null && c.IsAd) { e = c; }
            }
            if (e == null) { reason = "usuario no existe en el CSV"; return false; }
            if (!e.Active) { reason = "usuario dado de baja (Activo=NO)"; return false; }

            // 2) Autenticacion segun el tipo
            if (e.IsAd)
            {
                if (bare.Length == 0 || bare.IndexOfAny(new char[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|', '\0' }) >= 0)
                {
                    reason = "nombre de usuario con caracteres no validos";
                    return false;
                }
                int err;
                if (!NativeAuth.Validate(logonUser, domain, pass, out err))
                {
                    reason = "LogonUser error " + err + " (" + NativeAuth.Describe(err) + ")";
                    return false;
                }
            }
            else
            {
                if (!PasswordHasher.Verify(pass, e.Password)) { reason = "contrasena incorrecta"; return false; }
            }

            entry = e;
            return true;
        }

        // ---------------- Rutas con "jaula" ----------------
        private bool Resolve(string arg, out string virt, out string phys)
        {
            virt = null;
            phys = null;
            if (arg == null) { arg = ""; }
            arg = arg.Replace('\\', '/');
            if (arg.IndexOf(':') >= 0) { return false; }

            string cur = cwd;
            string combined;
            if (arg.StartsWith("/")) { combined = arg; }
            else if (cur == "/") { combined = "/" + arg; }
            else { combined = cur + "/" + arg; }

            List<string> parts = new List<string>();
            foreach (string seg in combined.Split('/'))
            {
                if (seg.Length == 0 || seg == ".") { continue; }
                if (seg == "..") { if (parts.Count > 0) { parts.RemoveAt(parts.Count - 1); } continue; }
                parts.Add(seg);
            }
            virt = "/" + string.Join("/", parts.ToArray());

            try
            {
                string root = userRoot;
                string rootSlash = root.EndsWith("\\") ? root : root + "\\";
                string rel = string.Join("\\", parts.ToArray());
                string full = Path.GetFullPath(Path.Combine(rootSlash, rel));
                string fullSlash = full.EndsWith("\\") ? full : full + "\\";
                if (!fullSlash.StartsWith(rootSlash, StringComparison.OrdinalIgnoreCase)) { return false; }
                phys = (full.Length > 3) ? full.TrimEnd('\\') : full;
                return true;
            }
            catch (Exception) { return false; }
        }

        private void DoCwd(string arg)
        {
            string v, p;
            if (Resolve(arg, out v, out p) && Directory.Exists(p))
            {
                cwd = v;
                Reply(250, "Directory changed to " + v);
            }
            else { Reply(550, "Directory not found."); }
        }

        // ---------------- Canal de datos ----------------
        private bool HasDataChannel() { return pasv != null || activeEp != null; }

        private void CleanupData()
        {
            TcpListener l = pasv;
            pasv = null;
            activeEp = null;
            try { if (l != null) { l.Stop(); } } catch (Exception) { }
        }

        private void CloseData()
        {
            TcpClient dc = dataClient;
            if (dc != null) { try { dc.Close(); } catch (Exception) { } }
            CleanupData();
        }

        private void DoPasv(bool extended)
        {
            CleanupData();
            TcpListener l = server.OpenPassive();
            if (l == null) { Reply(425, "No passive ports available."); return; }
            pasv = l;
            int port = ((IPEndPoint)l.LocalEndpoint).Port;

            if (extended)
            {
                Reply(229, "Entering Extended Passive Mode (|||" + port.ToString(Inv) + "|)");
                return;
            }

            IPAddress ip;
            if (string.IsNullOrEmpty(cfg.PassiveIp) || !IPAddress.TryParse(cfg.PassiveIp, out ip))
            {
                ip = ((IPEndPoint)ctrl.Client.LocalEndPoint).Address;
            }
            byte[] b = ip.GetAddressBytes();
            if (b.Length != 4) { Reply(425, "IPv4 required for PASV."); CleanupData(); return; }
            Reply(227, "Entering Passive Mode (" + b[0] + "," + b[1] + "," + b[2] + "," + b[3] + "," +
                       (port >> 8) + "," + (port & 255) + ")");
        }

        private void DoPort(string arg)
        {
            string[] a = arg.Split(',');
            if (a.Length != 6) { Reply(501, "Syntax error in PORT."); return; }
            int[] n = new int[6];
            for (int i = 0; i < 6; i++)
            {
                if (!int.TryParse(a[i].Trim(), out n[i]) || n[i] < 0 || n[i] > 255)
                {
                    Reply(501, "Syntax error in PORT.");
                    return;
                }
            }
            IPAddress ip = new IPAddress(new byte[] { (byte)n[0], (byte)n[1], (byte)n[2], (byte)n[3] });
            int port = n[4] * 256 + n[5];

            // Anti "FTP bounce": solo se permite conectar de vuelta al propio cliente
            if (!ip.Equals(clientAddr)) { Reply(504, "Address must match client address."); return; }
            if (port < 1024) { Reply(501, "Port not allowed."); return; }

            CleanupData();
            activeEp = new IPEndPoint(ip, port);
            Reply(200, "PORT command successful.");
        }

        private TcpClient OpenData()
        {
            try
            {
                TcpListener l = pasv;
                if (l != null)
                {
                    DateTime end = DateTime.UtcNow.AddSeconds(20);
                    while (DateTime.UtcNow < end && !killed)
                    {
                        if (l.Server.Poll(500000, SelectMode.SelectRead))
                        {
                            TcpClient c = l.AcceptTcpClient();
                            IPAddress ra = ((IPEndPoint)c.Client.RemoteEndPoint).Address;
                            if (ra.Equals(clientAddr)) { dataClient = c; return c; }
                            c.Close();
                        }
                    }
                    return null;
                }
                IPEndPoint ep = activeEp;
                if (ep != null)
                {
                    TcpClient c = new TcpClient();
                    IAsyncResult ar = c.BeginConnect(ep.Address, ep.Port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(15000)) { c.Close(); return null; }
                    c.EndConnect(ar);
                    dataClient = c;
                    return c;
                }
            }
            catch (Exception ex) { if (!killed) { FtpLog.Write(clientTag + " error en canal de datos: " + ex.Message); } }
            return null;
        }

        // 150 -> abrir datos -> trabajo -> cerrar -> 226/4xx. Durante la transferencia no cuenta inactividad.
        private void RunTransfer(Action<Stream> work)
        {
            if (cfg.RequireTls && !protP)
            {
                Reply(522, "Data connection must be encrypted (PBSZ 0 + PROT P).");
                CleanupData();
                return;
            }
            Reply(150, "Opening data connection.");
            busy = true;
            lastActivity = Environment.TickCount;
            TcpClient d = null;
            int rc = 426;
            string rm = "Transfer aborted.";
            try
            {
                d = OpenData();
                if (d == null) { rc = 425; rm = "Cannot open data connection."; }
                else
                {
                    d.ReceiveTimeout = 60000;
                    d.SendTimeout = 60000;
                    Stream s = d.GetStream();
                    SslStream ds = null;
                    if (protP)
                    {
                        ds = new SslStream(s, false);
                        ds.AuthenticateAsServer(cfg.Certificate, false, SslProtocols.Tls12, false);
                        s = ds;
                    }
                    try { work(s); }
                    finally { if (ds != null) { try { ds.Dispose(); } catch (Exception) { } } }
                    rc = 226;
                    rm = "Transfer complete.";
                }
            }
            catch (Exception ex) { if (!killed) { FtpLog.Write(clientTag + " error de transferencia: " + ex.Message); } }
            finally
            {
                if (d != null) { try { d.Close(); } catch (Exception) { } }
                dataClient = null;
                CleanupData();
                lastActivity = Environment.TickCount;
                busy = false;
            }
            Reply(rc, rm);
        }

        private void Copy(Stream src, Stream dst)
        {
            byte[] buf = new byte[65536];
            int n;
            while ((n = src.Read(buf, 0, buf.Length)) > 0)
            {
                dst.Write(buf, 0, n);
                lastActivity = Environment.TickCount;
            }
            dst.Flush();
        }

        // ---------------- LIST / NLST ----------------
        private void DoList(string arg, bool namesOnly)
        {
            UserEntry u = user;
            if (!u.CanRead) { Deny("read not allowed"); CleanupData(); return; }

            arg = arg.Trim();
            while (arg.StartsWith("-"))
            {
                int i = arg.IndexOf(' ');
                arg = (i < 0) ? "" : arg.Substring(i + 1).TrimStart();
            }

            string v, p;
            if (!Resolve(arg, out v, out p)) { Reply(550, "Invalid path."); CleanupData(); return; }
            bool isDir = Directory.Exists(p);
            if (!isDir && !File.Exists(p)) { Reply(550, "Path not found."); CleanupData(); return; }
            if (!HasDataChannel()) { Reply(425, "Use PASV or PORT first."); return; }

            string text;
            try { text = BuildListing(p, isDir, namesOnly); }
            catch (Exception ex)
            {
                FtpLog.Write(clientTag + " error al listar: " + ex.Message);
                Reply(550, "Cannot list directory.");
                CleanupData();
                return;
            }

            byte[] bytes = Encoding.UTF8.GetBytes(text);
            RunTransfer(delegate(Stream s) { s.Write(bytes, 0, bytes.Length); s.Flush(); });
        }

        private static string BuildListing(string phys, bool isDir, bool namesOnly)
        {
            StringBuilder sb = new StringBuilder();
            FileSystemInfo[] items;
            if (isDir) { items = new DirectoryInfo(phys).GetFileSystemInfos(); }
            else { items = new FileSystemInfo[] { new FileInfo(phys) }; }

            foreach (FileSystemInfo fi in items)
            {
                if (namesOnly) { sb.Append(fi.Name).Append("\r\n"); continue; }

                bool dir = (fi.Attributes & FileAttributes.Directory) != 0;
                long size = 0;
                FileInfo f = fi as FileInfo;
                if (!dir && f != null) { size = f.Length; }

                bool ro = (fi.Attributes & FileAttributes.ReadOnly) != 0;
                string perm = dir ? "drwxr-xr-x" : (ro ? "-r--r--r--" : "-rw-r--r--");

                DateTime t = fi.LastWriteTime;
                string date = ((DateTime.Now - t).TotalDays > 180 || t > DateTime.Now.AddDays(1))
                    ? t.ToString("MMM dd  yyyy", Inv)
                    : t.ToString("MMM dd HH:mm", Inv);

                sb.Append(perm).Append(" 1 owner group ")
                  .Append(size.ToString(Inv).PadLeft(12)).Append(' ')
                  .Append(date).Append(' ')
                  .Append(fi.Name).Append("\r\n");
            }
            return sb.ToString();
        }

        // ---------------- RETR / STOR ----------------
        private void DoRetr(string arg)
        {
            UserEntry u = user;
            if (!u.CanRead) { Deny("read not allowed"); CleanupData(); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || !File.Exists(p)) { Reply(550, "File not found."); CleanupData(); return; }
            if (!HasDataChannel()) { Reply(425, "Use PASV or PORT first."); return; }

            FtpLog.Write(clientTag + " descarga: " + v);
            RunTransfer(delegate(Stream s)
            {
                using (FileStream fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    Copy(fs, s);
                }
            });
        }

        private void DoStor(string arg)
        {
            UserEntry u = user;
            if (!u.CanWrite) { Deny("upload not allowed"); CleanupData(); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || v == "/") { Reply(550, "Invalid path."); CleanupData(); return; }
            if (Directory.Exists(p)) { Reply(550, "Target is a directory."); CleanupData(); return; }
            string parent = Path.GetDirectoryName(p);
            if (parent == null || !Directory.Exists(parent)) { Reply(550, "Parent directory not found."); CleanupData(); return; }
            if (File.Exists(p) && !u.CanDelete)
            {
                Deny("overwriting an existing file requires delete permission");
                CleanupData();
                return;
            }
            if (!HasDataChannel()) { Reply(425, "Use PASV or PORT first."); return; }

            // Sin permiso de eliminar solo se pueden crear archivos nuevos (CreateNew falla si ya existe)
            FileMode mode = u.CanDelete ? FileMode.Create : FileMode.CreateNew;

            FtpLog.Write(clientTag + " subida: " + v);
            RunTransfer(delegate(Stream s)
            {
                FileStream fs = new FileStream(p, mode, FileAccess.Write, FileShare.None);   // si falla, no se borra nada
                bool ok = false;
                try { Copy(s, fs); ok = true; }
                finally
                {
                    fs.Dispose();
                    if (!ok) { try { File.Delete(p); } catch (Exception) { } }               // no dejar archivos a medias
                }
            });
        }

        // ---------------- Operaciones de archivos ----------------
        private void DoSize(string arg)
        {
            if (!user.CanRead) { Deny("read not allowed"); return; }
            string v, p;
            if (Resolve(arg, out v, out p) && File.Exists(p))
            {
                try { Reply(213, new FileInfo(p).Length.ToString(Inv)); return; } catch (IOException) { throw; } catch (Exception) { }
            }
            Reply(550, "File not found.");
        }

        private void DoDele(string arg)
        {
            if (!user.CanDelete) { Deny("delete not allowed"); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || !File.Exists(p)) { Reply(550, "File not found."); return; }
            try { File.Delete(p); FtpLog.Write(clientTag + " borrado: " + v); Reply(250, "File deleted."); }
            catch (Exception ex) { FtpLog.Write(clientTag + " error DELE: " + ex.Message); Reply(550, "Cannot delete file."); }
        }

        private void DoMkd(string arg)
        {
            if (!user.CanWrite) { Deny("write not allowed"); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || v == "/" || Directory.Exists(p) || File.Exists(p))
            {
                Reply(550, "Cannot create directory.");
                return;
            }
            try { Directory.CreateDirectory(p); Reply(257, "\"" + v.Replace("\"", "\"\"") + "\" created."); }
            catch (Exception ex) { FtpLog.Write(clientTag + " error MKD: " + ex.Message); Reply(550, "Cannot create directory."); }
        }

        private void DoRmd(string arg)
        {
            if (!user.CanDelete) { Deny("delete not allowed"); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || v == "/" || !Directory.Exists(p)) { Reply(550, "Directory not found."); return; }
            try { Directory.Delete(p, false); Reply(250, "Directory removed."); }
            catch (Exception ex) { FtpLog.Write(clientTag + " error RMD: " + ex.Message); Reply(550, "Cannot remove directory (not empty?)."); }
        }

        private void DoRnfr(string arg)
        {
            if (!user.CanWrite) { Deny("write not allowed"); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || v == "/" || (!File.Exists(p) && !Directory.Exists(p)))
            {
                Reply(550, "File not found.");
                return;
            }
            renameFrom = p;
            Reply(350, "Ready for RNTO.");
        }

        private void DoRnto(string arg)
        {
            if (!user.CanWrite) { Deny("write not allowed"); return; }
            string from = renameFrom;
            renameFrom = null;
            if (from == null) { Reply(503, "Send RNFR first."); return; }
            string v, p;
            if (!Resolve(arg, out v, out p) || v == "/" || File.Exists(p) || Directory.Exists(p))
            {
                Reply(550, "Invalid destination.");
                return;
            }
            try
            {
                if (Directory.Exists(from)) { Directory.Move(from, p); } else { File.Move(from, p); }
                Reply(250, "Renamed.");
            }
            catch (Exception ex) { FtpLog.Write(clientTag + " error RNTO: " + ex.Message); Reply(550, "Rename failed."); }
        }
    }
}