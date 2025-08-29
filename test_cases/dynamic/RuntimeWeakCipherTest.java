import javax.net.ssl.*;

/**
 * Dynamic test case for runtime weak cipher detection
 * VULNERABILITY: Runtime detection of weak cipher suite negotiation
 * SEVERITY: CRITICAL
 * DYNAMIC DETECTION: Only detectable during actual SSL handshake
 */
public class RuntimeWeakCipherTest {
    
    public static void main(String[] args) {
        testWeakCipherNegotiation();
        testStrongCipherNegotiation();
        testCipherSuiteAnalysis();
    }
    
    public static void testWeakCipherNegotiation() {
        try {
            System.out.println("Testing weak cipher negotiation...");
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // Simulate weak cipher detection during handshake
            System.err.println("WEAK_CIPHER_DETECTED: SSL_RSA_WITH_RC4_128_SHA");
            System.err.println("WEAK_CIPHER_DETECTED: SSL_RSA_WITH_DES_CBC_SHA");
            System.err.println("WEAK_CIPHER_DETECTED: TLS_RSA_WITH_NULL_SHA");
            
            conn.setConnectTimeout(5000);
            conn.connect();
            
            System.out.println("Weak cipher test completed");
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Weak cipher test failed: " + e.getMessage());
        }
    }
    
    public static void testStrongCipherNegotiation() {
        try {
            System.out.println("Testing strong cipher negotiation...");
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            
            // Simulate strong cipher detection
            System.out.println("STRONG_CIPHER_NEGOTIATED: TLS_AES_256_GCM_SHA384");
            
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Strong cipher test failed: " + e.getMessage());
        }
    }
    
    public static void testCipherSuiteAnalysis() {
        try {
            System.out.println("Testing cipher suite analysis...");
            
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            
            SSLSocketFactory factory = context.getSocketFactory();
            String[] supportedCiphers = factory.getSupportedCipherSuites();
            
            System.out.println("Analyzing " + supportedCiphers.length + " supported cipher suites...");
            
            // Simulate analysis of cipher suites
            for (String cipher : supportedCiphers) {
                if (cipher.contains("NULL") || cipher.contains("DES") || 
                    cipher.contains("RC4") || cipher.contains("EXPORT")) {
                    System.err.println("WEAK_CIPHER_AVAILABLE: " + cipher);
                }
                // Only show first few to avoid spam
                if (cipher.contains("NULL")) break;
            }
            
            System.out.println("Cipher suite analysis completed");
            
        } catch (Exception e) {
            System.out.println("Cipher analysis failed: " + e.getMessage());
        }
    }
}
