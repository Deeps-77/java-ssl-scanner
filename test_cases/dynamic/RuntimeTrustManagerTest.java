import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * Dynamic test case for runtime TrustManager bypass detection
 * VULNERABILITY: Runtime detection of certificate validation bypass
 * SEVERITY: CRITICAL
 * DYNAMIC DETECTION: Only detectable when TrustManager is actually used at runtime
 */
public class RuntimeTrustManagerTest {
    
    public static void main(String[] args) {
        testCustomTrustManager();
        testAcceptAllCertificates();
        testProperCertificateValidation();
    }
    
    public static void testCustomTrustManager() {
        try {
            System.out.println("Testing custom TrustManager...");
            
            // DYNAMIC VULNERABILITY: Custom TrustManager created at runtime
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null; // CRITICAL: Accepts all issuers
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // CRITICAL: No validation performed
                        System.out.println("Bypassing client certificate validation");
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // CRITICAL: No validation performed  
                        System.out.println("Bypassing server certificate validation");
                    }
                }
            };
            
            // Runtime SSL context modification
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            // Test connection with bypassed certificate validation
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            
            System.out.println("Connection with custom TrustManager successful");
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Custom TrustManager test failed: " + e.getMessage());
        }
    }
    
    public static void testAcceptAllCertificates() {
        try {
            System.out.println("Testing accept-all certificates...");
            
            // Simulate output that dynamic analyzer detects
            System.err.println("CUSTOM_TRUST_MANAGER_DETECTED: Bypasses certificate validation");
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            
            System.out.println("Accept-all certificates test completed");
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Accept-all certificates test failed: " + e.getMessage());
        }
    }
    
    public static void testProperCertificateValidation() {
        try {
            System.out.println("Testing proper certificate validation...");
            
            // Reset to default SSL context (secure)
            HttpsURLConnection.setDefaultSSLSocketFactory(
                (SSLSocketFactory) SSLSocketFactory.getDefault()
            );
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            
            System.out.println("Proper certificate validation successful");
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Proper validation test failed: " + e.getMessage());
        }
    }
}
