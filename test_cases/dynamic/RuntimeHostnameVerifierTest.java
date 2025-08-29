import javax.net.ssl.*;

/**
 * Dynamic test case for runtime HostnameVerifier bypass detection
 * VULNERABILITY: Runtime detection of custom hostname verification
 * SEVERITY: HIGH  
 * DYNAMIC DETECTION: Only detectable when verifier is actually set at runtime
 */
public class RuntimeHostnameVerifierTest {
    
    public static void main(String[] args) {
        testCustomHostnameVerifier();
        testAcceptAllHostnameVerifier();
        testProperHostnameVerification();
    }
    
    public static void testCustomHostnameVerifier() {
        try {
            System.out.println("Testing custom hostname verifier...");
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // DYNAMIC VULNERABILITY: Setting custom verifier at runtime
            conn.setHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    System.out.println("Custom verification for: " + hostname);
                    return true; // CRITICAL: Always accepts any hostname
                }
            });
            
            conn.setConnectTimeout(5000);
            conn.connect();
            
            int responseCode = conn.getResponseCode();
            System.out.println("Response with custom verifier: " + responseCode);
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Custom verifier test failed: " + e.getMessage());
        }
    }
    
    public static void testAcceptAllHostnameVerifier() {
        try {
            System.out.println("Testing accept-all hostname verifier...");
            
            // DYNAMIC VULNERABILITY: Global hostname verifier bypass
            HostnameVerifier acceptAllVerifier = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // CRITICAL: Accepts all hostnames
                }
            };
            
            HttpsURLConnection.setDefaultHostnameVerifier(acceptAllVerifier);
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            
            System.out.println("Connection with accept-all verifier successful");
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Accept-all verifier test failed: " + e.getMessage());
        }
    }
    
    public static void testProperHostnameVerification() {
        try {
            System.out.println("Testing proper hostname verification...");
            
            // Reset to default secure verifier
            HttpsURLConnection.setDefaultHostnameVerifier(null);
            
            @SuppressWarnings("deprecation")
            java.net.URL url = new java.net.URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            
            System.out.println("Secure hostname verification successful");
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Proper verification test failed: " + e.getMessage());
        }
    }
}
