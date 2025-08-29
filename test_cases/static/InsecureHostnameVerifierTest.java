import javax.net.ssl.*;

/**
 * Test case for detecting insecure HostnameVerifier implementations
 * VULNERABILITY: Custom HostnameVerifier that always returns true
 * SEVERITY: HIGH
 * STATIC DETECTION: Method pattern analysis
 */
public class InsecureHostnameVerifierTest {
    
    public void setupInsecureHostnameVerifier() {
        try {
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    // VULNERABILITY: Always returns true - bypasses hostname verification
                    return true;
                }
            });
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void anotherInsecurePattern() {
        // VULNERABILITY: Using deprecated allow-all verifier
        HttpsURLConnection.setDefaultHostnameVerifier(
            HttpsURLConnection.getDefaultHostnameVerifier() // This could be overridden
        );
        
        // VULNERABILITY: Explicit bypass
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true; // CRITICAL: Accepts any hostname
            }
        };
    }
}
