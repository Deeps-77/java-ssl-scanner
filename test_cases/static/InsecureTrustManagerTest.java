import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * Test case for detecting insecure TrustManager implementations
 * VULNERABILITY: Custom TrustManager that accepts all certificates
 * SEVERITY: CRITICAL
 * STATIC DETECTION: Code pattern analysis
 */
public class InsecureTrustManagerTest {
    
    public void setupInsecureTrustManager() {
        try {
            // VULNERABILITY: TrustManager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null; // CRITICAL: Returns null - accepts all issuers
                    }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // CRITICAL: Empty implementation - no validation
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // CRITICAL: Empty implementation - no validation
                    }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
