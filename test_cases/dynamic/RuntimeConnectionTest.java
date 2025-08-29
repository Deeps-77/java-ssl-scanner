import java.net.*;
import javax.net.ssl.*;

/**
 * Dynamic test case for runtime HTTP/HTTPS connection analysis
 * VULNERABILITY: Runtime detection of insecure protocol usage
 * SEVERITY: HIGH
 * DYNAMIC DETECTION: Only detectable during actual connection attempts
 */
public class RuntimeConnectionTest {
    
    public static void main(String[] args) {
        testInsecureHttpConnection();
        testSecureHttpsConnection();
        testMixedContentScenario();
    }
    
    public static void testInsecureHttpConnection() {
        try {
            System.out.println("Testing insecure HTTP connection...");
            
            // DYNAMIC VULNERABILITY: Actual HTTP connection attempt
            @SuppressWarnings("deprecation")
            URL httpUrl = new URL("http://httpbin.org/get");
            HttpURLConnection conn = (HttpURLConnection) httpUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            
            // This triggers runtime detection by the dynamic analyzer
            conn.connect();
            
            int responseCode = conn.getResponseCode();
            System.out.println("HTTP Response: " + responseCode);
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("HTTP connection failed: " + e.getMessage());
        }
    }
    
    public static void testSecureHttpsConnection() {
        try {
            System.out.println("Testing secure HTTPS connection...");
            
            @SuppressWarnings("deprecation")
            URL httpsUrl = new URL("https://httpbin.org/get");
            HttpsURLConnection conn = (HttpsURLConnection) httpsUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            
            // This should be detected as secure by dynamic analyzer
            conn.connect();
            
            int responseCode = conn.getResponseCode();
            System.out.println("HTTPS Response: " + responseCode);
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("HTTPS connection failed: " + e.getMessage());
        }
    }
    
    public static void testMixedContentScenario() {
        try {
            System.out.println("Testing mixed content scenario...");
            
            // Simulate loading HTTPS page
            @SuppressWarnings("deprecation")
            URL secureUrl = new URL("https://httpbin.org/get");
            HttpsURLConnection secureConn = (HttpsURLConnection) secureUrl.openConnection();
            secureConn.connect();
            secureConn.disconnect();
            
            // Then loading insecure resource - mixed content vulnerability
            @SuppressWarnings("deprecation")
            URL insecureUrl = new URL("http://httpbin.org/get");
            HttpURLConnection insecureConn = (HttpURLConnection) insecureUrl.openConnection();
            insecureConn.connect();
            insecureConn.disconnect();
            
            System.out.println("Mixed content test completed");
            
        } catch (Exception e) {
            System.out.println("Mixed content test failed: " + e.getMessage());
        }
    }
}
