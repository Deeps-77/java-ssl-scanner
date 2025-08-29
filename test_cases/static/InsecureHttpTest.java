import java.net.*;
import javax.net.ssl.*;

/**
 * Test case for detecting insecure HTTP usage
 * VULNERABILITY: Using HTTP instead of HTTPS for sensitive data
 * SEVERITY: HIGH
 * STATIC DETECTION: URL protocol analysis
 */
public class InsecureHttpTest {
    
    public void insecureHttpConnections() {
        try {
            // VULNERABILITY: HTTP URLs for potentially sensitive endpoints
            URL loginUrl = new URL("http://example.com/login"); // CRITICAL: Login over HTTP
            URL apiUrl = new URL("http://api.example.com/user/data"); // HIGH: API over HTTP
            URL paymentUrl = new URL("http://payment.example.com/process"); // CRITICAL: Payment over HTTP
            
            HttpURLConnection loginConn = (HttpURLConnection) loginUrl.openConnection();
            HttpURLConnection apiConn = (HttpURLConnection) apiUrl.openConnection();
            HttpURLConnection paymentConn = (HttpURLConnection) paymentUrl.openConnection();
            
            // VULNERABILITY: Sending credentials over HTTP
            loginConn.setDoOutput(true);
            loginConn.setRequestMethod("POST");
            loginConn.getOutputStream().write("username=admin&password=secret".getBytes());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void mixedContentIssues() {
        try {
            // VULNERABILITY: Mixed content - HTTPS page loading HTTP resources
            URL securePageUrl = new URL("https://secure.example.com/page");
            URL insecureResourceUrl = new URL("http://cdn.example.com/script.js"); // Mixed content
            URL insecureImageUrl = new URL("http://images.example.com/logo.png"); // Mixed content
            
            HttpsURLConnection secureConn = (HttpsURLConnection) securePageUrl.openConnection();
            HttpURLConnection insecureConn1 = (HttpURLConnection) insecureResourceUrl.openConnection();
            HttpURLConnection insecureConn2 = (HttpURLConnection) insecureImageUrl.openConnection();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void correctHttpsUsage() {
        try {
            // SECURE: Using HTTPS for all sensitive communications
            URL secureLoginUrl = new URL("https://example.com/login");
            URL secureApiUrl = new URL("https://api.example.com/user/data");
            URL securePaymentUrl = new URL("https://payment.example.com/process");
            
            HttpsURLConnection secureLoginConn = (HttpsURLConnection) secureLoginUrl.openConnection();
            HttpsURLConnection secureApiConn = (HttpsURLConnection) secureApiUrl.openConnection();
            HttpsURLConnection securePaymentConn = (HttpsURLConnection) securePaymentUrl.openConnection();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
