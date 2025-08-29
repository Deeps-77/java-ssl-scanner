import javax.net.ssl.*;

/**
 * Test case for detecting weak SSL/TLS protocols
 * VULNERABILITY: Use of deprecated/weak SSL protocols
 * SEVERITY: HIGH
 * STATIC DETECTION: Protocol string analysis
 */
public class WeakProtocolTest {
    
    public void setupWeakProtocols() {
        try {
            // VULNERABILITY: Using weak SSL protocols
            SSLContext sslContext1 = SSLContext.getInstance("SSL"); // Weak: Generic SSL
            SSLContext sslContext2 = SSLContext.getInstance("SSLv2"); // CRITICAL: SSLv2
            SSLContext sslContext3 = SSLContext.getInstance("SSLv3"); // CRITICAL: SSLv3
            SSLContext sslContext4 = SSLContext.getInstance("TLSv1"); // Weak: TLS 1.0
            SSLContext sslContext5 = SSLContext.getInstance("TLSv1.1"); // Weak: TLS 1.1
            
            // VULNERABILITY: Enabling weak protocols on socket
            SSLSocketFactory factory = sslContext1.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("example.com", 443);
            
            // CRITICAL: Explicitly enabling weak protocols
            socket.setEnabledProtocols(new String[]{"SSLv2Hello", "SSLv3", "TLSv1"});
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void correctProtocolUsage() {
        try {
            // SECURE: Using strong protocols
            SSLContext secureContext = SSLContext.getInstance("TLSv1.3");
            SSLSocket secureSocket = (SSLSocket) secureContext.getSocketFactory().createSocket();
            secureSocket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
