import javax.net.ssl.*;

/**
 * Test case for detecting weak cipher suites
 * VULNERABILITY: Use of weak/deprecated cipher suites
 * SEVERITY: HIGH
 * STATIC DETECTION: Cipher string analysis
 */
public class WeakCipherTest {
    
    public void setupWeakCiphers() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
            
            // VULNERABILITY: Enabling weak cipher suites
            String[] weakCiphers = {
                "SSL_RSA_WITH_DES_CBC_SHA", // CRITICAL: DES encryption
                "SSL_RSA_WITH_RC4_128_SHA", // CRITICAL: RC4 cipher
                "SSL_RSA_WITH_NULL_SHA", // CRITICAL: NULL encryption
                "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", // CRITICAL: Export grade
                "SSL_DH_anon_WITH_DES_CBC_SHA", // CRITICAL: Anonymous DH
                "TLS_RSA_WITH_NULL_MD5", // CRITICAL: NULL encryption + weak hash
                "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" // HIGH: Anonymous ECDH
            };
            
            socket.setEnabledCipherSuites(weakCiphers);
            
            // VULNERABILITY: Including weak ciphers in allowed list
            String[] mixedCiphers = {
                "TLS_AES_256_GCM_SHA384", // Strong
                "SSL_RSA_WITH_RC4_128_SHA", // WEAK: RC4
                "TLS_AES_128_GCM_SHA256" // Strong
            };
            socket.setEnabledCipherSuites(mixedCiphers);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void correctCipherUsage() {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
            
            // SECURE: Using only strong cipher suites
            String[] strongCiphers = {
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256"
            };
            socket.setEnabledCipherSuites(strongCiphers);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
