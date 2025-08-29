import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.net.URL;
import java.net.HttpURLConnection;
import javax.crypto.Cipher;
import java.security.MessageDigest;

/**
 * Comprehensive test cases for Static Analysis vulnerabilities
 * Each method demonstrates a specific security vulnerability that should be detected by static analysis
 */
public class StaticAnalysisTestCases {

    // === SSL/TLS Trust Manager Vulnerabilities ===
    
    /**
     * Test Case 1: Anonymous TrustManager that accepts all certificates
     * Vulnerability: Bypasses certificate validation
     * Severity: CRITICAL
     */
    public void testAnonymousTrustManager() {
        try {
            // This should trigger: Anonymous HostnameVerifier/TrustManager detected
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Test Case 2: Insecure HostnameVerifier that allows all hostnames
     * Vulnerability: Allows man-in-the-middle attacks
     * Severity: CRITICAL
     */
    public void testInsecureHostnameVerifier() {
        try {
            URL url = new URL("https://example.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // This should trigger: Anonymous HostnameVerifier detected
            conn.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // Always return true - INSECURE!
                }
            });
            
            conn.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Test Case 3: Using deprecated SSL/TLS protocols
     * Vulnerability: Weak protocols vulnerable to attacks
     * Severity: HIGH
     */
    public void testWeakSSLProtocols() {
        try {
            // This should trigger: Deprecated SSL/TLS protocol detected
            SSLContext context = SSLContext.getInstance("SSL"); // Should use TLSv1.2 or TLSv1.3
            context.init(null, null, new SecureRandom());
            
            // Also test SSLv3 which is vulnerable
            SSLContext sslv3 = SSLContext.getInstance("SSLv3");
            sslv3.init(null, null, new SecureRandom());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Test Case 4: Weak cipher suites configuration
     * Vulnerability: Weak encryption algorithms
     * Severity: HIGH
     */
    public void testWeakCipherSuites() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("example.com", 443);
            
            // This should trigger: Weak cipher suites detected
            String[] weakCiphers = {
                "SSL_RSA_WITH_DES_CBC_SHA",           // DES - weak
                "SSL_RSA_WITH_RC4_128_MD5",          // RC4 - weak
                "TLS_RSA_WITH_NULL_SHA",             // NULL encryption
                "SSL_RSA_EXPORT_WITH_RC4_40_MD5"     // Export grade - weak
            };
            socket.setEnabledCipherSuites(weakCiphers);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // === Cryptographic Vulnerabilities ===
    
    /**
     * Test Case 5: Using insecure random number generation
     * Vulnerability: Predictable random numbers
     * Severity: HIGH
     */
    public void testInsecureRandom() {
        // This should trigger: Insecure random number generation
        java.util.Random random = new java.util.Random(); // Should use SecureRandom
        int randomInt = random.nextInt();
        
        // Even with seed - still insecure for cryptographic use
        java.util.Random seededRandom = new java.util.Random(System.currentTimeMillis());
        int anotherRandom = seededRandom.nextInt();
    }
    
    /**
     * Test Case 6: Weak cryptographic algorithms
     * Vulnerability: Easily breakable encryption
     * Severity: HIGH
     */
    public void testWeakCryptography() {
        try {
            // This should trigger: Weak cipher algorithms detected
            Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // DES is weak
            Cipher rc4Cipher = Cipher.getInstance("RC4"); // RC4 is broken
            
            // Weak hash algorithms
            MessageDigest md5 = MessageDigest.getInstance("MD5"); // MD5 is broken
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1"); // SHA-1 is weak
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // === Connection Security Vulnerabilities ===
    
    /**
     * Test Case 7: HTTP instead of HTTPS connections
     * Vulnerability: Unencrypted data transmission
     * Severity: MEDIUM
     */
    public void testInsecureHttpConnection() {
        try {
            // This should trigger: HTTP connection detected (should use HTTPS)
            URL url = new URL("http://api.example.com/sensitive-data");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.connect();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Test Case 8: Disabling SSL/TLS verification
     * Vulnerability: Bypasses security checks
     * Severity: CRITICAL
     */
    public void testDisabledSSLVerification() {
        try {
            // This should trigger: SSL verification disabled
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // Never verify - DANGEROUS
                }
            });
            
            // Also disable certificate verification
            TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAll, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // === Certificate Validation Vulnerabilities ===
    
    /**
     * Test Case 9: Custom TrustManager with improper validation
     * Vulnerability: Insufficient certificate checking
     * Severity: HIGH
     */
    public void testImproperCertificateValidation() {
        try {
            TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // No validation - INSECURE
                    }
                    
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Minimal validation - still INSECURE
                        if (certs == null || certs.length == 0) {
                            return; // Should throw exception
                        }
                    }
                }
            };
            
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers, new SecureRandom());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // === Multiple Vulnerabilities in One Method ===
    
    /**
     * Test Case 10: Multiple SSL/TLS vulnerabilities combined
     * Vulnerability: Multiple security issues in one method
     * Severity: CRITICAL
     */
    public void testMultipleVulnerabilities() {
        try {
            // 1. Weak protocol
            SSLContext context = SSLContext.getInstance("SSL");
            
            // 2. Accept all certificates
            TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            // 3. Insecure random
            java.util.Random insecureRandom = new java.util.Random();
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.setSeed(insecureRandom.nextLong()); // Still insecure due to weak seed
            
            context.init(null, trustAll, secureRandom);
            
            // 4. Accept all hostnames
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
            
            // 5. Use HTTP instead of HTTPS
            URL httpUrl = new URL("http://sensitive-api.example.com");
            HttpURLConnection httpConn = (HttpURLConnection) httpUrl.openConnection();
            
            // 6. Weak cipher
            Cipher weakCipher = Cipher.getInstance("DES");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        StaticAnalysisTestCases tests = new StaticAnalysisTestCases();
        System.out.println("Running static analysis test cases...");
        
        tests.testAnonymousTrustManager();
        tests.testInsecureHostnameVerifier();
        tests.testWeakSSLProtocols();
        tests.testWeakCipherSuites();
        tests.testInsecureRandom();
        tests.testWeakCryptography();
        tests.testInsecureHttpConnection();
        tests.testDisabledSSLVerification();
        tests.testImproperCertificateValidation();
        tests.testMultipleVulnerabilities();
        
        System.out.println("Static analysis test cases completed.");
    }
}
