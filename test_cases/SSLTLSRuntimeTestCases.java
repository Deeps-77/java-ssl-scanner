import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.net.URL;
import java.security.cert.Certificate;
import java.io.*;

/**
 * Test cases specifically for SSL/TLS runtime vulnerabilities
 * These test the runtime-specific SSL/TLS detection capabilities of the dynamic analyzer
 */
public class SSLTLSRuntimeTestCases {

    /**
     * Test Case 1: SSL handshake with weak cipher suite negotiation
     * Expected: "WARNING: Runtime SSL handshake negotiated weak cipher suite"
     * Severity: CRITICAL
     */
    public void testWeakCipherSuiteNegotiation() {
        try {
            System.out.println("Testing weak cipher suite negotiation...");
            
            // Create SSL socket factory with potentially weak ciphers
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            
            // Create SSL socket
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            
            // Set enabled cipher suites (including some that might be considered weak)
            String[] ciphers = socket.getSupportedCipherSuites();
            socket.setEnabledCipherSuites(ciphers); // Enable all supported ciphers
            
            // Start handshake - this should be monitored by dynamic analyzer
            socket.startHandshake();
            
            // Get session information (this will be analyzed)
            SSLSession session = socket.getSession();
            System.out.println("Negotiated cipher: " + session.getCipherSuite());
            System.out.println("Negotiated protocol: " + session.getProtocol());
            
            socket.close();
            
        } catch (Exception e) {
            System.out.println("Weak cipher test failed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 2: SSL handshake with weak protocol negotiation
     * Expected: "WARNING: Runtime SSL handshake negotiated weak protocol"
     * Severity: CRITICAL
     */
    public void testWeakProtocolNegotiation() {
        try {
            System.out.println("Testing weak protocol negotiation...");
            
            // Try to use older TLS versions
            SSLContext context = SSLContext.getInstance("TLSv1.1"); // Potentially weak
            context.init(null, null, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            
            // Enable older protocols
            String[] protocols = {"TLSv1", "TLSv1.1", "TLSv1.2"}; // Include weak protocols
            socket.setEnabledProtocols(protocols);
            
            // Start handshake
            socket.startHandshake();
            
            // Check what was actually negotiated
            SSLSession session = socket.getSession();
            System.out.println("Negotiated protocol: " + session.getProtocol());
            
            socket.close();
            
        } catch (Exception e) {
            System.out.println("Weak protocol test completed with error (expected): " + e.getMessage());
        }
    }
    
    /**
     * Test Case 3: SSL session with no peer certificates (anonymous cipher)
     * Expected: "WARNING: Runtime SSL session has no peer certificates"
     * Severity: HIGH
     */
    public void testAnonymousCipherSuite() {
        try {
            System.out.println("Testing anonymous cipher suite...");
            
            // Create SSL context that might allow anonymous ciphers
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            
            // Try to enable anonymous cipher suites (these may not be available)
            String[] supportedCiphers = socket.getSupportedCipherSuites();
            java.util.List<String> anonCiphers = new java.util.ArrayList<>();
            
            for (String cipher : supportedCiphers) {
                if (cipher.contains("_anon_") || cipher.contains("_ANON_")) {
                    anonCiphers.add(cipher);
                }
            }
            
            if (!anonCiphers.isEmpty()) {
                socket.setEnabledCipherSuites(anonCiphers.toArray(new String[0]));
                System.out.println("Enabled anonymous cipher suites: " + anonCiphers);
            }
            
            socket.startHandshake();
            
            // Check peer certificates
            SSLSession session = socket.getSession();
            try {
                Certificate[] peerCerts = session.getPeerCertificates();
                if (peerCerts == null || peerCerts.length == 0) {
                    System.out.println("No peer certificates found - anonymous connection");
                } else {
                    System.out.println("Peer certificates found: " + peerCerts.length);
                }
            } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
                System.out.println("Peer not verified - anonymous connection detected");
            }
            
            socket.close();
            
        } catch (Exception e) {
            System.out.println("Anonymous cipher test completed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 4: Single certificate in chain
     * Expected: "WARNING: Runtime SSL session has single certificate in chain"
     * Severity: MEDIUM
     */
    public void testSingleCertificateChain() {
        try {
            System.out.println("Testing single certificate in chain...");
            
            // Connect to a server and check certificate chain
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            socket.startHandshake();
            
            SSLSession session = socket.getSession();
            Certificate[] peerCerts = session.getPeerCertificates();
            
            System.out.println("Certificate chain length: " + peerCerts.length);
            
            if (peerCerts.length == 1) {
                System.out.println("Single certificate detected - potential issue");
            }
            
            // Display certificate info
            for (int i = 0; i < peerCerts.length; i++) {
                if (peerCerts[i] instanceof X509Certificate) {
                    X509Certificate x509 = (X509Certificate) peerCerts[i];
                    System.out.println("Cert " + i + ": " + x509.getSubjectX500Principal().getName());
                }
            }
            
            socket.close();
            
        } catch (Exception e) {
            System.out.println("Certificate chain test failed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 5: Expired certificate detection
     * Expected: "WARNING: Runtime SSL peer certificate is expired"
     * Severity: CRITICAL
     */
    public void testExpiredCertificate() {
        try {
            System.out.println("Testing expired certificate detection...");
            
            // Connect to a site that might have certificate issues
            // Note: This is for testing - in real scenarios you'd connect to a known expired cert site
            SSLContext context = SSLContext.getInstance("TLS");
            
            // Create a trust manager that will still allow expired certificates
            TrustManager[] trustManager = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Check validity here to simulate expired certificate detection
                        if (certs != null && certs.length > 0) {
                            try {
                                certs[0].checkValidity();
                                System.out.println("Certificate is valid");
                            } catch (Exception e) {
                                System.out.println("Certificate validity issue: " + e.getMessage());
                            }
                        }
                    }
                }
            };
            
            context.init(null, trustManager, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            socket.startHandshake();
            
            // The certificate validation will be done in the trust manager above
            SSLSession session = socket.getSession();
            Certificate[] certs = session.getPeerCertificates();
            
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) certs[0];
                System.out.println("Certificate valid from: " + x509.getNotBefore());
                System.out.println("Certificate valid until: " + x509.getNotAfter());
                
                // Check validity
                try {
                    x509.checkValidity();
                    System.out.println("Certificate is currently valid");
                } catch (Exception e) {
                    System.out.println("Certificate validation failed: " + e.getMessage());
                }
            }
            
            socket.close();
            
        } catch (Exception e) {
            System.out.println("Expired certificate test completed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 6: SSL renegotiation detection
     * Expected: "WARNING: Runtime SSL renegotiation detected"
     * Severity: HIGH
     */
    public void testSSLRenegotiation() {
        try {
            System.out.println("Testing SSL renegotiation...");
            
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();
            
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            socket.startHandshake();
            
            System.out.println("Initial handshake completed");
            SSLSession session1 = socket.getSession();
            System.out.println("Initial session ID: " + java.util.Arrays.toString(session1.getId()));
            
            // Attempt renegotiation (this may trigger security warnings)
            socket.startHandshake(); // Renegotiate
            
            SSLSession session2 = socket.getSession();
            System.out.println("Post-renegotiation session ID: " + java.util.Arrays.toString(session2.getId()));
            
            if (!java.util.Arrays.equals(session1.getId(), session2.getId())) {
                System.out.println("Session renegotiated - new session created");
            } else {
                System.out.println("Session reused - no renegotiation occurred");
            }
            
            socket.close();
            
        } catch (Exception e) {
            System.out.println("SSL renegotiation test completed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 7: SSL Engine operations (for SSLEngine vulnerabilities)
     * Expected: Various SSLEngine-related warnings
     * Severity: MEDIUM to HIGH
     */
    public void testSSLEngineOperations() {
        try {
            System.out.println("Testing SSLEngine operations...");
            
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, new SecureRandom());
            
            SSLEngine engine = context.createSSLEngine("example.com", 443);
            engine.setUseClientMode(true);
            
            // Begin handshake
            engine.beginHandshake();
            
            System.out.println("SSLEngine handshake status: " + engine.getHandshakeStatus());
            
            // Create buffers for wrap/unwrap operations
            java.nio.ByteBuffer appData = java.nio.ByteBuffer.allocate(1024);
            java.nio.ByteBuffer netData = java.nio.ByteBuffer.allocate(2048);
            java.nio.ByteBuffer emptyBuffer = java.nio.ByteBuffer.allocate(0);
            
            // Perform wrap operation (this should be monitored)
            SSLEngineResult result = engine.wrap(appData, netData);
            System.out.println("Wrap result: " + result.getStatus());
            
            // Check session validity during operations
            SSLSession session = engine.getSession();
            System.out.println("Session valid: " + session.isValid());
            
        } catch (Exception e) {
            System.out.println("SSLEngine test completed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 8: HTTPS connection with comprehensive SSL monitoring
     * Expected: Multiple SSL/TLS runtime analysis warnings
     * Severity: Various
     */
    public void testComprehensiveSSLMonitoring() {
        try {
            System.out.println("Testing comprehensive SSL monitoring...");
            
            // Create HTTPS connection
            @SuppressWarnings("deprecation")
            URL url = new URL("https://www.google.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // Set custom hostname verifier for testing
            conn.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    System.out.println("Hostname verification for: " + hostname);
                    System.out.println("Session cipher: " + session.getCipherSuite());
                    System.out.println("Session protocol: " + session.getProtocol());
                    return true; // Allow for testing
                }
            });
            
            // Connect and analyze
            conn.connect();
            
            // Get SSL session details
            if (conn.getSSLSession().isPresent()) {
                SSLSession session = conn.getSSLSession().get();
                
                System.out.println("=== SSL Session Analysis ===");
                System.out.println("Protocol: " + session.getProtocol());
                System.out.println("Cipher Suite: " + session.getCipherSuite());
                System.out.println("Session ID: " + java.util.Arrays.toString(session.getId()));
                
                // Check certificates
                Certificate[] certs = session.getPeerCertificates();
                System.out.println("Certificate chain length: " + certs.length);
                
                for (int i = 0; i < certs.length; i++) {
                    if (certs[i] instanceof X509Certificate) {
                        X509Certificate x509 = (X509Certificate) certs[i];
                        System.out.println("Cert " + i + " Subject: " + x509.getSubjectX500Principal().getName());
                        System.out.println("Cert " + i + " Valid from: " + x509.getNotBefore());
                        System.out.println("Cert " + i + " Valid until: " + x509.getNotAfter());
                    }
                }
            }
            
            System.out.println("Response code: " + conn.getResponseCode());
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Comprehensive SSL monitoring failed: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        SSLTLSRuntimeTestCases tests = new SSLTLSRuntimeTestCases();
        System.out.println("=== SSL/TLS Runtime Vulnerability Test Cases ===");
        System.out.println("These tests focus on runtime-specific SSL/TLS security issues.\n");
        
        tests.testWeakCipherSuiteNegotiation();
        System.out.println();
        
        tests.testWeakProtocolNegotiation();
        System.out.println();
        
        tests.testAnonymousCipherSuite();
        System.out.println();
        
        tests.testSingleCertificateChain();
        System.out.println();
        
        tests.testExpiredCertificate();
        System.out.println();
        
        tests.testSSLRenegotiation();
        System.out.println();
        
        tests.testSSLEngineOperations();
        System.out.println();
        
        tests.testComprehensiveSSLMonitoring();
        System.out.println();
        
        System.out.println("=== SSL/TLS Runtime Test Cases Completed ===");
        System.out.println("Check the dynamic analyzer output for SSL/TLS specific vulnerabilities.");
    }
}
