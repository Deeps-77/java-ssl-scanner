import java.net.URL;
import java.net.HttpURLConnection;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.security.AllPermission;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.io.*;
import java.lang.reflect.Method;
import java.util.Random;
import javax.crypto.Cipher;

/**
 * Comprehensive test cases for Dynamic Analysis vulnerabilities
 * Each method demonstrates runtime security issues that should be detected by the dynamic analyzer
 */
public class DynamicAnalysisTestCases {

    // === Runtime HTTP/HTTPS Connection Vulnerabilities ===
    
    /**
     * Test Case 1: Runtime HTTP connection (insecure)
     * Expected: "WARNING: Insecure HTTP connection"
     * Severity: HIGH
     */
    public void testRuntimeHttpConnection() {
        try {
            System.out.println("Testing insecure HTTP connection...");
            // This will trigger the dynamic analyzer when connect() is called
            @SuppressWarnings("deprecation")
            URL url = new URL("http://api.example.com/data");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.connect(); // This should trigger dynamic analysis warning
            
            // Read some data to make it realistic
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Data: " + line);
                    break; // Just read first line
                }
            }
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("HTTP connection failed (expected): " + e.getMessage());
        }
    }
    
    /**
     * Test Case 2: Runtime HTTPS connection with custom hostname verifier
     * Expected: "WARNING: Custom HostnameVerifier detected"
     * Severity: HIGH
     */
    public void testRuntimeCustomHostnameVerifier() {
        try {
            System.out.println("Testing HTTPS connection with custom hostname verifier...");
            @SuppressWarnings("deprecation")
            URL url = new URL("https://www.google.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // Set custom hostname verifier - this should be detected at runtime
            conn.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    System.out.println("Custom hostname verification for: " + hostname);
                    return true; // Always allow - INSECURE
                }
            });
            
            conn.connect(); // This should trigger dynamic analysis warning
            System.out.println("Response code: " + conn.getResponseCode());
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("HTTPS connection failed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 3: Runtime HTTPS connection with insecure trust manager
     * Expected: "WARNING: Potentially insecure HostnameVerifier implementation"
     * Severity: HIGH
     */
    public void testRuntimeInsecureTrustManager() {
        try {
            System.out.println("Testing HTTPS with insecure trust manager...");
            
            // Create trust manager that accepts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            
            @SuppressWarnings("deprecation")
            URL url = new URL("https://www.google.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sc.getSocketFactory());
            
            // Set hostname verifier that allows all
            conn.setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true; // Allow all hostnames - DANGEROUS
                }
            });
            
            conn.connect(); // This should trigger dynamic analysis warnings
            System.out.println("Connected successfully (insecurely): " + conn.getResponseCode());
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("Insecure HTTPS connection failed: " + e.getMessage());
        }
    }
    
    // === Security Manager and Permissions Vulnerabilities ===
    
    /**
     * Test Case 4: SecurityManager disabled check
     * Expected: "WARNING: SecurityManager is disabled"
     * Severity: HIGH
     */
    public void testSecurityManagerDisabled() {
        System.out.println("Testing SecurityManager status...");
        
        @SuppressWarnings("removal")
        SecurityManager sm = System.getSecurityManager();
        if (sm == null) {
            System.out.println("SecurityManager is disabled - this should be detected by dynamic analyzer");
        } else {
            System.out.println("SecurityManager is enabled: " + sm.getClass().getName());
        }
    }
    
    /**
     * Test Case 5: Custom Policy provider
     * Expected: "WARNING: Custom policy provider detected"
     * Severity: MEDIUM
     */
    public void testCustomPolicyProvider() {
        try {
            System.out.println("Testing custom policy provider...");
            
            // Create a custom policy
            Policy customPolicy = new Policy() {
                @Override
                public boolean implies(ProtectionDomain domain, java.security.Permission permission) {
                    return true; // Allow everything - INSECURE
                }
            };
            
            // Set custom policy (this should be detected)
            Policy.setPolicy(customPolicy);
            
            @SuppressWarnings("removal")
            Policy currentPolicy = Policy.getPolicy();
            System.out.println("Current policy: " + currentPolicy.getClass().getName());
            
        } catch (Exception e) {
            System.out.println("Policy test failed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 6: AllPermission usage
     * Expected: "WARNING: AllPermission granted"
     * Severity: CRITICAL
     */
    public void testAllPermissionUsage() {
        try {
            System.out.println("Testing AllPermission usage...");
            
            // Create permissions with AllPermission - DANGEROUS
            Permissions permissions = new Permissions();
            permissions.add(new AllPermission());
            
            // This demonstrates granting all permissions - should be detected
            System.out.println("AllPermission added to permissions set");
            
        } catch (Exception e) {
            System.out.println("AllPermission test failed: " + e.getMessage());
        }
    }
    
    // === Reflection and Deserialization Vulnerabilities ===
    
    /**
     * Test Case 7: Reflection API usage
     * Expected: "WARNING: Reflection API usage detected"
     * Severity: MEDIUM
     */
    public void testReflectionUsage() {
        try {
            System.out.println("Testing reflection usage...");
            
            // Use reflection to access private methods - should be detected
            Class<?> stringClass = String.class;
            Method[] methods = stringClass.getDeclaredMethods();
            
            for (Method method : methods) {
                if (method.getName().contains("intern")) {
                    method.setAccessible(true); // Bypassing access control
                    System.out.println("Found method via reflection: " + method.getName());
                    break;
                }
            }
            
        } catch (Exception e) {
            System.out.println("Reflection test failed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 8: Deserialization usage
     * Expected: "WARNING: Potential deserialization usage detected"
     * Severity: HIGH
     */
    public void testDeserializationUsage() {
        try {
            System.out.println("Testing deserialization usage...");
            
            // Create a simple serializable object
            String testData = "Test serialization data";
            
            // Serialize object
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(testData);
            oos.close();
            
            // Deserialize object - this should be detected as potential vulnerability
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
            ObjectInputStream ois = new ObjectInputStream(bais);
            String deserializedData = (String) ois.readObject(); // POTENTIAL VULNERABILITY
            ois.close();
            
            System.out.println("Deserialized data: " + deserializedData);
            
        } catch (Exception e) {
            System.out.println("Deserialization test failed: " + e.getMessage());
        }
    }
    
    // === Process Execution Vulnerabilities ===
    
    /**
     * Test Case 9: Process execution
     * Expected: "WARNING: Process execution API usage detected"
     * Severity: HIGH
     */
    public void testProcessExecution() {
        try {
            System.out.println("Testing process execution...");
            
            // Execute system command - should be detected as security risk
            ProcessBuilder pb = new ProcessBuilder("java", "-version");
            Process process = pb.start();
            
            // Read output
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Process output: " + line);
                }
            }
            
            int exitCode = process.waitFor();
            System.out.println("Process exit code: " + exitCode);
            
        } catch (Exception e) {
            System.out.println("Process execution test failed: " + e.getMessage());
        }
    }
    
    /**
     * Test Case 10: Runtime.exec() usage
     * Expected: "WARNING: Process execution API usage detected"
     * Severity: HIGH
     */
    public void testRuntimeExec() {
        try {
            System.out.println("Testing Runtime.exec() usage...");
            
            // Use Runtime.exec - should be detected
            Runtime runtime = Runtime.getRuntime();
            Process process = runtime.exec("echo Hello Dynamic Analysis");
            
            // Read output
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Runtime exec output: " + line);
                }
            }
            
            process.waitFor();
            
        } catch (Exception e) {
            System.out.println("Runtime.exec() test failed: " + e.getMessage());
        }
    }
    
    // === Cryptographic Vulnerabilities ===
    
    /**
     * Test Case 11: Insecure Random usage
     * Expected: "WARNING: Insecure Random usage detected"
     * Severity: HIGH
     */
    public void testInsecureRandomUsage() {
        System.out.println("Testing insecure random usage...");
        
        // Use insecure Random instead of SecureRandom - should be detected
        Random insecureRandom = new Random();
        int randomValue = insecureRandom.nextInt(1000);
        System.out.println("Insecure random value: " + randomValue);
        
        // Also test with seed (still insecure)
        Random seededRandom = new Random(System.currentTimeMillis());
        int seededValue = seededRandom.nextInt(1000);
        System.out.println("Seeded random value: " + seededValue);
    }
    
    /**
     * Test Case 12: Weak cipher usage
     * Expected: "WARNING: Weak cipher/hash usage detected"
     * Severity: HIGH
     */
    public void testWeakCipherUsage() {
        try {
            System.out.println("Testing weak cipher usage...");
            
            // Use weak DES cipher - should be detected
            Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            System.out.println("Created DES cipher: " + desCipher.getAlgorithm());
            
            // Use weak RC4 cipher - should be detected
            try {
                Cipher rc4Cipher = Cipher.getInstance("RC4");
                System.out.println("Created RC4 cipher: " + rc4Cipher.getAlgorithm());
            } catch (Exception e) {
                System.out.println("RC4 not available: " + e.getMessage());
            }
            
        } catch (Exception e) {
            System.out.println("Weak cipher test failed: " + e.getMessage());
        }
    }
    
    // === Combined Runtime Test Case ===
    
    /**
     * Test Case 13: Multiple runtime vulnerabilities combined
     * Expected: Multiple warnings from dynamic analyzer
     * Severity: CRITICAL
     */
    public void testMultipleRuntimeVulnerabilities() {
        System.out.println("Testing multiple runtime vulnerabilities...");
        
        // 1. Test SecurityManager status
        testSecurityManagerDisabled();
        
        // 2. Use insecure HTTP connection
        testRuntimeHttpConnection();
        
        // 3. Use reflection
        testReflectionUsage();
        
        // 4. Use insecure random
        testInsecureRandomUsage();
        
        // 5. Execute process
        testProcessExecution();
        
        System.out.println("Multiple runtime vulnerabilities test completed");
    }
    
    // === SSL/TLS Runtime-Specific Vulnerabilities ===
    
    /**
     * Test Case 14: SSL handshake with potentially weak ciphers
     * Expected: Runtime SSL analysis warnings
     * Severity: HIGH to CRITICAL
     */
    public void testSSLHandshakeVulnerabilities() {
        try {
            System.out.println("Testing SSL handshake vulnerabilities...");
            
            // Create SSL connection to test actual negotiated parameters
            @SuppressWarnings("deprecation")
            URL url = new URL("https://www.google.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            
            // Try to force older protocols or weaker ciphers
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            context.init(null, null, new SecureRandom());
            conn.setSSLSocketFactory(context.getSocketFactory());
            
            conn.connect();
            
            // Get SSL session information (this should be analyzed at runtime)
            SSLSession session = conn.getSSLSession();
            System.out.println("SSL Protocol: " + session.getProtocol());
            System.out.println("Cipher Suite: " + session.getCipherSuite());
            
            // Check certificate chain
            java.security.cert.Certificate[] certs = session.getPeerCertificates();
            System.out.println("Certificate chain length: " + certs.length);
            
            conn.disconnect();
            
        } catch (Exception e) {
            System.out.println("SSL handshake test failed: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        DynamicAnalysisTestCases tests = new DynamicAnalysisTestCases();
        System.out.println("=== Starting Dynamic Analysis Test Cases ===");
        System.out.println("These tests will trigger runtime security warnings in the dynamic analyzer.\n");
        
        // Run all test cases
        tests.testRuntimeHttpConnection();
        System.out.println();
        
        tests.testRuntimeCustomHostnameVerifier();
        System.out.println();
        
        tests.testRuntimeInsecureTrustManager();
        System.out.println();
        
        tests.testSecurityManagerDisabled();
        System.out.println();
        
        tests.testCustomPolicyProvider();
        System.out.println();
        
        tests.testAllPermissionUsage();
        System.out.println();
        
        tests.testReflectionUsage();
        System.out.println();
        
        tests.testDeserializationUsage();
        System.out.println();
        
        tests.testProcessExecution();
        System.out.println();
        
        tests.testRuntimeExec();
        System.out.println();
        
        tests.testInsecureRandomUsage();
        System.out.println();
        
        tests.testWeakCipherUsage();
        System.out.println();
        
        tests.testSSLHandshakeVulnerabilities();
        System.out.println();
        
        System.out.println("=== Multiple Vulnerabilities Test ===");
        tests.testMultipleRuntimeVulnerabilities();
        
        System.out.println("\n=== Dynamic Analysis Test Cases Completed ===");
        System.out.println("Check the dynamic analyzer output for detected vulnerabilities.");
    }
}
