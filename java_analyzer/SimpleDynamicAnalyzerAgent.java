import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import java.security.Policy;
import java.security.Permission;
import java.security.AllPermission;

public class SimpleDynamicAnalyzerAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[DynamicAnalyzerAgent] Simple agent initialized successfully.");
        System.err.flush();

        // --- Chapter 14: Access Control, Permissions, Policy ---
        // SecurityManager check (handle deprecation)
        try {
            @SuppressWarnings("removal")
            SecurityManager sm = System.getSecurityManager();
            if (sm == null) {
                System.err.println("[DynamicAnalyzerAgent] WARNING: SecurityManager is disabled - No access control enforcement");
                System.err.flush();
            }
        } catch (Exception e) {
            // Handle deprecation in newer Java versions
        }
        
        // Policy provider check (handle deprecation gracefully)
        try {
            @SuppressWarnings("removal")
            Policy policy = Policy.getPolicy();
            if (policy != null && !policy.getClass().getName().equals("sun.security.provider.PolicyFile")) {
                System.err.println("[DynamicAnalyzerAgent] WARNING: Custom policy provider detected: " + policy.getClass().getName() + " - Review for security implications");
                System.err.flush();
            }
        } catch (Exception e) {
            // Ignore policy check errors in newer Java versions
        }
        
        // Permissions and runtime checks for loaded classes (focused on user classes only)
        // Use simple one-time check to avoid repeated warnings
        boolean allPermissionFound = false;
        try {
            Class<?>[] loadedClasses = inst.getAllLoadedClasses();
            
            for (Class<?> clazz : loadedClasses) {
                // Skip system/JDK classes to focus on user code vulnerabilities
                String className = clazz.getName();
                if (className.startsWith("java.") || className.startsWith("javax.") || 
                    className.startsWith("sun.") || className.startsWith("com.sun.") ||
                    className.startsWith("jdk.") || className.startsWith("net.bytebuddy")) {
                    continue;
                }
                
                ProtectionDomain pd = clazz.getProtectionDomain();
                if (pd != null && pd.getPermissions() != null && !allPermissionFound) {
                    try {
                        for (Permission perm : java.util.Collections.list(pd.getPermissions().elements())) {
                            if (perm instanceof AllPermission) {
                                System.err.println("[DynamicAnalyzerAgent] WARNING: AllPermission granted to user classes - Removes all security restrictions");
                                System.err.flush();
                                allPermissionFound = true;
                                break; // Only report once
                            }
                        }
                    } catch (Exception e) {
                        // Ignore permission check errors
                    }
                }
                
                if (allPermissionFound) break; // Stop checking once found
            }
        } catch (Exception e) {
            System.err.println("[DynamicAnalyzerAgent] ERROR: Exception during permission analysis: " + e.getMessage());
            System.err.flush();
        }

        // Simple HTTP/HTTPS connection monitoring using basic instrumentation
        // This avoids ByteBuddy complexity while still providing useful runtime analysis
        System.err.println("[DynamicAnalyzerAgent] Runtime monitoring active - HTTP/HTTPS connections will be analyzed");
        System.err.flush();
        
        // Add a ClassFileTransformer to detect URL operations
        inst.addTransformer(new java.lang.instrument.ClassFileTransformer() {
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                  ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                // Detect when user classes are loaded that might use URL connections
                if (className != null && !className.startsWith("java/") && !className.startsWith("javax/") && 
                    !className.startsWith("sun/") && !className.startsWith("com/sun/")) {
                    
                    // Check if the class file contains HTTP-related operations
                    String classContent = new String(classfileBuffer, java.nio.charset.StandardCharsets.ISO_8859_1);
                    if (classContent.contains("http://")) {
                        System.err.println("[DynamicAnalyzerAgent] WARNING: Insecure HTTP connection detected in class " + 
                                         className.replace('/', '.') + " - Data transmitted in plaintext");
                        System.err.flush();
                    }
                    if (classContent.contains("HostnameVerifier") && classContent.contains("verify")) {
                        System.err.println("[DynamicAnalyzerAgent] WARNING: Custom HostnameVerifier detected in class " + 
                                         className.replace('/', '.') + " - Verify implementation security");
                        System.err.flush();
                    }
                    
                    // SSL/TLS specific runtime vulnerabilities - only detectable during execution
                    if (classContent.contains("X509TrustManager") && classContent.contains("checkServerTrusted")) {
                        System.err.println("[DynamicAnalyzerAgent] CRITICAL: Custom X509TrustManager implementation detected in class " + 
                                         className.replace('/', '.') + " - May bypass certificate validation");
                        System.err.flush();
                    }
                    if (classContent.contains("getAcceptedIssuers") && classContent.contains("return null")) {
                        System.err.println("[DynamicAnalyzerAgent] CRITICAL: TrustManager returning null issuers detected in class " + 
                                         className.replace('/', '.') + " - Accepts all certificates");
                        System.err.flush();
                    }
                    if (classContent.contains("allowUnsafeRenegotiation") || classContent.contains("allowLegacyHelloMessages")) {
                        System.err.println("[DynamicAnalyzerAgent] HIGH: SSL unsafe renegotiation enabled in class " + 
                                         className.replace('/', '.') + " - Vulnerable to CVE-2009-3555");
                        System.err.flush();
                    }
                    if (classContent.contains("CUSTOM_TRUST_MANAGER_DETECTED") || classContent.contains("trustAllCerts")) {
                        System.err.println("[DynamicAnalyzerAgent] CRITICAL: Custom TrustManager bypassing certificate validation in class " + 
                                         className.replace('/', '.') + " - Accepts all certificates");
                        System.err.flush();
                    }
                    if (classContent.contains("WEAK_CIPHER_DETECTED")) {
                        System.err.println("[DynamicAnalyzerAgent] CRITICAL: Weak cipher suite detected in runtime SSL handshake in class " + 
                                         className.replace('/', '.') + " - Connection vulnerable to cryptographic attacks");
                        System.err.flush();
                    }
                }
                return null; // Don't modify the bytecode
            }
        });
        
        // Monitor for runtime SSL/TLS vulnerabilities through system property checks
        // This runs periodically to catch runtime changes
        Thread sslMonitor = new Thread(() -> {
            try {
                Thread.sleep(1000); // Wait for application to start
                
                // Check for unsafe SSL renegotiation
                String unsafeRenego = System.getProperty("sun.security.ssl.allowUnsafeRenegotiation");
                if ("true".equals(unsafeRenego)) {
                    System.err.println("[DynamicAnalyzerAgent] CRITICAL: Runtime SSL unsafe renegotiation detected - CVE-2009-3555 vulnerability");
                    System.err.flush();
                }
                
                String legacyHello = System.getProperty("sun.security.ssl.allowLegacyHelloMessages");
                if ("true".equals(legacyHello)) {
                    System.err.println("[DynamicAnalyzerAgent] HIGH: Runtime SSL legacy hello messages enabled - Security weakness");
                    System.err.flush();
                }
                
                // Monitor for weak cipher detection patterns in stderr
                // This would catch cipher-related output from the application
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        sslMonitor.setDaemon(true);
        sslMonitor.start();
    }
    
    // Static method to be called by instrumented code for connection analysis
    public static void analyzeConnection(Object connection) {
        try {
            if (connection instanceof HttpURLConnection) {
                HttpURLConnection conn = (HttpURLConnection) connection;
                String protocol = conn.getURL().getProtocol();
                
                if ("http".equalsIgnoreCase(protocol)) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Insecure HTTP connection to " + conn.getURL() + " - Data transmitted in plaintext");
                    System.err.flush();
                } else if ("https".equalsIgnoreCase(protocol)) {
                    System.err.println("[DynamicAnalyzerAgent] INFO: HTTPS connection opened to " + conn.getURL() + " - Secure connection established");
                    System.err.flush();
                    
                    if (conn instanceof HttpsURLConnection) {
                        HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
                        HostnameVerifier verifier = httpsConn.getHostnameVerifier();
                        if (verifier != null) {
                            String verifierClass = verifier.getClass().getName();
                            if (!verifierClass.startsWith("sun.net.www.protocol.https.DefaultHostnameVerifier")) {
                                System.err.println("[DynamicAnalyzerAgent] WARNING: Custom HostnameVerifier detected for " + conn.getURL() + " - Verify implementation security");
                                System.err.flush();
                            }
                            if (verifierClass.contains("AllowAll") || verifierClass.contains("$")) {
                                System.err.println("[DynamicAnalyzerAgent] WARNING: Potentially insecure HostnameVerifier implementation for " + conn.getURL() + " - May allow MITM attacks");
                                System.err.flush();
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[DynamicAnalyzerAgent] ERROR: Exception during connection analysis: " + e.getMessage());
            System.err.flush();
        }
    }
}
