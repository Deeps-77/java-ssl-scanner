import java.lang.instrument.Instrumentation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;
import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import java.security.Policy;
import java.security.Permission;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.security.AllPermission;
import java.io.FilePermission;
import java.net.SocketPermission;

public class DynamicAnalyzerAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[DynamicAnalyzerAgent] ByteBuddy agent initialized.");
        System.out.flush();

        // --- Chapter 14: Access Control, Permissions, Policy ---
        // SecurityManager check
        if (System.getSecurityManager() == null) {
            System.err.println("[DynamicAnalyzerAgent] WARNING: SecurityManager is disabled - No access control enforcement");
            System.err.flush();
        }
        
        // Policy provider check
        Policy policy = Policy.getPolicy();
        if (policy != null && !policy.getClass().getName().equals("sun.security.provider.PolicyFile")) {
            System.err.println("[DynamicAnalyzerAgent] WARNING: Custom policy provider detected: " + policy.getClass().getName() + " - Review for security implications");
            System.err.flush();
        }
        
        // Permissions and runtime checks for loaded classes (focused on user classes only)
        try {
            java.util.HashSet<String> reportedWarnings = new java.util.HashSet<>();
            Class[] loadedClasses = inst.getAllLoadedClasses();
            
            for (Class<?> clazz : loadedClasses) {
                // Skip system/JDK classes to focus on user code vulnerabilities
                String className = clazz.getName();
                if (className.startsWith("java.") || className.startsWith("javax.") || 
                    className.startsWith("sun.") || className.startsWith("com.sun.") ||
                    className.startsWith("jdk.") || className.startsWith("net.bytebuddy")) {
                    continue;
                }
                
                ProtectionDomain pd = clazz.getProtectionDomain();
                if (pd != null && pd.getPermissions() != null) {
                    for (Permission perm : java.util.Collections.list(pd.getPermissions().elements())) {
                        String allPermMsg = "AllPermission granted to user class " + className;
                        if (perm instanceof AllPermission && !reportedWarnings.contains(allPermMsg)) {
                            System.err.println("[DynamicAnalyzerAgent] WARNING: " + allPermMsg + " - Removes all security restrictions");
                            System.err.flush();
                            reportedWarnings.add(allPermMsg);
                        }
                        
                        String filePermMsg = "Unrestricted file access for user class " + className;
                        if (perm instanceof FilePermission && perm.getActions().contains("read,write,delete") && !reportedWarnings.contains(filePermMsg)) {
                            System.err.println("[DynamicAnalyzerAgent] WARNING: " + filePermMsg + " - Can access/modify any file");
                            System.err.flush();
                            reportedWarnings.add(filePermMsg);
                        }
                        
                        String netPermMsg = "Unrestricted network access for user class " + className;
                        if (perm instanceof SocketPermission && perm.getActions().contains("connect,accept,listen,resolve") && !reportedWarnings.contains(netPermMsg)) {
                            System.err.println("[DynamicAnalyzerAgent] WARNING: " + netPermMsg + " - Can connect to any network resource");
                            System.err.flush();
                            reportedWarnings.add(netPermMsg);
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[DynamicAnalyzerAgent] ERROR: Exception during permission analysis: " + e.getMessage());
            System.err.flush();
        }

        // --- Extra runtime checks for Java 21 (removed - duplicate logic) ---
        // This section was removed to eliminate duplicate vulnerability detection
        // The logic above already handles all vulnerability types

        new AgentBuilder.Default()
            .ignore(ElementMatchers.none())
            .type(ElementMatchers.nameContains("Http")) // Broader matcher for debugging
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(ElementMatchers.named("connect"))
                       .intercept(Advice.to(ConnectAdvice.class))
            )
            .installOn(inst);
        
        // Runtime-specific SSL/TLS/JSSE instrumentation (not detectable by static analysis)
        new AgentBuilder.Default()
            .ignore(ElementMatchers.none())
            .type(ElementMatchers.nameContains("SSLSocket"))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(ElementMatchers.named("startHandshake"))
                       .intercept(Advice.to(SSLHandshakeAdvice.class))
            )
            .installOn(inst);
            
        new AgentBuilder.Default()
            .ignore(ElementMatchers.none())
            .type(ElementMatchers.nameContains("SSLSession"))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(ElementMatchers.named("getPeerCertificates"))
                       .intercept(Advice.to(CertificateChainAdvice.class))
            )
            .installOn(inst);
            
        new AgentBuilder.Default()
            .ignore(ElementMatchers.none())
            .type(ElementMatchers.nameContains("SSLEngine"))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(ElementMatchers.named("wrap").or(ElementMatchers.named("unwrap")))
                       .intercept(Advice.to(SSLEngineAdvice.class))
            )
            .installOn(inst);
    }

    public static class ConnectAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object thiz) {
            // Skip delegate classes to reduce repeated outputs
            if (thiz.getClass().getName().contains("Delegate")) {
                return;
            }
            System.err.println("[DynamicAnalyzerAgent] connect() called on " + thiz.getClass().getName());
            System.err.flush();
            try {
                if (thiz instanceof HttpURLConnection) {
                    HttpURLConnection conn = (HttpURLConnection) thiz;
                    String protocol = conn.getURL().getProtocol();
                    if ("http".equalsIgnoreCase(protocol)) {
                        System.err.println("[DynamicAnalyzerAgent] WARNING: Insecure HTTP connection to " + conn.getURL());
                        System.err.flush();
                    } else if ("https".equalsIgnoreCase(protocol)) {
                        System.err.println("[DynamicAnalyzerAgent] INFO: HTTPS connection opened to " + conn.getURL());
                        System.err.flush();
                        if (conn instanceof HttpsURLConnection) {
                            HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
                            HostnameVerifier verifier = httpsConn.getHostnameVerifier();
                            if (verifier != null) {
                                String verifierClass = verifier.getClass().getName();
                                System.err.println("[DynamicAnalyzerAgent] HostnameVerifier class: " + verifierClass + " for " + conn.getURL());
                                System.err.flush();
                                if (!verifierClass.startsWith("sun.net.www.protocol.https.DefaultHostnameVerifier")) {
                                    System.err.println("[DynamicAnalyzerAgent] WARNING: Custom HostnameVerifier detected for " + conn.getURL());
                                    System.err.flush();
                                }
                                if (verifierClass.contains("AllowAll") || verifierClass.contains("$")) {
                                    System.err.println("[DynamicAnalyzerAgent] WARNING: Potentially insecure HostnameVerifier implementation for " + conn.getURL());
                                    System.err.flush();
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("[DynamicAnalyzerAgent] ERROR: Exception during connection analysis: " + e);
                System.err.flush();
            }
        }
    }
    
    // SSL Handshake Advice - Detects actual handshake failures and weak negotiated parameters
    public static class SSLHandshakeAdvice {
        @Advice.OnMethodExit
        public static void exit(@Advice.This Object sslSocket) {
            try {
                // Use reflection to check the actual negotiated cipher suite and protocol after handshake
                java.lang.reflect.Method getSession = sslSocket.getClass().getMethod("getSession");
                Object session = getSession.invoke(sslSocket);
                
                java.lang.reflect.Method getCipherSuite = session.getClass().getMethod("getCipherSuite");
                String negotiatedCipher = (String) getCipherSuite.invoke(session);
                
                java.lang.reflect.Method getProtocol = session.getClass().getMethod("getProtocol");
                String negotiatedProtocol = (String) getProtocol.invoke(session);
                
                // Check for runtime-negotiated weak ciphers (only detectable after handshake)
                if (negotiatedCipher != null && (negotiatedCipher.contains("_RC4_") || 
                    negotiatedCipher.contains("_DES_") || negotiatedCipher.contains("_NULL_") ||
                    negotiatedCipher.contains("_EXPORT_") || negotiatedCipher.contains("_anon_"))) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL handshake negotiated weak cipher suite: " + negotiatedCipher + " - Server supports weak ciphers");
                    System.err.flush();
                }
                
                // Check for runtime-negotiated weak protocols
                if (negotiatedProtocol != null && (negotiatedProtocol.equals("SSLv2") || 
                    negotiatedProtocol.equals("SSLv3") || negotiatedProtocol.equals("TLSv1") ||
                    negotiatedProtocol.equals("TLSv1.1"))) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL handshake negotiated weak protocol: " + negotiatedProtocol + " - Server/client negotiated insecure protocol");
                    System.err.flush();
                }
            } catch (Exception e) {
                // Silently ignore reflection errors
            }
        }
    }
    
    // Certificate Chain Advice - Detects runtime certificate validation issues
    public static class CertificateChainAdvice {
        @Advice.OnMethodExit
        public static void exit(@Advice.Return java.security.cert.Certificate[] certs, @Advice.This Object session) {
            try {
                if (certs == null || certs.length == 0) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL session has no peer certificates - Possible anonymous or null cipher suite in use");
                    System.err.flush();
                    return;
                }
                
                // Check certificate chain length (too short might indicate issues)
                if (certs.length == 1) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL session has single certificate in chain - Self-signed or incomplete certificate chain detected");
                    System.err.flush();
                }
                
                // Check for expired certificates (runtime validation)
                java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) certs[0];
                try {
                    x509.checkValidity();
                } catch (java.security.cert.CertificateExpiredException e) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL peer certificate is expired: " + x509.getSubjectX500Principal().getName());
                    System.err.flush();
                } catch (java.security.cert.CertificateNotYetValidException e) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL peer certificate is not yet valid: " + x509.getSubjectX500Principal().getName());
                    System.err.flush();
                }
                
            } catch (Exception e) {
                // Silently ignore errors
            }
        }
    }
    
    // SSL Engine Advice - Detects SSL engine buffer handling issues and renegotiation
    public static class SSLEngineAdvice {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object sslEngine, @Advice.Origin String method) {
            try {
                // Check for SSL renegotiation attempts (security risk)
                java.lang.reflect.Method getHandshakeStatus = sslEngine.getClass().getMethod("getHandshakeStatus");
                Object handshakeStatus = getHandshakeStatus.invoke(sslEngine);
                
                if (handshakeStatus.toString().contains("NEED_TASK") && method.contains("wrap")) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL renegotiation detected in SSLEngine - Potential security risk from renegotiation attacks");
                    System.err.flush();
                }
                
                // Check for client-initiated renegotiation (CVE-2009-3555 related)
                java.lang.reflect.Method getSession = sslEngine.getClass().getMethod("getSession");
                Object session = getSession.invoke(sslEngine);
                java.lang.reflect.Method isValid = session.getClass().getMethod("isValid");
                boolean sessionValid = (Boolean) isValid.invoke(session);
                
                if (!sessionValid && method.contains("wrap")) {
                    System.err.println("[DynamicAnalyzerAgent] WARNING: Runtime SSL session invalidation during engine operation - Possible renegotiation or session fixation attempt");
                    System.err.flush();
                }
                
            } catch (Exception e) {
                // Silently ignore reflection errors
            }
        }
    }
}
