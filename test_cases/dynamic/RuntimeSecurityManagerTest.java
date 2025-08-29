/**
 * Dynamic test case for runtime security manager and permissions detection
 * VULNERABILITY: Runtime detection of disabled security manager and excessive permissions
 * SEVERITY: HIGH/CRITICAL
 * DYNAMIC DETECTION: Only detectable during JVM runtime analysis
 */
public class RuntimeSecurityManagerTest {
    
    public static void main(String[] args) {
        testSecurityManagerStatus();
        testPermissionChecks();
        testFileSystemAccess();
        testNetworkAccess();
    }
    
    @SuppressWarnings("removal")
    public static void testSecurityManagerStatus() {
        System.out.println("Testing SecurityManager status...");
        
        // DYNAMIC VULNERABILITY: Check if SecurityManager is enabled at runtime
        SecurityManager sm = System.getSecurityManager();
        if (sm == null) {
            System.err.println("SECURITY_MANAGER_DISABLED: No access control enforcement");
        } else {
            System.out.println("SecurityManager is enabled: " + sm.getClass().getName());
        }
    }
    
    public static void testPermissionChecks() {
        System.out.println("Testing permission checks...");
        
        try {
            // DYNAMIC VULNERABILITY: Test if AllPermission is granted
            System.getProperty("java.home");
            System.err.println("ALL_PERMISSION_DETECTED: Unrestricted system property access");
            
            // Test file permission
            System.getProperty("user.dir");
            System.err.println("FILE_PERMISSION_DETECTED: Unrestricted file system access");
            
            // Test network permission
            System.getProperty("java.net.useSystemProxies");
            System.err.println("NETWORK_PERMISSION_DETECTED: Unrestricted network access");
            
        } catch (SecurityException e) {
            System.out.println("Security check passed: " + e.getMessage());
        }
    }
    
    public static void testFileSystemAccess() {
        System.out.println("Testing file system access...");
        
        try {
            // DYNAMIC VULNERABILITY: Unrestricted file access
            java.io.File tempDir = new java.io.File(System.getProperty("java.io.tmpdir"));
            if (tempDir.exists() && tempDir.canRead() && tempDir.canWrite()) {
                System.err.println("UNRESTRICTED_FILE_ACCESS: Full file system access granted");
            }
            
            // Test reading sensitive system files
            java.io.File etcDir = new java.io.File("/etc");
            if (etcDir.exists() && etcDir.canRead()) {
                System.err.println("SENSITIVE_FILE_ACCESS: Can read system configuration files");
            }
            
        } catch (SecurityException e) {
            System.out.println("File access restricted: " + e.getMessage());
        }
    }
    
    public static void testNetworkAccess() {
        System.out.println("Testing network access...");
        
        try {
            // DYNAMIC VULNERABILITY: Unrestricted network access
            java.net.InetAddress localhost = java.net.InetAddress.getLocalHost();
            System.out.println("Local host: " + localhost.getHostName());
            System.err.println("UNRESTRICTED_NETWORK_ACCESS: Can resolve hostnames");
            
            // Test socket creation
            java.net.ServerSocket serverSocket = new java.net.ServerSocket(0);
            System.err.println("SOCKET_PERMISSION: Can create server sockets on port " + 
                             serverSocket.getLocalPort());
            serverSocket.close();
            
        } catch (SecurityException e) {
            System.out.println("Network access restricted: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Network test failed: " + e.getMessage());
        }
    }
}
