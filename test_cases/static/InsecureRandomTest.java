import java.security.SecureRandom;

/**
 * Test case for detecting insecure random number generation
 * VULNERABILITY: Use of weak random number generators for cryptographic purposes
 * SEVERITY: MEDIUM
 * STATIC DETECTION: Class and method usage analysis
 */
public class InsecureRandomTest {
    
    public void weakRandomGeneration() {
        // VULNERABILITY: Using java.util.Random for cryptographic purposes
        java.util.Random weakRandom = new java.util.Random();
        byte[] sessionKey = new byte[16];
        
        // CRITICAL: Generating cryptographic keys with weak random
        for (int i = 0; i < sessionKey.length; i++) {
            sessionKey[i] = (byte) weakRandom.nextInt(256);
        }
        
        // VULNERABILITY: Using Math.random() for security-sensitive values
        double randomValue = Math.random();
        int securityToken = (int) (randomValue * 1000000);
        
        // VULNERABILITY: Unseeded SecureRandom (predictable on some platforms)
        SecureRandom unseededSecureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16];
        unseededSecureRandom.nextBytes(randomBytes);
    }
    
    public void fixedSeedRandom() {
        // VULNERABILITY: Using fixed seed makes random predictable
        java.util.Random fixedSeedRandom = new java.util.Random(12345);
        SecureRandom fixedSecureRandom = new SecureRandom();
        fixedSecureRandom.setSeed(54321); // CRITICAL: Fixed seed
        
        byte[] predictableBytes = new byte[16];
        fixedSecureRandom.nextBytes(predictableBytes);
    }
    
    public void correctRandomUsage() {
        try {
            // SECURE: Properly seeded SecureRandom
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            
            // Alternative secure approach
            SecureRandom sha1Random = SecureRandom.getInstance("SHA1PRNG");
            sha1Random.setSeed(secureRandom.generateSeed(20)); // Proper seeding
            
            byte[] cryptographicKey = new byte[32];
            secureRandom.nextBytes(cryptographicKey);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
