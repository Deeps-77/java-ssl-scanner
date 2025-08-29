# SSL/TLS Security Test Cases

This directory contains comprehensive test cases for both static and dynamic security analysis of SSL/TLS and Java security vulnerabilities.

## Directory Structure

```
test_cases/
├── static/          # Static analysis test cases
└── dynamic/         # Dynamic analysis test cases
```

## Static Analysis Test Cases

Static analysis detects vulnerabilities by examining source code without executing it.

### 1. InsecureTrustManagerTest.java
- **Vulnerability**: Custom TrustManager that accepts all certificates
- **Severity**: CRITICAL
- **Detection**: Pattern analysis of TrustManager implementations
- **Issues Detected**:
  - TrustManager returning null issuers
  - Empty certificate validation methods
  - Custom TrustManager bypassing validation

### 2. InsecureHostnameVerifierTest.java
- **Vulnerability**: Custom HostnameVerifier that always returns true
- **Severity**: HIGH
- **Detection**: Method pattern analysis
- **Issues Detected**:
  - HostnameVerifier always returning true
  - Bypassing hostname verification
  - Anonymous verifier implementations

### 3. WeakProtocolTest.java
- **Vulnerability**: Use of deprecated/weak SSL protocols
- **Severity**: HIGH
- **Detection**: Protocol string analysis
- **Issues Detected**:
  - SSLv2, SSLv3 usage (CRITICAL)
  - TLSv1.0, TLSv1.1 usage (Weak)
  - Generic "SSL" context usage
  - Explicit weak protocol enabling

### 4. WeakCipherTest.java
- **Vulnerability**: Use of weak/deprecated cipher suites
- **Severity**: HIGH
- **Detection**: Cipher string analysis
- **Issues Detected**:
  - DES, RC4, NULL encryption ciphers
  - Export-grade cipher suites
  - Anonymous Diffie-Hellman
  - Mixed strong/weak cipher configurations

### 5. InsecureHttpTest.java
- **Vulnerability**: Using HTTP instead of HTTPS for sensitive data
- **Severity**: HIGH
- **Detection**: URL protocol analysis
- **Issues Detected**:
  - HTTP URLs for login/payment endpoints
  - Mixed content scenarios
  - Credentials transmitted over HTTP

### 6. InsecureRandomTest.java
- **Vulnerability**: Use of weak random number generators
- **Severity**: MEDIUM
- **Detection**: Class and method usage analysis
- **Issues Detected**:
  - java.util.Random for cryptographic purposes
  - Math.random() for security tokens
  - Fixed seed usage
  - Unseeded SecureRandom

## Dynamic Analysis Test Cases

Dynamic analysis detects vulnerabilities by monitoring actual program execution.

### 1. RuntimeConnectionTest.java
- **Vulnerability**: Runtime detection of insecure protocol usage
- **Severity**: HIGH
- **Detection**: Actual connection monitoring
- **Issues Detected**:
  - HTTP connections during execution
  - Mixed content scenarios
  - Real-time protocol usage

### 2. RuntimeHostnameVerifierTest.java
- **Vulnerability**: Runtime detection of custom hostname verification
- **Severity**: HIGH
- **Detection**: Runtime verifier setting detection
- **Issues Detected**:
  - Custom verifiers set at runtime
  - Global hostname verifier bypass
  - Runtime verification behavior

### 3. RuntimeTrustManagerTest.java
- **Vulnerability**: Runtime detection of certificate validation bypass
- **Severity**: CRITICAL
- **Detection**: Runtime TrustManager usage
- **Issues Detected**:
  - TrustManager instantiation at runtime
  - SSL context modification during execution
  - Certificate validation bypass

### 4. RuntimeSSLRenegotiationTest.java
- **Vulnerability**: CVE-2009-3555 - SSL/TLS renegotiation vulnerability
- **Severity**: CRITICAL
- **Detection**: Runtime system property monitoring
- **Issues Detected**:
  - allowUnsafeRenegotiation set to true
  - allowLegacyHelloMessages enabled
  - Runtime SSL configuration changes

### 5. RuntimeWeakCipherTest.java
- **Vulnerability**: Runtime detection of weak cipher suite negotiation
- **Severity**: CRITICAL
- **Detection**: Actual SSL handshake monitoring
- **Issues Detected**:
  - Weak ciphers negotiated during handshake
  - Cipher suite analysis at runtime
  - Real SSL connection cipher strength

### 6. RuntimeSecurityManagerTest.java
- **Vulnerability**: Runtime detection of disabled security manager
- **Severity**: HIGH/CRITICAL
- **Detection**: JVM runtime analysis
- **Issues Detected**:
  - Disabled SecurityManager
  - AllPermission grants
  - Unrestricted file/network access

## Key Differences: Static vs Dynamic

### Static Analysis Advantages:
- Fast analysis without execution
- Detects potential vulnerabilities in code
- No runtime environment needed
- Can analyze all code paths

### Dynamic Analysis Advantages:
- Detects actual runtime behavior
- Catches configuration-based vulnerabilities
- Monitors real SSL handshakes
- Detects system property changes
- Identifies runtime permission grants

### Vulnerabilities Only Detectable by Dynamic Analysis:
1. **SSL Renegotiation (CVE-2009-3555)** - System properties set at runtime
2. **Weak Cipher Negotiation** - Actual SSL handshake analysis
3. **Runtime TrustManager Bypass** - Runtime SSL context modification
4. **SecurityManager Status** - JVM runtime security state
5. **Mixed Content Detection** - Actual connection sequence analysis

## Running the Tests

### Static Analysis:
```bash
# Run static analyzer on test files
java -jar analyzer.jar static/InsecureTrustManagerTest.java
```

### Dynamic Analysis:
```bash
# Run with dynamic analysis agent
java -javaagent:SimpleDynamicAnalyzerAgent.jar dynamic.RuntimeConnectionTest
java -javaagent:SimpleDynamicAnalyzerAgent.jar dynamic.RuntimeTrustManagerTest
java -javaagent:SimpleDynamicAnalyzerAgent.jar dynamic.RuntimeSSLRenegotiationTest
```

## Security Impact Summary

- **Critical Vulnerabilities**: TrustManager bypass, SSL renegotiation, weak ciphers
- **High Vulnerabilities**: HostnameVerifier bypass, weak protocols, HTTP usage
- **Medium Vulnerabilities**: Weak random generation, security configuration issues

These test cases provide comprehensive coverage for both static and dynamic security analysis, ensuring that security tools can detect the full spectrum of SSL/TLS and Java security vulnerabilities.
