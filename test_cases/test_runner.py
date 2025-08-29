#!/usr/bin/env python3
"""
Test Case Runner for SSL/TLS Security Analysis
Runs both static and dynamic analysis test cases
"""

import sys
import os
import subprocess
from pathlib import Path

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

try:
    from analyzer import analyze_java_code
    from dynamic_analyzer import dynamic_analyze_java_code
except ImportError as e:
    print(f"Error importing analyzers: {e}")
    print("Make sure you're running from the correct directory")
    sys.exit(1)

def run_static_analysis():
    """Run static analysis on all test cases"""
    print("=" * 60)
    print("RUNNING STATIC ANALYSIS TEST CASES")
    print("=" * 60)
    
    static_dir = Path(__file__).parent / "static"
    test_files = list(static_dir.glob("*.java"))
    
    total_issues = 0
    
    for test_file in test_files:
        print(f"\n--- Analyzing {test_file.name} ---")
        
        try:
            with open(test_file, 'r', encoding='utf-8') as f:
                code = f.read()
            
            results = analyze_java_code(code)
            
            if results:
                print(f"Found {len(results)} issues:")
                for i, issue in enumerate(results, 1):
                    severity = issue.get('severity', 'UNKNOWN')
                    description = issue.get('issue', 'No description')
                    print(f"  {i}. [{severity}] {description}")
                total_issues += len(results)
            else:
                print("No issues detected")
                
        except Exception as e:
            print(f"Error analyzing {test_file.name}: {e}")
    
    print(f"\nStatic Analysis Summary: {total_issues} total issues detected")
    return total_issues

def run_dynamic_analysis():
    """Run dynamic analysis on all test cases"""
    print("\n" + "=" * 60)
    print("RUNNING DYNAMIC ANALYSIS TEST CASES")
    print("=" * 60)
    
    dynamic_dir = Path(__file__).parent / "dynamic"
    test_files = list(dynamic_dir.glob("*.java"))
    
    total_issues = 0
    
    for test_file in test_files:
        print(f"\n--- Analyzing {test_file.name} ---")
        
        try:
            with open(test_file, 'r', encoding='utf-8') as f:
                code = f.read()
            
            results = dynamic_analyze_java_code(code)
            
            if results:
                # Filter out standard output messages
                security_issues = [r for r in results if r.get('severity') not in ['INFO'] 
                                 or 'agent' in r.get('issue', '').lower()]
                
                print(f"Found {len(security_issues)} security issues:")
                for i, issue in enumerate(security_issues, 1):
                    severity = issue.get('severity', 'UNKNOWN')
                    description = issue.get('issue', 'No description')
                    # Truncate long descriptions
                    if len(description) > 80:
                        description = description[:77] + "..."
                    print(f"  {i}. [{severity}] {description}")
                total_issues += len(security_issues)
            else:
                print("No issues detected")
                
        except Exception as e:
            print(f"Error analyzing {test_file.name}: {e}")
    
    print(f"\nDynamic Analysis Summary: {total_issues} total security issues detected")
    return total_issues

def run_comprehensive_test():
    """Run a comprehensive test with mixed vulnerabilities"""
    print("\n" + "=" * 60)
    print("RUNNING COMPREHENSIVE VULNERABILITY TEST")
    print("=" * 60)
    
    # Create a test case with multiple vulnerability types
    comprehensive_test = '''
import java.net.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;

public class ComprehensiveSecurityTest {
    public static void main(String[] args) {
        testAllVulnerabilities();
    }
    
    public static void testAllVulnerabilities() {
        // HTTP vulnerability
        try {
            URL httpUrl = new URL("http://api.example.com/sensitive-data");
            HttpURLConnection httpConn = (HttpURLConnection) httpUrl.openConnection();
            httpConn.connect();
        } catch (Exception e) {}
        
        // TrustManager vulnerability
        try {
            TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAll, new SecureRandom());
        } catch (Exception e) {}
        
        // HostnameVerifier vulnerability
        try {
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (Exception e) {}
        
        // Weak protocol vulnerability
        try {
            SSLContext weakContext = SSLContext.getInstance("SSLv3");
        } catch (Exception e) {}
        
        // Weak cipher vulnerability
        try {
            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            socket.setEnabledCipherSuites(new String[]{"SSL_RSA_WITH_RC4_128_SHA"});
        } catch (Exception e) {}
        
        // Random vulnerability
        java.util.Random weakRandom = new java.util.Random(12345);
        byte[] key = new byte[16];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) weakRandom.nextInt(256);
        }
        
        // SSL renegotiation vulnerability (dynamic only)
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
        System.err.println("SSL_RENEGOTIATION_ENABLED: Unsafe renegotiation allowed");
        
        System.out.println("Comprehensive vulnerability test completed");
    }
}
'''
    
    print("Static Analysis Results:")
    static_results = analyze_java_code(comprehensive_test)
    static_count = len([r for r in static_results if r.get('severity') in ['HIGH', 'CRITICAL']])
    print(f"  High/Critical static issues: {static_count}")
    
    print("\nDynamic Analysis Results:")
    dynamic_results = dynamic_analyze_java_code(comprehensive_test)
    dynamic_count = len([r for r in dynamic_results if r.get('severity') in ['HIGH', 'CRITICAL']])
    print(f"  High/Critical dynamic issues: {dynamic_count}")
    
    print(f"\nTotal High/Critical Issues: {static_count + dynamic_count}")
    
    # Show unique vulnerabilities detected by each method
    print(f"\nDetection Comparison:")
    print(f"  Static Analysis: {static_count} high/critical issues")
    print(f"  Dynamic Analysis: {dynamic_count} high/critical issues")
    print(f"  Combined Coverage: {static_count + dynamic_count} total issues")

def main():
    """Main test runner"""
    print("SSL/TLS Security Analysis Test Suite")
    print("====================================")
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
        if test_type == 'static':
            run_static_analysis()
        elif test_type == 'dynamic':
            run_dynamic_analysis()
        elif test_type == 'comprehensive':
            run_comprehensive_test()
        else:
            print(f"Unknown test type: {test_type}")
            print("Usage: python test_runner.py [static|dynamic|comprehensive]")
    else:
        # Run all tests
        static_total = run_static_analysis()
        dynamic_total = run_dynamic_analysis()
        run_comprehensive_test()
        
        print("\n" + "=" * 60)
        print("FINAL SUMMARY")
        print("=" * 60)
        print(f"Static Analysis: {static_total} total issues")
        print(f"Dynamic Analysis: {dynamic_total} total security issues")
        print(f"Test Suite Completed Successfully!")

if __name__ == "__main__":
    main()
