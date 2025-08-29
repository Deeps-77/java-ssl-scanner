import subprocess
import tempfile
import os
import re

def extract_public_class_name(java_code: str) -> str:
    match = re.search(r'public\s+class\s+(\w+)', java_code)
    if match:
        return match.group(1)
    return None

def has_main_method(java_code: str) -> bool:
    # Looks for a main method signature in the code
    return bool(re.search(r'public\s+static\s+void\s+main\s*\(String\s*\[\]\s*\w*\)', java_code))

def dynamic_analyze_java_code(code: str) -> list:
    """
    Compiles and executes provided Java code with ByteBuddy agent.
    Returns structured runtime results.
    """
    compile_dir = None
    try:
        normalized_code = '\n'.join(code.splitlines())

        # Try to extract class name, but allow compilation even if not found
        class_name = extract_public_class_name(normalized_code)
        compile_dir = tempfile.mkdtemp()

        # If a public class is found, use its name for the file
        java_file_path = os.path.join(compile_dir, f"{class_name if class_name else 'TempClass'}.java")
        with open(java_file_path, "w", encoding="utf-8") as f:
            f.write(normalized_code)

        # Compile Java file
        compile_result = subprocess.run(
            ["javac", java_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if compile_result.returncode != 0:
            return [{
                "line": None,
                "issue": "Compilation failed.\n" + compile_result.stderr.strip(),
                "suggestion": "Fix compilation errors.",
                "severity": "ERROR",
                "details": compile_result.stderr.strip().splitlines()
            }]

        # If no public class, just report compilation success
        if not class_name:
            return [{
                "line": None,
                "issue": "Compilation succeeded. No public class found; dynamic analysis not applicable.",
                "suggestion": "Add a public class and main method for runtime analysis.",
                "severity": "INFO",
                "details": []
            }]

        # Check for main method
        if not has_main_method(normalized_code):
            return [{
                "line": None,
                "issue": "Compilation succeeded. No main method found; dynamic analysis not applicable.",
                "suggestion": "Add a public static void main(String[] args) method to enable dynamic analysis.",
                "severity": "INFO",
                "details": []
            }]

        # Prepare simplified agent path (avoiding ByteBuddy complexity)
        project_dir = os.path.dirname(__file__)
        simple_agent_java = os.path.abspath(os.path.join(project_dir, "..", "java_analyzer", "SimpleDynamicAnalyzerAgent.java"))
        java_analyzer_dir = os.path.abspath(os.path.join(project_dir, "..", "java_analyzer"))
        
        # Compile the simple agent if needed
        simple_agent_class = os.path.join(java_analyzer_dir, "SimpleDynamicAnalyzerAgent.class")
        if not os.path.exists(simple_agent_class):
            compile_agent_result = subprocess.run(
                ["javac", simple_agent_java],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=java_analyzer_dir
            )
            if compile_agent_result.returncode != 0:
                return [{
                    "line": None,
                    "issue": "Failed to compile dynamic analysis agent: " + compile_agent_result.stderr.strip(),
                    "suggestion": "Check Java environment and agent source code.",
                    "severity": "ERROR"
                }]

        # Copy compiled class to java_analyzer_dir for classpath resolution
        import shutil
        compiled_class = os.path.join(compile_dir, f"{class_name}.class") if class_name else None
        if compiled_class and os.path.exists(compiled_class):
            shutil.copy2(compiled_class, java_analyzer_dir)

        # Run with simplified agent
        report = []
        if class_name and has_main_method(normalized_code):
            # Create agent manifest for jar creation
            manifest_content = """Manifest-Version: 1.0
Premain-Class: SimpleDynamicAnalyzerAgent

"""
            manifest_path = os.path.join(java_analyzer_dir, "MANIFEST.MF")
            with open(manifest_path, "w") as f:
                f.write(manifest_content)
            
            # Create simple agent jar
            simple_agent_jar = os.path.join(java_analyzer_dir, "SimpleDynamicAnalyzerAgent.jar")
            jar_result = subprocess.run(
                ["jar", "cfm", simple_agent_jar, manifest_path, "SimpleDynamicAnalyzerAgent.class"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=java_analyzer_dir
            )
            
            if jar_result.returncode != 0:
                # Fall back to running without agent
                run_result = subprocess.run(
                    ["java", "-cp", java_analyzer_dir, class_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10
                )
            else:
                # Run with agent
                run_result = subprocess.run(
                    [
                        "java",
                        "-javaagent:" + simple_agent_jar,
                        "-cp", java_analyzer_dir,
                        class_name
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10
                )

            stdout_lines = run_result.stdout.strip().splitlines()
            stderr_lines = run_result.stderr.strip().splitlines()

            print("STDOUT:", stdout_lines)
            print("STDERR:", stderr_lines)

            # Parse agent logs from stderr for security events
            reported_warnings = set()
            consolidated_warnings = {}  # For grouping similar warnings
            
            for line in stderr_lines:
                if "[DynamicAnalyzerAgent]" in line:
                    # Enhanced deduplication - group by warning type rather than exact message
                    warning_type = None
                    if "AllPermission granted" in line:
                        warning_type = "AllPermission"
                    elif "Unrestricted file access" in line:
                        warning_type = "FilePermission"  
                    elif "Unrestricted network access" in line:
                        warning_type = "NetworkPermission"
                    elif "Insecure HTTP connection" in line:
                        warning_type = "InsecureHTTP"
                    elif "Custom HostnameVerifier" in line or "Potentially insecure HostnameVerifier" in line:
                        warning_type = "InsecureHostnameVerifier"
                    elif "SecurityManager is disabled" in line:
                        warning_type = "SecurityManagerDisabled"
                    elif "Custom policy provider" in line:
                        warning_type = "CustomPolicyProvider"
                    elif "HTTPS connection opened" in line:
                        warning_type = "SecureHTTPS"
                    elif "Custom X509TrustManager" in line or "TrustManager returning null issuers" in line:
                        warning_type = "InsecureTrustManager"
                    elif "Custom TrustManager bypassing certificate validation" in line:
                        warning_type = "InsecureTrustManager"
                    elif "CUSTOM_TRUST_MANAGER_DETECTED" in line:
                        warning_type = "InsecureTrustManager"
                    elif "SSL unsafe renegotiation" in line:
                        warning_type = "SSLRenegotiation"
                    elif "SSL legacy hello messages" in line:
                        warning_type = "SSLLegacyProtocol"
                    elif "WEAK_CIPHER_DETECTED" in line:
                        warning_type = "WeakCipher"
                    else:
                        warning_type = "Other"
                    
                    # Only report one warning per type
                    if warning_type in reported_warnings:
                        continue
                    reported_warnings.add(warning_type)
                    
                    # Store the first occurrence of each warning type
                    if warning_type not in consolidated_warnings:
                        consolidated_warnings[warning_type] = line.strip()
            
            # Process consolidated warnings
            for warning_type, line in consolidated_warnings.items():
                line_number = None
                match = re.search(r"line (\d+)", line)
                if match:
                    line_number = int(match.group(1))
                
                # Impact and suggestion code mapping with improved descriptions
                impact = ""
                suggestion_code = ""
                
                # Chapter 14: Java Security - Access Control, Permissions, Policy
                if "AllPermission granted" in line:
                    suggestion = "Restrict AllPermission; grant only necessary permissions in policy file."
                    severity = "CRITICAL"
                    impact = "AllPermission allows code to bypass all security restrictions, creating major security vulnerabilities."
                    suggestion_code = "// In policy file: Remove 'grant { permission java.security.AllPermission; }' and grant specific permissions only"
                elif "Unrestricted file access" in line:
                    suggestion = "Restrict file access permissions to only necessary directories."
                    severity = "HIGH"
                    impact = "Unrestricted file access can lead to unauthorized data access, modification, or deletion."
                    suggestion_code = "// In policy file: Grant specific FilePermission with restricted paths and actions"
                elif "Unrestricted network access" in line:
                    suggestion = "Restrict network access permissions to only required hosts and ports."
                    severity = "HIGH"
                    impact = "Unrestricted network access can allow data exfiltration or unauthorized connections."
                    suggestion_code = "// In policy file: Grant specific SocketPermission with restricted hosts and ports"
                elif "WARNING: Insecure HTTP connection" in line:
                    suggestion = "Use HTTPS instead of HTTP for secure communication."
                    severity = "HIGH"
                    impact = "Sensitive data transmitted over HTTP can be intercepted by attackers."
                    suggestion_code = "URL url = new URL(\"https://example.com\"); HttpURLConnection conn = (HttpURLConnection) url.openConnection();"
                elif "WARNING: Custom HostnameVerifier detected" in line or "WARNING: Potentially insecure HostnameVerifier" in line:
                    suggestion = "Use the default HostnameVerifier or implement strict hostname verification."
                    severity = "HIGH"
                    impact = "Custom or insecure hostname verifiers can allow man-in-the-middle attacks."
                    suggestion_code = "httpsConn.setHostnameVerifier(null); // Use default verifier"
                elif "INFO: HTTPS connection opened" in line:
                    suggestion = "No action needed. Connection is secure."
                    severity = "INFO"
                    impact = "Secure HTTPS connection established successfully."
                    suggestion_code = ""
                elif "WARNING: SecurityManager is disabled" in line:
                    suggestion = "Enable SecurityManager to enforce access control policies."
                    severity = "HIGH"
                    impact = "Without SecurityManager, code can perform privileged operations without security checks."
                    suggestion_code = "System.setSecurityManager(new SecurityManager());"
                elif "CRITICAL: Custom X509TrustManager" in line:
                    suggestion = "Remove custom TrustManager or implement proper certificate validation."
                    severity = "CRITICAL"
                    impact = "Custom TrustManager may bypass certificate validation, allowing man-in-the-middle attacks."
                    suggestion_code = "// Use default TrustManager or implement proper certificate chain validation"
                elif "CRITICAL: TrustManager returning null issuers" in line:
                    suggestion = "Implement proper certificate issuer validation in TrustManager."
                    severity = "CRITICAL"
                    impact = "TrustManager accepting all certificates enables attackers to intercept SSL/TLS connections."
                    suggestion_code = "public X509Certificate[] getAcceptedIssuers() { return trustStore.getCertificates(); }"
                elif "CRITICAL: Runtime SSL unsafe renegotiation detected" in line:
                    suggestion = "Disable SSL renegotiation to prevent CVE-2009-3555 attacks."
                    severity = "CRITICAL"
                    impact = "SSL renegotiation vulnerability allows man-in-the-middle attacks during handshake."
                    suggestion_code = "System.setProperty(\"sun.security.ssl.allowUnsafeRenegotiation\", \"false\");"
                elif "HIGH: Runtime SSL legacy hello messages enabled" in line:
                    suggestion = "Disable legacy SSL hello messages to prevent downgrade attacks."
                    severity = "HIGH"
                    impact = "Legacy SSL hello messages can be exploited for protocol downgrade attacks."
                    suggestion_code = "System.setProperty(\"sun.security.ssl.allowLegacyHelloMessages\", \"false\");"
                elif "HIGH: SSL unsafe renegotiation enabled" in line:
                    suggestion = "Remove unsafe SSL renegotiation configuration from code."
                    severity = "HIGH"
                    impact = "Code explicitly enables unsafe SSL renegotiation, creating security vulnerability."
                    suggestion_code = "// Remove System.setProperty(\"sun.security.ssl.allowUnsafeRenegotiation\", \"true\");"
                elif "WEAK_CIPHER_DETECTED" in line:
                    suggestion = "Configure SSL/TLS to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)."
                    severity = "CRITICAL"
                    impact = "Weak cipher suites in runtime SSL negotiation can be broken by attackers."
                    suggestion_code = "sslSocket.setEnabledCipherSuites(new String[]{\"TLS_AES_256_GCM_SHA384\", \"TLS_CHACHA20_POLY1305_SHA256\"});"
                else:
                    suggestion = "Review agent log for security implications."
                    severity = "INFO"
                    impact = "General runtime information detected."
                    suggestion_code = ""
                
                report.append({
                    "line": line_number,
                    "issue": line,
                    "suggestion": suggestion,
                    "severity": severity,
                    "impact": impact,
                    "suggestion_code": suggestion_code,
                    "details": [line]
                })
            if stdout_lines:
                report.append({
                    "line": None,
                    "issue": "Program standard output.",
                    "suggestion": "Review normal logs.",
                    "severity": "INFO",
                    "details": stdout_lines
                })
            non_agent_stderr = [l for l in stderr_lines if "[DynamicAnalyzerAgent]" not in l]
            if non_agent_stderr:
                report.append({
                    "line": None,
                    "issue": "Program error output.",
                    "suggestion": "Review error logs.",
                    "severity": "WARNING",
                    "details": non_agent_stderr
                })
            if not report:
                report.append({
                    "line": None,
                    "issue": "Program executed successfully.",
                    "suggestion": "No dynamic issues detected.",
                    "severity": "INFO"
                })
        else:
            report.append({
                "line": None,
                "issue": "Compilation succeeded. No runtime analysis performed.",
                "suggestion": "Add a public class and main method for runtime analysis.",
                "severity": "INFO",
                "details": []
            })
        return report

    except subprocess.TimeoutExpired:
        return [{
            "line": None,
            "issue": "Program execution timed out.",
            "suggestion": "Check for infinite loops.",
            "severity": "ERROR"
        }]
    except Exception as e:
        return [{
            "line": None,
            "issue": "Unexpected error during dynamic analysis.",
            "suggestion": str(e),
            "severity": "ERROR"
        }]
    finally:
        # Clean up temp files
        if compile_dir and os.path.exists(compile_dir):
            for f in os.listdir(compile_dir):
                try:
                    os.remove(os.path.join(compile_dir, f))
                except:
                    pass
            try:
                os.rmdir(compile_dir)
            except:
                pass