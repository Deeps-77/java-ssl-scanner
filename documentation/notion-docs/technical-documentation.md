# Technical Documentation - Function Reference

## Table of Contents
1. [Static Analysis Functions](#static-analysis-functions)
2. [Dynamic Analysis Functions](#dynamic-analysis-functions)
3. [Backend API Functions](#backend-api-functions)
4. [Utility Functions](#utility-functions)
5. [Configuration Functions](#configuration-functions)

---

## Static Analysis Functions

### Core Analysis Functions

#### `analyzeJavaCode(String javaCode, String filename)`
**Purpose**: Performs comprehensive static analysis on Java source code to identify SSL/TLS vulnerabilities.

**Input Parameters**:
- `javaCode` (String): Complete Java source code content
- `filename` (String): Name of the file being analyzed (for reporting)

**Output**:
```json
{
  "vulnerabilities": [
    {
      "type": "WEAK_CIPHER_SUITE",
      "severity": "HIGH",
      "line": 45,
      "description": "Weak cipher suite RC4 detected",
      "recommendation": "Use strong cipher suites like AES"
    }
  ],
  "summary": {
    "total_issues": 3,
    "high_severity": 1,
    "medium_severity": 2
  }
}
```

**Usage Example**:
```python
result = analyzeJavaCode(source_code, "SSLClient.java")
vulnerabilities = result["vulnerabilities"]
```

---

#### `detectTrustManagerVulnerabilities(CompilationUnit cu)`
**Purpose**: Identifies custom TrustManager implementations that bypass certificate validation.

**Input Parameters**:
- `cu` (CompilationUnit): Parsed Java AST representation

**Output**:
```json
{
  "vulnerabilities": [
    {
      "type": "TRUST_MANAGER_BYPASS",
      "severity": "CRITICAL",
      "line": 23,
      "method": "checkServerTrusted",
      "description": "TrustManager accepts all certificates without validation"
    }
  ]
}
```

**Detection Patterns**:
- Empty `checkServerTrusted()` methods
- `return null` in certificate validation
- `getAcceptedIssuers()` returning empty array

---

#### `detectWeakCipherSuites(CompilationUnit cu)`
**Purpose**: Identifies usage of cryptographically weak cipher suites.

**Input Parameters**:
- `cu` (CompilationUnit): Parsed Java AST representation

**Output**:
```json
{
  "vulnerabilities": [
    {
      "type": "WEAK_CIPHER_SUITE",
      "severity": "HIGH",
      "cipher": "SSL_RSA_WITH_RC4_128_MD5",
      "line": 67,
      "description": "RC4 cipher is cryptographically broken"
    }
  ]
}
```

**Detected Weak Ciphers**:
- RC4-based ciphers
- DES and 3DES
- Export-grade ciphers
- NULL encryption ciphers

---

#### `detectHostnameVerificationIssues(CompilationUnit cu)`
**Purpose**: Identifies disabled or improperly implemented hostname verification.

**Input Parameters**:
- `cu` (CompilationUnit): Parsed Java AST representation

**Output**:
```json
{
  "vulnerabilities": [
    {
      "type": "HOSTNAME_VERIFICATION_DISABLED",
      "severity": "HIGH",
      "line": 34,
      "description": "Hostname verification is disabled"
    }
  ]
}
```

**Detection Patterns**:
- `setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`
- Custom HostnameVerifier returning `true`
- `verify()` method always returning `true`

---

## Dynamic Analysis Functions

### JVM Instrumentation Functions

#### `premain(String agentArgs, Instrumentation inst)`
**Purpose**: Entry point for JVM instrumentation agent, sets up runtime monitoring.

**Input Parameters**:
- `agentArgs` (String): Agent arguments passed via `-javaagent`
- `inst` (Instrumentation): JVM instrumentation interface

**Output**: None (void method)

**Side Effects**:
- Registers ClassFileTransformer for bytecode modification
- Starts SSL monitoring thread
- Initializes vulnerability detection flags

**Usage**:
```bash
java -javaagent:agent.jar=ssl-monitoring MyApp
```

---

#### `transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer)`
**Purpose**: Transforms class bytecode to inject monitoring code for SSL/TLS operations.

**Input Parameters**:
- `loader` (ClassLoader): ClassLoader defining the class
- `className` (String): Name of class being transformed
- `classBeingRedefined` (Class<?>): Class being redefined (can be null)
- `protectionDomain` (ProtectionDomain): Security context
- `classfileBuffer` (byte[]): Original class bytecode

**Output**:
- `byte[]`: Modified bytecode with monitoring instrumentation
- `null`: If no transformation needed

**Transformation Targets**:
- `javax.net.ssl.*` classes
- `java.security.*` classes
- Application SSL/TLS code

---

#### `checkSSLRenegotiation(String methodName, Object[] args)`
**Purpose**: Monitors SSL renegotiation attempts to detect CVE-2009-3555 vulnerability.

**Input Parameters**:
- `methodName` (String): Name of intercepted method
- `args` (Object[]): Method arguments

**Output**:
```json
{
  "vulnerability_detected": true,
  "type": "SSL_RENEGOTIATION",
  "cve": "CVE-2009-3555",
  "severity": "HIGH",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Monitoring Points**:
- `SSLEngine.beginHandshake()`
- `SSLSocket.startHandshake()`
- Renegotiation-related method calls

---

#### `monitorWeakCiphers(SSLSession session)`
**Purpose**: Analyzes SSL session parameters to detect weak cipher usage at runtime.

**Input Parameters**:
- `session` (SSLSession): Active SSL session object

**Output**:
```json
{
  "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
  "is_weak": true,
  "protocol": "TLSv1.0",
  "vulnerability": {
    "type": "WEAK_CIPHER_RUNTIME",
    "severity": "HIGH",
    "description": "Weak cipher detected in active SSL session"
  }
}
```

**Analysis Parameters**:
- Cipher suite strength
- Protocol version security
- Key exchange algorithms

---

## Backend API Functions

### REST API Endpoints

#### `POST /analyze`
**Purpose**: Main analysis endpoint that processes uploaded Java files.

**Input Parameters**:
```json
{
  "file": "multipart/form-data",
  "analysis_type": "both|static|dynamic"
}
```

**Output**:
```json
{
  "status": "success",
  "analysis_id": "uuid-string",
  "results": {
    "static_analysis": {...},
    "dynamic_analysis": {...},
    "combined_summary": {...}
  },
  "execution_time": 2.3
}
```

**Error Responses**:
- 400: Invalid file format
- 413: File too large
- 500: Analysis execution error

---

#### `GET /results/{analysis_id}`
**Purpose**: Retrieves detailed analysis results for a specific analysis session.

**Input Parameters**:
- `analysis_id` (String): UUID of analysis session

**Output**:
```json
{
  "analysis_id": "uuid-string",
  "timestamp": "2024-01-15T10:30:00Z",
  "vulnerabilities": [...],
  "metrics": {
    "total_lines_analyzed": 450,
    "execution_time": 2.3,
    "vulnerabilities_found": 5
  }
}
```

---

#### `POST /dynamic-analyze`
**Purpose**: Executes dynamic analysis using JVM instrumentation.

**Input Parameters**:
```json
{
  "java_file": "base64-encoded-content",
  "agent_args": "ssl-monitoring,verbose",
  "timeout": 30
}
```

**Output**:
```json
{
  "dynamic_results": {
    "runtime_vulnerabilities": [...],
    "ssl_sessions": [...],
    "monitoring_events": [...]
  },
  "agent_output": "agent execution logs"
}
```

---

### Data Processing Functions

#### `combineAnalysisResults(static_results, dynamic_results)`
**Purpose**: Merges static and dynamic analysis results, removing duplicates and providing unified reporting.

**Input Parameters**:
- `static_results` (dict): Results from static code analysis
- `dynamic_results` (dict): Results from dynamic runtime analysis

**Output**:
```json
{
  "combined_vulnerabilities": [...],
  "deduplication_info": {
    "total_before": 12,
    "total_after": 9,
    "duplicates_removed": 3
  },
  "analysis_coverage": {
    "static_only": 5,
    "dynamic_only": 4,
    "both_detected": 0
  }
}
```

**Deduplication Logic**:
- Compare vulnerability types and line numbers
- Merge complementary information
- Prioritize dynamic results for runtime issues

---

#### `categorizeVulnerability(vulnerability_data)`
**Purpose**: Classifies vulnerabilities into appropriate security categories with severity scoring.

**Input Parameters**:
```json
{
  "type": "TRUST_MANAGER_BYPASS",
  "context": "SSL connection setup",
  "line": 45
}
```

**Output**:
```json
{
  "category": "Certificate Management",
  "subcategory": "Trust Manager",
  "severity": "CRITICAL",
  "cvss_score": 9.1,
  "cwe_id": "CWE-295",
  "recommendation": "Implement proper certificate validation"
}
```

---

## Utility Functions

### File Processing Functions

#### `validateJavaFile(file_content)`
**Purpose**: Validates that uploaded content is valid Java source code.

**Input Parameters**:
- `file_content` (String): Raw file content

**Output**:
```json
{
  "is_valid": true,
  "java_version": "1.8",
  "compilation_errors": [],
  "warnings": ["Unused import detected"]
}
```

**Validation Checks**:
- Syntax parsing
- Import resolution
- Basic compilation checks

---

#### `extractSSLTLSCode(java_code)`
**Purpose**: Identifies and extracts SSL/TLS related code sections for focused analysis.

**Input Parameters**:
- `java_code` (String): Complete Java source code

**Output**:
```json
{
  "ssl_imports": ["javax.net.ssl.*", "java.security.*"],
  "ssl_methods": ["setupSSLContext", "createTrustManager"],
  "ssl_code_blocks": ["lines 45-67", "lines 89-102"],
  "ssl_percentage": 15.3
}
```

---

### Report Generation Functions

#### `generateSecurityReport(analysis_results)`
**Purpose**: Creates comprehensive security report with detailed vulnerability information and remediation guidance.

**Input Parameters**:
- `analysis_results` (dict): Combined analysis results

**Output**:
```json
{
  "report_id": "uuid-string",
  "executive_summary": {
    "total_vulnerabilities": 9,
    "critical": 2,
    "high": 3,
    "medium": 4,
    "risk_score": 8.2
  },
  "detailed_findings": [...],
  "remediation_plan": [...],
  "compliance_mapping": {...}
}
```

**Report Sections**:
- Executive summary
- Detailed vulnerability descriptions
- Remediation recommendations
- Code examples and fixes

---

#### `formatVulnerabilityOutput(vulnerabilities, format_type)`
**Purpose**: Formats vulnerability data for different output formats (JSON, HTML, PDF).

**Input Parameters**:
- `vulnerabilities` (list): List of vulnerability objects
- `format_type` (String): "json", "html", "pdf", "csv"

**Output**: Formatted output according to specified type

**Supported Formats**:
- JSON: Machine-readable structured data
- HTML: Web-friendly formatted report
- PDF: Printable professional report
- CSV: Spreadsheet-compatible format

---

## Configuration Functions

### Analysis Configuration

#### `configureStaticAnalysis(config_options)`
**Purpose**: Configures static analysis parameters and detection rules.

**Input Parameters**:
```json
{
  "detection_rules": ["all", "ssl-only", "custom"],
  "severity_threshold": "medium",
  "exclude_patterns": ["test/**", "mock/**"],
  "include_experimental": false
}
```

**Output**:
```json
{
  "configuration_id": "uuid-string",
  "active_rules": 15,
  "excluded_files": 3,
  "analysis_scope": "ssl-tls-only"
}
```

---

#### `configureDynamicAnalysis(agent_options)`
**Purpose**: Sets up dynamic analysis agent with specific monitoring parameters.

**Input Parameters**:
```json
{
  "monitoring_level": "verbose",
  "ssl_monitoring": true,
  "timeout": 30,
  "memory_limit": "512m"
}
```

**Output**:
```json
{
  "agent_configured": true,
  "monitoring_points": 12,
  "estimated_overhead": "5%",
  "max_execution_time": 30
}
```

---

### Environment Setup Functions

#### `validateEnvironment()`
**Purpose**: Checks system requirements and dependencies for analysis tools.

**Output**:
```json
{
  "java_version": "11.0.2",
  "java_agent_support": true,
  "required_permissions": ["instrument", "modify"],
  "missing_dependencies": [],
  "environment_ready": true
}
```

**Validation Checks**:
- Java version compatibility
- JVM instrumentation support
- Required permissions
- Dependency availability

---

#### `initializeAnalysisEnvironment(config)`
**Purpose**: Sets up complete analysis environment with all required components.

**Input Parameters**:
- `config` (dict): Environment configuration parameters

**Output**:
```json
{
  "initialization_success": true,
  "static_analyzer_ready": true,
  "dynamic_agent_loaded": true,
  "web_interface_running": true,
  "backend_api_available": true
}
```

**Setup Tasks**:
- Initialize static analysis engine
- Load dynamic analysis agent
- Start backend API server
- Configure web interface

---

This technical documentation provides comprehensive coverage of all major functions in the Java SSL/TLS Security Analyzer, including their inputs, outputs, and usage patterns. Each function is designed for specific security analysis tasks and integrates with the overall system architecture.
