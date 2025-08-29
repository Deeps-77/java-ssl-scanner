# Setup Guide - Java SSL/TLS Security Analyzer

## Table of Contents
1. [Installation Guide](#installation-guide)
2. [Configuration Setup](#configuration-setup)
3. [Running the Application](#running-the-application)
4. [Usage Instructions](#usage-instructions)
5. [Troubleshooting](#troubleshooting)

---

## Installation Guide

### Step 1: Install Java Development Kit

**Option A: OpenJDK (Recommended)**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-11-jdk

# CentOS/RHEL
sudo yum install java-11-openjdk-devel

# Windows (using Chocolatey)
choco install openjdk11

# macOS (using Homebrew)
brew install openjdk@11
```

**Option B: Oracle JDK**
1. Download from [Oracle JDK Downloads](https://www.oracle.com/java/technologies/downloads/)
2. Follow platform-specific installation instructions
3. Verify installation: `java -version`

### Step 2: Install Python

**Windows:**
1. Download Python 3.9+ from [python.org](https://www.python.org/downloads/)
2. Run installer with "Add Python to PATH" checked
3. Verify: `python --version`

**Linux:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv

# CentOS/RHEL
sudo yum install python3 python3-pip
```

**macOS:**
```bash
# Using Homebrew
brew install python@3.9
```

### Step 3: Clone Project Repository

```bash
# Clone the repository
git clone [repository-url] java-ssl-scanner
cd java-ssl-scanner

# Verify project structure
ls -la
```

**Expected Directory Structure:**
```
java-ssl-scanner/
├── backend/
├── frontend/
├── java_analyzer/
├── tests/
├── documentation/
├── requirements.txt
├── README.md
└── ...
```

### Step 4: Install Python Dependencies

```bash
# Create virtual environment (recommended)
python -m venv ssl-analyzer-env

# Activate virtual environment
# Windows
ssl-analyzer-env\Scripts\activate
# Linux/macOS
source ssl-analyzer-env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Core Python Dependencies:**
- FastAPI: Web API framework
- Uvicorn: ASGI server
- JavaParser: Java AST parsing (if using Python wrapper)
- Other utilities as listed in requirements.txt

### Step 5: Build Java Components

```bash
# Navigate to Java analyzer directory
cd java_analyzer

# Compile static analyzer (Windows)
javac -cp "javaparser-core-3.26.4.jar" Analyzer.java

# Create analyzer JAR
jar cfm analyzer.jar MANIFEST.MF *.class

# Compile dynamic analysis agent (Windows)
javac -cp "libs\byte-buddy-1.14.10.jar;libs\byte-buddy-agent-1.14.10.jar" DynamicAnalyzerAgent.java
jar cfm DynamicAnalyzerAgent.jar META-INF\MANIFEST.MF *.class

# Linux/macOS (use : instead of ; for classpath)
javac -cp "libs/byte-buddy-1.14.10.jar:libs/byte-buddy-agent-1.14.10.jar" DynamicAnalyzerAgent.java
jar cfm DynamicAnalyzerAgent.jar META-INF/MANIFEST.MF *.class
```

**Build Verification:**
```bash
# Test static analyzer
java -jar analyzer.jar sample/TestFile.java

# Test dynamic agent
java -javaagent:DynamicAnalyzerAgent.jar -cp . DynamicAnalysisTarget
```

---

## Configuration Setup

### Environment Variables

**Set Required Environment Variables:**

**Windows (PowerShell):**
```powershell
$env:JAVA_HOME = "C:\Program Files\Java\jdk-11"
$env:PATH += ";$env:JAVA_HOME\bin"
$env:SSL_ANALYZER_HOME = "D:\java-ssl-scanner"
```

**Linux/macOS (Bash):**
```bash
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
export PATH=$PATH:$JAVA_HOME/bin
export SSL_ANALYZER_HOME=/path/to/java-ssl-scanner
```

### Application Configuration

**Create Configuration File:**
```bash
# Copy sample configuration
cp config/config.sample.json config/config.json
```

**Edit config/config.json:**
```json
{
  "analysis": {
    "static_analyzer_jar": "./java_analyzer/analyzer.jar",
    "dynamic_agent_jar": "./java_analyzer/DynamicAnalyzerAgent.jar",
    "timeout_seconds": 30,
    "max_file_size_mb": 10
  },
  "server": {
    "host": "127.0.0.1",
    "port": 8000,
    "debug": false
  },
  "logging": {
    "level": "INFO",
    "file": "logs/ssl-analyzer.log"
  }
}
```

### Security Configuration

**File Permissions (Linux/macOS):**
```bash
# Set appropriate permissions
chmod +x java_analyzer/*.jar
chmod +x run.sh
chmod 700 config/
chmod 600 config/config.json
```

**Firewall Configuration:**
- Open port 8000 for web interface access
- Ensure Java applications can run with instrumentation

---

## Running the Application

### Option 1: Using the Startup Script (Recommended)

**Windows:**
```batch
# Start all components
.\run.bat

# Or run individual components
.\scripts\start-backend.bat
.\scripts\start-frontend.bat
```

**Linux/macOS:**
```bash
# Make script executable
chmod +x run.sh

# Start all components
./run.sh

# Or run individual components
./scripts/start-backend.sh
./scripts/start-frontend.sh
```

### Option 2: Manual Startup

**Start Backend API Server:**
```bash
# Activate virtual environment
source ssl-analyzer-env/bin/activate  # Linux/macOS
# ssl-analyzer-env\Scripts\activate    # Windows

# Start FastAPI server
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

**Start Frontend Web Server:**
```bash
# In a new terminal
cd frontend
streamlit run app.py --server.port 7860
```


### Verification

**Check Services:**
```bash
# Test backend API
curl http://localhost:8000/health

# Expected response: {"status": "healthy", "version": "1.0.0"}


# Check logs
tail -f logs/ssl-analyzer.log
```

**Service URLs:**
- **Streamlit App**: http://localhost:8501
- **API Backend**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

---

## Usage Instructions

### Web Interface Usage

**Step 1: Access the Application**
1. Open web browser
2. Navigate to `http://localhost:8501`
3. You should see the SSL/TLS Analyzer Streamlit interface

**Step 2: Upload Java File for Analysis**
1. Click "Choose File" or drag-and-drop Java file
2. Select analysis type:
   - **Static Only**: Code pattern analysis
   - **Dynamic Only**: Runtime monitoring
   - **Both**: Comprehensive analysis (recommended)
3. Click "Analyze" button

**Step 3: Review Results**
1. Wait for analysis completion (usually 2-10 seconds)
2. Review vulnerability summary
3. Examine detailed findings
4. Download report if needed

### Command Line Usage

**Static Analysis Only:**
```bash
# Analyze single file
java -jar java_analyzer/analyzer.jar path/to/YourFile.java

# Analyze with verbose output
java -jar java_analyzer/analyzer.jar --verbose path/to/YourFile.java
```

**Dynamic Analysis Only:**
```bash
# Compile your Java application first
javac -cp . YourApplication.java

# Run with dynamic analysis agent
java -javaagent:java_analyzer/DynamicAnalyzerAgent.jar YourApplication
```

**API Usage:**
```bash
# Upload file for analysis
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@YourFile.java" \
  -F "analysis_type=both"

# Get analysis results
curl "http://localhost:8000/results/{analysis_id}"
```

### Sample Test Files

**Test with Provided Samples:**
```bash
# Static analysis test
java -jar java_analyzer/analyzer.jar java_analyzer/sample/SSLVulnerabilityTest.java

# Dynamic analysis test
cd java_analyzer
javac sample/AllVulnerabilitiesTest.java
java -javaagent:DynamicAnalyzerAgent.jar -cp . sample.AllVulnerabilitiesTest
```

---

## Troubleshooting

### Common Issues

**Issue 1: Java Analyzer Not Found**
```
Error: Could not find analyzer.jar
```
**Solution:**
```bash
# Verify Java analyzer is built
cd java_analyzer
ls -la *.jar

# Rebuild if necessary
javac -cp "javaparser-core-3.26.4.jar" Analyzer.java
jar cfm analyzer.jar MANIFEST.MF *.class
```

**Issue 2: Python Dependencies Missing**
```
ModuleNotFoundError: No module named 'fastapi'
```
**Solution:**
```bash
# Verify virtual environment is activated
which python  # Should point to virtual environment

# Reinstall dependencies
pip install -r requirements.txt
```

**Issue 3: Dynamic Agent Fails to Load**
```
Error opening zip file or JAR manifest missing
```
**Solution:**
```bash
# Check MANIFEST.MF exists
cat java_analyzer/META-INF/MANIFEST.MF

# Rebuild agent JAR with correct manifest
cd java_analyzer
jar cfm DynamicAnalyzerAgent.jar META-INF/MANIFEST.MF *.class
```

**Issue 4: Port Already in Use**
```
OSError: [Errno 48] Address already in use
```
**Solution:**
```bash
# Find process using port
lsof -i :8000  # Linux/macOS
netstat -an | findstr :8000  # Windows

# Kill process or use different port
uvicorn main:app --port 8001
```

**Issue 5: Permission Denied Errors**
```
Permission denied: './run.sh'
```
**Solution:**
```bash
# Make scripts executable
chmod +x run.sh
chmod +x scripts/*.sh
```

### Performance Issues

**Slow Analysis Performance:**
1. **Increase Java heap size:**
   ```bash
   export JAVA_OPTS="-Xmx2g -Xms512m"
   ```

2. **Use SSD storage** for better I/O performance

3. **Close unnecessary applications** to free memory

4. **Analyze smaller files** individually rather than large codebases

### Debugging

**Enable Debug Logging:**
```bash
# Edit config/config.json
{
  "logging": {
    "level": "DEBUG",
    "file": "logs/ssl-analyzer-debug.log"
  }
}
```

**Check Application Logs:**
```bash
# Backend logs
tail -f logs/ssl-analyzer.log

# Java analyzer logs
tail -f java_analyzer/analyzer.log

# System logs (Linux)
journalctl -f -u ssl-analyzer
```

**Verbose Analysis Output:**
```bash
# Static analysis with debug
java -Dlogging.level=DEBUG -jar java_analyzer/analyzer.jar file.java

# Dynamic analysis with verbose agent
java -javaagent:DynamicAnalyzerAgent.jar=verbose YourApp
```

### Getting Help

**Documentation Resources:**
- Project README.md
- API documentation: http://localhost:8000/docs
- Technical documentation in `documentation/` folder

**Log File Locations:**
- Application logs: `logs/ssl-analyzer.log`
- Java analyzer logs: `java_analyzer/analyzer.log`
- Web server logs: `frontend/access.log`

**Common Configuration Files:**
- Main config: `config/config.json`
- Java analyzer config: `java_analyzer/analyzer.properties`
- Logging config: `config/logging.conf`

---

This setup guide provides comprehensive instructions for installing, configuring, and running the Java SSL/TLS Security Analyzer across different platforms and deployment scenarios.
