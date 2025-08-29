import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;
import com.github.javaparser.ast.comments.LineComment;
import com.github.javaparser.ast.comments.BlockComment;
import com.github.javaparser.ast.Node;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;
import java.util.LinkedHashMap;

public class AutoPatcher {

    // Lists for quick lookup, shared across methods to reduce object creation
    private static final List<String> INSECURE_PROTOCOLS = Arrays.asList("sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1");
    private static final List<String> WEAK_CIPHER_KEYWORDS = Arrays.asList("null", "anon", "export", "rc4", "des", "md5");
    private static final List<String> RECOMMENDED_PROTOCOLS = Arrays.asList("TLSv1.2", "TLSv1.3");
    private static final List<String> RECOMMENDED_CIPHER_SUITES = Arrays.asList(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    );

    // NEW: Cryptography and XML related constants
    private static final List<String> WEAK_HASHING_ALGORITHMS = Arrays.asList("md5", "sha-1");
    private static final Set<String> XML_FACTORIES = new HashSet<>(Arrays.asList(
        "DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"
    ));
    // Pattern for hardcoded sensitive strings (password, key, secret, salt, token, auth)
    private static final String SENSITIVE_STRING_PATTERN = ".*(password|pass|secret|key|pwd|salt|token|auth).*";


    // Using LinkedHashMap to maintain insertion order for more readable logs
    private static Map<Integer, String> patchLogs = new LinkedHashMap<>(); // Store logs here

    // Consolidated strong cipher/protocol string literals for parsing
    private static final String STRONG_CIPHERS_ARRAY_EXPR =
        "new String[]{\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\", " +
        "\"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"}";

    private static final String STRONG_PROTOCOLS_ARRAY_EXPR =
        "new String[]{\"TLSv1.2\", \"TLSv1.3\"}";


    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: java AutoPatcher <JavaFile>");
            System.err.println("This tool attempts to automatically patch known SSL/JSSE vulnerabilities.");
            System.err.println("The patched code will be printed to standard output.");
            return;
        }

        String filePath = args[0];
        CompilationUnit cu;
        try (FileInputStream in = new FileInputStream(filePath)) {
            cu = StaticJavaParser.parse(in);
        } catch (IOException e) {
            System.err.println("Error reading file: " + filePath + " - " + e.getMessage());
            return;
        }

        System.err.println("Attempting to patch: " + filePath);

        // Apply patches using the visitor
        cu.accept(new SecurityPatchVisitor(), null);

        // Print ONLY the patched code to standard output (stdout)
        System.out.println(cu.toString());

        // Print patch logs to standard error (stderr), wrapped in markers
        System.err.println("--- PATCH LOG START ---");
        // Sort logs by line number before printing for consistent output
        List<Map.Entry<Integer, String>> sortedLogs = new ArrayList<>(patchLogs.entrySet());
        sortedLogs.sort(Comparator.comparingInt(Map.Entry::getKey));

        for (Map.Entry<Integer, String> entry : sortedLogs) {
            System.err.println("Line " + entry.getKey() + ": " + entry.getValue());
        }
        System.err.println("--- PATCH LOG END ---");
    }

    private static class SecurityPatchVisitor extends ModifierVisitor<Void> {

        /**
         * Helper method to record patch logs.
         * @param line The line number where the patch was applied.
         * @param message A description of the patch.
         */
        private void logPatch(int line, String message) {
            patchLogs.put(line, message);
        }

        /**
         * Visits MethodCallExpr nodes to apply patches related to method calls.
         * This includes system property settings, protocol enabling, hostname verification,
         * keystore password loading, weak hashing algorithms, and XML factory instantiation.
         *
         * @param mce The MethodCallExpr node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified MethodCallExpr (or null if the node is removed).
         */
        @Override
        public MethodCallExpr visit(MethodCallExpr mce, Void arg) {
            super.visit(mce, arg); // Call super to ensure full traversal and allow nested modifications

            int line = mce.getBegin().map(p -> p.line).orElse(-1);

            // 1. Patch: Remove debug logging and TLS renegotiation system properties
            if (mce.getNameAsString().equals("setProperty") &&
                mce.getArguments().size() == 2) {
                Expression arg0 = mce.getArgument(0);
                if (arg0.isStringLiteralExpr()) {
                    String key = arg0.asStringLiteralExpr().getValue();
                    if (key.equals("javax.net.debug") || key.equals("com.ibm.jsse2.renegotiate") || key.equals("jdk.tls.rejectClientInitiatedRenegotiation")) {
                        logPatch(line, "Removed System.setProperty(\"" + key + "\", ...) for security.");
                        return null; // Removing the method call expression
                    }
                }
            }

            // 2. Patch: Insecure HostnameVerifier (lambda or anonymous class always returns true)
            if (mce.getNameAsString().equals("setDefaultHostnameVerifier") &&
                mce.getArguments().size() == 1) {
                Expression argExpr = mce.getArgument(0);
                boolean patched = false;

                if (argExpr.isLambdaExpr()) {
                    LambdaExpr lambda = argExpr.asLambdaExpr();
                    if ((lambda.getBody().isExpressionStmt() && lambda.getBody().asExpressionStmt().getExpression().isBooleanLiteralExpr() &&
                         lambda.getBody().asExpressionStmt().getExpression().asBooleanLiteralExpr().getValue()) ||
                        (lambda.getBody().isBlockStmt() && lambda.getBody().asBlockStmt().getStatements().stream()
                            .filter(stmt -> stmt instanceof ReturnStmt)
                            .map(stmt -> (ReturnStmt) stmt)
                            .anyMatch(returnStmt -> returnStmt.getExpression().isPresent() && returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                                     returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()))) {
                        // Replace with a safer placeholder that requires manual config
                        mce.setArgument(0, StaticJavaParser.parseExpression("new javax.net.ssl.HostnameVerifier() {\n" +
                            "    @Override\n" +
                            "    public boolean verify(String hostname, javax.net.ssl.SSLSession session) {\n" +
                            "        // AUTO-PATCH: Manual review required. Implement strict hostname verification here.\n" +
                            "        // Example: return hostname.equals(\"your.secure.domain.com\");\n" +
                            "        return false; // Default to false for security until reviewed\n" +
                            "    }\n" +
                            "}"));
                        patched = true;
                    }
                } else if (argExpr.isObjectCreationExpr()) {
                    ObjectCreationExpr oce = argExpr.asObjectCreationExpr();
                    if (oce.getType().getNameAsString().equals("HostnameVerifier") && oce.getAnonymousClassBody().isPresent()) {
                        if (oce.getAnonymousClassBody().get().stream()
                            .filter(bodyDecl -> bodyDecl instanceof MethodDeclaration)
                            .map(bodyDecl -> (MethodDeclaration) bodyDecl)
                            .filter(md -> md.getNameAsString().equals("verify") && md.getBody().isPresent())
                            .anyMatch(md -> md.getBody().get().getStatements().isEmpty() ||
                                            md.getBody().get().getStatements().stream()
                                                .filter(stmt -> stmt instanceof ReturnStmt)
                                                .map(stmt -> (ReturnStmt) stmt)
                                                .anyMatch(returnStmt -> returnStmt.getExpression().isPresent() && returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                                                         returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()))) {
                            // Replace with a safer placeholder that requires manual config
                            mce.setArgument(0, StaticJavaParser.parseExpression("new javax.net.ssl.HostnameVerifier() {\n" +
                                "    @Override\n" +
                                "    public boolean verify(String hostname, javax.net.ssl.SSLSession session) {\n" +
                                "        // AUTO-PATCH: Manual review required. Implement strict hostname verification here.\n" +
                                "        // Example: return hostname.equals(\"your.secure.domain.com\");\n" +
                                "        return false; // Default to false for security until reviewed\n" +
                                "    }\n" +
                                "}"));
                            patched = true;
                        }
                    }
                }
                if (patched) {
                    logPatch(line, "Insecure HostnameVerifier replaced with secure placeholder requiring manual review.");
                }
            }

            // 3. Patch: Hardcoded password passed to keystore load()
            if (mce.getNameAsString().equals("load") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("KeyStore") &&
                mce.getArguments().size() == 2 &&
                (mce.getArgument(1).isCharLiteralExpr() || mce.getArgument(1).isStringLiteralExpr())) {
                logPatch(line, "Hardcoded password in KeyStore.load() replaced with environment variable lookup.");
                mce.setArgument(1, StaticJavaParser.parseExpression("System.getenv(\"KEYSTORE_PASSWORD\").toCharArray()"));
            }

            // 4. Patch: Use of outdated/weak SSL/TLS protocols in SSLContext.getInstance()
            if (mce.getNameAsString().equals("getInstance") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("SSLContext") &&
                mce.getArguments().size() >= 1 &&
                mce.getArgument(0).isStringLiteralExpr()) {
                String protocol = mce.getArgument(0).asStringLiteralExpr().getValue().toLowerCase();
                if (INSECURE_PROTOCOLS.contains(protocol)) {
                    logPatch(line, "Insecure SSLContext protocol '" + protocol.toUpperCase() + "' changed to 'TLSv1.2'.");
                    mce.setArgument(0, StaticJavaParser.parseExpression("\"TLSv1.2\""));
                }
            }

            // 5. Patch: Enabling weak/outdated protocols via setEnabledProtocols()
            if (mce.getNameAsString().equals("setEnabledProtocols") &&
                mce.getScope().isPresent() &&
                (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                
                Expression protocolsArg = mce.getArgument(0);
                boolean shouldPatch = false;

                if (protocolsArg.isArrayInitializerExpr()) {
                    ArrayInitializerExpr init = protocolsArg.asArrayInitializerExpr();
                    for (Expression expr : init.getValues()) {
                        if (expr.isStringLiteralExpr()) {
                            String protocol = expr.asStringLiteralExpr().getValue().toLowerCase();
                            if (INSECURE_PROTOCOLS.contains(protocol)) {
                                shouldPatch = true;
                                break;
                            }
                        }
                    }
                } else if (protocolsArg.isStringLiteralExpr()) {
                    String protocol = protocolsArg.asStringLiteralExpr().getValue().toLowerCase();
                    if (INSECURE_PROTOCOLS.contains(protocol)) {
                        shouldPatch = true;
                    }
                }
                
                if (shouldPatch) {
                    logPatch(line, "setEnabledProtocols() to use only 'TLSv1.2' and 'TLSv1.3'.");
                    mce.setArgument(0, StaticJavaParser.parseExpression(STRONG_PROTOCOLS_ARRAY_EXPR));
                }
            }

            // 6. Patch: Enabling weak CIPHER SUITES via setEnabledCipherSuites()
            if (mce.getNameAsString().equals("setEnabledCipherSuites") &&
                mce.getScope().isPresent() &&
                (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                
                Expression ciphersArg = mce.getArgument(0);
                boolean shouldPatch = false;

                if (ciphersArg.isArrayInitializerExpr()) {
                    ArrayInitializerExpr init = ciphersArg.asArrayInitializerExpr();
                    for (Expression expr : init.getValues()) {
                        if (expr.isStringLiteralExpr()) {
                            String cipherSuite = expr.asStringLiteralExpr().getValue().toLowerCase();
                            if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                                shouldPatch = true;
                                break;
                            }
                        }
                    }
                } else if (ciphersArg.isStringLiteralExpr()) {
                    String cipherSuite = ciphersArg.asStringLiteralExpr().getValue().toLowerCase();
                    if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                        shouldPatch = true;
                    }
                }
                
                if (shouldPatch) {
                    logPatch(line, "setEnabledCipherSuites() to use strong default cipher suites.");
                    mce.setArgument(0, StaticJavaParser.parseExpression(STRONG_CIPHERS_ARRAY_EXPR));
                }
            }

            // NEW PATCH: Weak Hashing Algorithms (MD5, SHA-1)
            if (mce.getNameAsString().equals("getInstance") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("MessageDigest") &&
                mce.getArguments().size() >= 1) {
                Expression arg0 = mce.getArgument(0);
                if (arg0.isStringLiteralExpr()) {
                    String algorithm = arg0.asStringLiteralExpr().getValue().toLowerCase();
                    if (WEAK_HASHING_ALGORITHMS.contains(algorithm)) {
                        logPatch(line, "Weak hashing algorithm '" + algorithm.toUpperCase() + "' updated to 'SHA-256'.");
                        mce.setArgument(0, StaticJavaParser.parseExpression("\"SHA-256\""));
                    }
                }
            }

            // NEW PATCH: XML External Entity (XXE) Vulnerabilities - Add hardening features
            if (mce.getNameAsString().equals("newInstance") &&
                mce.getScope().isPresent() &&
                XML_FACTORIES.contains(mce.getScope().get().toString())) {
                
                // Find the variable declaration for this factory
                mce.findAncestor(VariableDeclarator.class).ifPresent(vd -> {
                    String factoryName = vd.getNameAsString();
                    // Append hardening calls after the factory creation
                    BlockStmt parentBlock = mce.findAncestor(BlockStmt.class).orElse(null);
                    if (parentBlock != null) {
                        int insertIndex = parentBlock.getStatements().indexOf(mce.findAncestor(ExpressionStmt.class).orElse(null));
                        if (insertIndex != -1) {
                            NodeList<Statement> newStatements = new NodeList<>();
                            newStatements.add(StaticJavaParser.parseStatement(factoryName + ".setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"));
                            newStatements.add(StaticJavaParser.parseStatement(factoryName + ".setFeature(\"http://xml.org/sax/features/external-general-entities\", false);"));
                            newStatements.add(StaticJavaParser.parseStatement(factoryName + ".setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);"));
                            newStatements.add(StaticJavaParser.parseStatement(factoryName + ".setFeature(\"http://apache.org/xml/features/nonvalidating/load-external-dtd\", false);"));
                            newStatements.add(StaticJavaParser.parseStatement(factoryName + ".setXIncludeAware(false);"));
                            newStatements.add(StaticJavaParser.parseStatement(factoryName + ".setExpandEntityReferences(false);"));
                            
                            for (int i = 0; i < newStatements.size(); i++) {
                                parentBlock.addStatement(insertIndex + 1 + i, newStatements.get(i));
                            }
                            logPatch(line, "Added XXE hardening features for XML factory: " + factoryName);
                        }
                    }
                });
            }

            // NEW PATCH: Insecure HTTP URL Usage - Change to HTTPS
            if (mce.getNameAsString().equals("URL") && mce.getArguments().size() == 1) {
                Expression arg0 = mce.getArgument(0);
                if (arg0.isStringLiteralExpr()) {
                    String urlString = arg0.asStringLiteralExpr().getValue();
                    if (urlString.startsWith("http://") && !urlString.contains("localhost") && !urlString.contains("127.0.0.1")) {
                        String httpsUrlString = urlString.replaceFirst("http://", "https://");
                        mce.setArgument(0, StaticJavaParser.parseExpression("\"" + httpsUrlString + "\""));
                        logPatch(line, "Changed insecure 'http://' URL to 'https://': " + httpsUrlString);
                    }
                }
            }


            return mce;
        }

        /**
         * Visits ObjectCreationExpr nodes to apply patches during object instantiation.
         * This includes insecure TrustManager implementations, unseeded SecureRandom,
         * hardcoded cryptographic keys, and deserialization of untrusted data.
         *
         * @param oce The ObjectCreationExpr node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified ObjectCreationExpr.
         */
        @Override
        public ObjectCreationExpr visit(ObjectCreationExpr oce, Void arg) {
            super.visit(oce, arg); // Call super to ensure full traversal

            int line = oce.getBegin().map(p -> p.line).orElse(-1);

            // Patch: Insecure TrustManager (anonymous class with empty methods or return true)
            if (oce.getAnonymousClassBody().isPresent() &&
                (oce.getType().getNameAsString().equals("X509TrustManager") ||
                 oce.getType().getNameAsString().equals("TrustManager"))) {

                boolean foundInsecurePattern = false;
                for (BodyDeclaration bodyDecl : oce.getAnonymousClassBody().get()) {
                    if (bodyDecl instanceof MethodDeclaration) {
                        MethodDeclaration md = (MethodDeclaration) bodyDecl;
                        String methodName = md.getNameAsString();

                        if (("checkClientTrusted".equals(methodName) || "checkServerTrusted".equals(methodName)) && md.getBody().isPresent()) {
                            BlockStmt methodBody = md.getBody().get();
                            
                            // Check for empty body or body with 'return true'
                            if (methodBody.getStatements().isEmpty() ||
                                methodBody.getStatements().stream()
                                    .filter(stmt -> stmt instanceof ReturnStmt)
                                    .map(stmt -> (ReturnStmt) stmt)
                                    .anyMatch(returnStmt -> returnStmt.getExpression().isPresent() && returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                                             returnStmt.getExpression().get().asBooleanLiteralExpr().getValue())) {
                                foundInsecurePattern = true;
                            }
                            // Check for swallowing exceptions
                            else if (methodBody.getStatements().stream()
                                .filter(stmt -> stmt instanceof TryStmt)
                                .map(stmt -> (TryStmt) stmt)
                                .anyMatch(ts -> ts.getCatchClauses().stream()
                                    .anyMatch(catchClause -> {
                                        Type caughtType = catchClause.getParameter().getType();
                                        if (caughtType instanceof ClassOrInterfaceType) {
                                            String typeName = ((ClassOrInterfaceType) caughtType).getNameAsString();
                                            if (typeName.equals("Exception") || typeName.equals("Throwable") ||
                                                typeName.equals("CertificateException") || typeName.equals("NoSuchAlgorithmException")) {
                                                return catchClause.getBody().getStatements().isEmpty() ||
                                                       (catchClause.getBody().getStatements().size() == 1 &&
                                                        catchClause.getBody().getStatement(0).isExpressionStmt() &&
                                                        catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().isMethodCallExpr() &&
                                                        catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().asMethodCallExpr().getNameAsString().equals("printStackTrace"));
                                            }
                                        }
                                        return false;
                                    })
                                )) {
                                foundInsecurePattern = true; // Also consider this an insecure pattern for patching
                            }
                        }
                    }
                }

                if (foundInsecurePattern) {
                    logPatch(line, "Insecure TrustManager replaced with secure placeholder requiring manual review.");
                    // Replace the entire anonymous class with a secure placeholder
                    oce.replace(StaticJavaParser.parseExpression("new javax.net.ssl.X509TrustManager() {\n" +
                        "    @Override\n" +
                        "    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }\n" +
                        "    @Override\n" +
                        "    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) throws java.security.cert.CertificateException {\n" +
                        "        // AUTO-PATCH: Manual review required. Implement strict certificate validation here.\n" +
                        "        throw new java.security.cert.CertificateException(\"Insecure TrustManager automatically patched: Manual review required.\");\n" +
                        "    }\n" +
                        "    @Override\n" +
                        "    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) throws java.security.cert.CertificateException {\n" +
                        "        // AUTO-PATCH: Manual review required. Implement strict certificate validation here.\n" +
                        "        throw new java.security.cert.CertificateException(\"Insecure TrustManager automatically patched: Manual review required.\");\n" +
                        "    }\n" +
                        "}"));
                }
            }

            // NEW PATCH: Hardcoded Cryptographic Keys/Salts/IVs - Add Warning Comment
            if (oce.getType().getNameAsString().equals("SecretKeySpec") ||
                oce.getType().getNameAsString().equals("IvParameterSpec")) {
                boolean hasLiteralArgument = false;
                for (Expression argExpr : oce.getArguments()) {
                    if (argExpr.isStringLiteralExpr()) {
                        String value = argExpr.asStringLiteralExpr().getValue();
                        if (value.length() > 5 && value.toLowerCase().matches(SENSITIVE_STRING_PATTERN)) {
                            hasLiteralArgument = true;
                            break;
                        }
                    } else if (argExpr.isMethodCallExpr() && argExpr.asMethodCallExpr().getScope().isPresent() && argExpr.asMethodCallExpr().getScope().get().isStringLiteralExpr()) {
                        String value = argExpr.asMethodCallExpr().getScope().get().asStringLiteralExpr().getValue();
                        if (value.length() > 5 && value.toLowerCase().matches(SENSITIVE_STRING_PATTERN)) {
                            hasLiteralArgument = true;
                            break;
                        }
                    } else if (argExpr.isArrayCreationExpr()) {
                        ArrayCreationExpr ace = argExpr.asArrayCreationExpr();
                        if (ace.getInitializer().isPresent() && ace.getInitializer().get().getValues().isNonEmpty()) {
                            hasLiteralArgument = true; // Assume any direct array literal initialization is suspicious
                            break;
                        }
                    }
                }
                if (hasLiteralArgument) {
                    oce.getParentNode().ifPresent(parent -> {
                        if (parent instanceof ExpressionStmt || parent instanceof VariableDeclarator) {
                            String comment = "/* AUTO-PATCH: WARNING! This cryptographic key/salt/IV may be hardcoded.\n" +
                                             " * Storing sensitive keys directly in code is a severe security risk.\n" +
                                             " * Externalize this key/salt to a secure location (e.g., environment variable, KeyVault).\n" +
                                             " */";
                            parent.setComment(new BlockComment(comment));
                            logPatch(line, "Added warning comment for potentially hardcoded cryptographic key/salt/IV.");
                        }
                    });
                }
            }

            // NEW PATCH: Deserialization of Untrusted Data - Add Warning Comment
            if (oce.getType().getNameAsString().equals("ObjectInputStream")) {
                oce.getParentNode().ifPresent(parent -> {
                    if (parent instanceof ExpressionStmt) {
                        ExpressionStmt stmt = (ExpressionStmt) parent;
                        String comment = "/* AUTO-PATCH: WARNING! ObjectInputStream is used here.\n" +
                                         " * Deserializing untrusted data from an ObjectInputStream is a MAJOR security vulnerability (RCE).\n" +
                                         " * Avoid using ObjectInputStream with untrusted sources. Consider safer formats like JSON/XML (with XXE protection).\n" +
                                         " * If unavoidable, implement a robust deserialization filter (Java 9+).\n" +
                                         " */";
                        stmt.setComment(new BlockComment(comment));
                        logPatch(line, "Added warning comment for ObjectInputStream (deserialization vulnerability).");
                    }
                });
            }

            return oce;
        }

        /**
         * Visits VariableDeclarator nodes to apply patches related to variable declarations.
         * This includes hardcoded sensitive data and unseeded SecureRandom instances.
         *
         * @param vd The VariableDeclarator node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified VariableDeclarator.
         */
        @Override
        public VariableDeclarator visit(VariableDeclarator vd, Void arg) {
            super.visit(vd, arg); // Call super to ensure full traversal

            int line = vd.getBegin().map(p -> p.line).orElse(-1);

            // Patch: Unseeded SecureRandom instance during variable declaration
            if (vd.getType() instanceof ClassOrInterfaceType) {
                ClassOrInterfaceType classType = (ClassOrInterfaceType) vd.getType();
                if (classType.getNameAsString().equals("SecureRandom") &&
                    vd.getInitializer().isPresent() &&
                    vd.getInitializer().get().isObjectCreationExpr()) {
                    ObjectCreationExpr oce = vd.getInitializer().get().asObjectCreationExpr();
                    if (oce.getType().getNameAsString().equals("SecureRandom") && oce.getArguments().isEmpty()) {
                        logPatch(line, "Unseeded SecureRandom replaced with SecureRandom.getInstanceStrong() for variable: " + vd.getNameAsString());
                        vd.setInitializer(StaticJavaParser.parseExpression("SecureRandom.getInstanceStrong()"));
                    }
                }
            }

            // Patch: Hardcoded password/sensitive string assigned to variable
            if (vd.getInitializer().isPresent() && vd.getInitializer().get().isStringLiteralExpr()) {
                String val = vd.getInitializer().get().asStringLiteralExpr().getValue();
                // Using regex for more flexible pattern matching, and a minimum length to avoid false positives
                if (val.matches(SENSITIVE_STRING_PATTERN) && val.length() > 3) { // Check against new pattern
                    logPatch(line, "Hardcoded sensitive string assigned to variable '" + vd.getNameAsString() + "' replaced with environment lookup.");
                    // Replace with environment variable lookup. Use StandardCharsets for robustness.
                    vd.setInitializer(StaticJavaParser.parseExpression("System.getenv(\"" + vd.getNameAsString().toUpperCase() + "_SECRET\")"));
                }
            }

            // Patch: Weak cipher suites in array initialization (already present)
            if (vd.getType().isArrayType() &&
                vd.getType().asArrayType().getComponentType().toString().equals("String") &&
                vd.getInitializer().isPresent() &&
                vd.getInitializer().get() instanceof ArrayInitializerExpr) {

                ArrayInitializerExpr init = (ArrayInitializerExpr) vd.getInitializer().get();
                
                boolean weak = init.getValues().stream()
                        .filter(Expression::isStringLiteralExpr)
                        .map(expr -> expr.asStringLiteralExpr().getValue().toLowerCase())
                        .anyMatch(val -> WEAK_CIPHER_KEYWORDS.stream().anyMatch(val::contains));

                if (weak) {
                    logPatch(line, "Weak cipher suites array replaced with strong defaults.");
                    vd.setInitializer(StaticJavaParser.parseExpression(STRONG_CIPHERS_ARRAY_EXPR));
                }
            }

            return vd;
        }

        /**
         * Visits WhileStmt nodes to add a warning for potential infinite loops.
         * Direct patching is too risky without deeper semantic analysis.
         *
         * @param ws The WhileStmt node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified WhileStmt.
         */
        @Override
        public WhileStmt visit(WhileStmt ws, Void arg) {
            super.visit(ws, arg);
            int line = ws.getBegin().map(p -> p.line).orElse(-1);

            if (ws.getCondition().isBooleanLiteralExpr() &&
                ws.getCondition().asBooleanLiteralExpr().getValue()) {
                ws.setComment(new BlockComment("/* AUTO-PATCH: WARNING! Infinite loop (while(true)) detected.\n" +
                                               " * This could be a Denial-of-Service vulnerability if it ties up resources.\n" +
                                               " * Review the loop condition to ensure it terminates properly or has safeguards.\n" +
                                               " * Manual review is required to determine if this is intentional or a vulnerability.\n" +
                                               " */"));
                logPatch(line, "Added warning comment for potential infinite loop (while(true)).");
            }
            return ws;
        }

        /**
         * Visits TryStmt nodes to add a warning for overly broad exception catching.
         * Direct patching of catch blocks is complex and risky.
         *
         * @param ts The TryStmt node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified TryStmt.
         */
        @Override
        public TryStmt visit(TryStmt ts, Void arg) {
            super.visit(ts, arg);
            int line = ts.getBegin().map(p -> p.line).orElse(-1);

            ts.getCatchClauses().forEach(catchClause -> {
                Type caughtType = catchClause.getParameter().getType();
                if (caughtType instanceof ClassOrInterfaceType) {
                    String typeName = ((ClassOrInterfaceType) caughtType).getNameAsString();
                    if (typeName.equals("Exception") || typeName.equals("Throwable")) {
                        if (catchClause.getBody().getStatements().isEmpty() ||
                            (catchClause.getBody().getStatements().size() == 1 &&
                             catchClause.getBody().getStatement(0).isExpressionStmt() &&
                             catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().isMethodCallExpr() &&
                             catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().asMethodCallExpr().getNameAsString().equals("printStackTrace"))) {
                            String comment = "/* AUTO-PATCH: WARNING! Overly broad catch for '" + typeName + "' with minimal error handling.\n" +
                                             " * This may hide critical exceptions, including security-related ones. Catch more specific exceptions.\n" +
                                             " * Manual review is required to refine exception handling.\n" +
                                             " */";
                            catchClause.setComment(new BlockComment(comment));
                            logPatch(line, "Added warning comment for overly broad catch block (" + typeName + ").");
                        }
                    }
                }
            });
            return ts;
        }
    }
}
