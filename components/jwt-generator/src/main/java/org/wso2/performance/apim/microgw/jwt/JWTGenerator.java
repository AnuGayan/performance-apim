/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.performance.apim.microgw.jwt;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * JWT Token Generator for Microgateway Performance Tests
 */
public class JWTGenerator {

    private static final String WSO2CARBON = "wso2carbon";
    private static final int VALIDITY_PERIOD = 3600 * 24 * 365;
    private static PrintStream errorOutput = System.err;
    private static PrintStream standardOutput = System.out;
    @Parameter(names = "--consumer-key", description = "Consumer key", required = true)
    private String consumerKey;
    @Parameter(names = "--consumer-secret", description = "Consumer Secret", required = true)
    private String consumerSecret;
    @Parameter(names = {"--key-store-file"}, description = "Key Store File", required = true,
            validateValueWith = KeyStoreFileValidator.class)
    private File keyStoreFile;
    @Parameter(names = "--tokens-count", description = "Number of tokens to generate", required = true)
    private int tokensCount;
    @Parameter(names = {"--output-file"}, description = "Output File", required = true)
    private File outputFile;
    @Parameter(names = {"-h", "--help"}, description = "Display Help", help = true)
    private boolean help = false;
    @Parameter(names = "--apim-host", description = "API Manager host url", required = false)
    private String host;

    public static void main(String[] args) throws Exception {
        JWTGenerator jwtGenerator = new JWTGenerator();
        final JCommander jcmdr = new JCommander(jwtGenerator);
        jcmdr.setProgramName(JWTGenerator.class.getSimpleName());

        try {
            jcmdr.parse(args);
        } catch (Exception e) {
            errorOutput.println(e.getMessage());
            return;
        }

        if (jwtGenerator.help) {
            jcmdr.usage();
            return;
        }

        jwtGenerator.generateTokens();
    }

    private void generateTokens() throws Exception {
        long startTime = System.nanoTime();

        JSONObject head = new JSONObject();
        head.put("x5t", "MDJlNjIxN2E1OGZlOGVmMGQxOTFlMzBmNmFjZjQ0Y2YwOGY0N2I0YzE4YzZjNjRhYmRmMmQ0ODdiNDhjMGEwMA");
        head.put("kid", "MDJlNjIxN2E1OGZlOGVmMGQxOTFlMzBmNmFjZjQ0Y2YwOGY0N2I0YzE4YzZjNjRhYmRmMmQ0ODdiNDhjMGEwMA_RS256");
        head.put("typ", "at+jwt");
        head.put("alg", "RS256");

        String header = head.toString();

        String base64UrlEncodedHeader = Base64.getUrlEncoder()
                .encodeToString(header.getBytes(Charset.defaultCharset()));

        Signature signature = Signature.getInstance("SHA256withRSA");
        KeyStore keystore;
//        try (FileInputStream is = new FileInputStream(keyStoreFile)) {
//            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
//            keystore.load(is, WSO2CARBON.toCharArray());
//        }
//        Key key = keystore.getKey(WSO2CARBON, WSO2CARBON.toCharArray());
//        signature.initSign((PrivateKey) key);

        standardOutput.print("Generating tokens...\r");
        String iss;
        if (host != null) {
            iss = "https://" + host + "/oauth2/token";
        } else {
            iss = "https://localhost:9443/oauth2/token";
        }

        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        byte[] consumerKeyAndSecret = (consumerKey + ":" + consumerSecret).getBytes(StandardCharsets.UTF_8);
        String base64UrlEncodedAssertion = Base64.getUrlEncoder().encodeToString(consumerKeyAndSecret);

        try (BufferedWriter tokensWriter = new BufferedWriter(new FileWriter(outputFile))) {
            for (int i = 1; i <= tokensCount; i++) {
                var uri = URI.create(iss);
                var client = HttpClient.newBuilder().sslContext(sc).build();
                var request = HttpRequest
                        .newBuilder()
                        .uri(uri)
                        .header("Authorization", "Basic " + base64UrlEncodedAssertion)
                        .headers("Content-type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build();
                var response = client.send(request, HttpResponse.BodyHandlers.ofString());
                System.out.println(response.statusCode());
                System.out.println(response.body());
                if (response.statusCode() == 200) {
                    JSONObject responseMap = (JSONObject) new JSONTokener(response.body()).nextValue();
                    System.out.println(response.statusCode());
                    System.out.println(response.body());
                    tokensWriter.write(responseMap.get("access_token").toString());
                    tokensWriter.newLine();
                    standardOutput.print("Generated " + i + " tokens.    \r");
                } else {
                    System.out.printf(response.body().toString());
                }
            }
        } catch (IOException e) {
            errorOutput.println(e.getMessage());
        }
        long elapsed = System.nanoTime() - startTime;
        // Add whitespace to clear progress information
        standardOutput.format("Done in %d min, %d sec.                           %n",
                TimeUnit.NANOSECONDS.toMinutes(elapsed),
                TimeUnit.NANOSECONDS.toSeconds(elapsed) -
                        TimeUnit.MINUTES.toSeconds(TimeUnit.NANOSECONDS.toMinutes(elapsed)));
    }
}
