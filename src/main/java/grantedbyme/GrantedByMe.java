/*
 * =BEGIN MIT LICENSE
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 GrantedByMe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * =END MIT LICENSE
 */
package grantedbyme;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * GrantedByMe API class v1.0.26-master
 *
 * @author GrantedByMe <info@grantedby.me>
 */
public class GrantedByMe {

    public PrivateKey privateKey;

    public PublicKey serverKey;

    public String publicHash;

    public String apiURL;

    public Boolean isDebug;

    public static final int CHALLENGE_AUTHORIZE = 1;
    public static final int CHALLENGE_AUTHENTICATE = 2;
    public static final int CHALLENGE_PROFILE = 4;

    public static final int STATUS_UNREGISTERED = 0;
    public static final int STATUS_PENDING = 1;
    public static final int STATUS_LINKED = 2;
    public static final int STATUS_VALIDATED = 3;
    public static final int STATUS_EXPIRED = 4;
    public static final int STATUS_BANNED = 5;
    public static final int STATUS_DELETED = 6;

    /**
     * Creates a new GrantedByMe SDK instance.
     *
     * @param privateKey Service RSA private key encoded in PEM format
     * @param serverKey  Server RSA public key encoded in PEM format
     */
    public GrantedByMe(String privateKey, String serverKey) {
        this.isDebug = false;
        this.apiURL = "https://api.grantedby.me/v1/service/";
        if (privateKey != null && serverKey != null) {
            try {
                this.privateKey = CryptoUtil.loadPrivate(privateKey).getPrivate();
                this.serverKey = CryptoUtil.loadPublic(serverKey);
                this.publicHash = CryptoUtil.sha512(serverKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    ////////////////////////////////////////
    // Static methods
    ////////////////////////////////////////

    /**
     * Factory method to create new GrantedByMe SDK class instance loading local key files.
     * @param privateKeyPath The path to the service RSA private key
     * @param serverKeyPath The path to the server RSA public key
     * @return GrantedByMe
     */
    public static GrantedByMe fromPemFiles(String privateKeyPath, String serverKeyPath) {
        try {
            return new GrantedByMe(GrantedByMe.readFile(privateKeyPath), GrantedByMe.readFile(serverKeyPath));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reads an utf-8 encoded string file.
     *
     * @param path The path to the file
     * @return
     * @throws IOException
     */
    public static String readFile(String path)
            throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, Charset.forName("utf-8"));
    }

    ////////////////////////////////////////
    // API
    ////////////////////////////////////////

    /**
     * Initiate key exchange for encrypted communication.
     *
     * @param publicKey Service RSA public key encoded in PEM format
     * @return JSONObject
     */
    private JSONObject activateHandshake(String publicKey) {
        HashMap<String, Object> params = getParams(null, null);
        params.put("public_key", publicKey);
        return post(params, "activate_handshake");
    }

    /**
     * Active pending service using service key.
     *
     * @param serviceKey The activation service key
     * @return JSONObject
     */
    public JSONObject activateService(String serviceKey) {
        try {
            KeyPair kp = CryptoUtil.generateKeyPair();
            privateKey = kp.getPrivate();
            JSONObject handshakeResult = activateHandshake(CryptoUtil.savePublic(kp.getPublic().getEncoded()));
            if ((Boolean) handshakeResult.get("success")) {
                String publicPEM = (String) handshakeResult.get("public_key");
                serverKey = CryptoUtil.loadPublic(publicPEM);
                publicHash = CryptoUtil.sha512(publicPEM);
            }
        } catch (Exception e) {
            if (this.isDebug) e.printStackTrace();
        }
        // API call
        HashMap<String, Object> params = getParams(null, null);
        params.put("service_key", serviceKey);
        return post(params, "activate_service");
    }

    /**
     * Deactivates a service for reactivation.
     *
     * @return JSONObject
     */
    public JSONObject deactivateService() {
        HashMap<String, Object> params = getParams(null, null);
        return post(params, "deactivate_service");
    }

    /**
     * Links a service user account with a GrantedByMe account.
     *
     * @param challenge The challenge used to verify the user
     * @param authenticator_secret The secret used for user authentication
     * @return JSONObject
     */
    public JSONObject linkAccount(String challenge, String authenticator_secret) {
        HashMap<String, Object> params = getParams(null, null);
        params.put("challenge", challenge);
        params.put("authenticator_secret", authenticator_secret);
        return post(params, "link_account");
    }

    /**
     * Un-links a service user account with a GrantedByMe account.
     *
     * @param authenticator_secret The secret used for user authentication
     * @return JSONObject
     */
    public JSONObject unlinkAccount(String authenticator_secret) {
        HashMap<String, Object> params = getParams(null, null);
        params.put("authenticator_secret", authenticator_secret);
        return post(params, "unlink_account");
    }

    /**
     * Returns a challenge with required type.
     *
     * @param challenge_type The type of requested challenge
     * @return JSONObject
     */
    public JSONObject getChallenge(int challenge_type) {
        return getChallenge(challenge_type, null, null);
    }

    /**
     * Returns a challenge with required type.
     *
     * @param challenge_type The type of requested challenge
     * @param ip             The client IP address
     * @param userAgent      The client user-agent identifier
     * @return JSONObject
     */
    public JSONObject getChallenge(int challenge_type, String ip, String userAgent) {
        HashMap<String, Object> params = getParams(ip, userAgent);
        params.put("challenge_type", challenge_type);
        return post(params, "get_challenge");
    }

    /**
     * Returns a challenge state.
     *
     * @param challenge The challenge to check
     * @return JSONObject
     */
    public JSONObject getChallengeState(String challenge) {
        HashMap<String, Object> params = getParams(null, null);
        params.put("challenge", challenge);
        return post(params, "get_challenge_state");
    }

    /**
     * Notify the GrantedByMe server about the user has been logged out from the service.
     *
     * @param challenge The challenge representing an active authentication session
     * @return JSONObject
     */
    public JSONObject revokeChallenge(String challenge) {
        HashMap<String, Object> params = getParams(null, null);
        params.put("challenge", challenge);
        return post(params, "revoke_challenge");
    }

    ////////////////////////////////////////
    // Helpers
    ////////////////////////////////////////

    /**
     * Returns the default HTTP parameters.
     *
     * @param ip        The client IP address
     * @param userAgent The client user-agent identifier
     * @return
     */
    private HashMap<String, Object> getParams(String ip, String userAgent) {
        HashMap<String, Object> params = new HashMap<>();
        params.put("timestamp", System.currentTimeMillis() / 1000L);
        if (userAgent != null) {
            params.put("http_user_agent", userAgent);
        }
        if (ip != null) {
            params.put("remote_addr", ip);
        }
        return params;
    }

    /**
     * Sends a HTTP (POST) API request.
     *
     * @param params    The request parameter object
     * @param operation The API operation name
     * @return
     */
    private JSONObject post(HashMap params, String operation) {
        String fullURI = apiURL + operation + "/";
        log("post: " + fullURI);
        String urlParams = JSONObject.toJSONString(params);
        log("plainParams: " + urlParams);
        JSONObject cipherJSON = new JSONObject(params);
        JSONObject cipherParams;
        if (operation.equals("activate_handshake")) {
            cipherParams = cipherJSON;
        } else {
            cipherParams = CryptoUtil.encryptAndSign(cipherJSON, serverKey, privateKey, publicHash);
        }
        log("cipherParams: " + cipherParams.toJSONString());
        URL url;
        HttpURLConnection connection = null;
        try {
            //Create connection
            url = new URL(fullURI);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Content-Length", "" + Integer.toString(cipherParams.toJSONString().getBytes().length));
            connection.setRequestProperty("Content-Language", "en-US");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            //Send request
            DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
            outputStream.writeBytes(cipherParams.toJSONString());
            outputStream.flush();
            outputStream.close();
            //Get Response
            InputStream inputStream = connection.getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            StringBuffer stringBuffer = new StringBuffer();
            while ((line = bufferedReader.readLine()) != null) {
                stringBuffer.append(line);
                stringBuffer.append('\r');
            }
            bufferedReader.close();
            JSONObject cipherResult = (JSONObject) new JSONParser().parse(stringBuffer.toString());
            JSONObject plainResult;
            if (operation.equals("activate_handshake")) {
                plainResult = cipherResult;
            } else {
                plainResult = CryptoUtil.decryptAndVerify(cipherResult, serverKey, privateKey);
            }
            log(cipherResult.toJSONString());
            log(plainResult.toJSONString());
            return plainResult;
        } catch (Exception e) {
            if (this.isDebug) e.printStackTrace();
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Logging helper.
     *
     * @param message
     */
    private void log(String message) {
        if (isDebug) System.out.println("[GrantedByMe] " + message);
    }

    ////////////////////////////////////////
    // Static
    ////////////////////////////////////////

    /**
     * Generates a secure random authenticator secret.
     * @return
     */
    public static String generateAuthenticatorSecret() {
        return CryptoUtil.hexFromBytes(CryptoUtil.randomBytes(64));
    }

    /**
     * Generates hash digest of an authenticator secret.
     * @param authenticatorSecret The authenticator secret to hash
     * @return
     */
    public static String hashAuthenticatorSecret(String authenticatorSecret) {
        return CryptoUtil.sha512(authenticatorSecret);
    }

    ////////////////////////////////////////
    // Deprecated
    ////////////////////////////////////////

    /**
     * @deprecated Use getChallenge(CHALLENGE_AUTHORIZE)
     */
    @Deprecated
    public JSONObject getAccountToken() {
        return getChallenge(CHALLENGE_AUTHORIZE);
    }

    @Deprecated
    public JSONObject getAccountToken(String ip, String userAgent) {
        return getChallenge(CHALLENGE_AUTHORIZE, ip, userAgent);
    }

    /**
     * @deprecated Use getChallenge(CHALLENGE_AUTHENTICATE)
     */
    @Deprecated
    public JSONObject getSessionToken() {
        return getChallenge(CHALLENGE_AUTHENTICATE);
    }

    @Deprecated
    public JSONObject getSessionToken(String ip, String userAgent) {
        return getChallenge(CHALLENGE_AUTHENTICATE, ip, userAgent);
    }

    /**
     * @deprecated Use getChallenge(CHALLENGE_PROFILE)
     */
    @Deprecated
    public JSONObject getRegisterToken() {
        return getChallenge(CHALLENGE_PROFILE);
    }

    @Deprecated
    public JSONObject getRegisterToken(String ip, String userAgent) {
        return getChallenge(CHALLENGE_PROFILE, ip, userAgent);
    }


    /**
     * @deprecated Use revokeChallenge
     */
    @Deprecated
    public JSONObject revokeSessionToken(String challenge) {
        return revokeChallenge(challenge);
    }

    /**
     * @deprecated Use getChallengeState
     */
    public JSONObject getTokenState(String challenge) {
        return getChallengeState(challenge);
    }

}
