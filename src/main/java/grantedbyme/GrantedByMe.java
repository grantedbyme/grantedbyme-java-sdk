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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * GrantedByMe API class v1.0.13-master
 *
 * @author GrantedByMe <info@grantedby.me>
 */
public class GrantedByMe {

    private PrivateKey privateKey;
    private PublicKey serverKey;
    private String publicHash;
    private String apiURL;
    private Boolean isDebug;

    public static final int TOKEN_ACC = 1;
    public static final int TOKEN_AUTH = 2;
    public static final int TOKEN_REG = 4;

    /**
     * Constructor
     *
     * @param privateKey Your private key encoded in PEM format
     * @param serverKey  GrantedByMe server public key encoded in PEM format
     */
    public GrantedByMe(String privateKey, String serverKey) {
        this.isDebug = false;
        this.apiURL = "https://api.grantedby.me/v1/service/";
        try {
            this.privateKey = CryptoUtil.loadPrivate(privateKey).getPrivate();
            this.serverKey = CryptoUtil.loadPublic(serverKey);
            this.publicHash = CryptoUtil.sha512(serverKey);
        } catch (Exception e) {
            if (this.isDebug) e.printStackTrace();
        }
    }

    /**
     * Debug mode setter
     *
     * @param isEnabled Indicates whether the debug mode is enabled
     */
    public void setDebugMode(Boolean isEnabled) {
        this.isDebug = isEnabled;
    }

    /**
     * API URL setter
     *
     * @param url The GrantedByMe service API URL
     */
    public void setApiUrl(String url) {
        this.apiURL = url;
    }

    /**
     * Initiate key exchange for encrypted communication.
     *
     * @param publicKey Your public key encoded in PEM format
     * @return JSONObject
     */
    private JSONObject activateHandshake(String publicKey) {
        HashMap<String, Object> result = new HashMap<>();
        result.put("timestamp", System.currentTimeMillis() / 1000L);
        result.put("public_key", publicKey);
        return post(result, "activate_handshake");
    }

    /**
     * Active pending service using service key and owner authentication hash.
     *
     * @param serviceKey The activation service key
     * @param grantor    The owner authentication hash
     * @return JSONObject
     */
    public JSONObject activateService(String serviceKey, String grantor) {
        HashMap<String, Object> params = getParams();
        params.put("grantor", grantor);
        params.put("service_key", serviceKey);
        return post(params, "activate_service");
    }

    /**
     * De-active the service.
     *
     * @return JSONObject
     */
    public JSONObject deactivateService() {
        HashMap<String, Object> params = getParams();
        return post(params, "deactivate_service");
    }

    /**
     * Link an existing user account with a GBM account.
     *
     * @param token
     * @param grantor
     * @return JSONObject
     */
    public JSONObject linkAccount(String token, String grantor) {
        HashMap<String, Object> params = getParams();
        params.put("token", token);
        params.put("grantor", grantor);
        return post(params, "link_account");
    }

    /**
     * Unlink an existing user account with a GBM account.
     *
     * @param grantor
     * @return JSONObject
     */
    public JSONObject unlinkAccount(String grantor) {
        HashMap<String, Object> params = getParams();
        params.put("grantor", CryptoUtil.sha512(grantor));
        return post(params, "unlink_account");
    }

    /**
     * Retrieve an account link token.
     *
     * @return JSONObject
     */
    public JSONObject getAccountToken() {
        return getToken(TOKEN_ACC);
    }

    /**
     * Retrieve an authentication token.
     *
     * @return JSONObject
     */
    public JSONObject getSessionToken() {
        return getToken(TOKEN_AUTH);
    }

    /**
     * Retrieve a registration token.
     *
     * @return JSONObject
     */
    public JSONObject getRegisterToken() {
        return getToken(TOKEN_REG);
    }

    /**
     * Retrieve user account authentication token.
     *
     * @return JSONObject
     */
    public JSONObject getToken(int type) {
        HashMap<String, Object> params = getParams();
        params.put("token_type", type);
        params.put("http_user_agent", "Unknown");
        params.put("remote_addr", "0.0.0.0");
        return post(params, "get_session_token");
    }

    /**
     * Returns the token status
     *
     * @param token
     * @return JSONObject
     */
    public JSONObject getTokenState(String token) {
        HashMap<String, Object> params = getParams();
        params.put("token", token);
        return post(params, "get_session_state");
    }

    /**
     * Deprecated, use getTokenState
     */
    @Deprecated
    public JSONObject getAccountState(String token) {
        HashMap<String, Object> params = getParams();
        params.put("token", token);
        return post(params, "get_session_state");
    }

    /**
     * Deprecated, use getTokenState
     */
    @Deprecated
    public JSONObject getSessionState(String token) {
        HashMap<String, Object> params = getParams();
        params.put("token", token);
        return post(params, "get_session_state");
    }

    /**
     * Deprecated, use getTokenState
     */
    @Deprecated
    public JSONObject getRegisterState(String token) {
        HashMap<String, Object> params = getParams();
        params.put("token", token);
        return post(params, "get_session_state");
    }

    /**
     * Returns the default HTTP parameters sent by the client
     *
     * @return HashMap
     */
    private HashMap<String, Object> getParams() {
        HashMap<String, Object> result = new HashMap<>();
        result.put("timestamp", System.currentTimeMillis() / 1000L);
        return result;
    }

    /**
     * Logging helper
     *
     * @param message
     */
    private void log(String message) {
        if (isDebug) System.out.println("[GrantedByMe] " + message);
    }

    /**
     * HTTP communication helper
     *
     * @param params
     * @param operation
     * @return
     */
    private JSONObject post(HashMap params, String operation) {
        String fullURI = apiURL + operation + "/";
        log("post: " + fullURI);
        String urlParams = JSONObject.toJSONString(params);
        log("plainParams: " + urlParams);
        JSONObject cipherJSON = new JSONObject(params);
        JSONObject cipherParams = CryptoUtil.encryptAndSign(cipherJSON, serverKey, privateKey, publicHash);
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
            JSONObject plainResult = CryptoUtil.decryptAndVerify(cipherResult, serverKey, privateKey);
            if (isDebug) log(cipherResult.toJSONString());
            if (isDebug) log(plainResult.toJSONString());
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

}
