/*
 * =BEGIN CLOSED LICENSE
 *
 *  Copyright (c) 2016 grantedby.me
 *  http://www.grantedby.me
 *
 *  For information about the licensing and copyright please
 *  contact us at info@grantedby.me
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 * =END CLOSED LICENSE
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
 * GrantedByMe API class v1.0.10-master
 *
 * @author GrantedByMe <info@grantedby.me>
 */
public class GrantedByMe {

    private PrivateKey privateKey;
    private PublicKey serverKey;
    private String publicHash;
    private String apiURL;
    private Boolean isDebug;

    /**
     * Constructor
     * @param privateKey
     * @param serverKey
     */
    public GrantedByMe(String privateKey, String serverKey) {
        this.isDebug = true;
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
     * TBD
     * @param publicKey
     * @return
     */
    private JSONObject activateHandshake(String publicKey) {
        HashMap<String, Object> result = new HashMap<>();
        result.put("timestamp", System.currentTimeMillis() / 1000L);
        result.put("public_key", publicKey);
        return post(result, "activate_handshake");
    }

    /**
     * TBD
     * @param serviceKey
     * @param grantor
     * @return
     */
    public JSONObject activateService(String serviceKey, String grantor) {
        HashMap params = getParams();
        params.put("grantor", grantor);
        params.put("service_key", serviceKey);
        return post(params, "activate_service");
    }

    /**
     * TBD
     * @return
     */
    public JSONObject deactivateService() {
        HashMap params = getParams();
        return post(params, "deactivate_service");
    }

    /**
     * TBD
     * @return
     */
    public JSONObject getAccountToken() {
        HashMap params = getParams();
        params.put("token_type", 1);
        return post(params, "get_session_token");
    }

    /**
     * TBD
     * @param token
     * @return
     */
    public JSONObject getAccountState(String token) {
        HashMap params = getParams();
        params.put("token", token);
        return post(params, "get_session_state");
    }

    /**
     * TBD
     * @param token
     * @param grantor
     * @return
     */
    public JSONObject linkAccount(String token, String grantor) {
        HashMap params = getParams();
        params.put("token", token);
        params.put("grantor", grantor);
        return post(params, "link_account");
    }

    /**
     * TBD
     * @param grantor
     * @return
     */
    public JSONObject unlinkAccount(String grantor) {
        HashMap params = getParams();
        params.put("grantor", CryptoUtil.sha512(grantor));
        return post(params, "unlink_account");
    }

    /**
     * TBD
     * @return
     */
    public JSONObject getSessionToken() {
        HashMap params = getParams();
        params.put("token_type", 2);
        params.put("http_user_agent", "Unknown");
        params.put("remote_addr", "0.0.0.0");
        return post(params, "get_session_token");
    }

    /**
     * TBD
     * @param token
     * @return
     */
    public JSONObject getSessionState(String token) {
        HashMap params = getParams();
        params.put("token", token);
        return post(params, "get_session_state");
    }

    /**
     * Returns the default HTTP parameters sent by the client
     * @return
     */
    private HashMap getParams() {
        HashMap<String, Object> result = new HashMap<>();
        result.put("timestamp", System.currentTimeMillis() / 1000L);
        return result;
    }

    /**
     * Logging helper
     * @param message
     */
    private void log(String message) {
        if (isDebug) System.out.println("[GrantedByMe] " + message);
    }

    /**
     * HTTP communication helper
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