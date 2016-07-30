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


import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * CryptoUtil class
 *
 * @author GrantedByMe <info@grantedby.me>
 */
public final class CryptoUtil {

    private static final String PROVIDER = "BC";

    /**
     * TBD
     *
     * @param source
     * @return
     * @throws Exception
     */
    public static KeyPair loadPrivate(String source) throws Exception {
        PEMReader pemReader = new PEMReader(new StringReader(source));
        return (KeyPair) pemReader.readObject();
    }

    /**
     * TBD
     *
     * @param source
     * @return
     * @throws Exception
     */
    public static PublicKey loadPublic(String source) throws Exception {
        PEMReader pemReader = new PEMReader(new StringReader(source));
        return (PublicKey) pemReader.readObject();
    }

    /**
     * TBD
     *
     * @param source
     * @return
     * @throws Exception
     */
    public static String savePublic(byte[] source) throws Exception {
        return saveKeyPair(source, "PUBLIC KEY");
    }

    /**
     * TBD
     *
     * @param source
     * @return
     * @throws Exception
     */
    public static String savePrivate(byte[] source) throws Exception {
        return saveKeyPair(source, "PRIVATE KEY");
    }

    /**
     * TBD
     *
     * @param source
     * @param type
     * @return
     * @throws Exception
     */
    public static String saveKeyPair(byte[] source, String type) throws Exception {
        final StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(new PemObject(type, source));
        pemWriter.flush();
        pemWriter.close();
        return stringWriter.toString();
    }

    /**
     * Generates a new RSA keypair with fixed 2048bit size
     *
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception {
        final KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA", PROVIDER);
        factory.initialize(2048);
        return factory.generateKeyPair();
    }

    /**
     * TBD
     *
     * @param requestBody
     * @param serverPublicKey
     * @param privateKey
     * @return
     */
    public static JSONObject encryptAndSign(JSONObject requestBody, String serverPublicKey, String privateKey) {
        try {
            return CryptoUtil.encryptAndSign(requestBody,
                    CryptoUtil.loadPublic(serverPublicKey),
                    CryptoUtil.loadPrivate(privateKey).getPrivate(),
                    CryptoUtil.sha512(serverPublicKey));
        } catch (Exception e) {

        }
        return null;
    }

    /**
     * JSON object encryptor helper
     *
     * @param requestBody
     * @param serverPublicKey
     * @param privateKey
     * @param publicHash
     * @return
     */
    public static JSONObject encryptAndSign(JSONObject requestBody, PublicKey serverPublicKey, PrivateKey privateKey, String publicHash) {
        //if (BuildConfig.DEBUG) Log.d(TAG, "encryptAndSign: " + requestBody);
        // Convert JSON String to Bytes
        byte[] plainBytes = requestBody.toString().getBytes();
        // AES cipher
        byte[] cipherKey = randomBytes(32);
        byte[] cipherIv = randomBytes(16);
        byte[] cipherBytes;
        byte[] cipherSignature;
        String cipherText;
        JSONObject cipherJSON;
        // RSA payload
        byte[] payloadBytes;
        String payloadText;
        // RSA signature
        byte[] signatureBytes;
        String signatureText;
        // AES encrypt -> RSA encrypt -> RSA sign
        try {
            if (requestBody.toString().length() < 255) {
                cipherText = null;
                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", PROVIDER);
                cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                payloadBytes = cipher.doFinal(plainBytes);
                payloadText = new String(Base64.encode(payloadBytes), "UTF-8");
                // Generate RSA signature
                final Signature s = Signature.getInstance("SHA512WITHRSAANDMGF1", PROVIDER);
                //s.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                s.initSign(privateKey);
                s.update(plainBytes);
                signatureBytes = s.sign();
                signatureText = new String(Base64.encode(signatureBytes), "UTF-8");
            } else {
                cipherBytes = crypt(plainBytes, cipherKey, cipherIv, Cipher.ENCRYPT_MODE);
                cipherText = new String(Base64.encode(cipherBytes), "UTF-8");
                // Sign using HMAC
                final Mac hmac = Mac.getInstance("HmacSHA512", PROVIDER);
                final SecretKeySpec keySpec = new SecretKeySpec(cipherKey, "HmacSHA512");
                hmac.init(keySpec);
                cipherSignature = hmac.doFinal(plainBytes);
                // Wrap AES cipher data into JSON
                Map<String, Object> cipherParams = new HashMap<>();
                cipherParams.put("cipher_key", Base64.encode(cipherKey));
                cipherParams.put("cipher_iv", Base64.encode(cipherIv));
                cipherParams.put("signature", Base64.encode(cipherSignature));
                Long timestamp = System.currentTimeMillis() / 1000L;
                cipherParams.put("timestamp", timestamp);
                cipherJSON = new JSONObject(cipherParams);
                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", PROVIDER);
                cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                payloadBytes = cipher.doFinal(cipherJSON.toString().getBytes());
                payloadText = new String(Base64.encode(payloadBytes), "UTF-8");
                // Generate RSA signature
                final Signature s = Signature.getInstance("SHA512WITHRSAANDMGF1", PROVIDER);
                //s.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
                s.initSign(privateKey);
                s.update(cipherJSON.toString().getBytes());
                signatureBytes = s.sign();
                signatureText = new String(Base64.encode(signatureBytes), "UTF-8");
            }
        } catch (Exception e) {
            throw new RuntimeException("encryptAndSign failed", e);
        }
        // collect
        Map<String, Object> params = new HashMap<>();
        params.put("payload", payloadText);
        params.put("signature", signatureText);
        if (cipherText != null) {
            params.put("message", cipherText);
        }
        params.put("public_hash", publicHash);
        // return
        return new JSONObject(params);
    }

    /**
     * TBD
     *
     * @param responseBody
     * @param serverPublicKey
     * @param privateKey
     * @return
     */
    public static JSONObject decryptAndVerify(JSONObject responseBody, String serverPublicKey, String privateKey) {
        try {
            return CryptoUtil.decryptAndVerify(responseBody,
                    CryptoUtil.loadPublic(serverPublicKey),
                    CryptoUtil.loadPrivate(privateKey).getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * JSON object decryptor helper
     *
     * @param responseBody
     * @param serverPublicKey
     * @param privateKey
     * @return
     */
    public static JSONObject decryptAndVerify(JSONObject responseBody, PublicKey serverPublicKey, PrivateKey privateKey) {
        if (responseBody == null
                || !responseBody.containsKey("payload")
                || !responseBody.containsKey("signature")) {
            throw new RuntimeException("decryptAndVerify failed with invalid message");
        }
        JSONObject result;
        byte[] payload;
        try {
            // decrypt
            payload = Base64.decode((String) responseBody.get("payload"));
            final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            payload = cipher.doFinal(payload);
            // verify
            byte[] signature = Base64.decode((String) responseBody.get("signature"));
            final Signature s = Signature.getInstance("SHA512WITHRSAANDMGF1", PROVIDER);
            //s.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
            s.initVerify(serverPublicKey);
            s.update(payload);
            Boolean isValid = s.verify(signature);
            if (!isValid) {
                throw new RuntimeException("decryptAndVerify failed, signature error");
            }
            String payloadJson = new String(payload, "UTF-8");  // bytes to string
            result = (JSONObject) new JSONParser().parse(payloadJson);  // string to object
            // If server sent payload and signature only, and decrypted payload does not contain secret keys
            // assume that the message is non-compound RSA encrypted and signed message.
            if (!responseBody.containsKey("message") && !result.containsKey("signature") && !result.containsKey("cipher_key") && !result.containsKey("cipher_iv")) {
                return result;
            }
            // Use AES encryption for messages longer than the available RSA key space
            byte[] message = Base64.decode((String) responseBody.get("message"));
            byte[] cipherKey = Base64.decode((String) result.get("cipher_key"));
            byte[] cipherIv = Base64.decode((String) result.get("cipher_iv"));
            byte[] cipherResult = crypt(message, cipherKey, cipherIv, Cipher.DECRYPT_MODE);
            String cipherJson = new String(cipherResult, "UTF-8");
            result = (JSONObject) new JSONParser().parse(cipherJson);
        } catch (Exception e) {
            throw new RuntimeException("decryptAndVerify failed", e);
        }
        //if (BuildConfig.DEBUG) Log.d(TAG, "decryptAndVerify: " + result);
        return result;
    }

    /**
     * AES crypto helper (two-way)
     *
     * @param source
     * @param key
     * @param iv
     * @param mode
     * @return
     * @throws Exception
     */
    public static byte[] crypt(byte[] source, byte[] key, byte[] iv, int mode) throws Exception {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(source);
    }

    /**
     * Generates a message digest using given algorithm
     *
     * @param source
     * @param salt
     * @param algorithm
     * @return
     * @throws Exception
     */
    public static byte[] hash(byte[] source, byte[] salt, String algorithm) throws Exception {
        if (algorithm == null) {
            algorithm = "SHA-512";
        }
        final MessageDigest digest = MessageDigest.getInstance(algorithm, PROVIDER);
        byte[] output = digest.digest(source);
        if (salt != null) {
            digest.update(salt);
            digest.update(output);
            //return new BigInteger(1, digest.digest());
            return digest.digest();
        }
        return output;
    }

    /**
     * Generate a SHA-512 digest from a string input
     *
     * @param source
     * @return
     */
    public static String sha512(String source) {
        source = source.replace("\r\n", "\n");
        source = source.replace("\r", "\n");
        try {
            return CryptoUtil.hexFromBytes(hash(source.getBytes(), null, "SHA-512"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Generates a CRC-32 checksum from byte input
     *
     * @param bytes
     * @return
     * @throws Exception
     */
    public static String checksum(byte[] bytes) throws Exception {
        final Checksum checksumEngine = new CRC32();
        checksumEngine.update(bytes, 0, bytes.length);
        String hex = Long.toHexString(checksumEngine.getValue());
        return "00000000".substring(0, 8 - hex.length()) + hex.toUpperCase();
    }

    /**
     * Generates secure random bytes with given length
     *
     * @param len
     * @return
     */
    public static byte[] randomBytes(int len) {
        SecureRandom random = new SecureRandom();
        byte result[] = new byte[len]; //IV AES is always 16bytes
        random.nextBytes(result);
        return result;
    }

    final private static char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    /**
     * Byte to Hex conversion helper
     *
     * @param bytes
     * @return
     */
    public static String hexFromBytes(byte[] bytes) {
        final char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


}

