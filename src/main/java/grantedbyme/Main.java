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

import java.nio.charset.Charset;
import java.security.Security;

/**
 * Main CLI class
 *
 * @author GrantedByMe <info@grantedby.me>
 */
public class Main {

    static {
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 0);
    }

    public static void main(String[] args) {

            try {
                // parse commands
                String baseDir = "/tmp/";
                String command = "getSessionToken";
                if (args.length >= 1) {
                    baseDir = args[0];
                }
                if (args.length >= 2) {
                    command = args[1];
                }
                System.out.println("Reading 'private_key.pem' and 'server_key.pem' from: " + baseDir);
                // read keys
                String privateKey = FileUtil.readFile(baseDir + "private_key.pem", Charset.forName("utf-8"));
                String serverKey = FileUtil.readFile(baseDir + "server_key.pem", Charset.forName("utf-8"));
                // create sdk
                GrantedByMe sdk = new GrantedByMe(privateKey, serverKey);
                // run command
                Object result = null;
                if(command.equals("getSessionToken")) {
                    result = sdk.getSessionToken();
                } else if(command.equals("getAccountToken")) {
                    result = sdk.getAccountToken();
                }
                if(result != null) {
                    System.out.println(result.toString());
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Error initializing GrantedByMe SDK");
            }

    }
}
