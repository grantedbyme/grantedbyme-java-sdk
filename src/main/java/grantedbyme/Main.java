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

/**
 * Main CLI class
 *
 * @author GrantedByMe <info@grantedby.me>
 */
public class Main {
    public static void main(String[] args) {
        String serviceKey = null;
        String privateKey = null;
        String serverKey = null;
        if (args.length >= 3) {
            serviceKey = args[0];
            privateKey = args[1];
            serverKey = args[2];
        }
        for (String s : args) {
            System.out.println(s);
        }
        GrantedByMe api = new GrantedByMe(privateKey, serverKey);
        Object result = api.getSessionToken();
    }
}
