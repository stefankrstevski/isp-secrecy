package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using AES in CBC mode to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // Both agents can access this shared key from the enclosing method
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Repeat for ten request-reply rounds.
                 *
                 * Use a fresh, unpredictable IV for every encryption, including Bob's replies.
                 * Send the IV along with the ciphertext; it need not be secret.
                 * A cipher-generated IV can be accessed via cipher.getIV().
                 */
                for (int i = 1; i <= 10; i++) {
                    encrypt(this, "bob", key, message + " " + i);
                    print("Got '%s'", decrypt(this, "bob", key));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Wrap the received IV bytes in IvParameterSpec for the init() call:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, key, ivSpec);
                 *
                 * Encrypt and send a reply using a fresh IV in each round.
                 */
                for (int i = 1; i <= 10; i++) {
                    print("Got '%s'", decrypt(this, "alice", key));
                    encrypt(this, "alice", key, "I love you too Alice. Kisses, Bob. " + i);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static void encrypt(Agent agent, String receiver, Key key, String message) throws Exception {
        final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
        final byte[] iv = encrypt.getIV();

        agent.send(receiver, iv);
        agent.send(receiver, cipherText);
    }

    public static String decrypt(Agent agent, String sender, Key key) throws Exception {
        final byte[] iv = agent.receive(sender);
        final byte[] cipherText = agent.receive(sender);

        final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        final byte[] dt = decrypt.doFinal(cipherText);

        return new String(dt, StandardCharsets.UTF_8);
    }
}
