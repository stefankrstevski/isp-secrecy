package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * A DES key is represented by 8 bytes, but only 56 bits affect encryption; the remaining
 * bits are parity bits. Varying the last three bytes produces 2^24 byte representations
 * but only 2^21 effective keys. Any equivalent key that correctly decrypts the ciphertext
 * is acceptable; it need not match the original key byte for byte.
 * <p>
 * In main(), generate a demonstration key with the stated restriction, encrypt the supplied
 * message with DES/ECB/PKCS5Padding, and call bruteForceKey(). Verify that the returned key
 * decrypts the ciphertext to the complete original message. Use UTF-8 for text conversion.
 * The search must use only its arguments and the stated key restriction, not the original key.
 * DES and ECB are used only for this teaching exercise, not as recommended encryption.
 * <p>
 * To manually specify a key, use {@link javax.crypto.spec.SecretKeySpec}.
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // TODO
        final byte[] keyBytes = new byte[8];
        new SecureRandom().nextBytes(keyBytes);
        for (int i = 0; i < 5; i++) {
            keyBytes[i] = 0;
        }

        System.out.println("[KEY] " + Agent.hex(keyBytes));

        final Key key = new SecretKeySpec(keyBytes, "DES");

        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
        System.out.println("[CT] " + Agent.hex(cipherText));

        final byte[] recoveredKey = bruteForceKey(cipherText, message);
        if (recoveredKey == null) {
            System.out.println("Key not found.");
            return;
        }
        System.out.println("[RECOVERED KEY] " + Agent.hex(recoveredKey));

        final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(recoveredKey, "DES"));
        final byte[] dt = decrypt.doFinal(cipherText);
        final String decryptedMessage = new String(dt, StandardCharsets.UTF_8);
        System.out.println("[MESSAGE] " + decryptedMessage);
        System.out.println("[MATCH] " + message.equals(decryptedMessage));
    }

    /**
     * Recover an 8-byte representation of a key that decrypts ct to the known message.
     * Return null if no matching key exists within the restricted search space.
     */
    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        // TODO
        final byte[] keyBytes = new byte[8];
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");

        for (int i = 0; i < 256; i++) {
            keyBytes[5] = (byte) i;
            for (int j = 0; j < 256; j++) {
                keyBytes[6] = (byte) j;
                for (int k = 0; k < 256; k++) {
                    keyBytes[7] = (byte) k;
                    decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));
                    try {
                        final byte[] dt = decrypt.doFinal(ct);
                        if (Arrays.equals(dt, pt)) {
                            return keyBytes;
                        }
                    } catch (Exception e) {
                    }
                }
            }
        }

        return null;
    }
}
