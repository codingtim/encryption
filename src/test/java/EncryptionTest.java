import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;


class EncryptionTest {

    /**
     * https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption/992413#992413
     * <br/>
     * <br/>
     * Share the password (a char[]) and salt (a byte[]—8 bytes selected by a SecureRandom makes a good
     * salt—which doesn't need to be kept secret) with the recipient out-of-band.
     * Then to derive a good key from this information:
     *
     * <pre>
     * SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
     * KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
     * SecretKey tmp = factory.generateSecret(spec);
     * SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
     * </pre>
     * The magic numbers (which could be defined as constants somewhere) 65536 and 256 are the key
     * derivation iteration count and the key size, respectively.
     * <br/>
     * The key derivation function is iterated to require significant computational effort,
     * and that prevents attackers from quickly trying many different passwords.
     * The iteration count can be changed depending on the computing resources available.
     * <br/>
     * Used with a proper block-chaining mode, the same derived key can be used to encrypt many messages.
     * In Cipher Block Chaining (CBC), a random initialization vector (IV) is generated for each message,
     * yielding different cipher text even if the plain text is identical. CBC may not be the most secure
     * mode available to you (see AEAD below); there are many other modes with different security properties,
     * but they all use a similar random input. In any case, the outputs of each encryption operation are the
     * cipher text and the initialization vector:
     *
     * <pre>
     * Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
     * cipher.init(Cipher.ENCRYPT_MODE,secret);
     * AlgorithmParameters params = cipher.getParameters();
     * byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
     * byte[] ciphertext = cipher.doFinal("Hello, World!".getBytes(StandardCharsets.UTF_8));
     * </pre>
     *
     * Store the ciphertext and the iv. On decryption, the SecretKey is regenerated in exactly the same way,
     * using the password with the same salt and iteration parameters.
     * Initialize the cipher with this key and the initialization vector stored with the message:
     *
     */
    @Test
    void aes256_cbc() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        char[] password = "mySecurePassword123".toCharArray();
        byte[] salt = createSalt();
        System.out.println(Base64.getEncoder().encodeToString(salt));

        SecretKey encryptSecretKey = deriveKey(password, salt);
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptSecretKey);
        AlgorithmParameters params = encryptCipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = encryptCipher.doFinal("Hello, World!".getBytes(StandardCharsets.UTF_8));

        String ivString = Base64.getEncoder().encodeToString(iv);
        String cipherTextString = Base64.getEncoder().encodeToString(ciphertext);
        System.out.println(ivString);
        System.out.println(cipherTextString);

        SecretKey decryptSecretKey = deriveKey(password, salt);
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, decryptSecretKey, new IvParameterSpec(Base64.getDecoder().decode(ivString)));
        String plaintext = new String(decryptCipher.doFinal(Base64.getDecoder().decode(cipherTextString)), StandardCharsets.UTF_8);
        System.out.println(plaintext);
        assertEquals("Hello, World!", plaintext);
    }

    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    /**
     * https://www.javainterviewpoint.com/java-aes-256-gcm-encryption-and-decryption/
     */
    @Test
    void aes256_gcm() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        char[] password = "mySecurePassword123".toCharArray();
        byte[] salt = createSalt();
        System.out.println(Base64.getEncoder().encodeToString(salt));

        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        SecretKey encryptSecretKey = deriveKey(password, salt);
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptSecretKey, gcmParameterSpec);
        byte[] ciphertext = encryptCipher.doFinal("Hello, World!".getBytes(StandardCharsets.UTF_8));

        String ivString = Base64.getEncoder().encodeToString(iv);
        String cipherTextString = Base64.getEncoder().encodeToString(ciphertext);
        System.out.println(ivString);
        System.out.println(cipherTextString);

        SecretKey decryptSecretKey = deriveKey(password, salt);
        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, decryptSecretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, Base64.getDecoder().decode(ivString)));
        String plaintext = new String(decryptCipher.doFinal(Base64.getDecoder().decode(cipherTextString)), StandardCharsets.UTF_8);
        System.out.println(plaintext);
        assertEquals("Hello, World!", plaintext);
    }

    private SecretKey deriveKey(char[] password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private byte[] createSalt() {
        return new SecureRandom().generateSeed(8);
    }

    /**
     * https://stackoverflow.com/questions/36531479/java-chacha20-w-poly1305-as-mac-for-general-purpose-file-encryption
     */
    @Test
    void chacha20() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        char[] password = "mySecurePassword123".toCharArray();
        byte[] salt = createSalt();
        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        SecretKeySpec encryptSecretKey = new SecretKeySpec(deriveKey(password, salt).getEncoded(), "ChaCha20");
        Cipher encryptCipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
        IvParameterSpec parameterSpec = new IvParameterSpec(nonce);
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptSecretKey, parameterSpec);
        byte[] ciphertext = encryptCipher.doFinal("Hello, World!".getBytes(StandardCharsets.UTF_8));

        String saltString = Base64.getEncoder().encodeToString(salt);
        String nonceString = Base64.getEncoder().encodeToString(nonce);
        String cipherTextString = Base64.getEncoder().encodeToString(ciphertext);
        System.out.println(saltString);
        System.out.println(nonceString);
        System.out.println(cipherTextString);

        SecretKeySpec decryptSecretKey = new SecretKeySpec(deriveKey(password, salt).getEncoded(), "ChaCha20");
        Cipher decryptCipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, decryptSecretKey, new IvParameterSpec(nonce));
        String plaintext = new String(decryptCipher.doFinal(Base64.getDecoder().decode(cipherTextString)), StandardCharsets.UTF_8);
        System.out.println(plaintext);
        assertEquals("Hello, World!", plaintext);
    }

    private SecretKey generateChacheKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
