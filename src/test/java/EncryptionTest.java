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

/**
 * https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption/992413#992413
 */
class EncryptionTest {

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
}
