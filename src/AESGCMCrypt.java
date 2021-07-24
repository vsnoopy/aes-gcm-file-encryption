import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * This class can be used to encrypt/decrypt a byte array using the AES-128 GCM algorithm.
 * AES-256 can be used here, but many systems do not have the required java packages.
 * A 12 byte IV is recommended for GCM but you may also use 16 bytes. crypt
 *
 * @since 7/18/2021
 * @author snoopy
 * @version 1.0
 */
public class AESGCMCrypt {

    private final String ALGORITHM = "AES/GCM/NoPadding"; // AES-GCM
    private int keyLength; // 128, 192, 256, 512
    private int ivLength; // initialization vector (recommend 12)
    private SecureRandom secureRandom;


    public AESGCMCrypt(int keyLength, int ivLength) {
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        secureRandom = new SecureRandom();
    }
    /**
     *
     * @param password to derive key from
     * @param iv to derive key from
     * @return 128 bit PBE key
     */
    public byte[] generateSecretKey(String password, byte[] iv) throws CryptException {
        final int ITERATION_COUNT = 131072;
        KeySpec spec = new PBEKeySpec(password.toCharArray(), iv, ITERATION_COUNT, keyLength);
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptException("Error: ", e);
        }
    }

    /**
     * Securely generates an iv
     *
     * @return random iv
     */
    public byte[] createIV() {
        byte[] iv = new byte[ivLength];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Function to encrypt a byte array using AES-128 GCM
     *
     * @param data to be encrypted
     * @param key 128 bit PBE key
     * @param iv used with key
     * @return encrypted byte array
     */
    public byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws CryptException {
        try {
            // Prepare cipher
            Cipher encCipher = Cipher.getInstance(ALGORITHM);
            encCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM), new GCMParameterSpec(keyLength, iv));

            byte[] encData = encCipher.doFinal(data);

            // ByteBuffer to collect IV size, IV, and encrypted data into a byte array.
            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encData.length);

            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encData);

            return byteBuffer.array();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptException("Error: ", e);
        }
    }

    /**
     * Function to decrypt an encrypted byte array
     *
     * @param encDataAndIV encrypted data
     * @param key PBE key that was used to encrypt
     * @return decrypted byte array
     */
    public byte[] decrypt(byte[] encDataAndIV, byte[] key) throws CryptException {
        // Get stored IV
        byte[] iv = getIV(encDataAndIV);

        try {
            Cipher decCipher = Cipher.getInstance(ALGORITHM);
            decCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM),
                    new GCMParameterSpec(keyLength, iv));

            return decCipher.doFinal(encDataAndIV, 1 + ivLength, encDataAndIV.length - (1 + ivLength));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptException("Error: ", e);
        }
    }

    /**
     * Function to extract iv from the encrypted file
     *
     * @param encDataAndIV encrypted file
     * @return iv
     */
    public byte[] getIV(byte[] encDataAndIV) {
        int ivSize = encDataAndIV[0];
        // Check that IV is proper size
        if (ivSize != ivLength) {
            throw new IllegalStateException("Invalid IV length. Are you sure the file is AES-GCM encrypted?");
        }
        return Arrays.copyOfRange(encDataAndIV, 1, (ivSize + 1));
    }
}
