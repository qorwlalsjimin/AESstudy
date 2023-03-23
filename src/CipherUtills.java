//참고 https://devday.tistory.com/entry/%EC%9E%90%EB%B0%94%EC%97%90%EC%84%9C-bouncycastle%EC%9D%84-%ED%99%9C%EC%9A%A9%ED%95%98%EC%97%AC-AES-%EC%95%94%EB%B3%B5%ED%98%B8%ED%99%94%ED%95%98%EA%B8%B0
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

class CipherUtils {

    private static final String CIPHER_PROVIDER = "BC";

    private Cipher encrypter;
    private Cipher decrypter;

    public CipherUtils(String keyAlgorithm, String cipherAlgorithm,
                       String keyString) {
        if (Security.getProvider(CIPHER_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        byte[] key = keyString.getBytes();

        SecretKeySpec sks = new SecretKeySpec(key, keyAlgorithm);

        try {
            encrypter = Cipher.getInstance(cipherAlgorithm, CIPHER_PROVIDER);
            encrypter.init(Cipher.ENCRYPT_MODE, sks);

            decrypter = Cipher.getInstance(cipherAlgorithm, CIPHER_PROVIDER);
            decrypter.init(Cipher.DECRYPT_MODE, sks);
        } catch (Exception e) {
            System.err.println("Caught an exception:" + e);
            throw new AssertionError(e);
        }
    }

    public String encrypt(String data) throws Exception {
        if (data == null) {
            return null;
        }

        byte[] encryptedData;
        try {
            encryptedData = encrypter.doFinal(data.getBytes());
        } catch (Exception e) {
            throw new Exception(e);
        }
        return new String(Base64.encode(encryptedData));
    }

    public String decrypt(String encryptedData) throws Exception {
        if (encryptedData == null) {
            return null;
        }

        byte[] decryptedData = Base64.decode(encryptedData);
        try {
            return new String(decrypter.doFinal(decryptedData));
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

}

class AesExample {

    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/ECB/ZeroBytePadding";
    private static final String KEY_STRING = "abcdefgh01234567";

    public static void main(String[] args) {
        System.out.println("Key: " + KEY_STRING);

        CipherUtils cu = new CipherUtils(KEY_ALGORITHM, CIPHER_ALGORITHM,
                KEY_STRING);

        String data = "This is just an example";
        System.out.println("Data: " + data);

        try {
            String encryptedHex = cu.encrypt(data);
            System.out.println("Encrypted Hex: " + encryptedHex);

            String decryptedData = cu.decrypt(encryptedHex);
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}