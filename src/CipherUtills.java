//참고 https://devday.tistory.com/entry/%EC%9E%90%EB%B0%94%EC%97%90%EC%84%9C-bouncycastle%EC%9D%84-%ED%99%9C%EC%9A%A9%ED%95%98%EC%97%AC-AES-%EC%95%94%EB%B3%B5%ED%98%B8%ED%99%94%ED%95%98%EA%B8%B0
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

class CipherUtils {

    private static final String CIPHER_PROVIDER = "BC"; //TODO: chipher, BC

    private Cipher encrypter; //TODO:javax.crypto.Cipher
    private Cipher decrypter;

    //생성자
    public CipherUtils(String keyAlgorithm, String cipherAlgorithm, String keyString) { //TODO: 매개변수 각각의 의미
        if (Security.getProvider(CIPHER_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        byte[] key = keyString.getBytes(); //key를 바이트로 변환

        //java.security 패키지의 클래스
        SecretKeySpec sks = new SecretKeySpec(key, keyAlgorithm); //TODO: SecretKeySpec

        try {
            encrypter = Cipher.getInstance(cipherAlgorithm, CIPHER_PROVIDER);
            encrypter.init(Cipher.ENCRYPT_MODE, sks); //암호화 모드

            decrypter = Cipher.getInstance(cipherAlgorithm, CIPHER_PROVIDER);
            decrypter.init(Cipher.DECRYPT_MODE, sks); //복호화 모드
        } catch (Exception e) {
            System.err.println("Caught an exception:" + e);
            throw new AssertionError(e); //TODO: AssertionError
        }
    }

    //암호화 메서드
    public String encrypt(String data) throws Exception { //매개변수: 평문 데이터
        if (data == null) { //data NULL 체크
            return null;
        }

        byte[] encryptedData; //byte배열 안에 암호화한 데이터 대입
        try {
            encryptedData = encrypter.doFinal(data.getBytes()); //TODO:
        } catch (Exception e) {
            throw new Exception(e);
        }
        return new String(Base64.encode(encryptedData)); //우리가 읽을 수 있는 문자로 변환(의미는 모름)
    }

    //복호화 메서드
    public String decrypt(String encryptedData) throws Exception { //매개변수: 암호화된 데이터
        if (encryptedData == null) { //data NULL 체크
            return null;
        }

        byte[] decryptedData = Base64.decode(encryptedData); //TODO: Bouncycastle의 Base64
        try {
            return new String(decrypter.doFinal(decryptedData));
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

}

class AesExample {

    private static final String KEY_ALGORITHM = "AES"; //알고리즘 설정
    private static final String CIPHER_ALGORITHM = "AES/ECB/ZeroBytePadding"; //TODO
    private static final String KEY_STRING = "abcdefgh01234567"; //암호화할 키

    public static void main(String[] args) {
        System.out.println("Key: " + KEY_STRING);

        CipherUtils cu = new CipherUtils(KEY_ALGORITHM, CIPHER_ALGORITHM, KEY_STRING);

        String data = "This is just an example";
        System.out.println("Data: " + data);

        try {
            String encryptedHex = cu.encrypt(data); //CipherUtils 클래스의 enrypt() 메서드로 암호화
            System.out.println("Encrypted Hex: " + encryptedHex);

            String decryptedData = cu.decrypt(encryptedHex); //CipherUtils 클래스의 decrypt() 메서드로 복호화
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}