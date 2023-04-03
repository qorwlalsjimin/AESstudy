import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class AES256byBaek {
    byte[] iv;
    Key keySpec;

    /** 생성자 */
    public AES256byBaek() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //1. 256비트 비밀키 생성
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(256); //256비트(32바이트)
        byte[] keyBytes = kgen.generateKey().getEncoded();

        //2. iv 자동 생성
        iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        //3. keySpec 생성
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        this.keySpec = keySpec;
    }

    /** 암호화 */
    public String encryption(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] en_arr = cipher.doFinal(str.getBytes("UTF-8"));
        return new String(Base64.encode(en_arr));
    }

    /** 복호화 */
    public String decryption(String en_str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] b = Base64.decode(en_str.getBytes());
        return new String(cipher.doFinal(b), "UTF-8");
    }
}

/** 실행 예제 */
class AES256byBaekExam{
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        AES256byBaek aes = new AES256byBaek();
        String en = aes.encryption("010-1111-2222");
        String de = aes.decryption(en);
        System.out.println(en);
        System.out.println(de);
    }
}