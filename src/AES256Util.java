//참고 https://velog.io/@osmdark/JAVA%EC%95%94%EB%B3%B5%ED%98%B8%ED%99%94

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

//양방향 암호화 알고리즘인 AES256 암호화를 지원하는 클래스
public class AES256Util {
    private String iv;
    private Key keySpec;

    /**
     * 16자리의 키값을 입력하여 객체를 생성
     *
     * @param key 암/복호화를 위한 키값
     * @throws UnsupportedEncodingException 키값의 길이가 16이하일 경우 발생
     */
    final static String key = "abcdabcdabcdabcd";

    public AES256Util() throws UnsupportedEncodingException {
        this.iv = key.substring(0, 16);
        byte[] keyBytes = new byte[16];
        byte[] b = key.getBytes("UTF-8");
        int len = b.length;
        if (len > keyBytes.length) {
            len = keyBytes.length;
        }
        System.arraycopy(b, 0, keyBytes, 0, len);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        this.keySpec = keySpec;
    }

    /**
     * AES256 으로 암호화
     *
     * @param str 암호화할 문자열
     * @return
     * @throws NoSuchAlgorithmException
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    public String encrypt(String str) throws NoSuchAlgorithmException,
            GeneralSecurityException, UnsupportedEncodingException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));
        byte[] encrypted = c.doFinal(str.getBytes("UTF-8"));
        String enStr = new String(Base64.encode(encrypted));
        return enStr;
    }

    /**
     * AES256으로 암호화된 txt를 복호화
     *
     * @param str 복호화할 문자열
     * @return
     * @throws NoSuchAlgorithmException
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */
    public String decrypt(String str) throws NoSuchAlgorithmException,
            GeneralSecurityException, UnsupportedEncodingException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));
        byte[] byteStr = Base64.decode(str.getBytes());
        return new String(c.doFinal(byteStr), "UTF-8");
    }
}

class Main{
    public static void main(String[] args) {
        try{
            AES256Util aes = new AES256Util();
            String en = aes.encrypt("010-1111-2222");
            String de = aes.decrypt(en);
            System.out.println(en);
            System.out.println(de);
        }catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}