//Github: https://github.com/qorwlalsjimin/AESstudy
//Github Issues: https://github.com/qorwlalsjimin/AESstudy/issues?q=is%3Aissue+is%3Aclosed
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AES256byBaek {
    byte[] iv;
    SecretKeySpec keySpec;

    /** 생성자 */
    public AES256byBaek() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //1. 256비트 비밀키 생성
        KeyGenerator kgen = KeyGenerator.getInstance("AES"); //Key 만드는 KeyGenerator 객체 생성
        kgen.init(256); //256비트(32바이트) 키 지정
        byte[] keyBytes = kgen.generateKey().getEncoded(); //byte[]로 키 저장

        //2. iv 자동 생성
        iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        //3. keySpec 생성
        keySpec = new SecretKeySpec(keyBytes, "AES"); //(key, 암호화 알고리즘)
    }

    /** 암호화 */
    public String encryption(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, //Cipher.getInstance()
            InvalidAlgorithmParameterException, InvalidKeyException, //cipher.init()
            UnsupportedEncodingException, //str.getBytes()
            IllegalBlockSizeException, BadPaddingException /*doFinal()*/ {

        //1. 암호화 수행하는 Cipher 객체 생성
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //(암호화 알고리즘/블럭암호 모드/패딩 체계)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv)); //(암호화 모드, 키스펙, iv)로 초기화

        //2. 암호화
        byte[] en_arr = cipher.doFinal(str.getBytes("UTF-8")); //암호화 수행

        return new String(Base64.encode(en_arr)); //AES 암호문(byte[])을 => Base64 인코딩(byte[])해주고 => 문자열로 변환
    }

    /** 복호화 */
    public String decryption(String en_str) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {

        //1. 복호화 수행하는 Cipher 객체 생성
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //(암호화 알고리즘/블럭암호 모드/패딩 체계)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv)); //(복호화 모드, 키스펙, iv)로 초기화

        //2. 복호화
        byte[] b = Base64.decode(en_str.getBytes()); //Base64 디코딩

        return new String(cipher.doFinal(b), "UTF-8"); //복호화 수행 => 문자열로 변환
    }
}

/** 실행 예제 */
class AES256byBaekExam{
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        AES256byBaek aes = new AES256byBaek();

        String en = aes.encryption("010-1111-2222"); //암호화할 데이터 입력
        String de = aes.decryption(en); //복호화할 암호문 입력

        System.out.println("암호문: "+en);
        System.out.println("원문: "+de);
    }
}