import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class AES256byBaek {
    String iv;
    Key keySpec;

    /** 16자리의 키값을 입력하여 객체를 생성
     * 1. IV(초기화 벡터)에 키값을 16자리로 넣어준다
     * 2. 16자리를 넘긴 키값의 경우에 대응하여 keyBytes(진짜 쓰일 용도), b(16자리 확인 위한 연산 용도) 배열 두개를 만든다
     * 3. 2와 같은 목적으로 배열의 길이(키값에 따라 16보다 클 수 있음)가 있는 len 변수 생성
     * 4. 키값이 16자리라면 b 배열에 있던 내용을 keyBytes 배열에 복사한다
     * 5. 비밀 키를 지정해주는 SecretKeySpec 객체를 생성한다
     * 6. keySpec 변수(Key 객체)에 5에서 SecretKeySpec 객체를 넣어준다
     * */
    public AES256byBaek() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //1. 256비트 비밀키 생성
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(256); //256비트(32바이트)

        String key = new String(Hex.encode(kgen.generateKey().getEncoded()));

        iv = key.substring(0, 16); //16바이트
        byte[] keyBytes = new byte[32];
        byte[] b = key.getBytes("UTF-8");
        int len = b.length;

        if(len > keyBytes.length) len = keyBytes.length;

        System.arraycopy(b, 0, keyBytes, 0, len);

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        this.keySpec = keySpec;
    }

    public String encryption(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));
        byte[] en_arr = cipher.doFinal(str.getBytes("UTF-8"));
        return new String(Base64.encode(en_arr));
    }

    public String decryption(String en_str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes()));
        byte[] b = Base64.decode(en_str.getBytes());
        return new String(cipher.doFinal(b), "UTF-8");
    }
}

class AES256byBaekExam{
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        AES256byBaek aes = new AES256byBaek();
        String en = aes.encryption("010-1111-2222");
        String de = aes.decryption(en);
        System.out.println(en);
        System.out.println(de);
    }
}