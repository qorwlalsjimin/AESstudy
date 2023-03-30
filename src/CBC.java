import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

//참고 http://www.fun25.co.kr/blog/java-aes128-cbc-encrypt-decrypt-example
public class CBC {
    String iv = "0987654321654321"; //IV 초기화
    public Key getAESKey() throws Exception {
        Key keySpec;

        String key = "1234567890123456"; //키값
//        iv = key.substring(0, 16); //왜 필요한지 모르겠음
        byte[] keyBytes = new byte[16];
        byte[] b = key.getBytes("UTF-8");

        int len = b.length;
        if (len > keyBytes.length) {
            len = keyBytes.length;
        }

        System.arraycopy(b, 0, keyBytes, 0, len); //키값 Bytes로 변환해서 배열에 저장
        keySpec = new SecretKeySpec(keyBytes, "AES"); //키값으로 AES키값 만들기

        return keySpec; //AES 키값
    }

    // 암호화
    public String encAES(String str) throws Exception {
        Key keySpec = getAESKey(); //AES키값
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); //암호화 수행해주는 Chiper 객체 생성
        c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes("UTF-8"))); //암호화 모드 설정, AES키, IV로 초기화
        byte[] encrypted = c.doFinal(str.getBytes("UTF-8")); //AES 암호화
        String enStr = new String(Base64.encode(encrypted)); //암호문 Base64 인코딩해서 문자열로 변환
        return enStr;
    }

    // 복호화
    public String decAES(String enStr) throws Exception {
        Key keySpec = getAESKey(); //AES키값
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); //복호화 수행해주는 Cipher 객체 생성
        c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes("UTF-8"))); //복호화 모드, AES키, IV로 초기화
        byte[] byteStr = Base64.decode(enStr.getBytes("UTF-8")); //암호문 Base64 디코딩
        String decStr = new String(c.doFinal(byteStr), "UTF-8"); //복호화해서 문자열로 변환

        return decStr;
    }
}

class Main2{
    public static void main(String[] args) throws Exception {
        CBC aes = new CBC();
        String en = aes.encAES("010-1111-2222");
        String de = aes.decAES(en);
        System.out.println(en);
        System.out.println(de);
    }
}
