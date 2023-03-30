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
    private final String iv; //초기화 벡터
    private Key keySpec; //TODO: 어디에 쓰이는지 모르겠다 the specification of key?
    /*
    * Key 클래스
    *   The Key interface is the top-level interface for all keys.
    *   It defines the functionality shared by all key objects.
    * */

    /** 16자리의 키값을 입력하여 객체를 생성
     * 1. IV(초기화 벡터)에 키값을 16자리로 넣어준다
     * 2. 16자리를 넘긴 키값의 경우에 대응하여 keyBytes(진짜 쓰일 용도), b(16자리 확인 위한 연산 용도) 배열 두개를 만든다
     * 3. 2와 같은 목적으로 배열의 길이(키값에 따라 16보다 클 수 있음)가 있는 len 변수 생성
     * 4. 키값이 16자리라면 b 배열에 있던 내용을 keyBytes 배열에 복사한다
     * 5. 비밀 키를 지정해주는 SecretKeySpec 객체를 생성한다
     * 6. keySpec 변수(Key 객체)에 5에서 SecretKeySpec 객체를 넣어준다
     * */
    final static String key = "abcdabcdabcdabcd"; //암호화 & 복호화 키

    public AES256Util() throws UnsupportedEncodingException {
        this.iv = "aaaabbbbccccdddd"; //키값 16자리로 유지 (16자리보다 많을 경우를 위함)
//        this.iv = key.substring(0, 16); //키값 16자리로 유지 (16자리보다 많을 경우를 위함)
        byte[] keyBytes = new byte[16];
        byte[] b = key.getBytes("UTF-8"); //키값 문자마다 아스키코드로 바꾸기
        int len = b.length; //키값의 길이

        if (len > keyBytes.length) len = keyBytes.length; //키값 16으로 유지하기 위함
        System.arraycopy( b, 0, keyBytes, 0,   len ); //keyBytes에 b 내용 복사

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES"); //비밀키 지정 (키값, 암호화 알고리즘 이름)

//        System.out.println("keySpec: "+keySpec); //keySpec: javax.crypto.spec.SecretKeySpec@1568f
        //TODO: key와 keySpec의 차이점 - https://stackoverflow.com/questions/35729629/whats-the-difference-between-a-key-and-a-keyspec
        /*
        * SecretKeySpec 클래스
        *   이 클래스는 공급자 독립적 방식으로 비밀 키를 지정합니다.
        *   SecretKeyFactory를 거치지 않고 바이트 배열에서 SecretKey를 구성하는 데 사용할 수 있습니다.
        *   이 클래스는 바이트 배열로 표시될 수 있고 이와 관련된 키 매개변수(예: DES 또는 Triple DES 키)가 없는 원시 비밀 키에만 유용합니다.
        */

        this.keySpec = keySpec;
    }

    /** AES256 으로 암호화
     * 1. 암&복호화를 수행해주는 Cipher 객체 생성
     * 2. init() 메서드로 Cipher 객체 초기화 - 암호화모드, 키값, IV
     * 3. doFinal() 메서드로 AES 암호화 수행 => 결과: byte형
     * 4. Base64 인코딩하여 암호문을 문자열로 변환 => 결과: String형
     * */
    public String encrypt(String str) throws NoSuchAlgorithmException,
            GeneralSecurityException, UnsupportedEncodingException {

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); // 암호화 알고리즘 이름/블록암호 모드/패딩 체계
        c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes())); // opmode, key, iv
        byte[] encrypted = c.doFinal(str.getBytes("UTF-8")); //암호화 완료 (byte형)
        String enStr = new String(Base64.encode(encrypted)); //AES로 암호화한 암호문을 Base64 인코딩 수행 (문자형)

        return enStr;
    }

    /** AES256으로 암호화된 txt를 복호화
     * 1. 암&복호화를 수행해주는 Cipher 객체 생성
     * 2. init 메서드로 Cipher 객체 초기화 - 암호화모드, 키값, IV
     * 3. Base64 디코딩 => 결과: byte형
     * 4. doFinal() 메서드로 AES 복호화 & String 생성 => 결과: String형
     * */
    public String decrypt(String str) throws NoSuchAlgorithmException,
            GeneralSecurityException, UnsupportedEncodingException {

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"); //객체 생성
        c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes())); //초기화
        byte[] byteStr = Base64.decode(str.getBytes()); //암호문 => Base64 인코딩된 Byte 암호문 => Base64 디코딩 => AES로 복호화하면 풀릴 Byte 암호문
        return new String(c.doFinal(byteStr), "UTF-8"); //AES로 복호화
    }
}

/** 실행 */
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