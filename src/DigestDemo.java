import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

//참고 https://stackoverflow.com/questions/64679961/how-to-use-bouncycastle-with-java
public class DigestDemo
{
    public static String byteArrayToHex(byte[] a)
    {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] computeDigest(String digestName, byte[] data) throws NoSuchProviderException,
            NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance(digestName, "BC");
        digest.update(data);
        return digest.digest();
    }

    public static void main(String[] args) throws Exception
    {
        //TODO: BouncyCastleProvider
        Security.addProvider(new BouncyCastleProvider());
        System.out.println(byteArrayToHex(computeDigest("SHA-256", "Hello World!".getBytes())));
    }
}