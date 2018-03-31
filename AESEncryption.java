import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static java.nio.charset.StandardCharsets.*;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Main {

    public static void main(String[] args) throws Exception {

        File inputFile = new File("./assignment.zip");
        File encryptedFile = new File("./Crypto.txt");
        File decryptedFile = new File ("./decrypted-Crypto.zip");

        //Public Modulus
        BigInteger modulus = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9",
                16);

        //Chosen Exponent
        int exponent = 65537;


        //Password, Random Salt & IV
        String password = "|!TCmo?;i@(@e0$K";
        byte[] salt = new byte[]{-36, -93, 42, 53, 110, 6, 21, 97, -116, -117, -32, 13, 54, 20, 121, -121};
        byte[] initVector = new byte[]{-79, -99, -10, -50, 117, -65, 68, 20, -35, 16, 82, 4, 50, -5, -1, -125};


        try{
            System.out.println("Performing AES Encryption....");
            PerformAesEncryption(inputFile, encryptedFile, getAesKey(password, salt),Cipher.ENCRYPT_MODE, initVector);
            PerformAesEncryption(encryptedFile, decryptedFile,getAesKey(password, salt), Cipher.DECRYPT_MODE, initVector);
            System.out.println("Success.");
            System.out.println("Encrypted File Visible at: " + encryptedFile.getAbsolutePath());
            System.out.println("Performing RSA Password Encryption... ");
            String encrypted_password = RSAEnc(password, modulus, exponent);
            System.out.println("RSA Complete.");
            System.out.println("Encrypted Password: " + encrypted_password);
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    private static byte[] getAesKey(String password, byte[] salt) throws Exception{

        ////concat password & salt
        byte [] pw = password.getBytes();
        byte[] key = new byte[pw.length + salt.length];
        System.arraycopy(pw, 0, key, 0, pw.length);
        System.arraycopy(salt, 0, key, pw.length, salt.length);

        //sha hashing
        MessageDigest SHA256 = MessageDigest.getInstance("SHA-256");

        byte[] digest = key;

        // repeat hashing 200 times
        for(int i = 0; i < 200; i++){
            SHA256.update(digest);
            digest = SHA256.digest();
        }

        // key for AES
        StringBuffer hexDigest = new StringBuffer();
        for(int i = 0; i<digest.length; i++)
            hexDigest.append((Integer.toString((digest[i]&0xff) + 0x100, 16).substring(1)));
        return digest;
    }

    private static void PerformAesEncryption(File inputFile, File outputFile, byte[] keyByte, int mode, byte[] initVector) throws Exception{

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec key = new SecretKeySpec(keyByte, "AES");
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(mode, key, iv);

            FileInputStream inputStream = new FileInputStream(inputFile);

            //Padding
            int fLength = (int)inputFile.length();
            int padding = 16 - (fLength % 16);
            byte[] inputBytes = new byte[fLength + padding];
            inputStream.read(inputBytes);
            inputStream.close();
            pad(inputBytes, (int)inputFile.length(), padding);

            //Convert to hex and print to file
            byte[] outputBytes = cipher.doFinal(inputBytes);
            String outputFinal = DatatypeConverter.printHexBinary(outputBytes);
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
            System.out.println(outputFinal);
            outputStream.close();

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private static String RSAEnc(String pw, BigInteger N, int e){
        BigInteger privkey = new BigInteger(pw.getBytes(UTF_8));
        BigInteger x = BigInteger.valueOf(1);

        while(e > 0){
            if(e%2 == 1){
                x = (x.multiply(privkey)).mod(N);
            }
            privkey = (privkey.multiply(privkey)).mod(N);
            e /= 2;
        }
        x = x.mod(N);
        pw = x.toString(16);
        return pw;
    }

    private static void pad(byte[] b, int len, int padLen) {
        b[len] = (byte) 128;
        for (int i = 1; i < padLen; i++) {
            b[len + i] = (byte) 0;
        }
    }
}
