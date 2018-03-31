import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ElGamal {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NumberFormatException {
        String prime = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b1835106470" +
                "4fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f4" +
                "7a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";

        String generator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2" +
                "e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864" +
                "1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
                "64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";

        File inputFile = new File("./ElGamal.zip");
        CalcSig c = new CalcSig();
        c.generateXY(prime, generator);
        c.generateRS(inputFile);
    }
}

class CalcSig {
    private BigInteger p, g, x, y;
    private BigInteger k;
    private BigInteger r;
    private BigInteger[] xgcdArray = new BigInteger[3];

    //File to output submission values
    private File outputFile = new File("./elgamalEncrypted.txt");

    void generateXY(String prime, String generator){
         p = new BigInteger(prime,16);
         g = new BigInteger(generator, 16);

        int keyLen = p.bitLength() - 1; //key length < p
        SecureRandom sec_r = new SecureRandom();
        //Private key x
         x = new BigInteger(keyLen, sec_r);
        //Public key y = g^x (mod p)
         y = g.modPow(x, p);

        System.out.println(" Public Key y = "+y.toString(16)+"\n");
    }

    void generateRS(File inputFile) throws IOException, NoSuchAlgorithmException {
        System.out.println("Generating Signature for "+inputFile.getName());

        BigInteger mHash = null;
        BigInteger s = BigInteger.ZERO;

        int keyLen = p.bitLength() - 1;
        byte[] message = new byte[(int)inputFile.length()];

        FileInputStream inputStream = new FileInputStream(inputFile);

        //Dealing with return value of inputStream.read to avoid warnings
        final int readLength = inputStream.read(message);
        if(readLength < (int)(inputFile.length())){
            System.out.println("(Warning) Buffer is larger than message");
        }
        inputStream.close();

        MessageDigest SHA256 = MessageDigest.getInstance("SHA-256");
        byte[] hashed = SHA256.digest(message);

        //If s is still 0 at the end, start again
        while(s.equals(BigInteger.ZERO)){
            s = BigInteger.ZERO;
            // Generate K relatively prime to p-1
            // GCD of k and p-1 (relPrimeFlag) should be 1
            BigInteger relPrimeFlag = BigInteger.ZERO;

            while(!relPrimeFlag.equals(BigInteger.ONE)){
                SecureRandom sec_r = new SecureRandom();
                k = new BigInteger(keyLen, sec_r);
                relPrimeFlag = k.gcd(p.subtract(BigInteger.ONE));
            }
            r = g.modPow(k, p);

            mHash = new BigInteger(hashed);
            BigInteger xr = x.multiply(r);
            s = mHash.subtract(xr);

            try{
                s = s.multiply(mulInverse(k, p.subtract(BigInteger.ONE)));
                s = s.mod(p.subtract(BigInteger.ONE));
            }
            catch(Exception e){
                e.printStackTrace();
            }
        }
        FileWriter outputStream = new FileWriter(outputFile);
        outputStream.write(" k = " + k.toString(16) + "\n");
        outputStream.write(" r = " + r.toString(16) + "\n");
        outputStream.write(" s = " + s.toString(16) + "\n");
        outputStream.close();
        System.out.println("Values Saved to: " + outputFile.getName());

        testing(g, y, mHash, r, s, p);
    }

    private BigInteger[] euclidean (BigInteger a, BigInteger b){

        if(b.equals(BigInteger.ZERO)){
            xgcdArray[2] = BigInteger.ZERO;
            xgcdArray[1] = BigInteger.ONE;
            xgcdArray[0] = a;
            return xgcdArray;
        }
        //recursive Euclidean algorithm
        xgcdArray = euclidean(b, a.mod(b));
        //y1 and x1
        BigInteger tmpy = xgcdArray[1];
        BigInteger tmpx = xgcdArray[2];
        //x = y1-(b/a) * x1
        xgcdArray[2] = tmpy.subtract(tmpx.multiply(a.divide(b)));
        //y = x1
        xgcdArray[1] = tmpx;
        return xgcdArray;
    }

    private BigInteger mulInverse(BigInteger a, BigInteger b){
        BigInteger[] tmp = euclidean(a, b);
        //multiplicative inverse not possible
        if(!tmp[0].equals(BigInteger.ONE))
            throw new ArithmeticException("Mul Inverse is not possible");
        //is > 0
        if(tmp[1].compareTo(BigInteger.ZERO)==1)
            return tmp[1];
        else
            return tmp[1].add(b);
    }

    private void testing(BigInteger g, BigInteger y, BigInteger mHash, BigInteger r, BigInteger s, BigInteger p){
        System.out.println("Emulating Examiner's Checks.....");
        if(r.compareTo(BigInteger.ZERO) > 0 && r.compareTo(p) < 0){
            System.out.println("0 < r < p...... Correct!");
        }
        else{
            System.out.println("0 < r < p...... Error!");
        }
        if(s.compareTo(BigInteger.ZERO) > 0 && s.compareTo(p.subtract(BigInteger.valueOf(1))) < 0){
            System.out.println("0 < s < p-1...... Correct!");
        }
        else{
            System.out.println("0 < s < p-1...... Error!");
        }

        //Evaluation from Read.pudn.com

        BigInteger tmp1 = y.modPow(r, p).multiply(r.modPow(s, p)).mod(p);
        BigInteger tmp2 = g.modPow(mHash, p);
        if(tmp1.compareTo(tmp2) ==0){
            System.out.println("g^H(m) (mod p) = (y^r)(r^s)(mod p)...... Correct!");
        }
        else{
            System.out.println("g^H(m) (mod p) = (y^r)(r^s)(mod p)...... Error!");
        }
    }
}
