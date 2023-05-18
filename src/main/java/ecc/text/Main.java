package ecc.text;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class Main {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate ECC Key Pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(ECNamedCurveTable.getParameterSpec("prime192v1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // Get Public and Private Keys
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        // Convert Public Key to Hex String (for demonstration purposes)
        String publicKeyHex = Hex.toHexString(publicKey.getQ().getEncoded(false));
        System.out.println("Public Key: " + publicKeyHex);

        // Encrypt Text using Public Key
        String plainText = "Hello, World!";
        byte[] encryptedData = encrypt(plainText, publicKey);
        System.out.println("Encrypted Data: " + Hex.toHexString(encryptedData));

        // Decrypt Data using Private Key
        String decryptedText = decrypt(encryptedData, privateKey);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static byte[] encrypt(String plainText, ECPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String decrypt(byte[] encryptedData, ECPrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }
}
