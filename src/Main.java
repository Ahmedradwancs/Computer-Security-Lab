import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        try {
            // Load the keystore from the file system
            KeyStore keyStore = KeyStore.getInstance("JKS");

            // Load the keystore in a try statement to close it after use automatically
            try (FileInputStream fis = new FileInputStream("Lab1Store")) {
                // Load the keystore using the password provided as parameter
                keyStore.load(fis, "lab1StorePass".toCharArray());
            }

            // Lab1:  Task 1 and Task 2

            // Read the encrypted file into a byte array and print it
            byte[] encryptedFile = Files.readAllBytes(Paths.get("Ciphertext.enc"));

            // Split the encrypted file into parts
            // Key1 is the first 128 bytes of the encrypted file
            byte[] encryptedKey1 = Arrays.copyOfRange(encryptedFile, 0, 128);
            // IV is the next 128 bytes of the encrypted file
            byte[] encryptedIV = Arrays.copyOfRange(encryptedFile, 128, 256);
            // Key2 is the next 128 bytes of the encrypted file
            byte[] encryptedKey2 = Arrays.copyOfRange(encryptedFile, 256, 384);
            // Data is the rest of the encrypted file
            byte[] encryptedData = Arrays.copyOfRange(encryptedFile, 384, encryptedFile.length);


            // Get the private key from the keystore using the password provided as parameter
            Key privateKey = keyStore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());



            // Task 1: Decrypt Key1, IV, and Key2 using RSA and print them
            byte[] key1 = decryptRSA(encryptedKey1, privateKey);
            byte[] iv = decryptRSA(encryptedIV, privateKey);
            byte[] key2 = decryptRSA(encryptedKey2, privateKey);

            // Task2: Decrypt data using key1 and IV and print it
            byte[] plaintext = decryptAES(encryptedData, key1, iv);
            System.out.println(new String(plaintext));
            System.out.println(" \n ****************************************************************** \n");




            // Lab 2:  Task 3 and Task 4


            // Read MAC strings and convert them to byte arrays
            String mac1String = new String(Files.readAllBytes(Paths.get("Ciphertext.mac1.txt")));
            String mac2String = new String(Files.readAllBytes(Paths.get("Ciphertext.mac2.txt")));

            // Convert MAC strings to byte arrays
            byte[] mac1 = hexStringToByteArray(mac1String);
            byte[] mac2 = hexStringToByteArray(mac2String);

            // Task 3: Verify MAC strings and print the result of the verification process
            if (verifyMac(plaintext, key2, mac2)) {
                System.out.println("MAC2 verification is successful. `\n");
            } else if(verifyMac(plaintext, key2, mac1)  ){
                System.out.println("MAC1 verification is successful. `\n");
            }else {
                System.out.println("MACS verification has failed.");
            }

            // Verify Digital Signatures and print the result of the verification process
            // using the public key from the certificate file provided as parameter
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new FileInputStream("Lab1Sign.cert"));
            // Get the public key from the certificate file provided as parameter
            PublicKey publicKey = cert.getPublicKey();

            // Task 4: Verify the signature and print the result of the verification process using the public key
            // from the certificate file provided as parameter and the data provided as parameter
            if (verifySignature("ciphertext.enc.sig1", publicKey, plaintext)) {
                System.out.println("Signature1 verification is successful.");
            } else if (verifySignature("ciphertext.enc.sig2", publicKey, plaintext)){
                System.out.println("Signature2 verification 2 successful.");
            }else{
                System.out.println("Signatures verification have failed.");
            }
        // Catch exceptions and print error messages
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Decrypts data using RSA and the private key
    private static byte[] decryptRSA(byte[] data, Key privateKey) throws Exception {
        // Create a Cipher object and initialize it with the private key
        // and the RSA algorithm in ECB mode with PKCS1Padding scheme
        Cipher cipher = Cipher.getInstance("RSA");
        // Decrypt the data and return the result
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // Decrypt the data and return the result
        return cipher.doFinal(data);
    }

    // Decrypts data using AES and the key and IV provided as parameters
    private static byte[] decryptAES(byte[] data, byte[] key, byte[] iv) throws Exception {
        // Create a Cipher object and initialize it with the key
        // and IV provided as parameters and the AES algorithm in CBC mode with PKCS5Padding scheme
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // Create a SecretKeySpec object and an IvParameterSpec object using the key and IV provided as parameters
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        // Initialize the Cipher object with the key and IV provided as parameters
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Decrypt the data and return the result
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        // Decrypt the data and return the result
        return cipher.doFinal(data);
    }

    // Verifies the MAC of the data using the key provided as parameter and the calculated MAC
    private static boolean verifyMac(byte[] data, byte[] key, byte[] macToVerify) throws Exception {
        // Create a Mac object and initialize it with the key provided as parameter and the HmacMD5 algorithm
        Mac mac = Mac.getInstance("HmacMD5");
        // Create a SecretKeySpec object using the key provided as parameter and the HmacMD5 algorithm
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacMD5");
        // Initialize the Mac object with the key provided as parameter
        mac.init(keySpec);
        // Compute the MAC of the data provided as parameter
        // (calculated MAC)
        byte[] macBytes = mac.doFinal(data);
        // Return the result of the verification process
        return Arrays.equals(macBytes, macToVerify);
    }

    // Verifies the signature of the data using the public key provided as parameter
    // and the signature provided as parameter
    private static boolean verifySignature(String signatureFile, PublicKey publicKey, byte[] data) throws Exception {
        // Read the signature from the file system and verify it using the public key and the data provided as parameter
        byte[] signatureBytes = Files.readAllBytes(Paths.get(signatureFile));
        // Create a Signature object and initialize it with
        // the public key provided as parameter and the SHA1withRSA algorithm
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        // Update the Signature object with the data provided as parameter
        signature.update(data);
        // Return the result of the verification process
        return signature.verify(signatureBytes);
    }

    // This Method is copied from StackOverFlow website
    // Converts a hex string to a byte array
    private static byte[] hexStringToByteArray(String s) {
        // The length of the string must be even to represent a byte array in hex format,
        // so we add a leading 0 if needed to make the length even
        int len = s.length();
        // Each byte is represented by two characters in hex representation so the length of the byte array is half
        byte[] data = new byte[len / 2];
        // Convert each pair of characters to a byte and add it to the byte array
        for (int i = 0; i < len; i += 2) {
            // Character.digit(c, 16) converts the character c to its hexadecimal value
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        // Return the byte array
        return data;
    }
}