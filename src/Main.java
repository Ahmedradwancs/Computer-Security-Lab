import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {
        try {
            // Task 1: Get Key1, IV, and Key2
            FileInputStream encryptedFileInputStream = new FileInputStream("ciphertext.enc");
            byte[] encryptedFileBytes = new byte[encryptedFileInputStream.available()];
            encryptedFileInputStream.read(encryptedFileBytes);

            // Load keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream keystoreInputStream = new FileInputStream("lab1Store");
            keystore.load(keystoreInputStream, "lab1StorePass".toCharArray());

            // Get private key
            PrivateKey privateKey = (PrivateKey) keystore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());

            // Decrypt Key1 and Key2
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] key1Bytes = rsaCipher.doFinal(encryptedFileBytes, 0, 128);
            byte[] ivBytes = rsaCipher.doFinal(encryptedFileBytes, 128, 128);
            byte[] key2Bytes = rsaCipher.doFinal(encryptedFileBytes, 256, 128);

            // Decrypt the data using Key1 and IV
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key1Bytes, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);


            byte[] decryptedData = aesCipher.doFinal(encryptedFileBytes, 384, encryptedFileBytes.length - 384);

            // Verify Integrity using HmacMD5
            Mac hmacMD5 = Mac.getInstance("HmacMD5");
            SecretKeySpec key2Spec = new SecretKeySpec(key2Bytes, "HmacMD5");
            hmacMD5.init(key2Spec);

            byte[] calculatedHmac = hmacMD5.doFinal(decryptedData);
            // Compare calculatedHmac with the provided HmacMD5 from the file
            // read HmacMD5 from the file
            byte[] providedHmac = Files.readAllBytes(Paths.get("ciphertext.mac1.txt")); // Assuming you have the HmacMD5 stored in this file



            if (MessageDigest.isEqual(calculatedHmac, providedHmac)) {
                System.out.println("HmacMD5 is valid.");
            } else {
                System.out.println("HmacMD5 is NOT valid.");
            }

            // Verify Digital Signature
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            FileInputStream certFileInputStream = new FileInputStream("lab1Sign.cert");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certFileInputStream);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(cert.getPublicKey());
            signature.update(decryptedData);

            // Compare the result with the provided digital signatures
            byte[] signatureBytes1 = Files.readAllBytes(Paths.get("ciphertext.enc.sig1")); // Assuming you have the signature in this file
            byte[] signatureBytes2 = Files.readAllBytes(Paths.get("ciphertext.enc.sig2"));

            boolean isSignatureValid1 = signature.verify(signatureBytes1);
            boolean isSignatureValid2 = signature.verify(signatureBytes2);

            if (isSignatureValid1 && isSignatureValid2) {
                System.out.println("Digital Signatures are valid.");
            } else {
                System.out.println("Digital Signatures are NOT valid.");
            }

            // Check Message Authentication Codes (MACs)
            SecretKeySpec key1Spec = new SecretKeySpec(key1Bytes, "HmacMD5");

            Mac mac1 = Mac.getInstance("HmacMD5");
            mac1.init(key1Spec);
            byte[] calculatedMAC1 = mac1.doFinal(decryptedData);

            // Read ciphertext.mac1.txt and convert it to a byte array
            byte[] providedMAC1 = Files.readAllBytes(Paths.get("ciphertext.mac1.txt"));

            if (MessageDigest.isEqual(calculatedMAC1, providedMAC1)) {
                System.out.println("MAC1 is valid.");
            } else {
                System.out.println("MAC1 is NOT valid.");
            }

            // Repeat the process for MAC2
            Mac mac2 = Mac.getInstance("HmacMD5");
            mac2.init(key1Spec);
            byte[] calculatedMAC2 = mac2.doFinal(decryptedData);

            // Read ciphertext.mac2.txt and convert it to a byte array
            byte[] providedMAC2 = Files.readAllBytes(Paths.get("ciphertext.mac2.txt"));

            if (MessageDigest.isEqual(calculatedMAC2, providedMAC2)) {
                System.out.println("MAC2 is valid.");
            } else {
                System.out.println("MAC2 is NOT valid.");
            }

            // Task 2: Get the plaintext

            // At this point, 'decryptedData' contains the original plaintext message.
            String plaintextMessage = new String(decryptedData, "UTF-8");
            System.out.println("Decrypted Message: " + plaintextMessage);

            // Close resources
            encryptedFileInputStream.close();
            keystoreInputStream.close();
            certFileInputStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}