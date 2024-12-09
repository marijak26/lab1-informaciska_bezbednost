import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class Ccmp {
    private final SecretKey aesKey;
    private final SecureRandom random;

    public Ccmp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        this.aesKey = keyGen.generateKey();
        this.random = new SecureRandom();
    }

    public EncryptedFrame encrypt(ClearTextFrame frame) throws Exception {
        byte[] data = frame.getData();

        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedData = cipher.doFinal(data);

        byte[] mic = calculateMic(encryptedData);

        byte[] combinedData = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combinedData, 0, iv.length);
        System.arraycopy(encryptedData, 0, combinedData, iv.length, encryptedData.length);

        return new EncryptedFrame(combinedData, mic);
    }

    public ClearTextFrame decrypt(EncryptedFrame encryptedFrame) throws Exception {
        byte[] combinedData = encryptedFrame.getEncryptedData();

        byte[] iv = Arrays.copyOfRange(combinedData, 0, 16);
        byte[] encryptedData = Arrays.copyOfRange(combinedData, 16, combinedData.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] decryptedData = cipher.doFinal(encryptedData);

        byte[] calculatedMic = calculateMic(encryptedData);
        if (!Arrays.equals(calculatedMic, encryptedFrame.getMic())) {
            throw new SecurityException("Integrity check failed.");
        }

        return new ClearTextFrame(decryptedData);
    }

    private byte[] calculateMic(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256"));
        return Arrays.copyOf(mac.doFinal(data), 8);
    }
}
