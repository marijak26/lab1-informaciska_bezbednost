import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            Ccmp ccmp = new Ccmp();

            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter a message to encrypt:");
            String message = scanner.nextLine();

            ClearTextFrame clearTextFrame = new ClearTextFrame(message.getBytes());
            EncryptedFrame encryptedFrame = ccmp.encrypt(clearTextFrame);

            System.out.println("Encrypted Data (Hex): " + bytesToHex(encryptedFrame.getEncryptedData()));
            System.out.println("MIC (Hex): " + bytesToHex(encryptedFrame.getMic()));

            ClearTextFrame decryptedFrame = ccmp.decrypt(encryptedFrame);
            System.out.println("Decrypted Data: " + new String(decryptedFrame.getData()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }
}
