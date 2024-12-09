public class EncryptedFrame {
    private byte[] encryptedData;
    private byte[] mic;

    public EncryptedFrame(byte[] encryptedData, byte[] mic) {
        this.encryptedData = encryptedData;
        this.mic = mic;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getMic() {
        return mic;
    }
}
