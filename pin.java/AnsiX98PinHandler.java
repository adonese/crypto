package net.soluspay.cashq.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class AnsiX98PinHandler {

    //start of class
    // instance variables
    private String pinBlock;

    @SuppressWarnings("unused")
    private AnsiX98PinHandler() {

    }

    String toBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * Byte.SIZE);
        for (int i = 0; i < Byte.SIZE * bytes.length; i++) {
            sb.append((bytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
        }
        return sb.toString();
    }

    public AnsiX98PinHandler(String tmk, String key, String pan, String pin) {

        byte[] TMK = new byte[8];
        byte[] clearPinBlock = new byte[8];
        byte[] byteKey;
        StringBuilder p1 = new StringBuilder(16);
        p1.append("0");
        p1.append(pin.length());
        p1.append(pin);

        for (int i = 0; i < p1.capacity() - p1.length(); ) {
            p1.append("F");
        }
        StringBuilder p2 = new StringBuilder(16);
        p2.append("0000");

        for (int i = 0; i < 12; i++) {
            p2.append(pan.charAt(pan.length() - 13 + i));
        }

        try {

            byteKey = Hex.decodeHex((key.toCharArray()));
            TMK = Hex.decodeHex(tmk.toCharArray());

            byteKey = AnsiX98PinHandler.decrypt(byteKey, TMK);

            for (int i = 0; i < 8; i++) //XORing p1 and p2
            {
                clearPinBlock[i] = (byte) (Hex.decodeHex(p1.toString().toCharArray())[i]
                        ^ Hex.decodeHex(p2.toString().toCharArray())[i]);
            }

            byte[] encrypted = AnsiX98PinHandler.encrypt(clearPinBlock, byteKey);
            pinBlock = new String(Hex.encodeHex(encrypted));

        } catch (DecoderException e) {
        }
    }

    /**
     * @return The Encrypted PIN block.
     */
    public String getPinBlock() {
//        return pinBlock.toUpperCase();
        return pinBlock;
    }

    public static byte[] encrypt(byte[] byteKey, byte[] TMK) {

        try {

            DESKeySpec key = new DESKeySpec(TMK);
            ecipher = Cipher.getInstance("DES/CBC/NoPadding");
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // initialize the ciphers with the given key

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            ecipher.init(Cipher.ENCRYPT_MODE, keyFactory.generateSecret(key), ivspec);

            byte[] enc = ecipher.doFinal(byteKey);

            return enc;

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

    }

    private static Cipher ecipher;
    private static Cipher dcipher;

    public static byte[] decrypt(byte[] byteKey, byte[] TMK) {

        try {

            DESKeySpec key = new DESKeySpec(TMK);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");

            // KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
            SecretKey myDesKey = keyFactory.generateSecret(key);

            System.out.println("myDesKey:" + myDesKey);


            dcipher = Cipher.getInstance("DES/CBC/NoPadding");


            //DES/CBC/NoPadding //DES/ECB/PKCS5Padding

            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);


            //initialize the ciphers with the given key
            dcipher.init(Cipher.DECRYPT_MODE, myDesKey, ivspec);
            // initialize the ciphers with the given key
            // decode with base64 to get bytes

            //byte[] dec = BASE64DecoderStream.decode(byteKey);
            //byte[] dec = new String(byteKey).getBytes("UTF8");

            byte[] utf8 = dcipher.doFinal(byteKey);


            // create new string based on the specified charset
            return utf8;

        } catch (Exception e) {

            System.out.println(""+ e.toString());


        }

        return null;

    }
}//End of class