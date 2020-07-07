package net.soluspay.cashq.utils;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.sun.jersey.core.util.Base64;

public class IPINBlockGenerator {

    public static String getIPINBlock(String ipin,
                                      String publicKey, String uuid) {
        // clear ipin = uuid +  IPIN
        String cleraIpin = uuid + ipin;

        // prepare public key, get public key from its String representation as
        // base64
        byte[] keyByte = Base64.decode(publicKey);
        // generate public key
        X509EncodedKeySpec s = new X509EncodedKeySpec(keyByte);
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Key pubKey = null;
        try {
            pubKey = factory.generatePublic(s);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            // construct Cipher with encryption algrithm:RSA, cipher mode:ECB and padding:PKCS1Padding
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            // calculate ipin, encryption then encoding to base64
            ipin = (new String(Base64.encode(cipher.doFinal(cleraIpin
                    .getBytes()))));
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return ipin;
    }

//    public static void main(String[] args) {
//        System.out.println(new IPINBlockGenerator().getIPINBlock("0000","MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ4HwthfqXiK09AgShnnLqAqMyT5VUV0hvSdG+ySMx+a54Ui5EStkmO8iOdVG9DlWv55eLBoodjSfd0XRxN7an0CAwEAAQ==", UUID.randomUUID().toString()));
//    }

}
