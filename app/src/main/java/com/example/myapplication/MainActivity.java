package com.example.myapplication;

import android.os.Bundle;

import com.google.android.material.snackbar.Snackbar;

import androidx.appcompat.app.AppCompatActivity;

import android.util.Base64;
//import org.apache.commons.codec.binary.Base64;
import android.util.Log;
import android.view.View;

import androidx.core.view.WindowCompat;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import com.example.myapplication.databinding.ActivityMainBinding;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private AppBarConfiguration appBarConfiguration;
    private ActivityMainBinding binding;

    static {
        System.loadLibrary("myapplication");
    }

    public MainActivity() throws IOException {
    }

//    public native String invertMyString();
//    public native byte[] encrypt_w_aes(byte[] plainArray, int mode);
//    public native byte[] decrypt_w_aes(byte[] plainArray, int mode);
//    public native <string> byte[] StartingEncryption(string toEncrypt);
//    public native <string> byte[] StartingDecryption(string toDecrypt);
//    public native int startAes();
    public native byte[] calculateHash(byte[] plainArray);
    public native byte[] encryptAes256(byte[] key, byte[] plainText);
    public native byte[] decryptAes256(byte[] key, byte[] encText);
    //public native byte[] encryptTripleDES(byte[] plain_text);
    //public native byte[] decryptTripleDES(byte[] encText);
    public native byte[] new3DesEnc(byte[] plain_text);
    public native byte[] new3DesDec(byte[] encText);
    public native byte[] EncryptRSA(String key, byte[] plainText, String mode);
    public native byte[] DecryptRSA(String key, byte[] encText, String mode);

    //String publickey = new String(Files.readAllBytes(Paths.get("C:\\Users\\metho\\AndroidStudioProjects\\MyApplication\\app\\src\\main\\cpp\\publickey.txt")), StandardCharsets.UTF_8);
    //String privatekey = new String(Files.readAllBytes(Paths.get("C:\\Users\\metho\\AndroidStudioProjects\\MyApplication\\app\\src\\main\\cpp\\private.txt")), StandardCharsets.UTF_8);

    // KEYS FOR RSA
    String public_key = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1AThUE8dUz6x5DeDK3J\n" +
            "SKcBbqFVtplHCdf+036+2tZ1RmHcwsKZ6AF4dtCQ/8n+2lMQgdfWSe+gKEp2lIh0\n" +
            "YQUxgQneLXGzvsEjbFVLgxSdLnEfuZrJsNC3J9LHlnvwYYvBQGaSVCx7WhvxFyDC\n" +
            "BJ7SlpjSzVY9yduxRAHKYnsFRwKgEW15N3VYbspd/LTexNHXTbuzQ968wZbWd5rX\n" +
            "qHejM9pFEQsxqBq7uIk3eFvDMZzyi47NaM9eRHX6LyDF4CtL6SL9UKRTnMCrNpDh\n" +
            "WfxaC6xbMf4tf242Bk0TGe8mK6gH5baUs4C14Tq87yUkC9IVMegNlki89nsT5uRX\n" +
            "swIDAQAB\n" +
            "-----END PUBLIC KEY-----";
    String private_key = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpQIBAAKCAQEAm1AThUE8dUz6x5DeDK3JSKcBbqFVtplHCdf+036+2tZ1RmHc\n" +
            "wsKZ6AF4dtCQ/8n+2lMQgdfWSe+gKEp2lIh0YQUxgQneLXGzvsEjbFVLgxSdLnEf\n" +
            "uZrJsNC3J9LHlnvwYYvBQGaSVCx7WhvxFyDCBJ7SlpjSzVY9yduxRAHKYnsFRwKg\n" +
            "EW15N3VYbspd/LTexNHXTbuzQ968wZbWd5rXqHejM9pFEQsxqBq7uIk3eFvDMZzy\n" +
            "i47NaM9eRHX6LyDF4CtL6SL9UKRTnMCrNpDhWfxaC6xbMf4tf242Bk0TGe8mK6gH\n" +
            "5baUs4C14Tq87yUkC9IVMegNlki89nsT5uRXswIDAQABAoIBAQCYztBl6ylwv6x9\n" +
            "bSsLjnDb6nSeRF3wqh4asUknDSz6YsY/2Uk61fxXKBs9yzbec/8rD07OcW2EkR8i\n" +
            "hSDmQts+Gb37F5phW91dcOlJTSJedYmwh9yO4JxQOwn5RIjaplZ7ouUgV8rgxmMW\n" +
            "5Sbvemtp4FmRkgrVvGROlrhyENDu0lJzPtVks8XA1Re+CrOinhTCkISChqq/sHVC\n" +
            "sJfsI6OFHzk0Oexnh0sIG5MfaMNFp4Mh38UhrXFBJ6cIBuveEGzzED+AB6O30j3k\n" +
            "XT2pQbjCJcpekfpzfcW1VRfebLIgB+2mVjSleMKgA7ImyXOg4DCJiLWLulgOKmiE\n" +
            "x7qH684BAoGBAM1onwWBR3ERui4p22dNEoZ2tOygzEJKzhjsC1tRDAyO8Gr4QWNk\n" +
            "fNt/+8+gjJkMkkoKtjaqPrOdclhdPVCyQWvJt5ZAyAv0J7HDbZU8uShAOJI4eCpi\n" +
            "G2Xf20S0v84V12MEriWKZTmXUyWWKR87XkLTcVLCyfMTqPR1gMtHfpJpAoGBAMGQ\n" +
            "0lrFeNM2xqD7fZE/465wxp+kYPf/sMNkk6IqxJljtnzjWbySDU9csSwlN03Q36vu\n" +
            "/TGFIUWx2uTvjRHGEPvOC9agEZ8p9kHWrQb1ZgICpd/yWEy9nze66OayN3JyxkVR\n" +
            "pg2R5RRfnWuI9U6CyPhuZlptqDBUHXhG2kVB3Z27AoGBALYT0CpED3zl1uBG0CqA\n" +
            "gjRZE0VRv93fi1NCIUr/y6tyJSDdELE3CQpVJ3RDf33HTAF//0bzoAL9RLeZZtma\n" +
            "OS1/sFHq+KjH80u6zO9l1UcdrkfG8JW5Q0oJpccAZakbaUJniqrSQ6pKPjTqJ2d8\n" +
            "67BW13QiIHts6O5RHiqTJFpJAoGBAJEfMgbqDJdWdv8U7mSq4NnVJaVlCWqF4hHs\n" +
            "Yx9vLyzNbHEfxxSw75ezqAWv9VG7KybtrBindnWZTcLcswhDVlJjfc6w/eU2AbIE\n" +
            "8H7KF2ukbpaDTJ5kgG25DYqAzT9aO7qW54c+/eATe6O28CuntGNF6ikcE8AAIIQf\n" +
            "ot/P7QanAoGADQ5hDdPaq+wSFhYoeh//QfXrkbIcNl18ienY5Sn4jDrNgkkxghdc\n" +
            "WV3biTqIGMf15CI+//dSShbzI7nyoYQ8bl6HsFbEnGyS95PySdF6gUhsPKG83Ih2\n" +
            "SftvM2TzsO9D8XemkOHNwayPMN6YQA3SDZTZNNv3LYD7NkqhRQI0YUo=\n" +
            "-----END RSA PRIVATE KEY-----";

//    public PublicKey getFromString(String keystr) throws Exception
//    {
//        // Remove the first and last lines
//
//        String pubKeyPEM = keystr.replace("-----BEGIN PUBLIC KEY-----\n", "");
//        pubKeyPEM = pubKeyPEM.replace("-----END PUBLIC KEY-----", "");
//
//        // Base64 decode the data
//
//        byte [] encoded = Base64.decode(pubKeyPEM, 0);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PublicKey pubkey = kf.generatePublic(keySpec);
//        return pubkey;
//    }
//    public byte[] RSAEncrypt(final String plain) throws Exception {
//        byte[] ba = new byte[256];
//        if (public_key != null) {
//            Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
//            PublicKey pubKey = getFromString(public_key);
//            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
//
//            byte[] ba1 = plain.getBytes(); // sdelat to je samoe na c++ взять заполеннный массив нулями и вначале кинуть ему плейн
//            Arrays.fill(ba, (byte) 0);
//            System.arraycopy(ba1, 0, ba, 0, ba1.length);
//            byte[] encryptedBytes = cipher.doFinal(ba);
//            Log.d("Base64Encrypted", new String(Base64.encode(encryptedBytes, 0)));
//            return encryptedBytes;
//        }
//        else
//            return null;
//    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        setSupportActionBar(binding.toolbar);

        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        appBarConfiguration = new AppBarConfiguration.Builder(navController.getGraph()).build();
        NavigationUI.setupActionBarWithNavController(this, navController, appBarConfiguration);

        binding.fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Your own action.", Snackbar.LENGTH_LONG)
                        .setAnchorView(R.id.fab)
                        .setAction("Action", null).show();
            }
        });
//          invertMyString();
//        byte[] ba = new byte[100];
//        SecureRandom sr = new SecureRandom();
//        sr.nextBytes(ba);
//        Log.i(TAG, "onCreate: initial array = " + Arrays.toString(ba));
//        byte[] ba1 = calculateHash(ba);
//        if(ba1 == null) {
//            Log.d(TAG, "onCreate: calculateHash() = null");
//        } else {
//            StringBuilder sb = new StringBuilder();
//            for (byte b : ba1) {
//                sb.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: Hash = " + sb.toString());
//        }
//
//        try {
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] ba2 = digest.digest(ba);
//            StringBuilder sb = new StringBuilder();
//            for (byte b : ba2) {
//                sb.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: Hash = " + sb);
//        } catch (Exception e) {
//            Log.d(TAG, "onCreate: Exception : " + e.getMessage());
//        }


        //String plain = "TXaxsOMjDo6sN1B7VnImbnHLCXQ9wVDEfDJgI8bRlqB63ZqDE5wpJcEAjYOTkmjBwmSRmP0AuuSyJpmKGB0JPMzD2MSu3NKwauD1O64en684yBiMOhP6TzLDlMu6eKkmc7DOT1rBKK1HinLK5SOituqtMZCfJL5sWQCpzTpAjzWlIvZbmdaOw8ernenzrVJXIm7mta2FP9YQlpgcB6EeBNG4sRY8fGjxwhawBWuhV7a1XgvbBPZFA";
//        StringBuilder sb2 = new StringBuilder();
//        for (byte b : plainText) {
//            sb2.append(String.format("%02X", b));
//        }
//        Log.d(TAG, "onCreate: plainText = " + sb2.toString());
//
//        byte[] encryptResultJava;
//        byte[] encTextCplus;
//        try {
//            encryptResultJava = RSAEncrypt(plain);
////            encTextCplus = publicencryptRsa(private_key, plainText);
//            Log.d("BYTES", "Encrypted : " + Utils.encodeHex(encryptResultJava));
////            Log.w("BYTES", Utils.encodeHex(encTextCplus));
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }


        /* *********** OPENSSL TEST ********** */
        byte[] plainText = "TXaxsOMjDo6sN1B7VnImbnHLCXQ9wVDEfDJgI8bRlqB63ZqDE5wpJcEAjYOTkmjBwmSRmP0AuuSyJpmKGB0JPMzD2MSu3NKwauD1O64en684yBiMOhP6TzLDlMu6eKkmc7DOT1rBKK1HinLK5SOituqtMZCfJL5sWQCpzTpAjzWlIvZbmdaOw8ernenzrVJXIm7mta2FP9YQlpgcB6EeBNG4sRY8fGjxwhawBWuhV7a1XgvbBPZFA".getBytes(StandardCharsets.UTF_8);

        // RSA TEST !!!!!!!!!!!!!!!!!!!!!!
        byte[] rsa_encrypted = EncryptRSA(private_key, plainText, "Private");
        byte[] rsa_decrypted = DecryptRSA(public_key, rsa_encrypted, "Public");
        StringBuilder sb3 = new StringBuilder();
        for (byte b : plainText) {
            sb3.append(String.format("%02X", b));
        }
        Log.d(TAG, "onCreate: PlainTextBA(RSA) = " + sb3);

        StringBuilder sb4 = new StringBuilder();
        for (byte b : rsa_encrypted) {
            sb4.append(String.format("%02X", b));
        }
        Log.d(TAG, "onCreate: EncryptedTextBA(RSA) = " + sb4);

        StringBuilder sb5 = new StringBuilder();
        for (byte b : rsa_decrypted) {
            sb5.append(String.format("%02X", b));
        }
        Log.d(TAG, "onCreate: DecryptedTextBA(RSA) = " + sb5);

        // AES TEST !!!!!!!!!!!!!!!!!!!!!!
        byte [] keyData = "eQg2MDbk3uUtRhMw".getBytes();
        byte[] aes_encrypted = encryptAes256(keyData, plainText);
        byte[] aes_decrypted = decryptAes256(keyData, aes_encrypted);
        StringBuilder sbb = new StringBuilder();
        for (byte b : plainText) {
            sbb.append(String.format("%02X", b));
        }
        Log.i(TAG, "onCreate: PlainTextBA(AES256) = " + sbb);

        StringBuilder sbb1 = new StringBuilder();
        for (byte b : aes_encrypted) {
            sbb1.append(String.format("%02X", b));
        }
        Log.i(TAG, "onCreate: EncryptedTextBA(AES256) = " + sbb1);

        StringBuilder sbb2 = new StringBuilder();
        for (byte b : aes_decrypted) {
            sbb2.append(String.format("%02X", b));
        }
        Log.i(TAG, "onCreate: DecryptedTextBA(AES256) = " + sbb2);

        // TDES TEST !!!!!!!!!!!!!!!!!!!!!!
        byte[] tdes_encrypted = new3DesEnc(plainText);
        byte[] tdes_decrypted = new3DesDec(tdes_encrypted);
        StringBuilder sbbb = new StringBuilder();
        for (byte b : plainText) {
            sbbb.append(String.format("%02X", b));
        }
        Log.v(TAG, "onCreate: PlainTextBA(TDES) = " + sbbb);

        StringBuilder sbbb1 = new StringBuilder();
        for (byte b : tdes_encrypted) {
            sbbb1.append(String.format("%02X", b));
        }
        Log.v(TAG, "onCreate: EncryptedTextBA(TDES) = " + sbbb1);

        StringBuilder sbbb2 = new StringBuilder();
        for (byte b : tdes_decrypted) {
            sbbb2.append(String.format("%02X", b));
        }
        Log.v(TAG, "onCreate: DecryptedTextBA(TDES) = " + sbbb2);

//        Log.d(TAG, "onCreate: plainText = " + sb2.toString());
//        byte [] keyData = "eQg2MDbk3uUtRhMw".getBytes();
//        byte [] encryptedText = encryptAes256(keyData, plainText);
//        byte [] decryptedText = decryptAes256(keyData, encryptedText);
//          byte [] encText = EncryptRSA(private_key, plainText, "Private");
//            sb2 = new StringBuilder();
//            for (byte b : encText) {
//                sb2.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: encBa = " + sb2.toString());
//          byte[] decBa = DecryptRSA(public_key, encText, "Public");
//        sb2 = new StringBuilder();
//        for (byte b : decBa) {
//            sb2.append(String.format("%02X", b));
//        }
//        Log.d(TAG, "onCreate: decBa = " + sb2.toString());

        /* ********** T_DES CHECK ********** */
//        byte[] plainText1 = "k-D46dK)#+{Vf&xG@_B!_XZ]C&p2}52S@j)!2RMP-b9dcmB2phrQmzH:tPX.q!5:".getBytes();// thqyeuipmloqsa12mloqsadf  \\ c307d1e566991874
//        byte[] t_des_encrypted = encryptTripleDES(plainText1);
//        byte[] t_des_decrypted = decryptTripleDES(t_des_encrypted);
//
//        StringBuilder sb3 = new StringBuilder();
//        for (byte b : plainText1) {
//            sb3.append(String.format("%02X", b));
//        }
//        Log.d(TAG, "onCreate: PlainTextBA = " + sb3);
//
//        StringBuilder sb4 = new StringBuilder();
//        for (byte b : t_des_encrypted) {
//            sb4.append(String.format("%02X", b));
//        }
//        Log.d(TAG, "onCreate: EncryptedTextBA = " + sb4);
//
//        StringBuilder sb5 = new StringBuilder();
//        for (byte b : t_des_decrypted) {
//            sb5.append(String.format("%02X", b));
//        }
//        Log.d(TAG, "onCreate: DecryptedTextBA = " + sb5);

//          String decStr = new String(decBa, StandardCharsets.UTF_8);
//        Log.d(TAG, "onCreate: decStr = " + decStr);
        // plainTextHASH
//        try {
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] ba3 = digest.digest(plainText);
//            StringBuilder sb = new StringBuilder();
//            for (byte b : ba3) {
//                sb.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: txtHash = " + sb);
//        } catch (Exception e) {
//            Log.d(TAG, "onCreate: Exception : " + e.getMessage());
//        }

        //decryptedTextHash
//        try {
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            byte[] ba3 = digest.digest(decryptedText);
//            StringBuilder sb = new StringBuilder();
//            for (byte b : ba3) {
//                sb.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: decHash = " + sb);
//        } catch (Exception e) {
//            Log.d(TAG, "onCreate: Exception : " + e.getMessage());
//        }

//        byte[] ba2 = calculateHash(encryptedData);
//        if(ba2 == null) {
//            Log.d(TAG, "onCreate: calculateHash() = null");
//        } else {
//            StringBuilder sb1 = new StringBuilder();
//            for (byte b : ba2) {
//                sb1.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: originalHash = " + sb1.toString());
//        }
//        byte[] ba3 = calculateHash(decryptedData);
//        if(ba3 == null) {
//            Log.d(TAG, "onCreate: calculateHash() = null");
//        } else {
//            StringBuilder sb2 = new StringBuilder();
//            for (byte b : ba3) {
//                sb2.append(String.format("%02X", b));
//            }
//            Log.d(TAG, "onCreate: decryptedHash = " + sb2.toString());
//        }

    }

    @Override
    public boolean onSupportNavigateUp() {
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment_content_main);
        return NavigationUI.navigateUp(navController, appBarConfiguration)
                || super.onSupportNavigateUp();
    }
}