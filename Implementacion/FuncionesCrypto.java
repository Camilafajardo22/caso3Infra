import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
public class FuncionesCrypto {

    // RSA
    public static byte[] cifrarRSA(byte[] datos, Key clave) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clave);
        return cipher.doFinal(datos);
    }

    public static byte[] descifrarRSA(byte[] datos, Key clave) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clave);
        return cipher.doFinal(datos);
    }

    // AES

    public static byte[] cifrarAES(SecretKey llave, IvParameterSpec iv, String textoClaro) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llave, iv);
        return cipher.doFinal(textoClaro.getBytes());
    }

    public static byte[] descifrarAES(SecretKey llave, IvParameterSpec iv, byte[] datosCifrados) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llave, iv);
        return cipher.doFinal(datosCifrados);
    }

    // HMAC

    public static byte[] generarHMAC(SecretKey llaveHMAC, byte[] datos) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(llaveHMAC);
        return hmac.doFinal(datos);
    }

    public static boolean verificarHMAC(SecretKey llaveHMAC, byte[] datos, byte[] hmacEsperado) throws Exception {
        byte[] hmacCalculado = generarHMAC(llaveHMAC, datos);
        return MessageDigest.isEqual(hmacCalculado, hmacEsperado);
    }
}