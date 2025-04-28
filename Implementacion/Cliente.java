import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.io.*;
import java.math.BigInteger;

public class Cliente {
    
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private PublicKey llavePublica;
    private PrivateKey llavePrivada;
    private SecretKey llaveAES;
    private SecretKey llaveHMAC;
    
    public Cliente(String host, int puerto) throws Exception {
        socket = new Socket(host, puerto);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
        
        PublicKey llavePublica = cargarLlavePublica("Llaves/llave_publica.pem");
        PrivateKey llavePrivada = cargarLlavePrivada("Llaves/llave_privada.pem");

    }

    public void iniciar() throws Exception {
        // Paso 1: Enviar "HELLO" para iniciar la comunicación
        out.writeUTF("HELLO");
        System.out.println("[Cliente] Enviado: HELLO");
        
        // Paso 2: Recibir desafío del servidor
        int reto = in.readInt();
        byte[] retoBytes = new byte[reto];
        in.readFully(retoBytes);
        System.out.println("[Cliente] Reto recibido: " + reto);
        
        // Paso 3: Cifrar el reto con la clave pública del servidor
        byte[] retoCifrado = FuncionesCrypto.cifrarRSA(retoBytes, llavePublica);
        
        // Paso 4: Enviar el reto cifrado
        out.writeInt(retoCifrado.length);
        out.write(retoCifrado);
        System.out.println("[Cliente] Reto cifrado enviado al servidor");

        // Paso 5: Esperar confirmación del servidor
        String confirmacion = in.readUTF();
        if (!confirmacion.equals("OK")) {
            System.out.println("[Cliente] Error: el servidor no validó la autenticidad.");
            return;
        }
        
        // Paso 6: Generar parámetros Diffie-Hellman (p, g) en el cliente
        System.out.println("[Cliente] Generando parámetros Diffie-Hellman...");
        AlgorithmParameterGenerator paramsDH = AlgorithmParameterGenerator.getInstance("DH");
        paramsDH.init(1024);
        AlgorithmParameters parametros = paramsDH.generateParameters();
        DHParameterSpec dh = parametros.getParameterSpec(DHParameterSpec.class);
        
        BigInteger p = dh.getP();
        BigInteger g = dh.getG();
        
        // Generar la clave pública y privada del cliente en Diffie-Hellman
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dh);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey llavePrivadaDH = keyPair.getPrivate();
        PublicKey llavePublicaDH = keyPair.getPublic();

        // Enviar los parámetros p, g, g^x al servidor
        ByteArrayOutputStream arrayBytes = new ByteArrayOutputStream();
        arrayBytes.write(p.toByteArray());
        arrayBytes.write(g.toByteArray());
        arrayBytes.write(llavePublicaDH.getEncoded());
        
        byte[] datosFirmar = arrayBytes.toByteArray();

        // Firma RSA de los datos
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(llavePrivada);
        firma.update(datosFirmar);
        byte[] firmaBytes = firma.sign();

        // Enviar datos firmados al servidor
        out.writeInt(p.toByteArray().length);
        out.write(p.toByteArray());
        out.writeInt(g.toByteArray().length);
        out.write(g.toByteArray());
        out.writeInt(llavePublicaDH.getEncoded().length);
        out.write(llavePublicaDH.getEncoded());
        out.writeInt(firmaBytes.length);
        out.write(firmaBytes);
        System.out.println("[Cliente] Datos firmados enviados al servidor");

        // Paso 7: Esperar aceptación del servidor
        String respuestaServidor = in.readUTF();
        if (!respuestaServidor.equals("OK")) {
            System.out.println("[Cliente] El servidor rechazó los parámetros DH");
            return;
        }
        
        // Paso 8: Recibir g^y del servidor
        int gyLength = in.readInt();
        byte[] gyBytes = new byte[gyLength];
        in.readFully(gyBytes);
        System.out.println("[Cliente] Recibido g^y del servidor");

        // Reconstruir la clave pública del servidor para realizar el acuerdo DH
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec clavePubSpecServidor = new X509EncodedKeySpec(gyBytes);
        PublicKey clavePublicaServidor = keyFactory.generatePublic(clavePubSpecServidor);

        // Completar el acuerdo de claves DH
        KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
        acuerdo.init(llavePrivadaDH);
        acuerdo.doPhase(clavePublicaServidor, true);
        byte[] llaveMaestra = acuerdo.generateSecret();

        // Derivar las llaves de sesión utilizando SHA-512
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] separar = sha512.digest(llaveMaestra);
        llaveAES = new SecretKeySpec(Arrays.copyOfRange(separar, 0, 32), "AES");
        llaveHMAC = new SecretKeySpec(Arrays.copyOfRange(separar, 32, 64), "HMACSHA256");

        // Paso 9: Enviar IV (vector de inicialización) al servidor
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        out.writeInt(iv.length);
        out.write(iv);

        // Paso 10: Enviar solicitud al servidor con el identificador del servicio
        Scanner scanner = new Scanner(System.in);
        System.out.print("[Cliente] Ingrese el ID del servicio que desea consultar: ");
        int idServicio = scanner.nextInt();
        String solicitud = idServicio + "+" + socket.getLocalAddress().getHostAddress();

        byte[] datosCifrados = FuncionesCrypto.cifrarAES(llaveAES, ivSpec, solicitud);
        byte[] hmacSolicitud = FuncionesCrypto.generarHMAC(llaveHMAC, datosCifrados);

        out.writeInt(datosCifrados.length);
        out.write(datosCifrados);
        out.writeInt(hmacSolicitud.length);
        out.write(hmacSolicitud);

        System.out.println("[Cliente] Solicitud enviada al servidor");

        // Paso 11: Recibir respuesta cifrada del servidor
        int tamRespuesta = in.readInt();
        byte[] respuestaCifrada = new byte[tamRespuesta];
        in.readFully(respuestaCifrada);

        int tamHMACRespuesta = in.readInt();
        byte[] hmacRespuesta = new byte[tamHMACRespuesta];
        in.readFully(hmacRespuesta);

        // Verificar HMAC de la respuesta
        if (!FuncionesCrypto.verificarHMAC(llaveHMAC, respuestaCifrada, hmacRespuesta)) {
            System.out.println("[Cliente] Error: HMAC inválido en la respuesta.");
            return;
        }

        // Descifrar la respuesta
        String respuesta = new String(FuncionesCrypto.descifrarAES(llaveAES, ivSpec, respuestaCifrada));
        System.out.println("[Cliente] Respuesta del servidor: " + respuesta);
    }

    public static PrivateKey cargarLlavePrivada(String rutaArchivo) throws Exception {
        String keyPEM = leerContenido(rutaArchivo, "PRIVATE KEY");
        byte[] keyBytes = Base64.getDecoder().decode(keyPEM);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey cargarLlavePublica(String rutaArchivo) throws Exception {
        String keyPEM = leerContenido(rutaArchivo, "PUBLIC KEY");
        byte[] keyBytes = Base64.getDecoder().decode(keyPEM);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static String leerContenido(String ruta, String tipo) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(ruta));
        StringBuilder sb = new StringBuilder();
        String linea;
        boolean dentro = false;

        while ((linea = br.readLine()) != null) {
            if (linea.contains("BEGIN " + tipo)) {
                dentro = true;
            } else if (linea.contains("END " + tipo)) {
                break;
            } else if (dentro) {
                sb.append(linea.trim());
            }
        }
        br.close();
        return sb.toString();
    }
    public static void main(String[] args) {
        try {
            Cliente cliente = new Cliente("localhost", 12345);
            cliente.iniciar();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
