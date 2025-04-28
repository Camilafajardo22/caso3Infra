import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.io.*;
import java.math.BigInteger;

public class ClienteConcurrente extends Thread {

    private String host;
    private int puerto;
    
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private PublicKey llavePublica;
    private PrivateKey llavePrivada;
    private SecretKey llaveAES;
    private SecretKey llaveHMAC;
    private IvParameterSpec iv;

    public ClienteConcurrente(String host, int puerto) throws Exception {
        this.socket = new Socket(host, puerto);
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
        this.host = host;
        this.puerto = puerto;   

        this.llavePublica = cargarLlavePublica("Llaves/llave_publica.pem");
        this.llavePrivada = cargarLlavePrivada("Llaves/llave_privada.pem");


    }

    @Override
    public void run() {
        try {
            iniciarConexion();
            realizarConsulta();
            enviarFin();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void enviarFin() throws Exception {
        String fin = "FIN";
        byte[] finCifrado = FuncionesCrypto.cifrarAES(llaveAES, iv, fin);
        byte[] hmacFin = FuncionesCrypto.generarHMAC(llaveHMAC, finCifrado);
    
        out.writeInt(finCifrado.length);
        out.write(finCifrado);
    
        out.writeInt(hmacFin.length);
        out.write(hmacFin);
    
        System.out.println("[Cliente] Solicitud FIN cifrada enviada.");
    }

    private void iniciarConexion() throws Exception {
        // Paso 1: Enviar "HELLO"
        out.writeUTF("HELLO");
        System.out.println("[Cliente] Enviado: HELLO");

        
        // Paso 2a: Generar un reto (número aleatorio)
        SecureRandom random = new SecureRandom();
        byte[] reto = new byte[16]; // 128 bits
        random.nextBytes(reto);
        
        // Paso 2b: Enviar el reto al servidor
        out.writeInt(reto.length);
        out.write(reto);
        System.out.println("[Cliente] Enviado reto al servidor");
        
        // Paso 4: Recibir respuesta cifrada del servidor
        int tamRta = in.readInt();
        byte[] rtaCifrada = new byte[tamRta];
        in.readFully(rtaCifrada);
        System.out.println("[Cliente] Recibida respuesta cifrada");

        // Paso 5a: Descifrar la respuesta usando la llave pública del servidor
        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.DECRYPT_MODE, llavePublica);
        byte[] rtaDescifrada = cifrador.doFinal(rtaCifrada);

        // Paso 5b: Verificar que la respuesta descifrada sea igual al reto
        boolean retoValido = MessageDigest.isEqual(reto, rtaDescifrada);
        
        // Paso 6: Enviar "OK" o "ERROR" dependiendo del resultado
        if (retoValido) {
            out.writeUTF("OK");
            System.out.println("[Cliente] Reto validado correctamente. Se envió OK.");
        } else {
            out.writeUTF("ERROR");
            System.out.println("[Cliente] Error en validación del reto. Se envió ERROR.");
        }

        // Paso 7: Recibir G, P, G^x y Firma
        int tamG = in.readInt();
        byte[] gBytes = new byte[tamG];
        in.readFully(gBytes);
        BigInteger g = new BigInteger(gBytes);

        int tamP = in.readInt();
        byte[] pBytes = new byte[tamP];
        in.readFully(pBytes);
        BigInteger p = new BigInteger(pBytes);

        int tamGx = in.readInt();
        byte[] gxBytes = new byte[tamGx];
        in.readFully(gxBytes);

        int tamFirma = in.readInt();
        byte[] firmaBytes = new byte[tamFirma];
        in.readFully(firmaBytes);

        System.out.println("[Cliente] Recibidos G, P, G^x y firma del servidor");

        // Paso 9: Verificar Firma
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(gBytes);
        baos.write(pBytes);
        baos.write(gxBytes);
        byte[] datosFirmados = baos.toByteArray();

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(llavePublica);
        signature.update(datosFirmados);

        boolean firmaValida = signature.verify(firmaBytes);

        // Paso 10: Enviar OK o ERROR

        if (firmaValida) {
            out.writeUTF("OK");
            System.out.println("[Cliente] Firma verificada exitosamente. Se envió OK.");
        } else {
            out.writeUTF("ERROR");
            System.out.println("[Cliente] Error en verificación de firma. Se envió ERROR.");
        }

        // Paso 11: Cliente genera G^y y lo envía
        DHParameterSpec dhSpec = new DHParameterSpec(p, g);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair keyPairCliente = keyGen.generateKeyPair();

        PrivateKey llavePrivadaDH = keyPairCliente.getPrivate(); // 'y'
        PublicKey llavePublicaDH = keyPairCliente.getPublic();   // 'G^y'

        byte[] gyBytes = llavePublicaDH.getEncoded();
        out.writeInt(gyBytes.length);
        out.write(gyBytes);

        System.out.println("[Cliente] G^y generado y enviado al servidor");

        // Paso 11a: Cliente calcula (G^x)^y

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(gxBytes);
        PublicKey clavePublicaServidorDH = keyFactory.generatePublic(x509Spec);

        KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
        acuerdo.init(llavePrivadaDH); // usar MI llave privada DH
        acuerdo.doPhase(clavePublicaServidorDH, true);

        byte[] llaveMaestra = acuerdo.generateSecret();

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(llaveMaestra);

        byte[] k_ab1_bytes = Arrays.copyOfRange(digest, 0, 32);  // para AES
        byte[] k_ab2_bytes = Arrays.copyOfRange(digest, 32, 64); // para HMAC

        llaveAES = new SecretKeySpec(k_ab1_bytes, "AES");
        llaveHMAC = new SecretKeySpec(k_ab2_bytes, "HmacSHA256");

        System.out.println("[Cliente] Llaves de sesión K_AB1 y K_AB2 derivadas correctamente");

        // Paso 12a: Generar IV aleatorio
        SecureRandom random2 = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        this.iv = new IvParameterSpec(ivBytes);

        out.writeInt(ivBytes.length);
        out.write(ivBytes);

        System.out.println("[Cliente] IV generado y enviado al servidor");

        // Paso 13: Recibir tabla de servicios cifrada y HMAC

        int tamTabla = in.readInt();
        byte[] tablaCifrada = new byte[tamTabla];
        in.readFully(tablaCifrada);

        int tamHmacTabla = in.readInt();
        byte[] hmacTabla = new byte[tamHmacTabla];
        in.readFully(hmacTabla);

        System.out.println("[Cliente] Recibida tabla de servicios cifrada y HMAC");

        // Paso13b: Verificar HMAC de tabla

        boolean tablaValida = FuncionesCrypto.verificarHMAC(llaveHMAC, tablaCifrada, hmacTabla);

        if (!tablaValida) {
            System.out.println("[Cliente] Error: HMAC de tabla inválido. Terminando conexión.");
            out.writeUTF("ERROR");
            return;
        }

        System.out.println("[Cliente] HMAC de tabla válido");
    }

    private void realizarConsulta() throws Exception {
        // Paso 14: Enviar solicitud de servicio (id_servicio + IP_cliente)

        Random random = new Random();
        int idServicio = random.nextInt(3) + 1; // genera 1, 2 o 3
        System.out.println("[Cliente] Servicio aleatorio generado: " + idServicio);
        String solicitud = idServicio + "+" + socket.getLocalAddress().getHostAddress();

        byte[] solicitudCifrada = FuncionesCrypto.cifrarAES(llaveAES, iv, solicitud);

        byte[] hmacSolicitud = FuncionesCrypto.generarHMAC(llaveHMAC, solicitudCifrada);

        out.writeInt(solicitudCifrada.length);
        out.write(solicitudCifrada);

        out.writeInt(hmacSolicitud.length);
        out.write(hmacSolicitud);

        System.out.println("[Cliente] Solicitud enviada al servidor");

        // Paso 16: Recibir respuesta cifrada + HMAC y verificar

        int tamRespuesta = in.readInt();
        byte[] respuestaCifrada = new byte[tamRespuesta];
        in.readFully(respuestaCifrada);

        int tamHmacRespuesta = in.readInt();
        byte[] hmacRespuesta = new byte[tamHmacRespuesta];
        in.readFully(hmacRespuesta);

        // Paso 17: verificar HMCAP de la respuesta
        boolean respuestaValida = FuncionesCrypto.verificarHMAC(llaveHMAC, respuestaCifrada, hmacRespuesta);

        if (!respuestaValida) {
            System.out.println("[Cliente] Error: HMAC de respuesta inválido");
            out.writeUTF("ERROR");
            return;
        }

        String respuesta = new String(FuncionesCrypto.descifrarAES(llaveAES, iv, respuestaCifrada));
        System.out.println("[Cliente] Respuesta del servidor: " + respuesta);

        // Paso 18: Confirmar al servidor

        out.writeUTF("OK");
        System.out.println("[Cliente] Confirmación OK enviada al servidor");

    }


    public static PrivateKey cargarLlavePrivada(String rutaArchivo) throws Exception {
        String keyPEM = leerContenido(rutaArchivo, "PRIVATE KEY");
        byte[] keyBytes = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static PublicKey cargarLlavePublica(String rutaArchivo) throws Exception {
        String keyPEM = leerContenido(rutaArchivo, "PUBLIC KEY");
        byte[] keyBytes = Base64.getDecoder().decode(keyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private static String leerContenido(String ruta, String tipo) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(ruta));
        StringBuilder sb = new StringBuilder();
        String linea;
        boolean dentro = false;
        while ((linea = br.readLine()) != null) {
            if (linea.contains("BEGIN " + tipo)) dentro = true;
            else if (linea.contains("END " + tipo)) break;
            else if (dentro) sb.append(linea.trim());
        }
        br.close();
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
    
            System.out.print("Ingrese el número de clientes concurrentes (4, 16, 32, 64): ");
            int numeroClientes = scanner.nextInt();
    
            List<ClienteConcurrente> clientes = new ArrayList<>();
    
            for (int i = 0; i < numeroClientes; i++) {
                ClienteConcurrente cliente = new ClienteConcurrente("localhost", 12345);
                cliente.start();
                clientes.add(cliente);
            }
    
            for (ClienteConcurrente cliente : clientes) {
                cliente.join();
            }
    
            System.out.println("Todos los clientes finalizaron.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
