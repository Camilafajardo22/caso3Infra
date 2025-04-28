import java.net.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.io.*;
import java.security.*;

public class ServidorPrincipal {
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

    private static final int PUERTO = 12345;
    
    public static void main(String[] args) {
        try {

            PublicKey llavePublica = cargarLlavePublica("Llaves/llave_publica.pem");
            PrivateKey llavePrivada = cargarLlavePrivada("Llaves/llave_privada.pem");

            System.out.println("Llave privada generada: " + llavePrivada);
            System.out.println("Llave pública generada: " + llavePublica);

            Map<Integer, String> tablaServicios = new HashMap<>();
            tablaServicios.put(1, "Consulta de vuelo");
            tablaServicios.put(2, "Disponibilidad");
            tablaServicios.put(3, "Costo");

            ServerSocket serverSocket = new ServerSocket(PUERTO);
            System.out.println("Servidor escuchando en puerto " + PUERTO);

            while (true) {
                Socket socketCliente = serverSocket.accept();
                DelegadoServidor delegado = new DelegadoServidor(socketCliente, llavePrivada, llavePublica, tablaServicios);
                delegado.start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}