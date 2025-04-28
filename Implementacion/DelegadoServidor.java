import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DelegadoServidor extends Thread {

    private Socket socketCliente;
    private PrivateKey llavePrivada;
    private PublicKey llavePublica;
    private Map<Integer, String> tablaServicios;
    private MedirTiempos medidorTiempos = new MedirTiempos("Concurrente");

    public DelegadoServidor(Socket socket, PrivateKey priv, PublicKey pub, Map<Integer, String> servicios) {
        this.socketCliente = socket;
        this.llavePrivada = priv;
        this.llavePublica = pub;
        this.tablaServicios = servicios;
    }

    @Override
    public void run() {
        try {
            DataInputStream in = new DataInputStream(socketCliente.getInputStream());
            DataOutputStream out = new DataOutputStream(socketCliente.getOutputStream());
            System.out.println("[Servidor] Conexión con cliente: " + socketCliente.getInetAddress());

            // Paso 1
            String saludo = in.readUTF();
            if (!saludo.equals("HELLO")) {
                System.out.println("[Servidor] Error: no se recibió HELLO");
                out.writeUTF("ERROR");
                return;
            }
            System.out.println("[Servidor] Recibido: " + saludo);

            // Paso 2
            System.out.println("[Servidor] Recibiendo reto del cliente");
            int reto = in.readInt();
            byte[] retoBytes = new byte[reto];
            in.readFully(retoBytes);
            System.out.println("[Servidor] Reto recibido: " + reto);

            // Paso 3
            byte[] Rta = FuncionesCrypto.cifrarRSA(retoBytes, llavePrivada);
            System.out.println("[Servidor] Llave privada del servidor cifrada");

            // Paso 4
            System.out.println("[Servidor] Enviando reto cifrados");
            out.writeInt(Rta.length);
            out.write(Rta);
            System.out.println("[Servidor] Reto cifrado enviado al cliente");

            // Paso 6
            System.out.println("[Servidor] Esperando respuesta del cliente");
            String confirmacion = in.readUTF();
            if (!confirmacion.equals("OK")) {
                System.out.println("[Servidor] Cliente no pudo verificar la autenticidad");
                return;
            }

            System.out.println("[Servidor] Autenticación RSA completada con éxito");

            // Paso 7
            System.out.println("[Servidor] Generando parámetros DH");
            AlgorithmParameterGenerator paramsDH = AlgorithmParameterGenerator.getInstance("DH");
            paramsDH.init(1024);
            AlgorithmParameters parametros = paramsDH.generateParameters();
            DHParameterSpec dh = parametros.getParameterSpec(DHParameterSpec.class);

            BigInteger p = dh.getP(); 
            BigInteger g = dh.getG(); 

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dh);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey llavePrivadaDh = keyPair.getPrivate();
            PublicKey llavePublicaDH = keyPair.getPublic();

            byte[] gBytes = g.toByteArray();
            byte[] pBytes = p.toByteArray();
            byte[] gxBytes = llavePublicaDH.getEncoded(); 

            // concatenar g, p, g^x para firmarlos
            ByteArrayOutputStream arrayBytes = new ByteArrayOutputStream();
            System.out.println("[Servidor] Enviando g");
            arrayBytes.write(gBytes);
            System.out.println("[Servidor] Enviando p");
            arrayBytes.write(pBytes);
            System.out.println("[Servidor] Enviando gx");
            arrayBytes.write(gxBytes);
            byte[] datosFirmar = arrayBytes.toByteArray();

            // firmar los datos
            long tiempoInicioFirma = System.nanoTime();

            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initSign(llavePrivada);
            firma.update(datosFirmar);
            byte[] firmaBytes = firma.sign();

            long tiempoFinFirma = System.nanoTime();
            long tiempoFirma = tiempoFinFirma - tiempoInicioFirma;
            System.out.println("[Servidor] Tiempo de firma: " + tiempoFirma + " ns");

            out.writeInt(gBytes.length);
            out.write(gBytes);

            out.writeInt(pBytes.length);
            out.write(pBytes);

            out.writeInt(gxBytes.length);
            out.write(gxBytes);

            out.writeInt(firmaBytes.length);
            out.write(firmaBytes);

            
            System.out.println("[Servidor] Enviados p, g, g^x y firma al cliente");
            
            // Paso 10
            System.out.println("[Servidor] Esperando respuesta del cliente");
            String respuesta = in.readUTF();
            if (!respuesta.equals("OK")) {
                System.out.println("[Servidor] El cliente no aceptó los parámetros Diffie-Hellman. Finalizando conexión");
                return;
            }
            System.out.println("[Servidor] Cliente aceptó los parámetros Diffie-Hellman");

            // Paso 11
            System.out.println("[Servidor] Recibiendo g^y del cliente");
            int gy = in.readInt();
            byte[] gyBytes = new byte[gy];
            in.readFully(gyBytes);
            System.out.println("[Servidor] g^y recibido correctamente");

            // Reconstruir la clave pública DH del cliente (g^y)
            System.out.println("[Servidor] Reconstruyendo clave pública del cliente");
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec clavePubSpecCliente = new X509EncodedKeySpec(gyBytes);
            PublicKey clavePubDHCliente = keyFactory.generatePublic(clavePubSpecCliente);

            KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
            acuerdo.init(llavePrivadaDh); 
            acuerdo.doPhase(clavePubDHCliente, true);
            byte[] llaveMaestra = acuerdo.generateSecret();

            // Calcular el digesr SHA-512 de la llave maestra  y separarlo
            System.out.println("[Servidor] Calcular digest SHA-512");
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] separar = sha512.digest(llaveMaestra);

            byte[] k_AB1_bytes = new byte[32]; 
            byte[] k_AB2_bytes = new byte[32]; 
            System.arraycopy(separar, 0, k_AB1_bytes, 0, 32);
            System.arraycopy(separar, 32, k_AB2_bytes, 0, 32);

            // Paso 11b
            SecretKey llaveAES = new SecretKeySpec(k_AB1_bytes, "AES");
            SecretKey llaveHMAC = new SecretKeySpec(k_AB2_bytes, "HMACSHA256");

            System.out.println("[Servidor] Llaves de sesión derivadas correctamente");

            // Paso 12b
            System.out.println("[Servidor] Recibiendo IV del cliente");
            int iv = in.readInt();
            byte[] ivBytes = new byte[iv];
            in.readFully(ivBytes);
            IvParameterSpec IV = new IvParameterSpec(ivBytes);

            System.out.println("[Servidor] IV recibido correctamente");

            // Paso 13
            System.out.println("[Servidor] Enviando tabla de servicios al cliente");
            StringBuilder tablaStr = new StringBuilder();
            for (Map.Entry<Integer, String> entry : tablaServicios.entrySet()) {
                tablaStr.append(entry.getKey()).append(":").append(entry.getValue()).append(";");
            }
            String datosServicios = tablaStr.toString();

            // CIFRAR AES

            long tiempoInicioCifrado = System.nanoTime();

            byte[] serviciosCifrados = FuncionesCrypto.cifrarAES(llaveAES, IV, datosServicios);

            long tiempoFinCifrado = System.nanoTime();
            long tiempoCifrado = tiempoFinCifrado - tiempoInicioCifrado;
            System.out.println("[Servidor] Tiempo para cifrar la tabla (AES): " + tiempoCifrado + " ns");

            // CIFRAR RSA
            long tiempoInicioCifradoRSA = System.nanoTime();

            byte[] serviciosCifradosRSA = FuncionesCrypto.cifrarRSA(datosServicios.getBytes(), llavePublica);

            long tiempoFinCifradoRSA = System.nanoTime();
            long tiempoCifradoRSA = tiempoFinCifradoRSA - tiempoInicioCifradoRSA;
            System.out.println("[Servidor] Tiempo para cifrar la tabla (RSA): " + tiempoCifradoRSA + " ns");

            byte[] hmacServicios = FuncionesCrypto.generarHMAC(llaveHMAC, serviciosCifrados);

            out.writeInt(serviciosCifrados.length);
            out.write(serviciosCifrados);
            out.writeInt(hmacServicios.length);
            out.write(hmacServicios);

            System.out.println("[Servidor] Tabla de servicios enviada con HMAC");

            while (true) {
                // Paso 14: Leer solicitud cifrada
                int tamDatos;
                try {
                    tamDatos = in.readInt();
                } catch (EOFException e) {
                    System.out.println("[Servidor] Cliente cerró conexión.");
                    break;
                }

                byte[] datosCifrados = new byte[tamDatos];
                in.readFully(datosCifrados);

                int tamHMAC = in.readInt();
                byte[] hmacRecibido = new byte[tamHMAC];
                in.readFully(hmacRecibido);

                System.out.println("[Servidor] Solicitud recibida del cliente");

                // Paso 15

                


                long tiempoInicioVerificacion = System.nanoTime();

                boolean valido = FuncionesCrypto.verificarHMAC(llaveHMAC, datosCifrados, hmacRecibido);

                long tiempoFinVerificacion = System.nanoTime();
                long tiempoVerificacion = tiempoFinVerificacion - tiempoInicioVerificacion;
                System.out.println("[Servidor] Tiempo para verificar HMAC: " + tiempoVerificacion + " ns");
                medidorTiempos.guardarTiempo("VerificarHMAC", tiempoVerificacion);

                if (!valido) {
                    out.writeUTF("ERROR");
                    System.out.println("[Servidor] HMAC inválido en solicitud");
                    continue; 
                }

                String solicitud = new String(FuncionesCrypto.descifrarAES(llaveAES, IV, datosCifrados));
                System.out.println("[Servidor] Solicitud del cliente: " + solicitud);

                if (solicitud.equals("FIN")) {
                    System.out.println("[Servidor] Cliente indicó FIN. Cerrando conexión.");
                    return;
                }

                //Simular firmar de nuevo
                long inicioFirma = System.nanoTime();
                Signature firmaNueva = Signature.getInstance("SHA256withRSA");
                firmaNueva.initSign(llavePrivada);
                firmaNueva.update(datosServicios.getBytes()); // firmaNueva cualquier dato
                firma.sign();
                long finFirma = System.nanoTime();
                medidorTiempos.guardarTiempo("Firmar", finFirma - inicioFirma);

                //Simular cifrar AES de nuevo
                long inicioCifradoAES = System.nanoTime();
                FuncionesCrypto.cifrarAES(llaveAES, IV, datosServicios);
                long finCifradoAES = System.nanoTime();
                medidorTiempos.guardarTiempo("CifrarAES", finCifradoAES - inicioCifradoAES);

                // Simular cifrar RSA de nuevo
                long inicioCifradoRSA = System.nanoTime();
                FuncionesCrypto.cifrarRSA(datosServicios.getBytes(), llavePublica);
                long finCifradoRSA = System.nanoTime();
                medidorTiempos.guardarTiempo("CifrarRSA", finCifradoRSA - inicioCifradoRSA);

                String[] partes = solicitud.split("\\+");
                int idServicio = Integer.parseInt(partes[0]);
                String ipCliente = partes[1];

                String respuestaCliente;
                if (!tablaServicios.containsKey(idServicio)) {
                    respuestaCliente = "-1,-1"; 
                } else {
                    String ipServidor = socketCliente.getLocalAddress().getHostAddress();
                    int puerto = 5000 + idServicio;
                    respuestaCliente = ipServidor + "," + puerto;
                }
                System.out.println("[Servidor] Respuesta al cliente: " + respuestaCliente);

                // Paso 16
                System.out.println("[Servidor] Cifrando respuesta");
                byte[] respuestaCifrada = FuncionesCrypto.cifrarAES(llaveAES, IV, respuestaCliente);
                byte[] hmacRespuesta = FuncionesCrypto.generarHMAC(llaveHMAC, respuestaCifrada);

                out.writeInt(respuestaCifrada.length);
                out.write(respuestaCifrada);
                out.writeInt(hmacRespuesta.length);
                out.write(hmacRespuesta);
                System.out.println("[Servidor] Respuesta cifrada enviada al cliente");

                // Paso 18: Esperar confirmación OK
                System.out.println("[Servidor] Esperando respuesta del cliente");
                String finalConfirm = in.readUTF();
                if (finalConfirm.equals("OK")) {
                    System.out.println("[Servidor] Transacción finalizada exitosamente");
                } else {
                    System.out.println("[Servidor] El cliente reportó un error en la respuesta");
                }
            }

            /* 
            // Paso 14
            System.out.println("[Servidor] Esperando solicitud del cliente");
            int tamDatos = in.readInt();
            byte[] datosCifrados = new byte[tamDatos];
            in.readFully(datosCifrados);

            int tamHMAC = in.readInt();
            byte[] hmacRecibido = new byte[tamHMAC];
            in.readFully(hmacRecibido);
            System.out.println("[Servidor] Solicitud recibida del cliente");

            //Paso 15
            System.out.println("[Servidor] Verificando HMAC");

            long tiempoInicioVerificacion = System.nanoTime();

            boolean valido = FuncionesCrypto.verificarHMAC(llaveHMAC, datosCifrados, hmacRecibido);

            long tiempoFinVerificacion = System.nanoTime();
            long tiempoVerificacion = tiempoFinVerificacion - tiempoInicioVerificacion;
            System.out.println("[Servidor] Tiempo para verificar HMAC: " + tiempoVerificacion + " ns");

            if (!valido) {
                out.writeUTF("ERROR");
                System.out.println("[Servidor] HMAC inválido en solicitud");
                return;
            }

            String solicitud = new String(FuncionesCrypto.descifrarAES(llaveAES, IV, datosCifrados));
            System.out.println("[Servidor] Solicitud del cliente: " + solicitud);

            String[] partes = solicitud.split("\\+");
            int idServicio = Integer.parseInt(partes[0]);
            String ipCliente = partes[1];

            String respuestaCliente;
            if (!tablaServicios.containsKey(idServicio)) {
                respuestaCliente = "-1,-1"; 
            } else {
                String ipServidor = socketCliente.getLocalAddress().getHostAddress();
                int puerto = 5000 + idServicio;
                respuestaCliente = ipServidor + "," + puerto;
            }
            System.out.println("[Servidor] Respuesta al cliente: " + respuestaCliente);

            // Paso 16
            System.out.println("[Servidor] Cifrando respuesta");
            byte[] respuestaCifrada = FuncionesCrypto.cifrarAES(llaveAES, IV, respuestaCliente);
            byte[] hmacRespuesta = FuncionesCrypto.generarHMAC(llaveHMAC, respuestaCifrada);

            out.writeInt(respuestaCifrada.length);
            out.write(respuestaCifrada);
            out.writeInt(hmacRespuesta.length);
            out.write(hmacRespuesta);
            System.out.println("[Servidor] Respuesta cifrada enviada al cliente");

            // Paso 18
            System.out.println("[Servidor] Esperando respuesta del cliente");
            String finalConfirm = in.readUTF();
            if (finalConfirm.equals("OK")) {
                System.out.println("[Servidor] Transacción finalizada exitosamente");
            } else {
                System.out.println("[Servidor] El cliente reportó un error en la respuesta");
            }
            */



        } catch (Exception e) {
            System.err.println("[Servidor] Error durante la ejecución del protocolo: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                socketCliente.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

