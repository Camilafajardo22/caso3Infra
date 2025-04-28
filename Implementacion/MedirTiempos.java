import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class MedirTiempos {

    private static final String ARCHIVO = "tiemposConcurrente16.csv";
    private static String escenario;

    public MedirTiempos(String escenario) {
        this.escenario = escenario;
    }

    public static synchronized void guardarTiempo(String operacion, long tiempoNano) {
        try (PrintWriter out = new PrintWriter(new FileWriter(ARCHIVO, true))) {
            double tiempoMs = tiempoNano / 1_000_000.0;
            out.println(escenario + "," + operacion + "," + tiempoMs);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

