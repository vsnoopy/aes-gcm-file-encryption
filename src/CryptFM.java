import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CryptFM {

    public static byte[] readFileToBytes(String file) throws IOException {
        Path path = Paths.get(file);
        return Files.readAllBytes(path);
    }

    public static void writeBytesToFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            fileOutputStream.write(data);
        }
    }
}
