import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * CLI that implements the AESGCMCrypt class. Using the CLI you can encrypt/decrypt
 * files, display a help menu, and quit the program.
 */
public class CryptMain {
    public static void main(String[] args) {
        String choice;
        StringBuilder sb = new StringBuilder();

        sb.append("+---------------------------------------------------------------+\n");
        sb.append("|              AES-GCM-128 File encryptor/decryptor             |\n");
        sb.append("|                           by: vsnoopy                         |\n");
        sb.append("+---------------------------------------------------------------+\n");
        sb.append("|                        Available commands                     |\n");
        sb.append("| 'e' => encrypt a file                                         |\n");
        sb.append("| 'd' => decrypt a file                                         |\n");
        sb.append("| 'h' => help                                                   |\n");
        sb.append("| 'q' => exit program                                           |\n");
        sb.append("+---------------------------------------------------------------+\n");
        String menu = sb.toString();

        AESGCMCrypt aesgcmCrypt = new AESGCMCrypt(128,12);
        Scanner scanner = new Scanner(System.in);

        System.out.print(menu);

        do {
            byte[] data;
            byte[] encData;
            byte[] key;
            String filepath;
            String password;

            System.out.print("Crypt# ");
            choice = scanner.nextLine();

            switch (choice) {

                case "e": //encrypt
                    System.out.print("File to encrypt (if file is not in same dir, use absolute path): ");
                    try {
                        filepath = scanner.nextLine();
                        data = readFileToBytes(filepath);
                    } catch (IOException e) {
                        System.out.println("Error: file cannot be found");
                        break;
                    }

                    System.out.print("Password (dont forget or you cant decrypt): ");
                    password = scanner.nextLine();

                    if (!requestConfirmation(scanner)) break;

                    System.out.println("Generating IV...");
                    byte[] iv = aesgcmCrypt.createIV();

                    System.out.println("Generating key...");
                    try {
                        key = aesgcmCrypt.generateSecretKey(password, iv);
                    } catch (CryptException e) {
                        System.out.println("Error: could not generate key");
                        break;
                    }

                    System.out.println("Encrypting...");
                    try {
                        encData = aesgcmCrypt.encrypt(data, key, iv);
                    } catch (CryptException e) {
                        System.out.println("Error: could not encrypt");
                        break;
                    }

                    System.out.println("Writing encrypted file...");
                    try {
                        writeBytesToFile(filepath + ".glm8", encData);
                    } catch (IOException ex) {
                        System.out.println("Error: could not write encrypted data");
                        break;
                    }
                    System.out.println(filepath + " has been successfully encrypted.");
                    System.out.println("File formatted as follows: \n\t IV_LENGTH | IV | ENCRYPTED DATA");
                    System.out.println("key (hex, save this somewhere secure): " + bytesToHex(key));
                    System.out.println("IV length: " + iv.length);
                    System.out.println("IV (hex): " + bytesToHex(iv));
                    break;

                case "d": //decrypt
                    System.out.print("File to decrypt (if file is not in same dir, use absolute path): ");
                    try {
                        filepath = scanner.nextLine();
                        encData = readFileToBytes(filepath);
                    } catch (IOException e) {
                        System.out.print("Error: file cannot be found");
                        break;
                    }

                    while(true) {
                        if (requestConfirmation(scanner, "Decryption method (y=password/n=key): ")) {
                            System.out.print("Enter password: ");
                            password = scanner.nextLine();
                            iv = aesgcmCrypt.getIV(encData);
                            System.out.println("Decrypting...");
                            try {
                                key = aesgcmCrypt.generateSecretKey(password, iv);
                                data = aesgcmCrypt.decrypt(encData, key);
                                writeBytesToFile(filepath.replace(".glm8", ""), data);
                                System.out.println(filepath + " successfully decrypted...");
                                break;
                            } catch (CryptException | IOException e) {
                                System.out.println("Error: invalid password...");
                                if (!requestConfirmation(scanner, "Try again? (y/n): ")) {
                                    break;
                                }
                            }

                        } else {
                            System.out.print("Enter key (hex format): ");
                            key = hexStringToByteArray(scanner.nextLine());
                            System.out.println("Decrypting...");
                            try {
                                data = aesgcmCrypt.decrypt(encData, key);
                                writeBytesToFile(filepath.replace(".glm8", ""), data);
                                System.out.println(filepath + " successfully decrypted...");
                                break;
                            } catch (CryptException | IOException e) {
                                System.out.println("Error: invalid key");
                                if (!requestConfirmation(scanner, "Try again? (y/n): ")) {
                                    break;
                                }
                            }
                        }
                    }
                    break;

                case "h": //display menu
                    System.out.print(menu);
                    break;

                case "q": //quit
                    break;
                default:
                    System.out.println(choice + " is not a valid Menu Option! Please Select Another.");
            }
        } while (!choice.equals("q"));

        //Exit commands
        System.out.print("Exiting...");
        scanner.close();
    }

    private static boolean requestConfirmation(Scanner scanner) {
        while (true) {
            System.out.print("Are you sure you want to continue? (y/n): ");
            String in = scanner.nextLine().toLowerCase();
            if (in.equals("y") || in.equals("yes"))
                return true;
            else if (in.equals("n") || in.equals("no"))
                return false;
        }
    }
    private static boolean requestConfirmation(Scanner scanner, String msg) {
        while (true) {
            System.out.print(msg);
            String in = scanner.nextLine().toLowerCase();
            if (in.equals("y") || in.equals("yes"))
                return true;
            else if (in.equals("n") || in.equals("no"))
                return false;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return String.valueOf(hexChars);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static void writeBytesToFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            fileOutputStream.write(data);
        }
    }

    private static byte[] readFileToBytes(String file) throws IOException {
        Path path = Paths.get(file);
        return Files.readAllBytes(path);
    }
}
