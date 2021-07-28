import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * CLI that drives the AESGCMCrypt class. Using the CLI you can encrypt/decrypt
 * files, change the key size and iv size, display a help menu, and quit the program.
 */
public class CryptMain {

    public static void main(String[] args) {
        String menu = "+---------------------------------------------------------------+\n" +
                "|              AES-GCM File encryptor/decryptor                 |\n" +
                "|                           by: vsnoopy                         |\n" +
                "+---------------------------------------------------------------+\n" +
                "|                        Available commands                     |\n" +
                "| 'e' => encrypt a file                                         |\n" +
                "| 'd' => decrypt a file                                         |\n" +
                "| 's' => settings                                               |\n" +
                "| 'h' => help                                                   |\n" +
                "| 'q' => exit program                                           |\n" +
                "+---------------------------------------------------------------+\n";

        AESGCMCrypt crypt = new AESGCMCrypt();
        Scanner scanner = new Scanner(System.in);
        String choice;

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
                    System.out.println("Current settings: ");
                    System.out.println("key length = " + crypt.getKeyLength() + "\nIV length = " + crypt.getIvLength() + "\n");

                    if (!requestConfirmation(scanner)) break;

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

                    System.out.println("Generating IV...");
                    byte[] iv = crypt.createIV();

                    System.out.println("Generating key...");
                    try {
                        key = crypt.generateSecretKey(password, iv);
                    } catch (CryptException e) {
                        System.out.println("Error: could not generate key");
                        break;
                    }

                    System.out.println("Encrypting...");
                    try {
                        encData = crypt.encrypt(data, key, iv);
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
                    System.out.println(filepath + " has been successfully encrypted.\n");
                    System.out.println("File formatted as follows: \n\t IV_LENGTH | IV | ENCRYPTED DATA\n");
                    System.out.println("========Encryption Information=======");
                    System.out.println("key (hex, save this somewhere secure): " + bytesToHex(key));
                    System.out.println("IV length (stored in file): " + iv.length);
                    System.out.println("IV (hex, also stored in file): " + bytesToHex(iv));
                    break;

                case "d": //decrypt
                    System.out.println("Current settings: ");
                    System.out.println("key length = " + crypt.getKeyLength() + "\nIV length = " + crypt.getIvLength() + "\n");

                    if (!requestConfirmation(scanner)) break;

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
                            iv = crypt.getIV(encData);
                            System.out.println("Decrypting...");
                            try {
                                key = crypt.generateSecretKey(password, iv);
                                data = crypt.decrypt(encData, key);
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
                                data = crypt.decrypt(encData, key);
                                writeBytesToFile(filepath.replace(".glm8", ""), data);
                                System.out.println(filepath + " successfully decrypted...");
                                break;
                            } catch (CryptException | IOException e) {
                                System.out.println("Error: invalid key.");
                                if (!requestConfirmation(scanner, "Try again? (y/n): ")) {
                                    break;
                                }
                            }
                        }
                    }
                    break;

                case "s": // Settings
                    int keyLength = crypt.getKeyLength();
                    int ivLength = crypt.getIvLength();

                    System.out.println("Current settings: ");
                    System.out.println("key length = " + keyLength + "\nIV length = " + ivLength + "\n");

                    while(requestConfirmation(scanner, "Do you want to change the key length? (y/n): ")) {
                            System.out.print("Enter key size (128,196,256,512): ");
                            keyLength = Integer.parseInt(scanner.nextLine());
                            if (keyLength == 128 || keyLength == 196 || keyLength == 256 || keyLength == 512) {
                                crypt.setKeyLength(keyLength);
                                break;
                            } else System.out.println("Error: invalid key length");
                    }
                    if (requestConfirmation(scanner, "Do you want to change the iv length? (y/n): ")) {
                        System.out.print("Enter iv size (recommended you use 12 or 16): ");
                        ivLength = Integer.parseInt(scanner.nextLine());
                        crypt.setIvLength(ivLength);
                    }
                    System.out.println("Updated settings:");
                    System.out.println("key length = " + keyLength + "\nIV length = " + ivLength + "\n");
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
