import java.io.IOException;
import java.util.Scanner;

public class CryptMain {
    public static void main(String[] args) {
        String choice;
        String menu = """
                +---------------------------------------------------------------+
                |              AES-GCM-128 File encryptor/decryptor             |
                |                           by: vsnoopy                         |
                +---------------------------------------------------------------+
                |                        Available commands                     |
                | 'e' => encrypt a file                                         |
                | 'd' => decrypt a file                                         |
                | 'h' => help                                                   |
                | 'q' => exit program                                           |
                +---------------------------------------------------------------+
                """;

        AESGCMCrypt aesgcmCrypt = new AESGCMCrypt();
        Scanner scanner = new Scanner(System.in);

        System.out.print(menu);

        do {
            byte[] data;
            byte[] encData;
            byte[] key;
            String filepath;
            String password;

            choice = getInput(scanner);

            switch (choice) {

                case "e": //encrypt
                    System.out.print("File to encrypt (if file is not in same dir, use absolute path): ");
                    try {
                        filepath = getInput(scanner);
                        data = CryptFM.readFileToBytes(filepath);
                    } catch (IOException e) {
                        System.out.println("Error: file cannot be found");
                        break;
                    }

                    System.out.print("Password (dont forget or you cant decrypt): ");
                    password = getInput(scanner);

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
                        CryptFM.writeBytesToFile(filepath + ".glm8", encData);
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
                        filepath = getInput(scanner);
                        encData = CryptFM.readFileToBytes(filepath);
                    } catch (IOException e) {
                        System.out.print("Error: file cannot be found");
                        break;
                    }

                    while(true) {
                        if (requestConfirmation(scanner, "Decryption method (y=password/n=key): ")) {
                            System.out.print("Enter password: ");
                            password = getInput(scanner);
                            iv = aesgcmCrypt.getIV(encData);
                            System.out.println("Decrypting...");
                            try {
                                key = aesgcmCrypt.generateSecretKey(password, iv);
                                data = aesgcmCrypt.decrypt(encData, key);
                                CryptFM.writeBytesToFile(filepath.replace(".glm8", ""), data);
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
                            key = hexStringToByteArray(getInput(scanner));
                            System.out.println("Decrypting...");
                            try {
                                data = aesgcmCrypt.decrypt(encData, key);
                                CryptFM.writeBytesToFile(filepath.replace(".glm8", ""), data);
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
                    System.out.print("""
                            +---------------------------------------------------------------+
                            |                        Available commands                     |
                            | 'e' => encrypt a file                                         |
                            | 'd' => decrypt a file                                         |
                            | 'h' => help                                                   |
                            | 'q' => exit program                                           |
                            +---------------------------------------------------------------+
                            """);
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
        return new String(hexChars);
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

    private static String getInput(Scanner scanner) {
        System.out.print("Crypt# ");
        return scanner.nextLine();
    }
}
