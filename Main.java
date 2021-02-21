import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;


public class Main {
    public static void main(String[] args)
            throws NoSuchAlgorithmException, InvalidKeyException {
        if (!checkArgs(args)) return;
        int compChoice = getCompChoice(args.length);
        String keyString = getKey();
        printHMAC(args[compChoice], keyString);
        int userChoice = getChoice(args);
        if (userChoice == -1) return;
        String winner = whoIsWin(compChoice, userChoice, args.length);
        System.out.println("your move: " + args[userChoice] + "\ncomputer move: " + args[compChoice]);
        System.out.println(winner);
        System.out.println("HMAC key: " + keyString);
    }

    public static boolean checkArgs(String[] args) {
        if (args.length < 3 || args.length % 2 == 0) {
            System.out.println("There must be at least 3 odd arguments. For example:\n" +
                    "\'rock paper scissors\' or \'rock paper scissors lizard Spock\'");
            return false;
        }
        Set<String> st = new HashSet<>();
        for (String key : args) {
            if (!st.add(key)) {
                System.out.println("All elements must be different. For example:\n" +
                        "\'rock paper scissors\' not \'rock paper rock\'");
                return false;
            }
        }
        return true;
    }

    public static int getCompChoice(int length) {
        int a = (int) (Math.random() * length);
        return a;
    }

    public static String getKey() {
        SecureRandom rand = new SecureRandom();
        byte[] key = new byte[16];
        rand.nextBytes(key);
        String keyString = hex(key);
        return keyString;
    }

    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes) {
            result.append(String.format("%02x", aByte));
        }
        return result.toString().toUpperCase();
    }

    public static void printHMAC(String value, String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] hmac256 = calculateHMAC(value.getBytes(), key.getBytes());
        String hmac256StringValue = hex(hmac256);
        System.out.println("HMAC:\n" + hmac256StringValue);
    }

    public static byte[] calculateHMAC(byte[] data, byte[] key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    public static int getChoice(String[] args) {
        while (true) {
            System.out.println("Available moves:");
            for (int i = 0; i < args.length; i++)
                System.out.println(i + 1 + " - " + args[i]);
            System.out.print("0 - exit\nEnter your move: ");
            Scanner scan = new Scanner(System.in);
            int choice;
            try {
                choice = scan.nextInt();
            } catch (NoSuchElementException | IllegalStateException e) {
                continue;
            }
            if (choice < 0 || choice > args.length) continue;
            return choice - 1;
        }
    }

    public static String whoIsWin(int comp, int user, int lenth) {
        if (comp == user) return "Draw!";
        int i = 0;
        while (i < (lenth - 1) / 2) {
            if (++comp % lenth == user) {
                return "You win!";
            }
            i++;
        }
        return "Computer win!";
    }
}
