package com.johanpmeert;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Bech32;
import org.bitcoinj.core.ECKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

import static org.bitcoinj.core.Utils.sha256hash160;

public class Main {

    public static String vanityString = "jpmrt";
    public static AtomicLong bech32Counter = new AtomicLong(1);
    public static final long starttime = System.nanoTime();
    public static volatile boolean stopCalled = false;
    public static final int NUMBER_OF_THREADS = 8;

    public static void main(String[] args) {
        System.out.println("Bitcoin Bech32 vanity key generator");
        System.out.println("-----------------------------------");
        System.out.println("Looking for " + vanityString + " with " + NUMBER_OF_THREADS + " threads");
        if (!vanityString.toLowerCase(Locale.ROOT).equals(vanityString)) {
            System.out.println("String contains uppercase characters, illegal");
            System.exit(0);
        }
        if (vanityString.matches(".*[1bio]")) {
            System.out.println("String cannot contain any character of the following list: 1 b i o");
            System.exit(0);
        }
        ExecutorService exec = Executors.newFixedThreadPool(NUMBER_OF_THREADS);
        Runnable vanityThreadLambda = () -> {
            final String upperLimit = "F".repeat(56);
            SecureRandom sR = new SecureRandom();
            // DigitalRandom sr = new DigitalRandom();
            byte[] random32bytes = new byte[32];
            while (!stopCalled) {
                // sr.nextBytes(random32bytes);
                sR.nextBytes(random32bytes);
                String hexRandom = byteArrayToHexString(random32bytes);
                if (hexRandom.substring(0, 55).equals(upperLimit)) {
                    continue;
                }
                // generate compressed Public key
                String compressedPubKey = privToCompressedPublic(hexRandom);
                // generate Bech32 address
                String rawCompressedBitcoinAddress = hashShaRipemd(compressedPubKey);
                String PubKey5bit = hexString8To5bit(rawCompressedBitcoinAddress);
                PubKey5bit = "00" + PubKey5bit;
                String bech32String = Bech32.encode("bc", hexStringToByteArray(PubKey5bit));
                if (bech32String.contains(vanityString)) {
                    String privCompressedKey = Base58CheckEncode("80" + hexRandom + "01");
                    System.out.println("\nPrivate key (WIF): " + privCompressedKey);
                    System.out.println("Bech32 Bitcoin address: " + bech32String);
                    long stoptime = System.nanoTime();
                    System.out.println("That took " + (stoptime - starttime) / 1.0e9 + " seconds");
                    long bech32Counter2 = bech32Counter.longValue();
                    System.out.println("Speed: " + bech32Counter2 * 1.0e9 / (stoptime - starttime) + " addresses/sec");
                    System.out.println("Executed on " + NUMBER_OF_THREADS + " threads");
                    System.out.println("Thread " + Thread.currentThread().getName() + " found solution");
                    stopCalled = true;
                    return;
                }
                bech32Counter.incrementAndGet();
            }
            exec.shutdown();
        };
        for (int teller = 0; teller < NUMBER_OF_THREADS; teller++) {
            exec.execute(vanityThreadLambda);
        }
    }

    public static String Base58CheckEncode(String address) {
        String base58encoded = "";
        byte[] checksum1 = hexStringToByteArray(address);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] checksum2 = md.digest(checksum1);  // first SHA256 hash
            byte[] checksum3 = md.digest(checksum2);  // second SHA256 hash
            String checksum4 = byteArrayToHexString(checksum3);
            address = address + checksum4.substring(0, 8);  // take the first 4 bytes of the double hash and add them at the end of the original hex string
            base58encoded = Base58.encode(hexStringToByteArray(address));  // encode with base58
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return base58encoded;
    }

    public static String hexString8To5bit(String convert) {
        // converts a hex string into a 5bit encoded hex string
        // so the output string contains only 00h up to 19h (and not 00h-FFh)
        StringBuilder binaryString = new StringBuilder(new BigInteger(convert, 16).toString(2)); // convert our hex String to binary
        int bitCounter = (int) (5.0 * Math.ceil(binaryString.length() / 5.0));
        while (binaryString.length() < bitCounter) {
            binaryString.insert(0, "0"); // make sure that the string has multiple of 5 in number of bits, padding with 0 in front if necessary
        }
        byte[] bit5 = new byte[bitCounter / 5];
        for (int teller = 0; teller < (bitCounter / 5); teller++) {
            String next5Bits = binaryString.substring(0, 5); // take the first 5 bits
            binaryString = new StringBuilder(binaryString.substring(5)); // erase those 5 bits from remainder
            bit5[teller] = Byte.parseByte(next5Bits, 2); // converted the 5 bits to a byte and put it in the byte[]
        }
        return byteArrayToHexString(bit5); // convert back to HEX
    }

    public static byte[] privToCompressedPublic(byte[] address) {
        ECKey key = ECKey.fromPrivate(address);
        return key.getPubKey();
    }

    public static String privToCompressedPublic(String address) {
        return byteArrayToHexString(privToCompressedPublic(hexStringToByteArray(address)));
    }

    public static byte[] hashShaRipemd(byte[] address) {
        return sha256hash160(address);
    }

    public static String hashShaRipemd(String address) {
        return byteArrayToHexString(hashShaRipemd(hexStringToByteArray(address)));
    }

    public static byte[] hexStringToByteArray(String hex) {
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
