package com.yudakan.sttp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * -- STTP --
 * Sequential Two Times Pad
 * Key Class
 *
 * @author yka
 * @version 1.0
 */
public final class Key {

    /* Attributes */
    public static final String DEFAULT_PATH_MYKEY = "./.packetKeys/myKey";
    public static final String DEFAULT_PATH_KYORIKEY = "./.packetKeys/kyoriKey";
    private int chestSize, msgfLen; // bytes of message per chest
    private byte[] key;
    private File keyFile;


    /* Constructors */
    private Key() {}

    public Key(File f) throws IllegalStateException, IOException {
        if (f.length() > Integer.MAX_VALUE)
            throw new IllegalStateException("Key File too big.");
        if (f.length() < Hash.length()+1)
            throw new IllegalStateException("Key File too small.");

        key = loadBytesAs(f);
        chestSize = key.length*2;
        msgfLen = key.length-Hash.length();
        keyFile = f;
    }

    private Key(Keygen keygen) {
        this.chestSize = keygen.chestSize;
        this.msgfLen = keygen.msgfLen;
        this.key = keygen.key;
        this.keyFile = keygen.keyFile;
    }

    public static class Keygen {

        /* Attributes */
        private int chestSize, msgfLen;
        private byte[] key;
        private File keyFile;


        /* Constructors */
        public Keygen() {
            msgfLen = 512;
            chestSize = (msgfLen+Hash.length()) * 2;
        }


        /* Methods */
        public Keygen setChestSize(int chestSize) throws IllegalArgumentException {
            if (chestSize < (1+Hash.length())*2)
                throw new IllegalArgumentException("Chest Size too small.");
            if (chestSize % 2 != 0)
                throw new IllegalArgumentException("Chest Size must be even.");

            this.chestSize = chestSize;
            msgfLen = chestSize/2 - Hash.length();

            return this;
        }

        public Keygen setBmpc(int msgfLen) throws IllegalArgumentException {
            if (msgfLen < 1)
                throw new IllegalArgumentException("Bytes Of Message Per Chest must be a natural number.");

            this.msgfLen = msgfLen;
            chestSize = (msgfLen + Hash.length()) * 2;

            return this;
        }

        public Keygen setKeyFile(File f) throws IllegalArgumentException, IOException {
            keyFile = createReplaceFile(f);
            return this;
        }

        public Keygen setLength(int len) throws IllegalArgumentException {
            if (len < 1+Hash.length())
                throw new IllegalArgumentException("Key size too small.");

            chestSize = len*2;
            msgfLen = len - Hash.length();

            return this;
        }

        public Key build() {
            key = new byte[chestSize/2];
            generate(key);
            return new Key(this);
        }

        public static void generate(byte[] key) {
            try {
                SecureRandom rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
                rand.nextBytes(key);
            }
            catch (Exception e) {
                throw new IllegalStateException(e.getMessage());
            }
        }
    }


    /* Getters & Setters */
    public int getChestSize() {
        return chestSize;
    }

    public int getMsgfLen() {
        return msgfLen;
    }

    public int getLength() {
        return key.length;
    }

    public byte[] getKey() {
        return key.clone();
    }

    public byte[] getKey_ByRef() {
        return key;
    }

    public File getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(File f) throws IOException {
        keyFile = createReplaceFile(f);
    }


    /* Methods */
    public static File createReplaceFile(File f) throws IllegalArgumentException, IOException {
        if (f.isDirectory())
            throw new IllegalArgumentException("This is not a file, it's a directory.");

        if (!f.exists() && f.getParentFile().mkdirs()) f.createNewFile();
        return f;
    }

    public static byte[] loadBytesAs(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        byte[] key = new byte[(int)f.length()];
        in.read(key);
        in.close();

        return key;
    }

    public static void saveBytesAs(byte[] bytes, File f) throws IOException {
        FileOutputStream out = new FileOutputStream(f);
        out.write(bytes);
        out.close();
    }

    public static void pack(Key myKey, Key kyoriKey) throws IOException {
        if (myKey.getKeyFile() == null)    myKey.saveAs(new File(DEFAULT_PATH_MYKEY));
        else                               myKey.save();
        if (kyoriKey.getKeyFile() == null) kyoriKey.saveAs(new File(DEFAULT_PATH_KYORIKEY));
        else                               kyoriKey.save();
    }

    public void save() throws IllegalStateException, IOException {
        if (keyFile == null)
            throw new IllegalStateException("Key File not specified.");

        saveBytesAs(key, keyFile);
    }

    public void saveAs(File f) throws IllegalArgumentException, IOException {
        saveBytesAs(key, createReplaceFile(f));
        keyFile = f;
    }
}
