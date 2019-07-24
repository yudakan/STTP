package com.yudakan.sttp;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;

/**
 * -- STTP --
 * Sequential Two Times Pad
 * Tunnel Class
 *
 * @author yka
 * @version 1.0
 */
public final class Tunnel {

    /* Attributes */
    private DataInputStream in;
    private DataOutputStream out;
    private PrintStream log;
    private Key myKey, kyoriKey;

    private byte whoami = -1;

    final private Calendar cal = Calendar.getInstance();
    final private SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy 'at' HH:mm:ss");


    /* Constructors */
    private Tunnel() {}

    private Tunnel(Builder builder) {
        this.in = builder.in;
        this.out = builder.out;
        this.log = builder.log;
        this.myKey = builder.myKey;
        this.kyoriKey = builder.kyoriKey;
    }

    public static class Builder {

        /* Attributes */
        private DataInputStream in;
        private DataOutputStream out;
        private PrintStream log;
        private Key myKey, kyoriKey;


        /* Constructors */
        public Builder() {}


        /* Methods */
        // public
        public Builder setIn(InputStream in) {
            this.in = new DataInputStream(in);
            return this;
        }

        public Builder setOut(OutputStream out) {
            this.out = new DataOutputStream(out);
            return this;
        }

        public Builder setLog(OutputStream log) {
            this.log = new PrintStream(log, true);
            return this;
        }

        public Builder setMyKey(Key myKey) {
            this.myKey = myKey;
            return this;
        }

        public Builder setKyoriKey(Key kyoriKey) {
            this.kyoriKey = kyoriKey;
            return this;
        }

        public Tunnel build() throws IllegalStateException, IOException {
            try {
                if (in == null)           in = new DataInputStream(System.in);
                if (out == null)          out = new DataOutputStream(System.out);
                if (log == null)          log = new PrintStream(System.err, true);
                if (myKey == null)        myKey = new Key(new File(Key.DEFAULT_PATH_MYKEY));
                if (kyoriKey == null)     kyoriKey = new Key(new File(Key.DEFAULT_PATH_KYORIKEY));

                return new Tunnel(this);
            }
            catch (FileNotFoundException e) {
                throw new IllegalStateException("There are no keys created in default directory.");
            }
        }
    }


    /* Methods */
    public boolean push(byte[] msg, boolean passByValue) { // Send message

        // Who am I?
        if (whoami == -1) whoami = 0;

        // Vars
        final int nChests;
        final byte[] header; // msgLen
        byte[] hash = null;
        byte[] msgf = new byte[myKey.getMsgfLen()];
        byte[] newKeyNoCrypt = new byte[myKey.getLength()];
        byte[] newKey = new byte[myKey.getLength()];

        // Get msg
        msg = passByValue ? msg.clone() : msg;

        // Initialize final vars
        nChests = (int)Math.ceil( (double)msg.length / myKey.getMsgfLen() );
        header = ByteBuffer.allocate(4).putInt(msg.length).array();

        // Any Chest //
        // i -> count chests
        // j -> count bytes of message per chest
        // k -> count bytes of message per whole message
        for (int i=0, j, k=0; i < nChests; i++) {

            // Get piece of msg
            if (i != nChests-1) {
                for (j=0; j < myKey.getMsgfLen(); j++, k++)
                    msgf[j] = msg[k];
            }
            else { // Last iteration
                for (j=0; k < msg.length; j++, k++)
                    msgf[j] = msg[k];
            }

            // Generate hash & new key
            hash = Hash.create(msgf);
            Key.Keygen.generate(newKeyNoCrypt);
            System.arraycopy(newKeyNoCrypt, 0, newKey, 0, newKey.length);

            // Encrypt
            xor(myKey.getKey_ByRef(), hash, msgf);
            xor(myKey.getKey_ByRef(), newKey);

            // Update actual key
            System.arraycopy(newKeyNoCrypt, 0, myKey.getKey_ByRef(), 0, myKey.getLength());

            // Send
            try {
                if (i == 0) out.write(header);
                out.write(hash);
                out.write(msgf);
                out.write(newKey);
                out.flush();
            }
            catch (IOException e) {
                error("IOException when trying to send data in push method.", e, i, nChests, k, msg.length);
                return false;
            }
        }

        return true;
    }

    public void push(byte[] msg) {
        push(msg, false);
    }

    public byte[] pull() { // Receive message

        // Who am I?
        if (whoami == -1) {
            Key tempKey = myKey;
            myKey = kyoriKey;
            kyoriKey = tempKey;
            whoami = 1;
        }

        // Vars
        final int nChests;
        byte[] msg;
        byte[] header = new byte[4];
        byte[] hash = new byte[Hash.length()];
        byte[] msgf = new byte[kyoriKey.getMsgfLen()];
        byte[] newKey = new byte[kyoriKey.getLength()];
        ByteArrayInputStream in;

        // Get header --> msgLen
        try {
            this.in.readFully(header);
            msg = new byte[ByteBuffer.wrap(header).asIntBuffer().get()];
        }
        catch (IOException e) {
            error("IOException when trying to get header in pull method.", e, 0, 0, 0, 0);
            return null;
        }

        // Get all chests
        try {
            nChests = (int) Math.ceil((double) msg.length / kyoriKey.getMsgfLen());
            byte[] dataInput = new byte[nChests * kyoriKey.getChestSize()];
            this.in.readFully(dataInput);
            in = new ByteArrayInputStream(dataInput);
        }
        catch (IOException e) {
            error("IOException when trying to get all input data.", e, 0, 0, 0, msg.length);
            return null;
        }

        // Any Chest //
        // i -> count chests
        // j -> count bytes of message per chest
        // k -> count bytes of message per whole message
        for (int i=0, j, k=0; i < nChests; i++) {

            // Receive
            try {
                in.read(hash);
                in.read(msgf);
                in.read(newKey);
                i++; // Num Chests
            }
            catch (IOException e) {
                error("IOException when trying to receive data in pull method.", e, i, nChests, k, msg.length);
                return null;
            }

            // Decrypt
            xor(kyoriKey.getKey_ByRef(), hash, msgf);
            xor(kyoriKey.getKey_ByRef(), newKey);

            // Check integrity
            if (!Arrays.equals(hash, Hash.create(msgf))) {
                error("Hash error: Corrupted Integrity or Wrong Key.", null, i, nChests, k, msg.length);
                return null;
            }

            // Update key
            System.arraycopy(newKey, 0, kyoriKey.getKey_ByRef(), 0, kyoriKey.getLength());

            // Building msg...
            for (j=0; j < msgf.length && k < msg.length; k++, j++)
                msg[k] = msgf[j];
        }

        return msg;
    }

    public boolean saveKeys() {
        try {
            if (whoami == 0)      Key.pack(myKey, kyoriKey);
            else if(whoami == 1)  Key.pack(kyoriKey, myKey);

            return true;
        }
        catch (IOException e) { return false; }
    }

    public boolean close(boolean inClose, boolean outClose, boolean logClose) { // Close streams & save keys
        try {
            saveKeys();

            if (inClose) in.close();
            if (outClose) out.close();
            if (logClose) log.close();

            return true;
        }
        catch (IOException e) { return false; }
    }

    public boolean close() {
        return close(true, true, true);
    }

    private void error(String issue, Exception e, int i, int nChests, int k, int msgLen) {
        log.println("------------------------------------------------------------");
        log.println(issue);
        log.println("Time:              " + sdf.format(cal.getTime()));
        log.println("Actual keys saved: " + (saveKeys() ? "Yes" : "No"));
        log.println("Actual chests:     " + i+1 + '/' + nChests);
        log.println("Actual bytes msg:  " + k+1 + '/' + msgLen);
        log.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        if (e != null) e.printStackTrace(log);
    }

    public static void xor(byte[] key, byte[] arr) {
        for (int i=0; i < key.length; i++)
            arr[i] ^= key[i];
    }

    public static void xor(byte[] key, byte[] arr1, byte[] arr2) {
        int k=0, i;

        for (i=0; i < arr1.length; i++, k++)
            arr1[i] ^= key[k];

        for (i=0; i < arr2.length; i++, k++)
            arr2[i] ^= key[k];
    }
}
