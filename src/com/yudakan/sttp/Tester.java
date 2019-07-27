package com.yudakan.sttp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * -- STTP --
 * Sequential Two Times Pad
 * Tester Class
 *
 * @author yka
 * @version 1.0
 */
public final class Tester {
    private Tester() {}

    /* MAIN */
    public static void main(String[] args) throws Exception {

        // Generate Keys
        Key apurochiKey = new Key.Keygen().setBmpc(16).build();
        Key kyoriKey = new Key.Keygen().build();
        Key.pack(apurochiKey, kyoriKey);

        // Variables
        int port   = args.length > 0 ? Integer.parseInt(args[0]) : TCP.DEFAULT_PORT;
        byte[] msg = args.length > 1 ? args[1].getBytes() : TCP.DEFAULT_MSG;

        // Create and run server in a new threat
        Server server = new Server(port, msg);
        server.start();

        // Create and run client in a new threat
        Client client = new Client(port);
        client.start();

        // Order to stop and wait for it
        client.stop();
        server.stop();

        // Check messages
        System.out.println("*** Server sent by port " + server.getPort() + ':');
        System.out.println(new String(server.getSms()));
        System.out.println();
        System.out.println("*** Client received by port " + client.getPort() + ':');
        System.out.println(new String(client.getSms()));
    }
}

abstract class TCP implements Runnable {

    /* Attributes */
    public static final int DEFAULT_PORT;
    public static final byte[] DEFAULT_MSG;

    protected volatile Thread th;
    protected volatile boolean running;
    protected volatile ServerSocket serverSocket;
    protected volatile Socket socket;
    protected volatile DataInputStream in;
    protected volatile DataOutputStream out;
    protected volatile int port;
    protected volatile byte[] msg;

    static {
        DEFAULT_PORT = 4097;
        DEFAULT_MSG = ("After accidentally breaking a statue of a kappa that serves as the guardian god of Asakusa, middleschool" +
                "students Kazuki, Toi, and Enta are transformed into kappas by Keppi, the prince of the KappaKingdom. " +
                "They come to assist Keppi in collecting the Dishes of Hope, which fulfill the wishes ofwhoever" +
                "possesses them. Dishes are acquired by collecting the shirikodama of zombies created by Reoand Mabu, " +
                "agents of the Otter Empire that has warred with the Kappa Kingdom for generations.To defeat the zombies, " +
                "the boys must make the sound \"Sarazanmai\", which can only be produced whenthe three are united. " +
                "They struggle to connect, as each time the sound is made, one of the boys'secrets is revealed.")
                .getBytes();
    }

    {
        port = DEFAULT_PORT;
    }


    /* Constructors */
    public TCP() {}

    public TCP(int port) {
        this.port = port;
    }


    /* Getters & Setters */
    public int getPort() {
        return port;
    }

    public byte[] getSms() {
        return (byte[])this.msg.clone();
    }

    public void setSms(byte[] msg) {
        this.msg = (byte[])msg.clone();
    }

    public boolean isRunning() {
        return running;
    }


    /* Methods */
    public synchronized boolean start() {
        if (th != null)
            return false;
        else {
            th = new Thread(this);
            th.start();
            return true;
        }
    }

    public synchronized boolean stop() {
        if (th == null)
            return false;
        else {
            try {
                if (serverSocket != null && !serverSocket.isClosed())
                    serverSocket.close();
                th.join();
            }
            catch (Exception e) {
                e.printStackTrace();
                System.exit(-1);
            }

            return true;
        }
    }
}

class Server extends TCP {

    /* Constructors */
    public Server() {}

    public Server(int port) {
        super(port);
    }

    public Server(byte[] msg) {
        this.msg = (byte[])msg.clone();
    }

    public Server(int port, byte[] msg) {
        super(port);
        this.msg = (byte[])msg.clone();
    }


    /* Methods */
    @Override
    public void run() {
        running = true;

        try {
            serverSocket = new ServerSocket(port);

            while (true) {
                try { socket = serverSocket.accept(); }
                catch (SocketException e) {
                    break;
                }

                Tunnel sttp = new Tunnel.Builder()
                        .setIn(socket.getInputStream())
                        .setOut(socket.getOutputStream())
                        .setLog(new FileOutputStream(new File("serverLog.txt")))
                        .build();
                sttp.push(msg);

                //sttp.close();
                socket.close();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        running = false;
        th = null;
    }
}

class Client extends TCP {

    /* Attributes */
    protected String ip;

    {
        ip = "127.0.0.1";
    }


    /* Constructors */
    public Client() {}

    public Client(int port) {
        super(port);
    }

    public Client(String ip) {
        this.ip = ip;
    }

    public Client(String ip, int port) {
        super(port);
        this.ip = ip;
    }


    /* Methods */
    @Override
    public void run() {
        running = true;

        try {
            socket = new Socket(ip, port);

            Tunnel sttp = new Tunnel.Builder()
                    .setIn(socket.getInputStream())
                    .setOut(socket.getOutputStream())
                    .setLog(new FileOutputStream(new File("clientLog.txt")))
                    .build();
            msg = sttp.pull();

            sttp.close();
            socket.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        running = false;
        th = null;
    }
}
