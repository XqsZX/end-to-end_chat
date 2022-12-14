package chat.client;

import chat.server.ServerChatMain;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

public class ClientChatMain extends JFrame implements ActionListener, KeyListener {
    public static void main(String[] args) {
        new ClientChatMain();
    }
    // TextArea
    private JTextArea jta;
    // ScrollPane
    private JScrollPane jsp;
    // Panel
    private JPanel jp;
    // TextField
    private JTextField jtf;
    // Button
    private JButton jb;

    // Output Stream
    BufferedWriter bufferedWriter = null;

    // AES Key & iv
    private final String AES_Key = "CSE433SIntroToCS";
    private final String AES_iv = "XINZHAO 512912ZX";

    public ClientChatMain() {
        // initialize
        jta = new JTextArea();
        // set jta uneditable
        jta.setEditable(false);
        jsp = new JScrollPane(jta);
        jp = new JPanel();
        jtf = new JTextField(10);
        jb = new JButton("send");

        // add TextField and Button to the Panel
        jp.add(jtf);
        jp.add(jb);

        // add ScrollPane and Panel into the Frame
        this.add(jsp, BorderLayout.CENTER);
        this.add(jp, BorderLayout.SOUTH);

        // set title, size, position, close, visible
        this.setTitle("Chat_client");
        this.setSize(300, 300);
        this.setLocation(600, 300);
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setVisible(true);

        /************************************************** TCP Client **************************************************/
        // Bind an action listener to the Button
        jb.addActionListener(this);

        // Bind a key listener to the TextField
        jtf.addKeyListener(this);

        try {
            // Creat a client socket
            Socket socket = new Socket("127.0.0.1", 8888);

            // Get the input stream of socket(read line by line)
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Get the output stream of socket
            bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            // Read the data in a loop and output it to the text field
            String line = null;
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
                line = Decrypt(line, AES_Key, AES_iv);
                jta.append(line + System.lineSeparator());
            }

            // Close the socket channel
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        /************************************************** TCP Client **************************************************/
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            SendDataToSocket();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private void SendDataToSocket() throws Exception {
        // Get the information in the TextField
        String text = jtf.getText();

        // splice the content to be sent
        text = "Client: " + text;

        // Show
        jta.append(text + System.lineSeparator());

        text = Encrypt(text, AES_Key, AES_iv);

        try {
            // Send
            bufferedWriter.write(text);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            // Clear TextField
            jtf.setText("");
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String Encrypt(String Text, String AES_Key, String AES_iv) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte[] textBytes = Text.getBytes();
            int plaintextLength = textBytes.length;

            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }

            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(textBytes, 0, plaintext, 0, textBytes.length);

            SecretKeySpec keySpec = new SecretKeySpec(AES_Key.getBytes(), "AES");
            // CBC mode, need an iv
            IvParameterSpec ivSpec = new IvParameterSpec(AES_iv.getBytes());

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(plaintext);

            return ClientChatMain.encode(encrypted).trim();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String Decrypt(String Text, String AES_Key, String AES_iv) throws Exception {
        try
        {
            byte[] encrypted = ClientChatMain.decode(Text);

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(AES_Key.getBytes(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(AES_iv.getBytes());

            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            byte[] original = cipher.doFinal(encrypted);
            String originalString = new String(original);
            return originalString.trim();
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String encode(byte[] byteArray) {
        return Base64.getEncoder().encodeToString(byteArray);
    }

    private static byte[] decode(String base64EncodedString) {
        return Base64.getDecoder().decode(base64EncodedString);
    }

    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_ENTER) {
            try {
                SendDataToSocket();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    @Override
    public void keyReleased(KeyEvent e) {

    }
}
