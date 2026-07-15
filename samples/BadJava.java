import java.sql.*;
import java.io.*;
import java.util.*;

public class BadJava {

    // Hardcoded credentials
    private static final String DB_PASSWORD = "supersecret123";
    private static final String API_KEY = "sk-proj-WIVmWdgUk1guFfQwRHZWIPh0VsOdQzzH9wKmEtggwcxBP0NE";
    private static final String AWS_SECRET = "AhCHYcprXYVaArFkt2sGXUItbxqzJlTjuqaa60w1";

    // SQL injection — user input concatenated directly into query
    public ResultSet getUser(Connection conn, String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }

    // Null pointer dereference — no null check before use
    public int getLength(String s) {
        return s.length();
    }

    // Resource leak — stream never closed
    public String readFile(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        return new String(data);
    }

    // Command injection — user input passed to Runtime.exec
    public void runCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec("ls " + userInput);
    }

    // Empty catch block — silently swallows exceptions
    public void riskyOp() {
        try {
            int result = 10 / 0;
        } catch (Exception e) {
            // do nothing
        }
    }

    // Predictable random — used for security token
    public String generateToken() {
        Random rand = new Random();
        return String.valueOf(rand.nextInt(100000));
    }

    // Infinite loop potential — no termination condition guard
    public void processQueue(Queue<String> queue) {
        while (!queue.isEmpty()) {
            String item = queue.poll();
            if (item.equals("requeue")) {
                queue.add(item);
            }
        }
    }

    // Path traversal — no sanitisation of file path
    public String readUserFile(String filename) throws IOException {
        File f = new File("/app/data/" + filename);
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }

    // Deprecated and unsafe MD5 for password hashing
    public String hashPassword(String password) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
}
