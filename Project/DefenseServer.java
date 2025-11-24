import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;

public class DefenseServer {

    private static HashMap<String, Integer> failedAttempts = new HashMap<>();
    private static HashMap<String, Long> blockedIPs = new HashMap<>();

    private static final int LOCK_TIME = 20000; // 20 seconds
    private static final String CORRECT_PASSWORD = "secret123";

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/login", new LoginHandler());
        server.setExecutor(null);

        System.out.println("Defense Server running on http://127.0.0.1:8080/login");
        server.start();
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {

            String ip = exchange.getRemoteAddress().getAddress().toString();

            // If blocked
            if (blockedIPs.containsKey(ip) && System.currentTimeMillis() < blockedIPs.get(ip)) {
                sendResponse(exchange, "IP BLOCKED due to brute force", 403);
                return;
            }

            // Read password
            String body = new String(exchange.getRequestBody().readAllBytes());
            String[] parts = body.split("=");
            String password = (parts.length > 1) ? parts[1] : "";

            // Wrong password
            if (!password.equals(CORRECT_PASSWORD)) {

                failedAttempts.put(ip, failedAttempts.getOrDefault(ip, 0) + 1);

                if (failedAttempts.get(ip) >= 3) {
                    blockedIPs.put(ip, System.currentTimeMillis() + LOCK_TIME);
                    sendResponse(exchange, "ACCOUNT LOCKED", 403);
                    return;
                }

                sendResponse(exchange, "Invalid password", 401);
                return;
            }

            // Correct password
            failedAttempts.put(ip, 0);
            sendResponse(exchange, "Login Successful!", 200);
        }
    }

    private static void sendResponse(HttpExchange exchange, String response, int code) throws IOException {
        exchange.sendResponseHeaders(code, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}
