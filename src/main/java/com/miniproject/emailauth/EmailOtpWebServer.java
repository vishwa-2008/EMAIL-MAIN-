package com.miniproject.emailauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public final class EmailOtpWebServer {
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Duration CODE_LIFETIME = Duration.ofMinutes(5);
    private static final Duration RESEND_DELAY = Duration.ofSeconds(60);
    private static final int MAX_ATTEMPTS = 5;
    private static final int MAX_BODY_SIZE = 2048;
    private static final int MAX_TRACKED_EMAILS = 10000;

    private final Map<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final Map<String, Instant> lastSent = new ConcurrentHashMap<>();

    private EmailOtpWebServer() {}

    public static void main(String[] args) throws IOException {
        int port;
        try {
            port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
            if (port < 1 || port > 65535) {
                throw new NumberFormatException("outside valid port range");
            }
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("PORT must be a valid TCP port between 1 and 65535.", ex);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        EmailOtpWebServer app = new EmailOtpWebServer();
        server.createContext("/", app::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("Email OTP website is running on http://localhost:" + port);
    }

    private void handle(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");

        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();
        if ("/api/send".equals(path) && "POST".equals(method)) {
            sendCode(exchange);
        } else if ("/api/verify".equals(path) && "POST".equals(method)) {
            verifyCode(exchange);
        } else if (("/".equals(path) || "/index.html".equals(path)) && "GET".equals(method)) {
            serveWebsite(exchange);
        } else {
            sendJson(exchange, 404, false, "Page not found.");
        }
    }

    private void serveWebsite(HttpExchange exchange) throws IOException {
        try (InputStream input = EmailOtpWebServer.class.getResourceAsStream("/web/index.html")) {
            if (input == null) {
                sendJson(exchange, 500, false, "Website files are missing. Rebuild the project.");
                return;
            }
            byte[] content = input.readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.getResponseHeaders().set(
                    "Content-Security-Policy",
                    "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                            + "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                            + "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
            exchange.sendResponseHeaders(200, content.length);
            exchange.getResponseBody().write(content);
        } finally {
            exchange.close();
        }
    }

    private void sendCode(HttpExchange exchange) throws IOException {
        Map<String, String> form = readForm(exchange);
        if (form == null) return;

        String email = form.getOrDefault("email", "").trim().toLowerCase(Locale.ROOT);
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            sendJson(exchange, 400, false, "Enter a valid email address.");
            return;
        }

        Credentials credentials = loadCredentials();
        if (credentials == null) {
            sendJson(exchange, 503, false,
                    "Email is not configured yet. Add GMAIL_ADDRESS and GMAIL_APP_PASSWORD to the server environment.");
            return;
        }

        Instant now = Instant.now();
        lastSent.entrySet().removeIf(entry -> now.isAfter(entry.getValue().plus(Duration.ofHours(24))));
        challenges.entrySet().removeIf(entry -> now.isAfter(entry.getValue().expiresAt()));
        Instant[] reservation = new Instant[1];
        lastSent.compute(email, (key, previousSend) -> {
            if (previousSend == null || now.isAfter(previousSend.plus(RESEND_DELAY))) {
                reservation[0] = now;
                return now;
            }
            return previousSend;
        });
        if (reservation[0] == null) {
            Instant previousSend = lastSent.get(email);
            long seconds = Math.max(1, Duration.between(now, previousSend.plus(RESEND_DELAY)).toSeconds());
            sendJson(exchange, 429, false, "Please wait " + seconds + " seconds before requesting another code.");
            return;
        }
        if (lastSent.size() > MAX_TRACKED_EMAILS) {
            lastSent.remove(email, reservation[0]);
            sendJson(exchange, 503, false, "The service is temporarily busy. Please try again later.");
            return;
        }

        String code = String.format("%06d", RANDOM.nextInt(1_000_000));
        try {
            sendEmail(credentials, email, code);
        } catch (Exception ex) {
            lastSent.remove(email, reservation[0]);
            System.err.println("Unable to send verification email: " + ex.getClass().getSimpleName());
            sendJson(exchange, 502, false, "Could not send the email. Check the SMTP settings and try again.");
            return;
        }

        challenges.put(email, new Challenge(code, now.plus(CODE_LIFETIME)));
        lastSent.put(email, now);
        sendJson(exchange, 200, true, "Your verification code is on its way. Check your inbox.");
    }

    private void verifyCode(HttpExchange exchange) throws IOException {
        Map<String, String> form = readForm(exchange);
        if (form == null) return;

        String email = form.getOrDefault("email", "").trim().toLowerCase(Locale.ROOT);
        String code = form.getOrDefault("code", "").trim();
        if (!EMAIL_PATTERN.matcher(email).matches() || !code.matches("\\d{6}")) {
            sendJson(exchange, 400, false, "Enter the email address and the 6-digit code.");
            return;
        }

        Challenge challenge = challenges.get(email);
        if (challenge == null) {
            sendJson(exchange, 400, false, "Request a new verification code to continue.");
            return;
        }
        if (Instant.now().isAfter(challenge.expiresAt())) {
            challenges.remove(email, challenge);
            sendJson(exchange, 400, false, "That code has expired. Request a new one.");
            return;
        }
        if (challenge.attempts() >= MAX_ATTEMPTS) {
            challenges.remove(email, challenge);
            sendJson(exchange, 429, false, "Too many attempts. Request a new verification code.");
            return;
        }

        challenge.incrementAttempts();
        boolean matches = MessageDigest.isEqual(
                challenge.code().getBytes(StandardCharsets.US_ASCII),
                code.getBytes(StandardCharsets.US_ASCII));
        if (!matches) {
            int remaining = MAX_ATTEMPTS - challenge.attempts();
            if (remaining == 0) challenges.remove(email, challenge);
            sendJson(exchange, remaining == 0 ? 429 : 400, false,
                    remaining == 0
                            ? "Too many attempts. Request a new verification code."
                            : "That code does not match. " + remaining + " attempts remaining.");
            return;
        }

        challenges.remove(email, challenge);
        sendJson(exchange, 200, true, "Email verified successfully. You're all set.");
    }

    private Map<String, String> readForm(HttpExchange exchange) throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null
                || !contentType.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            sendJson(exchange, 415, false, "Unsupported request format.");
            return null;
        }
        byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY_SIZE + 1);
        if (body.length > MAX_BODY_SIZE) {
            sendJson(exchange, 413, false, "Request is too large.");
            return null;
        }
        Map<String, String> values = new HashMap<>();
        String rawForm = new String(body, StandardCharsets.UTF_8);
        for (String pair : rawForm.split("&")) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }
        return values;
    }

    private static void sendJson(HttpExchange exchange, int status, boolean success, String message)
            throws IOException {
        byte[] body = ("{\"success\":" + success + ",\"message\":\"" + jsonEscape(message) + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void sendEmail(Credentials credentials, String recipient, String code) throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");
        props.put("mail.smtp.writetimeout", "10000");

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(credentials.email(), credentials.password());
            }
        });

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(credentials.email(), "Secure Access"));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient, false));
        message.setSubject("Your email verification code");
        message.setText(
                "Your one-time verification code is: " + code + "\n\n"
                        + "This code is valid for 5 minutes. Do not share it with anyone.",
                "UTF-8");
        Transport.send(message);
    }

    private static Credentials loadCredentials() {
        String email = System.getenv("GMAIL_ADDRESS");
        String password = System.getenv("GMAIL_APP_PASSWORD");
        if (email != null && !email.isBlank() && password != null && !password.isBlank()) {
            return new Credentials(email.trim(), password.trim().replaceAll("\\s+", ""));
        }

        Properties properties = new Properties();
        try (InputStream input = EmailOtpWebServer.class.getResourceAsStream("/config.properties")) {
            if (input != null) properties.load(input);
        } catch (IOException ex) {
            System.err.println("Unable to read SMTP configuration: " + ex.getClass().getSimpleName());
        }
        if (properties.isEmpty()) {
            try (InputStream input = java.nio.file.Files.newInputStream(
                    java.nio.file.Path.of("config.properties"))) {
                properties.load(input);
            } catch (IOException ignored) {
                return null;
            }
        }

        String propertyEmail = properties.getProperty("GMAIL_ADDRESS");
        String propertyPassword = properties.getProperty("GMAIL_APP_PASSWORD");
        if (propertyEmail == null || propertyEmail.isBlank()
                || propertyPassword == null || propertyPassword.isBlank()) {
            return null;
        }
        return new Credentials(propertyEmail.trim(), propertyPassword.trim().replaceAll("\\s+", ""));
    }

    private record Credentials(String email, String password) {}

    private static final class Challenge {
        private final String code;
        private final Instant expiresAt;
        private int attempts;

        private Challenge(String code, Instant expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
        }

        private String code() {
            return code;
        }

        private Instant expiresAt() {
            return expiresAt;
        }

        private synchronized int attempts() {
            return attempts;
        }

        private synchronized void incrementAttempts() {
            attempts++;
        }
    }
}
