package com.miniproject.emailauth;

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public final class EmailAuthenticationApp extends JFrame {
    private static final Color NAVY = new Color(20, 42, 78);
    private static final Color BLUE = new Color(37, 99, 235);
    private static final Color BG = new Color(245, 247, 251);
    private static final Color TEXT = new Color(36, 48, 66);
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ExecutorService MAIL_EXECUTOR = Executors.newSingleThreadExecutor();
    private static final String CONFIG_FILE_NAME = "config.properties";

    private final JTextField emailField = new JTextField();
    private final JTextField otpField = new JTextField();
    private final JLabel statusLabel = new JLabel("Enter your email address to begin.");
    private final JButton sendButton = new JButton("Send verification code");
    private final JButton verifyButton = new JButton("Verify and continue");
    private final JLabel timerLabel = new JLabel("Code expires in 5:00");
    private final JButton settingsButton = new JButton("⚙ SMTP Settings");

    private String currentOtp;
    private String currentEmail;
    private Instant expiresAt;
    private int attempts;
    private boolean verified;
    private Timer countdownTimer;

    public EmailAuthenticationApp() {
        super("Email Authentication | Java Mini Project");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(800, 640));
        setSize(940, 680);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());
        getContentPane().setBackground(BG);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(NAVY);
        header.setBorder(new EmptyBorder(20, 30, 20, 30));

        JLabel brand = new JLabel("SECURE ACCESS");
        brand.setForeground(Color.WHITE);
        brand.setFont(new Font("SansSerif", Font.BOLD, 14));
        JLabel subtitle = new JLabel("JAVA  •  GMAIL SMTP  •  EMAIL OTP AUTHENTICATION");
        subtitle.setForeground(new Color(204, 218, 241));
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JPanel heading = new JPanel();
        heading.setOpaque(false);
        heading.setLayout(new BoxLayout(heading, BoxLayout.Y_AXIS));
        heading.add(brand);
        heading.add(Box.createVerticalStrut(4));
        heading.add(subtitle);
        header.add(heading, BorderLayout.WEST);

        settingsButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        settingsButton.setForeground(Color.WHITE);
        settingsButton.setBackground(new Color(36, 68, 120));
        settingsButton.setFocusPainted(false);
        settingsButton.setBorder(new EmptyBorder(8, 14, 8, 14));
        settingsButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        settingsButton.addActionListener(e -> openSettingsDialog());
        header.add(settingsButton, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);

        JPanel outer = new JPanel(new GridBagLayout());
        outer.setBackground(BG);
        outer.setBorder(new EmptyBorder(20, 20, 20, 20));

        JPanel card = new JPanel();
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(226, 232, 240)),
                new EmptyBorder(28, 36, 28, 36)));
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setPreferredSize(new Dimension(520, 460));

        JLabel title = new JLabel("Verify your email");
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        title.setFont(new Font("SansSerif", Font.BOLD, 26));
        title.setForeground(TEXT);

        JLabel intro = new JLabel("<html><div style='width:420px'>We will send a one-time 6-digit verification code to your inbox. Enter the code below to complete access confirmation.</div></html>");
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        intro.setFont(new Font("SansSerif", Font.PLAIN, 13));
        intro.setForeground(new Color(100, 116, 139));

        JPanel top = new JPanel();
        top.setOpaque(false);
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(title);
        top.add(Box.createVerticalStrut(6));
        top.add(intro);
        top.add(Box.createVerticalStrut(20));
        card.add(top);

        addLabel(card, "EMAIL ADDRESS");
        styleField(emailField, "you@example.com");
        card.add(emailField);
        card.add(Box.createVerticalStrut(14));

        sendButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        styleButton(sendButton, BLUE, Color.WHITE);
        card.add(sendButton);

        card.add(Box.createVerticalStrut(20));
        JSeparator separator = new JSeparator();
        separator.setForeground(new Color(226, 232, 240));
        separator.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(separator);
        card.add(Box.createVerticalStrut(18));

        addLabel(card, "6-DIGIT VERIFICATION CODE");
        styleField(otpField, "Enter 6-digit code");
        card.add(otpField);
        card.add(Box.createVerticalStrut(14));

        verifyButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        styleButton(verifyButton, NAVY, Color.WHITE);
        card.add(verifyButton);
        card.add(Box.createVerticalStrut(14));

        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        statusLabel.setForeground(new Color(71, 85, 105));
        card.add(statusLabel);
        card.add(Box.createVerticalStrut(12));

        timerLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        timerLabel.setForeground(new Color(100, 116, 139));
        timerLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        timerLabel.setVisible(false);
        card.add(timerLabel);

        outer.add(card);
        add(outer, BorderLayout.CENTER);

        sendButton.addActionListener(e -> sendOtp());
        verifyButton.addActionListener(e -> verifyOtp());
        otpField.addActionListener(e -> verifyOtp());
    }

    private void addLabel(JPanel panel, String text) {
        JLabel label = new JLabel(text);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setFont(new Font("SansSerif", Font.BOLD, 11));
        label.setForeground(new Color(71, 85, 105));
        panel.add(label);
        panel.add(Box.createVerticalStrut(6));
    }

    private void styleField(JTextField field, String placeholder) {
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        field.setPreferredSize(new Dimension(440, 40));
        field.setFont(new Font("SansSerif", Font.PLAIN, 14));
        field.setForeground(TEXT);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(203, 213, 225)),
                new EmptyBorder(8, 12, 8, 12)));
        field.setToolTipText(placeholder);
        field.setAlignmentX(Component.LEFT_ALIGNMENT);
    }

    private void styleButton(JButton button, Color background, Color foreground) {
        button.setFont(new Font("SansSerif", Font.BOLD, 13));
        button.setBackground(background);
        button.setForeground(foreground);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        button.setPreferredSize(new Dimension(440, 42));
        button.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        button.setAlignmentX(Component.LEFT_ALIGNMENT);
    }

    private void sendOtp() {
        if (verified) {
            setStatus("This email is already verified in this session.", new Color(22, 101, 52));
            return;
        }

        String email = emailField.getText().trim();
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            setStatus("Enter a valid email address.", new Color(185, 28, 28));
            return;
        }

        Credentials credentials = loadCredentials();
        if (credentials == null) {
            setStatus("SMTP credentials not configured. Click '⚙ SMTP Settings' above.", new Color(185, 28, 28));
            openSettingsDialog();
            return;
        }

        String otp = String.format("%06d", RANDOM.nextInt(1_000_000));
        sendButton.setEnabled(false);
        sendButton.setText("Sending...");
        setStatus("Sending verification code…", new Color(71, 85, 105));

        MAIL_EXECUTOR.submit(() -> {
            try {
                sendEmail(credentials.email(), credentials.password(), email, otp);
                SwingUtilities.invokeLater(() -> {
                    currentOtp = otp;
                    currentEmail = email;
                    expiresAt = Instant.now().plusSeconds(300);
                    attempts = 0;
                    otpField.setText("");
                    startCountdown();
                    setStatus("Code sent! Check your inbox and spam folder.", new Color(22, 101, 52));
                    sendButton.setText("Resend verification code");
                    sendButton.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    setStatus("Email failed to send. Check Gmail settings or internet.", new Color(185, 28, 28));
                    sendButton.setText("Send verification code");
                    sendButton.setEnabled(true);
                    JOptionPane.showMessageDialog(this,
                            "Could not send email. Please check your Gmail address and Google App Password.\n\nError: "
                                    + safeMessage(ex),
                            "SMTP Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
    }

    private static void sendEmail(String sender, String appPassword, String recipient, String otp) throws Exception {
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
                return new PasswordAuthentication(sender, appPassword);
            }
        });

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(sender, "Secure Access"));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient, false));
        message.setSubject("Your Email Verification Code: " + otp);
        message.setText(
                "Hello,\n\n"
                        + "Your one-time verification code is: " + otp + "\n\n"
                        + "This code is valid for 5 minutes. Do not share this code with anyone.\n\n"
                        + "If you did not request this verification, you can safely ignore this email.\n\n"
                        + "Secure Access | Java Email Authentication Mini Project",
                "UTF-8");
        Transport.send(message);
    }

    private void verifyOtp() {
        if (verified) {
            setStatus("Email verified successfully.", new Color(22, 101, 52));
            return;
        }
        if (currentOtp == null || currentEmail == null || expiresAt == null) {
            setStatus("Please request a verification code first.", new Color(185, 28, 28));
            return;
        }
        if (!emailField.getText().trim().equalsIgnoreCase(currentEmail)) {
            setStatus("Email address was modified. Please request a new code.", new Color(185, 28, 28));
            return;
        }
        if (Instant.now().isAfter(expiresAt)) {
            clearOtp();
            stopCountdown();
            timerLabel.setText("Code expired");
            timerLabel.setForeground(new Color(185, 28, 28));
            setStatus("Code expired. Please request a new code.", new Color(185, 28, 28));
            return;
        }
        if (++attempts > 5) {
            clearOtp();
            stopCountdown();
            setStatus("Too many attempts. Please request a new code.", new Color(185, 28, 28));
            return;
        }

        String entered = otpField.getText().trim();
        if (entered.matches("\\d{6}") && entered.equals(currentOtp)) {
            verified = true;
            clearOtp();
            stopCountdown();
            timerLabel.setVisible(false);
            setStatus("Email verified successfully! Access granted.", new Color(22, 101, 52));
            emailField.setEditable(false);
            otpField.setEditable(false);
            sendButton.setEnabled(false);
            verifyButton.setEnabled(false);
            JOptionPane.showMessageDialog(this,
                    "Authentication successful!\n\nVerified Email: " + currentEmail,
                    "Access Granted", JOptionPane.INFORMATION_MESSAGE);
        } else {
            setStatus("Incorrect code. Attempts remaining: " + Math.max(0, 5 - attempts),
                    new Color(185, 28, 28));
        }
    }

    private void startCountdown() {
        stopCountdown();
        timerLabel.setVisible(true);
        updateTimerDisplay();
        countdownTimer = new Timer(1000, e -> {
            if (expiresAt == null || Instant.now().isAfter(expiresAt)) {
                stopCountdown();
                clearOtp();
                timerLabel.setText("Code has expired.");
                timerLabel.setForeground(new Color(185, 28, 28));
                setStatus("Code expired. Click resend to receive a fresh code.", new Color(185, 28, 28));
            } else {
                updateTimerDisplay();
            }
        });
        countdownTimer.start();
    }

    private void updateTimerDisplay() {
        if (expiresAt == null) return;
        long secondsRemaining = Math.max(0, Duration.between(Instant.now(), expiresAt).getSeconds());
        long mins = secondsRemaining / 60;
        long secs = secondsRemaining % 60;
        timerLabel.setText(String.format("⏱ Code expires in %d:%02d", mins, secs));
        timerLabel.setForeground(secondsRemaining < 60
                ? new Color(185, 28, 28)
                : new Color(71, 85, 105));
    }

    private void stopCountdown() {
        if (countdownTimer != null) {
            countdownTimer.stop();
            countdownTimer = null;
        }
    }

    private void clearOtp() {
        currentOtp = null;
        expiresAt = null;
    }

    private void setStatus(String text, Color color) {
        statusLabel.setText("<html><div style='width:420px'>" + text + "</div></html>");
        statusLabel.setForeground(color);
    }

    private static String safeMessage(Exception ex) {
        String message = ex.getMessage();
        if (message == null || message.isBlank()) return ex.getClass().getSimpleName();
        return message.length() > 200 ? message.substring(0, 200) : message;
    }

    private void openSettingsDialog() {
        Credentials current = loadCredentials();
        String initialEmail = current != null ? current.email() : "";
        String initialPassword = current != null ? current.password() : "";

        JTextField emailInput = new JTextField(initialEmail);
        JPasswordField passInput = new JPasswordField(initialPassword);
        JPanel panel = new JPanel(new GridLayout(0, 1, 6, 6));
        panel.setPreferredSize(new Dimension(380, 160));
        panel.add(new JLabel("Sender Gmail Address:"));
        panel.add(emailInput);
        panel.add(new JLabel("Google App Password (16 characters, no spaces):"));
        panel.add(passInput);
        panel.add(new JLabel("<html><small style='color:gray'>Saved securely in local config.properties for this session.</small></html>"));

        int result = JOptionPane.showConfirmDialog(
                this, panel, "SMTP Gmail Configuration",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            String savedEmail = emailInput.getText().trim();
            String savedPass = new String(passInput.getPassword()).trim().replaceAll("\\s+", "");
            if (!savedEmail.isEmpty() && !savedPass.isEmpty()) {
                saveCredentials(savedEmail, savedPass);
                setStatus("SMTP credentials saved successfully.", new Color(22, 101, 52));
            }
        }
    }

    private record Credentials(String email, String password) {}

    private Credentials loadCredentials() {
        String envEmail = System.getenv("GMAIL_ADDRESS");
        String envPass = System.getenv("GMAIL_APP_PASSWORD");
        if (envEmail != null && !envEmail.isBlank() && envPass != null && !envPass.isBlank()) {
            return new Credentials(envEmail.trim(), envPass.trim().replaceAll("\\s+", ""));
        }

        File dotenvFile = new File(".env");
        if (dotenvFile.exists()) {
            Properties envProps = new Properties();
            try (InputStream in = new FileInputStream(dotenvFile)) {
                envProps.load(in);
                String propEmail = envProps.getProperty("GMAIL_ADDRESS");
                String propPass = envProps.getProperty("GMAIL_APP_PASSWORD");
                if (propEmail != null && !propEmail.isBlank() && propPass != null && !propPass.isBlank()) {
                    return new Credentials(propEmail.trim(), propPass.trim().replaceAll("\\s+", ""));
                }
            } catch (Exception ignored) {
            }
        }

        File configFile = new File(CONFIG_FILE_NAME);
        if (configFile.exists()) {
            Properties props = new Properties();
            try (InputStream in = new FileInputStream(configFile)) {
                props.load(in);
                String propEmail = props.getProperty("GMAIL_ADDRESS");
                String propPass = props.getProperty("GMAIL_APP_PASSWORD");
                if (propEmail != null && !propEmail.isBlank() && propPass != null && !propPass.isBlank()) {
                    return new Credentials(propEmail.trim(), propPass.trim().replaceAll("\\s+", ""));
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private void saveCredentials(String email, String password) {
        Properties props = new Properties();
        File configFile = new File(CONFIG_FILE_NAME);
        if (configFile.exists()) {
            try (InputStream in = new FileInputStream(configFile)) {
                props.load(in);
            } catch (Exception ignored) {
            }
        }
        props.setProperty("GMAIL_ADDRESS", email);
        props.setProperty("GMAIL_APP_PASSWORD", password);
        try (OutputStream out = new FileOutputStream(configFile)) {
            props.store(out, "Gmail SMTP Configuration");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not save credentials: " + ex.getMessage());
        }
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }
        SwingUtilities.invokeLater(() -> new EmailAuthenticationApp().setVisible(true));
    }
}
