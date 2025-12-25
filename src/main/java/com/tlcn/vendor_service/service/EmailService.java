package com.tlcn.vendor_service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.mail.Authenticator;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.Message;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

/**
 * EmailService - Handles all email sending operations
 * Responsibilities: 
 * - SMTP configuration
 * - Email composition
 * - Email sending with error handling
 */
@Slf4j
@Service
public class EmailService {

    @Value("${email.username}")
    private String emailUsername;

    @Value("${email.password}")
    private String emailPassword;

    private Session mailSession;

    /**
     * Initialize SMTP session on application startup
     */
    @PostConstruct
    public void initializeMailSession() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        mailSession = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(emailUsername, emailPassword);
            }
        });
        
        log.info("Mail session initialized successfully");
    }

    /**
     * Send a simple email
     *
     * @param to       Recipient email address
     * @param subject  Email subject
     * @param content  Email body content
     */
    public void sendEmail(String to, String subject, String content) {
        try {
            MimeMessage message = new MimeMessage(mailSession);
            message.setFrom(new InternetAddress(emailUsername));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject);
            message.setText(content);
            
            Transport.send(message);
            log.info("Email sent successfully to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage(), e);
            throw new EmailSendingException("Email sending failed: " + e.getMessage(), e);
        }
    }

    /**
     * Send OTP email for registration
     *
     * @param to  Recipient email address
     * @param otp OTP code
     */
    public void sendRegistrationOtp(String to, String otp) {
        String subject = "Vendor Registration OTP";
        String content = String.format(
            "Your OTP for vendor registration is: %s\n\n" +
            "This OTP will expire in 3 minutes.\n" +
            "Do not share this OTP with anyone.",
            otp
        );
        sendEmail(to, subject, content);
    }

    /**
     * Send OTP email for password reset
     *
     * @param to  Recipient email address
     * @param otp OTP code
     */
    public void sendPasswordResetOtp(String to, String otp) {
        String subject = "Password Reset OTP";
        String content = String.format(
            "Your OTP for password reset is: %s\n\n" +
            "This OTP will expire in 3 minutes.\n" +
            "If you did not request this, please ignore this email.",
            otp
        );
        sendEmail(to, subject, content);
    }

    /**
     * Send verification email (after OTP verification)
     *
     * @param to          Recipient email address
     * @param vendorName  Vendor shop name
     */
    public void sendVerificationEmail(String to, String vendorName) {
        String subject = "Vendor Account Verification";
        String content = String.format(
            "Congratulations! Your vendor account has been verified.\n\n" +
            "Shop Name: %s\n" +
            "Status: Active\n\n" +
            "You can now login and start selling.",
            vendorName
        );
        sendEmail(to, subject, content);
    }

    /**
     * Send password reset email
     *
     * @param to          Recipient email address
     * @param vendorName  Vendor shop name
     * @param resetToken  Password reset token
     */
    public void sendPasswordResetEmail(String to, String vendorName, String resetToken) {
        String subject = "Password Reset Request";
        String resetLink = "http://localhost:3000/vendor/reset-password?token=" + resetToken; // Frontend URL
        String content = String.format(
            "Dear %s,\n\n" +
            "You have requested to reset your password.\n\n" +
            "Please click the link below to reset your password:\n" +
            "%s\n\n" +
            "This link will expire in 15 minutes.\n\n" +
            "If you did not request this password reset, please ignore this email.\n\n" +
            "Best regards,\n" +
            "Vendor Support Team",
            vendorName, resetLink
        );
        sendEmail(to, subject, content);
    }

    /**
     * Send password changed notification
     *
     * @param to          Recipient email address
     * @param vendorName  Vendor shop name
     */
    public void sendPasswordChangedNotification(String to, String vendorName) {
        String subject = "Password Changed Successfully";
        String content = String.format(
            "Dear %s,\n\n" +
            "Your password has been changed successfully.\n\n" +
            "If you did not make this change, please contact vendor support immediately.\n\n" +
            "Best regards,\n" +
            "Vendor Support Team",
            vendorName
        );
        sendEmail(to, subject, content);
    }

    /**
     * Custom exception for email sending failures
     */
    public static class EmailSendingException extends RuntimeException {
        public EmailSendingException(String message) {
            super(message);
        }

        public EmailSendingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
