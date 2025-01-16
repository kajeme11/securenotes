package com.secure.notes.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    /*
        Need to configure in properties
        to set mail sender such as
        host sender, port, username, password, etc
     */
    @Autowired
    private JavaMailSender javaMailSender;

    public void sendPasswordResetEmail(String toEmail, String resetUrl){
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setTo(toEmail);
        simpleMailMessage.setSubject("Password Reset Request");
        simpleMailMessage.setText("Click the link to reset your password: \n" + resetUrl);
        javaMailSender.send(simpleMailMessage);
    }

}
