package com.secure.notes.security.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class MessageResponse {

    /*
        send message to user, used in signup
     */
    private String message;

    public MessageResponse(String message) {
        this.message = message;
    }

}