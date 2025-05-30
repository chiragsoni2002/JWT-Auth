package com.example.JWTToken.dto;

import lombok.Data;

@Data
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String id;
    private String username;
    private String email;
    private String role;

    public JwtResponse(String token, String id, String username, String email, String role) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
    }
} 