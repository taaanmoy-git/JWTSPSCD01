package com.jwt.d01.jwtscd01.models;

public class JwtResponse {

    private String jwtToken;
    private String username;

    public JwtResponse(String jwtToken, String username) {
        this.jwtToken = jwtToken;
        this.username = username;
    }

    public JwtResponse() {
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String toString() {
        return "JwtResponse [jwtToken=" + jwtToken + ", username=" + username + "]";
    }

    // Static inner Builder class
    public static class Builder {
        private String jwtToken;
        private String username;

        public Builder setJwtToken(String jwtToken) {
            this.jwtToken = jwtToken;
            return this;
        }

        public Builder setUsername(String username) {
            this.username = username;
            return this;
        }

        public JwtResponse build() {
            return new JwtResponse(jwtToken, username); // ✅ Correctly assigns values
        }
    }

}
