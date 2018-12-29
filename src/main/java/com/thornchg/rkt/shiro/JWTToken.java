package com.thornchg.rkt.shiro;

import com.thornchg.rkt.utils.JwtUtils;
import org.apache.shiro.authc.HostAuthenticationToken;

public class JWTToken implements HostAuthenticationToken {
	private static final long serialVersionUID = 9217639903967592166L;

    private String username;
	private String token;
	private String salt;

    private String host;

    public JWTToken(String token) {
        this(token, null);
    }
    public JWTToken(String username,String token,String salt,String host) {
        this.username=username;
        this.token = token;
        this.salt=salt;
        this.host = host;

    }

    public JWTToken(String token, String host) {
        this.token = token;
        this.host = host;
        this.username=JwtUtils.getUsername(token);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getToken(){
        return this.token;
    }

    public String getHost() {
        return host;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public String toString(){
        return token + ':' + host;
    }
}
