package com.example.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSecurity implements AuthenticationManager {


    /***
     * 验证账号密码逻辑
     *
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Object credentials = authentication.getCredentials();
        Object principal = authentication.getPrincipal();
        if (principal.equals(credentials)) {
            System.out.println(1);
            return new UsernamePasswordAuthenticationToken(principal,credentials, AuthorityUtils.createAuthorityList("ROLE_ADMIN","ROLE_USER"));
        } else {
          throw new UsernameNotFoundException("User " + principal + " was not found in the database");
        }
    }
}
