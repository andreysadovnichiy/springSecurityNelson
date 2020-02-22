package com.example.demo.auth;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.lang.String.format;

@Service
public class ApplicationUserService implements UserDetailsService {
    private ApplicationUserDao userDao;

    public ApplicationUserService(@Qualifier("fake") ApplicationUserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return userDao
                .selectApplicationUserByUsername(s)
                .orElseThrow(
                        () -> new UsernameNotFoundException(format("Username %s not found", s)));
    }
}
