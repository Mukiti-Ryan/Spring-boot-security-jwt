package com.bezkoder.springjwt.security.services;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsService {
//    Implementation will be used for configuring DaoAuthenticationProvider by AuthenticationManagerBuilder.userDetailsService()
//    Has a method to load User by username and returns a UserDetails object that Spring Security can use for authentication and validation
//    UserDetails contains necessary information (such as: username, password, authorities) to build an Authentication object.
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
