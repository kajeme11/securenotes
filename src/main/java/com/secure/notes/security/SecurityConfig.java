package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/*
       change the default authentication from Basic Authentication
       declared on SpringBootWebSecurityConfiguration

       We need to specify our own SecurityFilterChainBean

 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        /**
         * request.anyRequest() will try to authenticate user for any endpoint
         * But what about endpoint that should be puvlic and don't need authentication
         * We can use requestMatchers(<pattern>)
         *
         * /public/login
         * /public/signup
         * /public/contact
         * See the pattern /public/**
         */
        http.authorizeHttpRequests((request) -> request
                .requestMatchers("/contact").permitAll()
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin").denyAll()
                .anyRequest().authenticated());
        //disable csrf
        http.csrf(csrf -> csrf.disable());
        /*
        * We will not see the log in page anymore
        * There will be an alert box instead
        *
        * */
        //        http.formLogin(Customizer.withDefaults());
        /*
            Make API stateless
            cookies are not stored in server
         */
        http.sessionManagement((session) ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
