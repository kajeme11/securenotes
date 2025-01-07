package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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
        http.authorizeHttpRequests((request) ->
                request.anyRequest().authenticated());
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
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }


    /**
     *
     * These is used for development, testing, prototype purpose
     * we can use basic auth with the credentials created below
     * to use in memory credentials, not stored in database,
     *
     * Use this multi user interaction with server
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager =
                new InMemoryUserDetailsManager();
        if(!manager.userExists("user1")){
            manager.createUser(
                    User.withUsername("user1")
                            .password("{noop}password1")
                            .roles("USER")
                            .build()
            );
        }
        if(!manager.userExists("admin")){
            manager.createUser(
                    User.withUsername("admin")
                            .password("{noop}password1")
                            .roles("ADMIN")
                            .build()
            );
        }
        return manager;
    }

}
