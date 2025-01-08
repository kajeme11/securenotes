package com.secure.notes.security;

import com.secure.notes.models.Role;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import com.secure.notes.models.AppRole;
import com.secure.notes.models.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;
import java.time.LocalDate;

/*
       change the default authentication from Basic Authentication
       declared on SpringBootWebSecurityConfiguration

       We need to specify our own SecurityFilterChainBean

 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true,
                        securedEnabled = true,
                        jsr250Enabled = true)
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
                request
//                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
//                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated());
        //disable csrf
        http.csrf(csrf -> csrf.disable());
        http.addFilterBefore(new CustomLoggingFilter(), UsernamePasswordAuthenticationFilter.class);
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

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /*
            data initializer to create user for development, testing
            we inject both role and user repositories to send data to our db
            password encoder is injected by spring boot after its bean it's created
            by the method above this one passwordEncoder()
     */
    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository,
                                      UserRepository userRepository,
                                      PasswordEncoder passwordEncoder) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com", passwordEncoder.encode("password1"));
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com", passwordEncoder.encode("adminPass"));
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
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
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource){

        //IN MEMORY DETAILS MANAGER
//        InMemoryUserDetailsManager manager =
//DATABASE DETAILS MANAGER, needs data source configured in application properties
//it also populates other user details automatically with default values
//        JdbcUserDetailsManager manager =
//                new JdbcUserDetailsManager(dataSource);
//        if(!manager.userExists("user1")){
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1")
//                            .roles("USER")
//                            .build()
//            );
//        }
//        if(!manager.userExists("admin")){
//            manager.createUser(
//                    User.withUsername("admin")
//                            .password("{noop}password1")
//                            .roles("ADMIN")
//                            .build()
//            );
//        }
//        return manager;
//    }

}
