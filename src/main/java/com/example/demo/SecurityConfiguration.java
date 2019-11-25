package com.example.demo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/")
                .access("hasAnyAuthority('USER','ADMIN')").antMatchers("/student")
                .access("hasAuthority('USER')")
                .antMatchers("/teacher")
                .access("hasAuthority('ADMIN')")
                .antMatchers("/course")
                .access("hasAnyAuthority('ADMIN','USER')")
                .antMatchers("/admin")
                .access("hasAuthority('ADMIN')")
                .antMatchers("/user")
                .access("hasAuthority('USER')")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/logout")
                .permitAll().and();

    }

    @Override protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("user1"))
                .authorities("User2").and()
                .withUser("")
                .password(passwordEncoder().encode("user2"))
                .authorities("USER").and()
                .withUser("user3")
                .password(passwordEncoder().encode("user3"))
                .authorities("USER","ADMIN");

    }

}
