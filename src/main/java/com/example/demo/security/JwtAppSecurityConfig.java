package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtConfigKey;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.example.demo.security.AppUserPermission.COURSE_WRITE;
import static com.example.demo.security.AppUserRole.STUDENT;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

@Configuration
@EnableConfigurationProperties(JwtConfig.class)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class JwtAppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder encoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final JwtConfigKey jwtConfigKey;

    @Autowired
    public JwtAppSecurityConfig(PasswordEncoder encoder,
                                ApplicationUserService applicationUserService,
                                JwtConfig jwtConfig,
                                JwtConfigKey jwtConfigKey) {
        this.encoder = encoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.jwtConfigKey = jwtConfigKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(
                        authenticationManager(), jwtConfig, jwtConfigKey))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, jwtConfigKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                    .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                    .antMatchers("/api/**").hasRole(STUDENT.name())
//                   .antMatchers(DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .antMatchers(POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                    .antMatchers(PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                   .antMatchers(GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated();

    }

    @Bean
    public DaoAuthenticationProvider provider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(encoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(provider());
    }
}
