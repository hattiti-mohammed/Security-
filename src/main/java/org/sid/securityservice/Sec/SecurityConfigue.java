package org.sid.securityservice.Sec;
import org.sid.securityservice.Sec.Entities.AppUser;
import org.sid.securityservice.Sec.Filters.JWTAuthrisationFilter;
import org.sid.securityservice.Sec.Filters.JwtAuthentificationFilter;
import org.sid.securityservice.Sec.Service.Accountservice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfigue  {
  @Autowired
    private Accountservice accountService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            AppUser appUser = accountService.loadUserByUsername(username);
            if (appUser == null) {
                throw new UsernameNotFoundException("User not found with username: " + username);
            }
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            appUser.getAppRoles().forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role.getRolename()));
            });
            return new User(appUser.getUsername(), appUser.getPassword(), authorities);
        };
    }

    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationManagerBuilder auth) throws Exception {
        // Configurez ici l'AuthenticationManager
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
        return auth.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = authenticationManagerBean(authenticationManagerBuilder());

        http
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests().antMatchers("/h2-console/**","/refreshtoken/**","/login").permitAll()
                /*.authorizeRequests().antMatchers(HttpMethod.POST,"/user/**").hasAuthority("ADMIN")
                .and()
                .authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER")
                .and()*/
                //.authorizeRequests().antMatchers(HttpMethod.POST,"/addRoleToUSer/**").hasAuthority("ADMIN")
                .anyRequest().authenticated()
                .and()
                .addFilter(new JwtAuthentificationFilter(authenticationManager))
                .addFilterBefore( new JWTAuthrisationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Helper method if needed to get AuthenticationManagerBuilder
    private AuthenticationManagerBuilder authenticationManagerBuilder() {
        return new AuthenticationManagerBuilder(objectPostProcessor());
    }

    // Helper method if needed for ObjectPostProcessor
    private ObjectPostProcessor<Object> objectPostProcessor() { 
        // Return an appropriate ObjectPostProcessor instance
        return new ObjectPostProcessor<>() {
            @Override
            public <O> O postProcess(O object) {
                // Custom processing or just return the object
                return object;
            }
        };
    }
}
