package com.snort.config;

import com.snort.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.snort.service.UserService;

@Configuration
@EnableWebSecurity
public class SecurityConfigration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;
    @Autowired
    private JWTRequestFilter jwtRequestFilter;
    @Autowired
    private JwtAuthEntryPoint jwtAuthEntryPoint;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;


    /*

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers(
                 "/registration**",
                    "/js/**",
                    "/css/**",
                    "/img/**").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/login")
        .permitAll()
        .and()
        .logout()
        .invalidateHttpSession(true)
        .clearAuthentication(true)
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        .logoutSuccessUrl("/login?logout")
        .permitAll();
    }	*/
    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


  /*  @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }*/

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
		/*http.cors().and().csrf().disable();
		http.authorizeRequests().antMatchers(
						"/registration**",
						"/js/**",
						"/css/**",
						"/img/**").permitAll()
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.loginPage("/authenticate")
				.permitAll()
				.and()
				.logout()
				.invalidateHttpSession(true)
				.clearAuthentication(true)
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessUrl("/login?logout")
				.permitAll()
				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and().
				addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);;*/
		/*http.cors();
		http.csrf().disable()
				.authorizeRequests()
				.antMatchers("/").permitAll()
				.anyRequest().authenticated().and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
				and().
				addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);;*/

        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/authenticate",
                        "/registration**",
                        "/js/**",
                        "/css/**",
                        "/img/**").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .invalidateHttpSession(true)
                .clearAuthentication(true).and()
                .exceptionHandling().authenticationEntryPoint(this.jwtAuthEntryPoint)
                .and().antMatcher("/index").authorizeRequests().and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                http.addFilterBefore(this.jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());
    }
 /*   @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
        auth.setUserDetailsService(userService);
        auth.setPasswordEncoder(passwordEncoder());
        return auth;
    }*/

}
