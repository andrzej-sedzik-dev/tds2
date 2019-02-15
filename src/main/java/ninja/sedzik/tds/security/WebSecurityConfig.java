package ninja.sedzik.tds.security;


import ninja.sedzik.tds.security.jwt.JwtAuthEntryPoint;
import ninja.sedzik.tds.security.jwt.JwtAuthTokenFilter;
import ninja.sedzik.tds.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		prePostEnabled = true
)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private JwtAuthEntryPoint unauthorizedHandler;

    @Bean
    public JwtAuthTokenFilter authenticationJwtTokenFilter() {
        return new JwtAuthTokenFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().
                authorizeRequests()
                .antMatchers("/**").permitAll()
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/signup**").permitAll()
                .antMatchers("/auth/login").permitAll()
                .antMatchers("/login").permitAll()
                .antMatchers("/auth").permitAll()
                .anyRequest().permitAll() // BY AS - becouse block Angular
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                .and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }


    /*
      @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.csrf().disable().exceptionHandling().authenticationEntryPoint(authenticationEntryPoint).and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        .authorizeRequests()
        .antMatchers("/**").permitAll()
        .antMatchers("/registration").permitAll()
        .antMatchers("/login").permitAll()
        .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        .anyRequest().authenticated();

        httpSecurity.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(new CrsfHeaderFilter(), CsrfFilter.class);

        httpSecurity.headers().cacheControl();
        httpSecurity.headers().httpStrictTransportSecurity().includeSubDomains(true).maxAgeInSeconds(31536000);
  }
     */















}
