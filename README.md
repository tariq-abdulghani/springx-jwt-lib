# springx-jwt-lib 0.0.1-SNAPSHOT
`is a lib for spring projects used to encapsulate JWT
logic`
## project goals
1. reusable solution for JWTs
2. provide JwtFilter 
3. provide JWT util that enables u

    1. validate token
    2. generate token with many options


6. provide Http Stateless Config class


# install
till now its hosted here its not on maven repo yet
download the source and build and include the jar file 
as a dependency.

# usage
1. create a configuration class that configures the JWT util
provide the secret and expiration time // required
its better to get them from properties file
```java

import api.JwtUtil;
import jwt.JwtUtilImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtUtilConfig {
    private String secret ="secret*,".repeat(5);
    @Bean
    JwtUtil provide (){
        return  new JwtUtilImpl(secret, 5*60*60*1000);
    }
}
```

2. add the JWT filter and configure paths
here i used `StatelessHttpConfiguration` to apply defaults
like stateless and error handler its optional step 
if you want to write that code by your self
```java

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userService;
    private final JwtTokenFilter jwtTokenFilter;
    private final JwtUtil jwtUtil;


    public SecurityConfig(UserDetailsService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        jwtTokenFilter = new JwtTokenFilter(jwtUtil, userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        StatelessHttpConfiguration.apply(http);

        http.authorizeRequests()
                // Our public endpoints
                .antMatchers("/api/public/**").permitAll()
                .antMatchers("/api/login").permitAll()

                // Our private endpoints
                .antMatchers(HttpMethod.GET, "/api/users/**").hasRole("ADMIN")
                .anyRequest().authenticated();

        http.addFilterBefore(
                jwtTokenFilter,
                UsernamePasswordAuthenticationFilter.class
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}

```
3. create authentication service
authenticates users and generate tokens.
```java
import api.JwtUtil;
import demo.model.AuthenticationData;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class AuthService {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;


    public AuthService(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    public String authenticate(AuthenticationData authenticationData){
        var user = userDetailsService.loadUserByUsername(authenticationData.getName());
        return jwtUtil.generateToken(user.getUsername(),
                user.getAuthorities()
                        .stream()
                        .map(a -> a.getAuthority())
                        .collect(Collectors.toList())
        );
    }
}

```

4. create controller
```java

import demo.model.AuthenticationData;
import demo.model.JwtTokenResponse;
import demo.service.AuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
public class Auth {

    private final AuthService authService;

    public Auth(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(path = "login")
    JwtTokenResponse login(@RequestBody AuthenticationData authenticationData){
        return new JwtTokenResponse(authService.authenticate(authenticationData));
    }
}
```

```java

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/users")
public class Users {

    @GetMapping
    String ping(){
        return "ping users ...";
    }
}
```

# api
### JWT Util
```java

import io.jsonwebtoken.*;

import java.util.Collection;
import java.util.Map;

public interface JwtUtil {
	
	boolean validate(String token);

	String getSubject(String token) throws UnsupportedJwtException,  MalformedJwtException, ExpiredJwtException;

	String generateToken(String subject);

	Jws<Claims> parse(String token) throws JwtException;

	void setExpirationInMs(int expirationInMs);

	String generateToken(String subject, Collection<String> roles);
	
	String generateToken(String subject, Collection<String> roles, Map<String, Object> otherClaims);
}

```

### StatelessHttpConfiguration
```java
public class StatelessHttpConfiguration {

    /**
     * Makes HttpSecurity stateless and set default authentication entry point handler
     * @param http
     * @throws Exception
     */
    public static void apply(HttpSecurity http) throws Exception {

        http.cors().and().csrf().disable();

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(
                        (request, response, ex) -> {
                            response.sendError(
                                    HttpServletResponse.SC_UNAUTHORIZED,
                                    ex.getMessage()
                            );
                        }
                )
                .and();
    }
}
```