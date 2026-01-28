package demago.gamjappang.config;

import demago.gamjappang.config.oauth.PrincipalOauth2UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    private PrincipalOauth2UserService principalOauth2UserService;

    @Autowired
    public void setPrincipalOauth2UserService(PrincipalOauth2UserService principalOauth2UserService) {
        this.principalOauth2UserService = principalOauth2UserService;
    }

    // 해당 메서드로 리턴되는 오브젝트를 IoC로 등록해줌
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN") // hasAuthority("ROLE_ADMIN")
                        .anyRequest().permitAll()
                )

                .formLogin(login -> login
                                .loginPage("/loginForm")
                                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해줌
                                .defaultSuccessUrl("/")
//                         .usernameParameter("username") // 유저네임 파라미터 변경 가능
//                        .permitAll()
                )

                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/loginForm")
                        .userInfoEndpoint(userInfo -> userInfo.userService(principalOauth2UserService))
                        .failureHandler((request, response, exception) -> {
                            System.err.println("OAUTH2 LOGIN FAILED");
                            exception.printStackTrace();
                            response.sendRedirect("/loginForm?error"); // 기존 동작 유지
                        })
                );

        return http.build();
    }
}