package com.example.demosecurityquartz.controller;


import com.example.demosecurityquartz.controller.exception.MyAccessDeniedHandler;
import com.example.demosecurityquartz.controller.exception.MyAuthenticationEntryPoint;
import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.pattern.PathPatternParser;


@Configuration
@EnableWebSecurity    // 添加 security 过滤器
@EnableMethodSecurity(prePostEnabled = true)	// 启用方法级别的权限认证
public class SecurityConfig {
    @Resource
    private AuthenticationConfiguration authenticationConfiguration;

    @Resource
    private CustomAuthorizationManager customAuthorizationManager;


    @Resource
    private MyAccessDeniedHandler myAccessDeniedHandler;

    @Resource
    private MyAuthenticationEntryPoint myAuthenticationEntryPoint;


    @Bean
    public JwtRequestFilter authenticationJwtTokenFilter() {
        return new JwtRequestFilter();
    }

    /**
     * 加密方式
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 认证管理器，登录的时候参数会传给 authenticationManager
     *
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //关闭csrf
        http.csrf().disable()
                // 允许跨域（也可以不允许，看具体需求）
                .cors().and()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 配置路径是否需要认证
                .authorizeHttpRequests( authoriz ->{
                            // 对于登录接口 允许匿名访问
                            try {
                                authoriz.requestMatchers(HttpMethod.POST,"/account/**")
                                                .permitAll()
//                                                // 配置权限
//                                                .requestMatchers("/test")
//                                                .hasAuthority("admin")
                                                // 除上面外的所有请求全部需要鉴权认证
                                                .anyRequest().access(customAuthorizationManager)

                                        .and()
                                                .authenticationManager(authenticationManager(authenticationConfiguration))
                                                .sessionManagement()
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                                        .exceptionHandling()
                                        .authenticationEntryPoint(myAuthenticationEntryPoint)
                                        .accessDeniedHandler(myAccessDeniedHandler)
                                        .and()
                                        //此处为添加jwt过滤
                                        .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                )

        ;
        http.headers().frameOptions().disable();
        return http.build();

    }


    /**
     *跨域资源配置
     */
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource()
//    {
//        final CorsConfiguration configuration = new CorsConfiguration();
//
//        //此处发现如果不加入自己的项目地址，会被拦截。
//        configuration.setAllowedOriginPatterns(List.of("http://localhost:8080"));
//        configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS", "DELETE", "PUT", "PATCH"));
//        configuration.setAllowedHeaders(List.of("Access-Control-Allow-Origin", "X-Requested-With", "Origin", "Content-Type", "Accept", "Authorization"));
//        configuration.setAllowCredentials(true);
//
//        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//
//        return source;
//    }

//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource (new PathPatternParser());
//        CorsConfiguration corsConfig = new CorsConfiguration();
//
//        // 允许所有请求方法
//        corsConfig.addAllowedMethod ("*");
//        // 允许所有域，当请求头
//        corsConfig.addAllowedOriginPattern ("*");
//        // 允许全部请求头
//        corsConfig.addAllowedHeader ("*");
//        // 允许携带 Authorization 头
//        corsConfig.setAllowCredentials (true);
//        // 允许全部请求路径
//        source.registerCorsConfiguration ("/**", corsConfig);
//
//        return source;
//    }
}
