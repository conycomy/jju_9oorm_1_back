package com.example.goorm_back.config;

import com.example.goorm_back.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class FilterConfig implements WebMvcConfigurer {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.csrf(csrf -> csrf.disable())
			.cors(cors -> {
			}) // CORS 활성화

			.authorizeHttpRequests(auth -> auth
				// 인증 없이 접근 가능한 엔드포인트
				.requestMatchers(
					"/auth/**",           // 카카오 콜백 등
					"/oauth2/**",         // OAuth2 관련
					"/login/**",          // 로그인 관련
					"/",                  // 루트
					"/error",             // 에러 페이지
					"/favicon.ico",       // 파비콘
					"/static/**"          // 정적 리소스
				).permitAll()
				// 그 외는 인증 필요
				.anyRequest().authenticated()
			)
			.oauth2Login().disable()
			.addFilterBefore(jwtAuthenticationFilter,
				UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	;

	// 전체 CORS 허용 (실서비스에서는 도메인 지정 권장)
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
			.allowedOrigins("*")  // 개발 중만!
			.allowedMethods("*")
			.allowedHeaders("*")
			.allowCredentials(false);
	}

	@Bean
	public RestTemplate restTemplate() {
		return new RestTemplate();
	}
}

