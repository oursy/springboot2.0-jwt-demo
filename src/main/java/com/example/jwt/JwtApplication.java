package com.example.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.Collections;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setMaxAge(1800L);
		config.setExposedHeaders(Arrays.asList("Authorization","Link","X-Total-Count"));
		config.setAllowedOrigins(Collections.singletonList("*"));
		if (config.getAllowedOrigins() != null && !config.getAllowedOrigins().isEmpty()) {
			System.out.println("Registering CORS filter");
			source.registerCorsConfiguration("/api/**", config);
			source.registerCorsConfiguration("/management/**", config);
			source.registerCorsConfiguration("/v2/api-docs", config);
			source.registerCorsConfiguration("/*/api/**", config);
			source.registerCorsConfiguration("/*/management/**", config);
		}
		return new CorsFilter(source);
	}
}
