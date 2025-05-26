package com.example.goorm_back.controller;

import com.example.goorm_back.service.AuthService;
import com.example.goorm_back.dto.JwtResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;

	@GetMapping("/auth/kakao/callback")
	public ResponseEntity<JwtResponseDto>
	kakaoCallback(@RequestParam("code") String code) {
		log.info("💡 받은 인가코드 = {}", code);

		JwtResponseDto jwt = authService.kakaoLogin(code).getBody();
		return ResponseEntity.ok(jwt);
	}
}


	/* 테스트용
	@GetMapping("/auth/kakao/callback")
	public ResponseEntity<String> kakaoCallback(@RequestParam("code") String code) {
		log.info("💡 받은 인가코드 = {}", code);
		return ResponseEntity.ok("받은 인가코드: " + code);
	}
}
*/

/*
	// 마이페이지용
	@GetMapping("/api/mypage")
	public ResponseEntity<String> myPage(HttpServletRequest request) {
		String token = jwtTokenProvider.resolveToken(request); // JwtTokenProvider 안에 있어야 함!
		Long userId = jwtTokenProvider.getUserIdFromToken(token);
		return ResponseEntity.ok("안녕 공주님! 당신의 ID는 " + userId);
	}
}

 */