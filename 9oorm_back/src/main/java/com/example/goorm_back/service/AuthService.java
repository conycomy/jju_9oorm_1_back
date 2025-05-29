package com.example.goorm_back.service;


import com.example.goorm_back.domain.user.Member;
import com.example.goorm_back.domain.user.Role;
import com.example.goorm_back.dto.JwtResponseDto;
import com.example.goorm_back.dto.KakaoTokenResponseDto;
import com.example.goorm_back.dto.KakaoUserInfoDto;
import com.example.goorm_back.jwt.JwtTokenProvider;
import com.example.goorm_back.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import jakarta.annotation.PostConstruct;

@Service
@RequiredArgsConstructor
@Transactional
@Log4j2
public class AuthService {


	private final MemberRepository memberRepository;
	private final JwtTokenProvider jwtTokenProvider;
	private final RestTemplate restTemplate;

	private final String kakaoClientId = System.getenv("KAKAO_CLIENT_ID");
	private final String kakaoClientSecret = System.getenv("KAKAO_CLIENT_SECRET");
	private final String kakaoRedirectUri = System.getenv("KAKAO_REDIRECT_URI");


	@PostConstruct
	public void init() {
		log.info("Kakao Client ID: {}", kakaoClientId);
		log.info("Kakao Client Secret: {}", kakaoClientSecret);
		log.info("Kakao Redirect URI: {}", kakaoRedirectUri);
	}

	public ResponseEntity<JwtResponseDto> kakaoLogin(String code) {
		// 1. 인가코드로 access_token 요청
		KakaoTokenResponseDto tokenDto = requestAccessToken(code);

		// 2. access_token으로 사용자 정보 요청
		KakaoUserInfoDto userInfo = getKakaoInfo(tokenDto.getAccess_token());

		// 3. 사용자 정보 추출
		KakaoUserInfoDto.KakaoAccount account = userInfo.getKakaoAccount();
		String email = account.getEmail();
		String nickname =
			(account.getProfile() != null && account.getProfile().getNickname() != null)
				? account.getProfile().getNickname()
				: "이름없는 공주";

		// 4. 회원 DB 조회 or 저장
		Member member = memberRepository.findByKakaoId(userInfo.getId())
			.orElseGet(() -> memberRepository.save(
				Member.builder()
					.kakaoId(userInfo.getId())
					.email(email)
					.nickname(nickname)
					.role(Role.GENERAL)
					.build()
			));

		// 5. JWT 발급
		String jwt = jwtTokenProvider.generateToken(
			member.getId(), member.getEmail(), member.getRole().name());

		return ResponseEntity.ok(new JwtResponseDto(true, jwt, null));
	}

	private KakaoTokenResponseDto requestAccessToken(String code) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("grant_type", "authorization_code");
		body.add("client_id", kakaoClientId);
		if (kakaoClientSecret != null && !kakaoClientSecret.isEmpty()) {
			body.add("client_secret", kakaoClientSecret);
		}
		body.add("redirect_uri", kakaoRedirectUri);
		body.add("code", code);

		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
		ResponseEntity<KakaoTokenResponseDto> response = restTemplate.postForEntity(
			"https://kauth.kakao.com/oauth/token",
			request,
			KakaoTokenResponseDto.class
		);

		return response.getBody();
	}

	public KakaoUserInfoDto getKakaoInfo(String accessToken) {
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		HttpEntity<String> entity = new HttpEntity<>(headers);
		ResponseEntity<KakaoUserInfoDto> response = restTemplate.exchange(
			"https://kapi.kakao.com/v2/user/me",
			HttpMethod.GET,
			entity,
			KakaoUserInfoDto.class
		);

		return response.getBody();
	}
}
