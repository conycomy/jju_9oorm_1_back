package com.example.goorm_back.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
// 로그인(토큰 재발급) 성공 시
@Setter
@Getter
public class JwtResponseDto {

	private boolean isJwtSuccess;
	private String accessToken;
	private String refreshToken; //선택 사항

	//  Refresh Token을 발급하지 않았으므로 , Optional<String> 또는 nullable에 대한 명확한 프론트 처리 필요
}
