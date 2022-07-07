package io.getarrays.userservice.filter;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    // 들어오는 요청을 필터링 한 후 프로그램에 액세스 할 수 있는지 여부결정
    // OncePerRequest 이기 때문에 애플리케이션에 들어오는 모든 요청을 가로챌 것이다.
    // 로그인 경로인지 아닌지 체크한다.
    // 로그인 경로이면 아무것도 하지 않는다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login")) {
            filterChain.doFilter(request, response); // 로그인 접근이라면 아무것도 하지않고 다음 필터로 전달
        }else{
            // 인증이 있는지 체크
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if(authorizationHeader!= null && authorizationHeader.startsWith("Bearer ")) {
                // 토큰과 함께 요청을 보낼 때마다 Bearer 과 공백을 입력한 후 토큰을 입력한다.
                // 이유는 토큰을 전달하는 요청을 보내는 사람이 누구든지 토큰이 유효한지 확인하면 아무 것도 할 필요가 없다는 것을 의미한다.
                // 즉 유효한게 확인되면 권한과 토큰을 함께 제공한다. 더이상의 검증은 필요치 않다.
                try {
                    String token = authorizationHeader.substring(
                        "Bearer ".length()); // 토큰만 필요하므로 앞부분 제거
                    Algorithm algorithm = Algorithm.HMAC256(
                        "secret".getBytes()); // 중복되는 코드는 util 함수로 리팩토링 하면서 빼자
                    // 알고리즘을 알기 때문에 검증가능
                    JWTVerifier verifier = JWT.require(algorithm).build(); // verifier 생성
                    DecodedJWT decodedJWT = verifier.verify(token);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    // 사용자가 인증되었고 토큰이 유효하므로 암호는 필요하지 않는다.
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    Arrays.stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                    // SecurityContextHolder에 설정한다. - 이것이 유저이름 역할이다 여기를 접근하여 판단할 것이다.
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response); // 그 다음 필터를 진행하라!
                } catch (Exception exception) {
                    // 인증이 유효하지 않은 등 예외에 대한 처리가 필요하다
                    log.info("Error logging in: {}", exception.getMessage());
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    // response.sendError(FORBIDDEN.value()); // 이게 있으면 아래 작업 수행 불가 - 주석처리

                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            }else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
