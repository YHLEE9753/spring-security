

# RefreshToken
- 사용자가 애플리케이션에 들어가 로그인을 진행한다.
- 로그인 완료 시 accessToken 과 refreshToken 을 얻는다.
- 프론트는 accessToken 과 refreshToken 을 클라이언트 어딘가에 저장한다.
- 리소스에 access 해야 하는 경우 accssToken 을 보낸다.
- 프론트는 accessToken 이 만료될 때마다 forbidden 이나 유사한 응답을 기다린다.
- 응답을 확인한 후 만료된 token 으로 판단되면 refreshToken 을 찾은 후 즉시 다른 요청을 보낸다.
- 사용자가 토큰이 만료되었음을 깨닫고 실제로 accessToken 을 얻으려는 또 다른 요청이 있었던 것처럼 진행이된다.
- 즉 refreshToken 을 통해 유효성을 확인한 다음 다른 accessToken 을 전달한다.
- 이러한 과정을 통해 유저는 계속해서 애플리케이션을 사용하고 리소스에 접근할 수 있다.
