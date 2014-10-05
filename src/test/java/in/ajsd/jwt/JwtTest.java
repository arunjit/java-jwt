package in.ajsd.jwt;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class JwtTest {

  private static final byte[] SECRET = {1, 2, 3, 4, 5};

  private static final JwtData JWT = JwtData.newBuilder()
      .setIssuer("ajsd.in")
      .setExpires(123123L)
      .build();

  @Test
  public void signedShouldVerify() throws Exception {
    String token = JwtSigner.createToken(SECRET, JWT);
    JwtData jwt = JwtVerifier.verifyToken(SECRET, token);
    assertThat(jwt).isEqualTo(JWT);
  }
}
