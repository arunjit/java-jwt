package in.ajsd.jwt;

import static com.google.common.truth.Truth.assertThat;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class JwtDataTest {

  private static final JwtData JWT = JwtData.newBuilder()
      .setIssuer("ajsd.in")
      .setExpires(123123L)
      .build();

  private final Gson gson = new GsonBuilder().create();

  @Test
  public void built() {
    assertThat(JWT.getType()).isEqualTo("JWT");
    assertThat(JWT.getAlgorithm()).isEqualTo(Algorithm.HS256.getJwtName());
    assertThat(JWT.getIssuer()).isEqualTo("ajsd.in");
    assertThat(JWT.getExpires()).isEqualTo(123123L);
    assertThat(JWT.getAudience()).isNull();
    assertThat(JWT.getSubject()).isNull();
  }

  @Test
  public void serializeHeader() {
    String json = gson.toJson(JWT.getHeader());
    assertThat(json).isEqualTo("{\"typ\":\"JWT\",\"alg\":\"HS256\"}");
  }

  @Test
  public void serializeDeserializeClaims() {
    String json = gson.toJson(JWT.getClaims());
    assertThat(json).isEqualTo("{\"iss\":\"ajsd.in\",\"exp\":123123}");
    JwtData jwt = JwtData.of(null, gson.fromJson(json, JwtData.Claims.class));
    assertThat(jwt.getIssuer()).isEqualTo("ajsd.in");
    assertThat(jwt.getExpires()).isEqualTo(123123L);
    assertThat(jwt.getAudience()).isNull();
    assertThat(jwt.getSubject()).isNull();
  }
}
