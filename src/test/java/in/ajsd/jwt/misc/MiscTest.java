package in.ajsd.jwt.misc;

import static com.google.common.truth.Truth.assertThat;

import static java.util.Arrays.asList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

@RunWith(JUnit4.class)
public class MiscTest {

  private final Gson gson = new GsonBuilder().create();

  private static final Map<String, Object> claims = new HashMap<>();
  static {
    claims.put("iss", "ajsd.in");
    claims.put("exp", 123123);
    claims.put("aud", asList("foo", "bar"));
  }

  @Test
  public void serializeMap() {
    assertThat(gson.toJson(claims))
        .isEqualTo("{\"aud\":[\"foo\",\"bar\"],\"iss\":\"ajsd.in\",\"exp\":123123}");
  }

  @Test
  @Ignore("Number vs int/long/double value for exp")
  public void serializeDeserializeMap() {
    Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
    Map<String, Object> actual = gson.fromJson(gson.toJson(claims), mapType);
    assertThat(actual).hasKey("iss").withValue(claims.get("iss"));
    assertThat(actual).hasKey("exp").withValue(claims.get("exp"));
    assertThat(actual).hasKey("aud").withValue(claims.get("aud"));
  }
}
