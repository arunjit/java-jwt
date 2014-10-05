package in.ajsd.jwt;

import com.google.common.collect.ImmutableMap;

import java.util.Map;

/** JWT token signing algorithms. Only HS256 is supported for now. */
public enum Algorithm {
  HS256("HS256", "HmacSHA256"),
  ;
  private final String jwtName;
  private final String name;

  private Algorithm(String jwtName, String name) {
    this.jwtName = jwtName;
    this.name = name;
  }

  public String getJwtName() {
    return jwtName;
  }

  public String getName() {
    return name;
  }

//  private static final Map<String, Algorithm> ALGOS =
//      ImmutableMap.<String, Algorithm>builder()
//          .put(Algorithm.HS256.getName(), Algorithm.HS256)
//          .build();

  private static final Map<String, Algorithm> JWT_ALGOS =
      ImmutableMap.<String, Algorithm>builder()
          .put(Algorithm.HS256.getJwtName(), Algorithm.HS256)
          .build();

  public static Algorithm fromJwt(String algorithm) {
    return JWT_ALGOS.get(algorithm);
  }
}
