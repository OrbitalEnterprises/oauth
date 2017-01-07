package enterprises.orbital.oauth;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.AbstractRequest;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.services.Base64Encoder;

public class EVEOAuthServiceImpl extends OAuth20Service {

  public EVEOAuthServiceImpl(DefaultApi20 api, OAuthConfig config) {
    super(api, config);
  }

  @Override
  protected <T extends AbstractRequest> T createAccessTokenRequest(
                                                                   String code,
                                                                   T request) {
    final OAuthConfig config = getConfig();
    String authorization = config.getApiKey() + ":" + config.getApiSecret();
    String encoded = Base64Encoder.getInstance().encode(authorization.getBytes());
    request.addHeader("Authorization", "Basic " + encoded);
    request.addParameter(OAuthConstants.GRANT_TYPE, OAuthConstants.AUTHORIZATION_CODE);
    request.addParameter(OAuthConstants.CODE, code);
    return request;
  }

  @Override
  public void signRequest(
                          OAuth2AccessToken accessToken,
                          AbstractRequest request) {
    request.addHeader("Authorization", "Bearer " + accessToken.getAccessToken());
  }

}
