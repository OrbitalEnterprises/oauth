package enterprises.orbital.oauth;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

import enterprises.orbital.base.OrbitalProperties;

public class EVEApi extends DefaultApi20 {
  private static final String PROP_AUTH_URL            = "enterprises.orbital.oauth.authURL";
  private static final String PROP_ACCESS_TOKEN_URL    = "enterprises.orbital.oauth.accessURL";
  private static final String DEFAULT_AUTH_URL         = "https://login.eveonline.com/oauth/authorize/";
  private static final String DEFAULT_ACCESS_TOKEN_URL = "https://login.eveonline.com/oauth/token";

  // Test site URLs are as follows:
  //
  // AUTH = https://sisilogin.testeveonline.com/oauth/authorize/
  //
  // ACCESS = https://sisilogin.testeveonline.com/oauth/token
  //
  // Use a properties files to override the defaults

  private static class InstanceHolder {
    private static final EVEApi INSTANCE = new EVEApi();
  }

  public static EVEApi instance() {
    return InstanceHolder.INSTANCE;
  }

  @Override
  public String getAccessTokenEndpoint() {
    return OrbitalProperties.getGlobalProperty(PROP_ACCESS_TOKEN_URL, DEFAULT_ACCESS_TOKEN_URL);
  }

  @Override
  public Verb getAccessTokenVerb() {
    return Verb.POST;
  }

  @Override
  public OAuth20Service createService(
                                      OAuthConfig config) {
    return new EVEOAuthServiceImpl(this, config);
  }

  @Override
  protected String getAuthorizationBaseUrl() {
    return OrbitalProperties.getGlobalProperty(PROP_AUTH_URL, DEFAULT_AUTH_URL);
  }

}
