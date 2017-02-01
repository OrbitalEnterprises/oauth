package enterprises.orbital.oauth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * Handle requests to authenticate via EVE.
 */
public class EVEAuthHandler {
  private static final Logger log = Logger.getLogger(EVEAuthHandler.class.getName());

  public static String doGet(
                             String clientID,
                             String secretKey,
                             String callback,
                             String scope,
                             String state,
                             HttpServletRequest req)
    throws IOException {
    AuthUtil.prepAuthFlow(req);

    try {
      // Construct an OAuth request for EVE.
      ServiceBuilder builder = new ServiceBuilder().responseType("code").apiKey(clientID).apiSecret(secretKey).callback(callback);
      if (scope != null && !scope.isEmpty()) builder = builder.scope(scope);
      if (state != null && !state.isEmpty()) builder = builder.state(state);
      OAuth20Service service = builder.build(EVEApi.instance());
      return service.getAuthorizationUrl(null);
    } catch (Exception e) {
      log.log(Level.SEVERE, "Error while attempting EVE authentication: ", e);
      return null;
    }
  }

  public static OAuth2AccessToken doRefresh(
                                            String clientID,
                                            String secretKey,
                                            String refreshToken)
    throws IOException {
    try {
      // Construct a refresh request to EVE.
      ServiceBuilder builder = new ServiceBuilder().apiKey(clientID).apiSecret(secretKey);
      OAuth20Service service = builder.build(EVEApi.instance());
      return service.refreshAccessToken(refreshToken);
    } catch (Exception e) {
      log.log(Level.SEVERE, "Error while attempting to refresh access token: ", e);
      return null;
    }
  }

}
