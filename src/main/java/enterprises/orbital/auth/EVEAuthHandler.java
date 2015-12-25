package enterprises.orbital.auth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.oauth.OAuthService;

/**
 * Handle requests to authenticate via EVE.
 */
public class EVEAuthHandler {
  private static final Logger log = Logger.getLogger(EVEAuthHandler.class.getName());

  public static String doGet(Class<? extends Api> apiClass, String clientID, String secretKey, String callback, HttpServletRequest req) throws IOException {
    AuthUtil.prepAuthFlow(req);

    try {
      // Construct an OAuth request for EVE.
      OAuthService service = new ServiceBuilder().provider(apiClass).apiKey(clientID).apiSecret(secretKey).callback(callback).build();
      return service.getAuthorizationUrl(null);
    } catch (Exception e) {
      log.log(Level.SEVERE, "Error while attempting EVE authentication: ", e);
      return null;
    }
  }

}
