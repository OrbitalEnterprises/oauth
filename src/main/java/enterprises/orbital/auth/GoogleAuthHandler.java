package enterprises.orbital.auth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Google2Api;
import org.scribe.model.Token;
import org.scribe.oauth.OAuthService;

/**
 * Handle requests to authenticate via Google.
 */
public class GoogleAuthHandler {
  private static final Logger log = Logger.getLogger(GoogleAuthHandler.class.getName());

  public static String doGet(String googleApiKey, String googleApiSecret, String googleScope, String callback, HttpServletRequest req) throws IOException {
    AuthUtil.prepAuthFlow(req);

    try {
      // Start the OAuth procedure with google. We'll resume this flow in the callback handler. We save the request token in session state so we can check it
      // in the callback.
      OAuthService service = new ServiceBuilder().provider(Google2Api.class).apiKey(googleApiKey).scope(googleScope).apiSecret(googleApiSecret)
          .callback(callback).build();
      Token requestToken = service.getRequestToken();
      req.getSession().setAttribute("google_req_token", requestToken);
      return service.getAuthorizationUrl(requestToken);
      // res.sendRedirect(service.getAuthorizationUrl(requestToken));
    } catch (Exception e) {
      log.log(Level.SEVERE, "error attempting google authentication", e);
      return null;
    }
  }

}
