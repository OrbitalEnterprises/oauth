package enterprises.orbital.oauth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * Handle requests to authenticate via Google.
 */
public class GoogleAuthHandler {
  private static final Logger log = Logger.getLogger(GoogleAuthHandler.class.getName());

  public static String doGet(
                             String googleApiKey,
                             String googleApiSecret,
                             String googleScope,
                             String callback,
                             HttpServletRequest req)
    throws IOException {
    AuthUtil.prepAuthFlow(req);

    try {
      // Start the OAuth procedure with google. We'll resume this flow in the callback handler. We save the request token in session state so we can check it
      // in the callback.
      OAuth20Service service = new ServiceBuilder().apiKey(googleApiKey).scope(googleScope).apiSecret(googleApiSecret).callback(callback)
          .build(GoogleApi20.instance());
      return service.getAuthorizationUrl(null);
    } catch (Exception e) {
      log.log(Level.SEVERE, "error attempting google authentication", e);
      return null;
    }
  }

}
