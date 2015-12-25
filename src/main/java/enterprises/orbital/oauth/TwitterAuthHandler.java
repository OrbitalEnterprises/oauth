package enterprises.orbital.oauth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.TwitterApi;
import org.scribe.model.Token;
import org.scribe.oauth.OAuthService;

/**
 * Handle requests to authenticate via Twitter.
 */
public class TwitterAuthHandler {
  private static final Logger log = Logger.getLogger(TwitterAuthHandler.class.getName());

  public static String doGet(String twitterApiKey, String twitterApiSecret, String callback, HttpServletRequest req) throws IOException {
    AuthUtil.prepAuthFlow(req);

    try {
      // Start the OAuth procedure with twitter. We'll resume this flow in the callback handler. We save the request token in session state so we can check it
      // in the callback.
      OAuthService service = new ServiceBuilder().provider(TwitterApi.Authenticate.class).apiKey(twitterApiKey).apiSecret(twitterApiSecret).callback(callback)
          .build();
      Token requestToken = service.getRequestToken();
      req.getSession().setAttribute("twitter_req_token", requestToken);
      return service.getAuthorizationUrl(requestToken);
    } catch (Exception e) {
      log.log(Level.SEVERE, "error attempting twitter authentication", e);
      return null;
    }
  }

}
