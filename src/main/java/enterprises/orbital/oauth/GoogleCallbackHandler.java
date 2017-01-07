package enterprises.orbital.oauth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.gson.Gson;
import com.google.gson.JsonParser;

/**
 * Handle the callback portion of Google auth.
 */
public class GoogleCallbackHandler {
  private static final Logger log = Logger.getLogger(GoogleCallbackHandler.class.getName());

  public static String doGet(
                             String googleApiKey,
                             String googleApiSecret,
                             String googleScope,
                             String redirectCallback,
                             String standardRedirect,
                             HttpServletRequest req)
    throws IOException {
    // Construct the service to use for verification.
    OAuth20Service service = new ServiceBuilder().apiKey(googleApiKey).scope(googleScope).apiSecret(googleApiSecret).callback(redirectCallback)
        .build(GoogleApi20.instance());

    String caller = standardRedirect;
    try {
      // Exchange for access token
      OAuth2AccessToken accessToken = service.getAccessToken(req.getParameter("code"));

      // Attempt to retrieve credentials.
      OAuthRequest request = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v2/userinfo?alt=json", service.getConfig());
      service.signRequest(accessToken, request);
      Response response = request.send();
      if (!response.isSuccessful()) throw new IOException("credential request was not successful!");

      // Save whether a user is already signed in. If so, then we may be changing an association for a screen name.
      UserAccount existing = AuthUtil.getCurrentUser(req);

      // Two cases to handle here:
      // 1) the credentials match an existing user for auth source "google". If so, then we mark this user as logged in from google.
      // 2) the credentials don't match an existing user. In this case, we need to create the user for the first time.
      String screenName = (new Gson()).fromJson((new JsonParser()).parse(response.getBody()).getAsJsonObject().get("email"), String.class);
      UserAuthSource sourceVal = AuthUtil.getBySourceScreenname("google", screenName);
      if (sourceVal != null) {
        // Already exists
        if (existing != null) {
          // User already signed in so change the associated to the current user. There may also be a redirect we should prefer.
          sourceVal.updateAccount(existing);
          if (req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR) != null) {
            caller = (String) req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
            req.getSession().removeAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
          }
        } else {
          // Otherwise, sign in as usual.
          AuthUtil.signOn(req, sourceVal.getOwner(), sourceVal);
        }
      } else {
        // New user unless already signed in, in which case it's a new association.
        UserAccount newUser = existing == null ? AuthUtil.createNewUserAccount(false) : existing;
        sourceVal = AuthUtil.createSource(newUser, "google", screenName, response.getBody());
        if (existing != null) {
          // For existing users, there may be a redirect we need to handle.
          if (req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR) != null) {
            caller = (String) req.getSession().getAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
            req.getSession().removeAttribute(AuthUtil.ADDAUTH_REDIRECT_SESSION_VAR);
          }
        } else {
          // Otherwise, new user needs to sign in.
          AuthUtil.signOn(req, newUser, sourceVal);
        }
      }

    } catch (Exception e) {
      log.log(Level.WARNING, "Failed google authentication with error: ", e);
      caller = null;
    }

    return caller;
  }

}
