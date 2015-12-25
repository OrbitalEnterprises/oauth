package enterprises.orbital.auth;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

/**
 * Handle sign off requests.
 */
public class LogoutHandler {

  public static String doGet(String source, String redirect, HttpServletRequest req) throws IOException {
    if (source != null) {
      // Attempting to remove a source, verify signed on.
      UserAccount acct = AuthUtil.getCurrentUser(req);
      // If not logged in, ignore.
      if (acct == null) return null;
      // Find and remove source if it exists.
      AuthUtil.removeSourceIfExists(acct, source);
      // If this was the currently signed in source, then fall through to the logout behavior below, otherwise redirect back as specified by the caller.
      if (!source.equals(req.getSession().getAttribute(AuthUtil.SOURCE_SESSION_VAR))
          && req.getParameter("redirect") != null) { return req.getParameter("redirect"); }
    }

    // Logout the current user.
    AuthUtil.signOff(req);
    return redirect;
  }

}
