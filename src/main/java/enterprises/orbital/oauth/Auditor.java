package enterprises.orbital.oauth;

import java.util.logging.Logger;

/**
 * Orbital auditing facilities.
 */
public class Auditor {
  // We use this logger (at INFO level) to form an audit log.
  public static final Logger                log         = Logger.getLogger(Auditor.class.getName());
  private static ThreadLocal<StringBuilder> builderPool = new ThreadLocal<StringBuilder>() {
                                                          @Override
                                                          protected StringBuilder initialValue() {
                                                            return new StringBuilder();
                                                          }
                                                        };

  public static void audit(UserAccount user, Object... info) {
    StringBuilder builder = builderPool.get();
    builder.setLength(0);

    // Log user if available
    builder.append("USER: [");
    if (user == null)
      builder.append("INTERNAL");
    else
      builder.append(user.getUid());
    builder.append("] AUDIT: ");
    for (int i = 0; i < info.length; i++) {
      builder.append(String.valueOf(info[i]));
      builder.append(" ");
    }

    log.info(builder.toString());
  }
}
