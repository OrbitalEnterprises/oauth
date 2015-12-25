package enterprises.orbital.oauth;

import java.util.Date;

/**
 * Interface representing a user. The embedding context should provide an implementation of this interface to represent real users in the underlying system.
 */
public interface UserAccount {

  /**
   * Determine whether this account is disabled. A disabled account will not be allowed to login.
   * 
   * @return true if this account is disabled, false otherwise.
   */
  public boolean isDisabled();

  /**
   * Get the unique ID for this account.
   * 
   * @return the unique ID for this account.
   */
  public String getUid();

  /**
   * Update the last login time of this account to the current time.
   */
  public void touch();

  /**
   * Retrieve the time at which this user account was created (UTC).
   * 
   * @return the time at which this user account was created (UTC).
   */
  public Date getJoinTime();

  /**
   * Retrieve the time (UTC) at which this user account last signed on. Can be null if user has never signed on.
   * 
   * @return the time (UTC) at which this user account last signed on, or null if this user has never signed on.
   */
  public Date getLastSignOn();
}
