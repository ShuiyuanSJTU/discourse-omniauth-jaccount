# name: jAccount auth
# about: login with jAccount
# version: 0.0.1
# authors: Rong Cai(feynixs)

gem 'omniauth-jaccount', '0.1.5'

class JAccountAuthenticator < ::Auth::Authenticator

  def name
    'jaccount'
  end

  def enabled?
    true
  end

  def after_authenticate(auth_token)
    result = Auth::Result.new

    # Grap the info we need from OmniAuth
    data = auth_token[:info]
    name = screen_name = data["name"]
    ja_uid = auth_token["uid"]
    email = data["email"]

    # Plugin specific data storage
    current_info = ::PluginStore.get("auth-jaccount", "ja_uid_#{ja_uid}")

    # Check if the user is trying to connect an existing account
    unless current_info
      existing_user = User.joins(:user_emails).find_by(user_emails: { email: email })
      if existing_user
        ::PluginStore.set("auth-jaccount", "ja_uid_#{ja_uid}", { user_id: existing_user.id })
        result.user = existing_user
      end
    else
      result.user = User.where(id: current_info[:user_id]).first
    end
    account_name = email.split("@")[0]
    result.name ||= account_name
    result.username = account_name
    result.email ||= email
    result.email_valid = true
    result.extra_data = {
      jaccount_uid: ja_uid,
      jaccount_screen_name: screen_name
    }
    result
  end

  def after_create_account(user, auth)
    data = auth[:extra_data]
    ::PluginStore.set("auth-jaccount", "ja_uid_#{data[:jaccount_uid]}", { user_id: user.id })
  end

  def register_middleware(omniauth)
    omniauth.provider :jaccount,
    SiteSetting.jaccount_app_id != "" ? SiteSetting.jaccount_app_id : ENV['JACCOUNT_APP_ID'],
    SiteSetting.jaccount_secret != "" ? SiteSetting.jaccount_secret : ENV['JACCOUNT_SECRET'],
    scope: 'basic'

  end

  def description_for_user(user)
    ""
  end

  # can authorisation for this provider be revoked?
  def can_revoke?
    false
  end

  # can exising discourse users connect this provider to their accounts
  def can_connect_existing_user?
    true
  end
end

auth_provider title: 'with jAccount',
              authenticator: JAccountAuthenticator.new
