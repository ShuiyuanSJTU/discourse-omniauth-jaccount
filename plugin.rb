# name: jAccount auth
# about: login with jAccount
# version: 0.0.2
# authors: Rong Cai(feynixs)
# url: https://github.com/ShuiyuanSJTU/discourse-omniauth-jaccount

gem 'omniauth-jaccount', '0.1.3'
PLUGIN_NAME ||= 'auth-jaccount'.freeze
enabled_site_setting :jaccount_auth_enabled

class JAccountAuthenticator < ::Auth::Authenticator

  def name
    'jaccount'
  end

  def enabled?
    SiteSetting.jaccount_auth_enabled
  end

  def after_authenticate(auth_token)
    result = Auth::Result.new

    # Grap the info we need from OmniAuth
    data = auth_token[:info]
    name = screen_name = data["name"]
    ja_uid = auth_token["uid"]
    email = data["email"]
    ja_uid = email if ja_uid&.strip == ""
    account_name = email.split("@")[0]

    # Plugin specific data storage
    current_info = UserCustomField.find_by(name: PLUGIN_NAME, value: ja_uid)

    # Check if the user is trying to connect an existing account
    unless current_info
      # try to find by email
      existing_user = User.joins(:user_emails).find_by(user_emails: { email: email.downcase })
      if existing_user
        result.user = existing_user
        existing_user.custom_fields[PLUGIN_NAME] = ja_uid
        existing_user.save_custom_fields!
      end
    else # existing user
      result.user = User.find_by(id: current_info.user_id)
    end
    
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
    user.custom_fields[PLUGIN_NAME] = data[:jaccount_uid]
    user.save_custom_fields
  end

  def register_middleware(omniauth)
    omniauth.provider :jaccount,
    client_id: ENV["JACCOUNT_APP_ID"],
    client_secret: ENV["JACCOUNT_SECRET"],
    scope: "basic"

  end

  def description_for_user(user)
    ucf = UserCustomField.find_by(name: PLUGIN_NAME, user_id: user.id)
    if ucf
      ucf.value
    else
      "jAccount"
    end
  end

  # can authorisation for this provider be revoked?
  def can_revoke?
    false
  end

  # can exising discourse users connect this provider to their accounts
  def can_connect_existing_user?
    false
  end
end

auth_provider title: 'with jAccount',
              authenticator: JAccountAuthenticator.new

after_initialize do
  User.register_custom_field_type PLUGIN_NAME, :string

  # delete jaccount info when make user anonymous
  on(:user_anonymized) do |params|
    user = params[:user]
    UserCustomField.find_by(name:PLUGIN_NAME,user_id:user.id).destroy
  end

end
