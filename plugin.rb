# frozen_string_literal: true

# name: discourse-omniauth-jaccount
# about: login with jAccount
# version: 0.0.5
# authors: Rong Cai(feynixs), Jiajun Du
# url: https://github.com/ShuiyuanSJTU/discourse-omniauth-jaccount


PLUGIN_NAME ||= 'auth-jaccount'.freeze
enabled_site_setting :jaccount_auth_enabled

class JAccountAuthenticator < ::Auth::Authenticator

  class JAccountStrategy < OmniAuth::Strategies::OAuth2
    option :name, "jaccount"

    option :client_options, {
      site: 'https://api.sjtu.edu.cn/v1',
      authorize_url: 'https://jaccount.sjtu.edu.cn/oauth2/authorize',
      token_url: 'https://jaccount.sjtu.edu.cn/oauth2/token'
    }

    option :authorize_params, {scope: "essential"}

    def request_phase
      super
    end

    uid { raw_info["id"].to_s }

    info do
      {
        'account' => raw_info['account'],
        'email' => raw_info['account'] + "@sjtu.edu.cn",
        'name' => raw_info['name'],
        'code' => id_token['code'],
        'type' => id_token['type']
      }
    end

    extra do
      {raw_info: raw_info, id_token: id_token}
    end

    def id_token
      id_token = access_token.params["id_token"]
      payload = JWT.decode(id_token, nil, false)[0]
      payload
    end

    def raw_info
      @raw_info ||= access_token.get('https://api.sjtu.edu.cn/v1/me/profile').parsed
      @raw_info["entities"][0]
    end

    def callback_url
      full_host + script_name + callback_path
    end
  end

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

    name = screen_name = data["name"].to_s.strip
    email = data["email"].to_s.strip
    account = data["account"].to_s.strip
    code = data["code"].to_s.strip
    type = data["type"].to_s.strip

    ja_uid = auth_token["uid"]
    ja_uid = email if ja_uid&.strip == "" # 集体账号没有 jAcount UID

    if SiteSetting.jaccount_auth_debug_mode
      Rails.logger.warn("[DEBUG] jaccount login,#{data}")
    end

    # 部分身份和学工号的 jAccount 不允许注册
    blocked_types = SiteSetting.jaccount_auth_block_types.split("|")
    if blocked_types.include?(type)
      result.failed = true
      result.failed_reason = I18n.t("jaccount_auth.failed_reason.blocked_type", type: type, email: SiteSetting.contact_email)
      Rails.logger.warn("jaccount login blocked beacause of type `#{type}`,#{data}")
      return result
    end

    if SiteSetting.jaccount_auth_block_code_regex != ""
      if SiteSetting.jaccount_auth_types_must_have_code.split("|").include?(type) && code.empty?
        result.failed = true
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.no_code", type: type, email: SiteSetting.contact_email)
        Rails.logger.warn("jaccount login blocked beacause of no code,#{data}")
        return result
      end
      blocked_code_regexp = Regexp.new(SiteSetting.jaccount_auth_block_code_regex)
      if code && code.match?(blocked_code_regexp)
        result.failed = true
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.blocked_code", code: code, email: SiteSetting.contact_email)
        Rails.logger.warn("jaccount login blocked beacause of code `#{code}`,#{data}")
        return result
      end
    end

    # Plugin specific data storage
    current_info = UserCustomField.find_by(name: PLUGIN_NAME, value: ja_uid)

    # Check if the user is trying to connect an existing account
    unless current_info
      # try to find by email
      existing_user = User.joins(:user_emails).find_by(user_emails: { email: email.downcase })
      if existing_user
        result.user = existing_user
        existing_user.custom_fields[PLUGIN_NAME] = ja_uid
        existing_user.save_custom_fields
      end
    else # existing user
      result.user = User.find_by(id: current_info.user_id)
    end
    
    result.name ||= account
    result.username = account
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
    omniauth.provider JAccountStrategy,
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
