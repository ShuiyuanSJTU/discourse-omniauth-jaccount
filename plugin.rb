# frozen_string_literal: true

# name: discourse-omniauth-jaccount
# about: login with jAccount
# version: 0.1.1
# authors: Rong Cai(feynixs), Jiajun Du, pangbo
# url: https://github.com/ShuiyuanSJTU/discourse-omniauth-jaccount


PLUGIN_NAME ||= 'auth-jaccount'.freeze
PROVIDER_NAME ||= 'jaccount'.freeze
enabled_site_setting :jaccount_auth_enabled

class ::Auth::JAccountAuthenticator < ::Auth::Authenticator

  class JAccountStrategy < OmniAuth::Strategies::OAuth2
    option :name, PROVIDER_NAME

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
        'code' => raw_info['code'],
        'type' => raw_info['userType']
      }
    end

    extra do
      {raw_info: raw_info}
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

    provider = auth_token[:provider] || PROVIDER_NAME
    if auth_token[:provider] != PROVIDER_NAME
      Rails.logger.warn("jaccount provider name not match, #{auth_token[:provider]} != #{PROVIDER_NAME}")
    end

    ja_uid = auth_token["uid"]
    ja_uid = email if ja_uid&.strip == "" # 集体账号没有 jAcount UID

    # 部分身份和学工号的 jAccount 不允许注册
    blocked_types = SiteSetting.jaccount_auth_block_types.split("|")
    if blocked_types.include?(type)
      result.failed = true
      result.failed_reason = I18n.t("jaccount_auth.failed_reason.blocked_type", type: type, email: SiteSetting.contact_email)
      Rails.logger.warn("jaccount login blocked beacause of type `#{type}`,#{data}")
    end

    if SiteSetting.jaccount_auth_block_code_regex != ""
      if SiteSetting.jaccount_auth_types_must_have_code.split("|").include?(type) && code.empty?
        result.failed = true
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.no_code", type: type, email: SiteSetting.contact_email)
        Rails.logger.warn("jaccount login blocked beacause of no code,#{data}")
      end
      blocked_code_regexp = Regexp.new(SiteSetting.jaccount_auth_block_code_regex)
      if code && code.match?(blocked_code_regexp)
        result.failed = true
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.blocked_code", code: code, email: SiteSetting.contact_email)
        Rails.logger.warn("jaccount login blocked beacause of code `#{code}`,#{data}")
      end
    end

    # Plugin specific data storage
    association =
    UserAssociatedAccount.find_or_initialize_by(
      provider_name: provider,
      provider_uid: ja_uid,
      )
      
      # Check if the user is trying to connect an existing account
      if association.user_id.nil?
        # try to find by email
        existing_user = User.find_by_email(email.downcase)
        if existing_user
          result.user = existing_user
          association.user = existing_user
          UserAssociatedAccount.where(provider_name: provider, user_id: existing_user.id).destroy_all
        end
      else # existing user
        result.user = User.find_by(id: association.user_id)
      end
      
      association.info = auth_token[:info] || {}
      association.extra = auth_token[:extra] || {}
      association.last_used = Time.zone.now
      
      association.save!
      
      if SiteSetting.jaccount_auth_debug_mode
        Rails.logger.warn <<~EOS 
          [DEBUG] jaccount login, #{result.user&.username}(#{result.user&.id})
          #{auth_token[:info]}
          #{auth_token[:extra]}
          #{result.failed_reason}
        EOS
      end

      if result.failed
        result.user = nil
        return result
      end

      result.name ||= account
      result.username = account
      result.email ||= email
    result.email_valid = true
    result.extra_data = {
      jaccount_uid: ja_uid,
      jaccount_screen_name: screen_name,
      jaccount_provider: provider
    }
    result
  end

  def after_create_account(user, auth_result)
    data = auth_result[:extra_data]
    association =
      UserAssociatedAccount.find_or_initialize_by(
        provider_name: data[:jaccount_provider],
        provider_uid: data[:jaccount_uid],
      )
    association.user = user
    association.save!
  end

  def register_middleware(omniauth)
    omniauth.provider JAccountStrategy,
    client_id: ENV["JACCOUNT_APP_ID"],
    client_secret: ENV["JACCOUNT_SECRET"],
    scope: "essential"
  end

  def description_for_user(user)
    association = UserAssociatedAccount.find_by(
        provider_name: PROVIDER_NAME,
        user_id: user.id,
      )
    if association
      association.provider_uid
    else
      ""
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
              authenticator: ::Auth::JAccountAuthenticator.new

