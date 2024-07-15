# frozen_string_literal: true

# name: discourse-omniauth-jaccount
# about: login with jAccount
# version: 0.2.1
# authors: Rong Cai(feynixs), Jiajun Du, pangbo
# url: https://github.com/ShuiyuanSJTU/discourse-omniauth-jaccount

enabled_site_setting :jaccount_auth_enabled
class ::Auth::JAccountAuthenticator < ::Auth::Authenticator
  PLUGIN_NAME ||= 'auth-jaccount'.freeze
  PROVIDER_NAME ||= 'jaccount'.freeze

  class JAccountStrategy < OmniAuth::Strategies::OAuth2
    option :name, PROVIDER_NAME

    option :client_options, {
      site: 'https://api.sjtu.edu.cn/v1',
      authorize_url: 'https://jaccount.sjtu.edu.cn/oauth2/authorize',
      token_url: 'https://jaccount.sjtu.edu.cn/oauth2/token'
    }

    option :authorize_params, {scope: "essential"}

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
    PROVIDER_NAME
  end

  def enabled?
    SiteSetting.jaccount_auth_enabled
  end

  def lookup_user_from_code(extra)
    begin
      identities = extra["raw_info"]["identities"]
    rescue
      return nil
    end

    if identities.nil? || !identities.is_a?(Array) || identities.length == 0
      nil
    else
      query_codes = identities.compact.map{|id| id["code"]}\
        .compact.map{|code| ["code":code.to_s].to_json}
      association_record = UserAssociatedAccount.where(
          "extra -> 'raw_info' -> 'identities' @> ANY(ARRAY[?]::jsonb[])", query_codes)
      User.where(id: association_record.pluck(:user_id))
    end
  end

  def is_blocked_indentity?(type, code)
    if SiteSetting.jaccount_auth_block_types.split("|").include?(type)
      return :type_blocked
    end
    if SiteSetting.jaccount_auth_block_code_regex != ""
      if SiteSetting.jaccount_auth_types_must_have_code.split("|").include?(type) && 
          code.to_s.strip.empty?
        return :no_code
      end
      blocked_code_regexp = Regexp.new(SiteSetting.jaccount_auth_block_code_regex)
      if code && code.match?(blocked_code_regexp)
        return :code_blocked
      end
    end
  end

  def is_allowed_jaccount?(raw_info)
    failed_reason = nil
    
    # 检查默认身份
    code = raw_info["code"].to_s.strip
    type = raw_info["userType"].to_s.strip
    failed_reason = is_blocked_indentity?(type, code)
    
    if failed_reason.nil?
      return true, nil
    elsif !SiteSetting.jaccount_auth_check_all_identities
      return false, failed_reason
    end
    
    # 开始检查所有身份
    passed = false
    valid_identities = raw_info.identities.to_a.reject do |id|
      begin
        Time.parse(id['expireDate']) < Time.now
      rescue
        true
      end
    end.each do |id|
      if is_blocked_indentity?(id["userType"], id["code"]).nil?
        passed = true
        break
      end
    end

    if passed
      return true, nil
    else
      return false, failed_reason
    end
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
    ja_uid = email if ja_uid.to_s.strip.empty? # 集体账号没有 jAcount UID
    # byebug
    should_allow_login, failed_reason = is_allowed_jaccount?(auth_token[:extra][:raw_info])
    if !should_allow_login
      result.failed = true
      case failed_reason
      when :type_blocked
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.blocked_type", email: SiteSetting.contact_email, type: type)
        Rails.logger.warn("jaccount login blocked beacause of type `#{type}`,#{data}")
      when :no_code
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.no_code", email: SiteSetting.contact_email, type: type)
        Rails.logger.warn("jaccount login blocked beacause of no code,#{data}")
      when :code_blocked
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.blocked_code", email: SiteSetting.contact_email, code: code)
        Rails.logger.warn("jaccount login blocked beacause of code `#{code}`,#{data}")
      else
        result.failed_reason = I18n.t("jaccount_auth.failed_reason.unknown", email: SiteSetting.contact_email, code: code, type: type)
        Rails.logger.warn("jaccount login blocked beacause of unknown reason,#{data}")
      end
    end

    # Plugin specific data storage
    association = UserAssociatedAccount.find_or_initialize_by(
      provider_name: provider,
      provider_uid: ja_uid,
      )

    # Check if the user is trying to connect an existing account
    if association.user_id.nil?
      # try to find by email
      existing_user = User.find_by_email(email.downcase)
      # try to find by code
      if existing_user.nil?
        association_record_by_code = lookup_user_from_code(auth_token[:extra])
        if association_record_by_code.nil? || association_record_by_code.length == 0
          existing_user = nil
        elsif association_record_by_code.length == 1
          existing_user = association_record_by_code.first
        elsif association_record_by_code.length > 1
          result.failed = true
          result.failed_reason = I18n.t("jaccount_auth.failed_reason.multiple_user_found", email: SiteSetting.contact_email, error_code: association_record_by_code.pluck(:id))
          Rails.logger.warn("jaccount login failed because of multiple user found,#{association_record_by_code.pluck(:id)},#{data}")
        end
      end
      if !existing_user.nil?
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

after_initialize do
  add_to_serializer(:admin_detailed_user, :jaccount_type, include_condition: -> { SiteSetting.jaccount_display_account_type }) do
    association = UserAssociatedAccount.find_by(
      provider_name: ::Auth::JAccountAuthenticator::PROVIDER_NAME,
      user_id: object.id,
    )
    if association.nil?
      return I18n.t("jaccount_auth.admin_user_details.no_jaccount")
    end
    identities = association.extra.dig('raw_info','identities')
    if identities.nil? || !identities.is_a?(Array) || identities.length == 0
      return I18n.t("jaccount_auth.admin_user_details.no_identities") + "(#{association.extra.dig('raw_info','userType')})"
    end
    valid_identities = identities.reject{|id| id['expireDate'].nil?}.reject do |id|
      begin
        Time.parse(id['expireDate']) < Time.now
      rescue
        true
      end
    end.pluck('userTypeName').uniq.compact
    return valid_identities.join(', ') if valid_identities.length > 0
    # check if there is an alumni identity
    alumni_identities = identities.select{|id| id['userType'] == 'alumni'}
    return alumni_identities.pluck('userTypeName').first.to_s if alumni_identities.length > 0
    I18n.t("jaccount_auth.admin_user_details.no_valid_identities") + "(#{association.extra.dig('raw_info','userType')})"
  end
end