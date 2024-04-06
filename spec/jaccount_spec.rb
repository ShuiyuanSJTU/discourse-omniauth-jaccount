# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Auth::JAccountAuthenticator do
  def jaccount_test_info
    @jaccount_test_info ||= JSON.parse(
      File.read(File.join(File.dirname(__FILE__), 'jaccount_test_info.json')))
  end
  def jaccount_test_auth_token(key)
    raw_info = jaccount_test_info[key.to_s]
    OmniAuth::AuthHash.new({
      :provider => 'jaccount',
      :uid => raw_info['id'],
      :info =>
        {
          account: raw_info['account'],
          email: raw_info['account'] + "@sjtu.edu.cn",
          name: raw_info['name'],
          code: raw_info['code'],
          type: raw_info['userType']
        },
      :extra =>
        {
          raw_info: OmniAuth::AuthHash.new(raw_info)
        }
    })
  end

  let(:normal_account) { jaccount_test_auth_token("normal_user") }
  let(:team_account) { jaccount_test_auth_token("team_user") }
  let(:type_blocked_account) { jaccount_test_auth_token("should_block_type_user") }
  let(:code_blocked_account) { jaccount_test_auth_token("should_block_code_user") }
  let(:authenticator) { described_class.new }
  fab!(:user)

  describe "should get correct info for new user" do
    it "can authenticate for a normal user" do
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to be_nil

      raw_info = jaccount_test_info["normal_user"]
      expect(result.email).to eq(raw_info["account"] + "@sjtu.edu.cn")
      expect(result.name).to eq(raw_info["account"])
      expect(result.username).to eq(raw_info["account"])
      expect(result.extra_data[:jaccount_uid]).to eq(raw_info["id"])
      expect(result.email_valid).to be_truthy

      expect(UserAssociatedAccount.find_by(
        provider_name: "jaccount", provider_uid: raw_info["id"])).to be_present
    end

    it "can authenticate for a team account" do
      result = authenticator.after_authenticate(team_account)
      expect(result.failed).to be_falsey
      expect(result.user).to be_nil

      raw_info = jaccount_test_info["team_user"]
      expect(result.email).to eq(raw_info["account"] + "@sjtu.edu.cn")
      expect(result.name).to eq(raw_info["account"])
      expect(result.username).to eq(raw_info["account"])
      expect(result.extra_data[:jaccount_uid]).to eq(raw_info["account"] + "@sjtu.edu.cn")
      expect(result.email_valid).to be_truthy

      expect(UserAssociatedAccount.find_by(
        provider_name: "jaccount", provider_uid: raw_info["id"])).to be_nil

      association = UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: raw_info["account"] + "@sjtu.edu.cn")
      expect(association).to be_present
      expect(association.user_id).to be_nil
      expect(association.extra["raw_info"]).to eq(raw_info)
    end
  end

  describe "should find existing user" do
    it "can find existing user by uid" do
      UserAssociatedAccount.create!(user_id: user.id, provider_name: "jaccount", provider_uid: jaccount_test_info["normal_user"]["id"])
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
    end
    it "can find existing user by email" do
      expect(UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: jaccount_test_info["normal_user"]["id"])).to be_nil
      user.update!(email: jaccount_test_info["normal_user"]["account"] + "@sjtu.edu.cn")
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
      expect(UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: jaccount_test_info["normal_user"]["id"])).to be_present
    end
    it "can update existing user association" do
      UserAssociatedAccount.create!(user_id: user.id, provider_name: "jaccount", provider_uid: "SOME_RANDOM_UID")
      user.update!(email: jaccount_test_info["normal_user"]["account"] + "@sjtu.edu.cn")
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
      expect(UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: "SOME_RANDOM_UID")).to be_nil
      expect(UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: jaccount_test_info["normal_user"]["id"])).to be_present
    end
  end
  describe "should block user" do
    before(:example) do
      SiteSetting.jaccount_auth_block_code_regex = "^(AA)?(7\\d{2}602\\d{6})$"
      SiteSetting.jaccount_auth_block_types = "outside"
    end
    it "should block user by code" do
      result = authenticator.after_authenticate(code_blocked_account)
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
      expect(result.failed_reason).to eq(
        I18n.t("jaccount_auth.failed_reason.blocked_code", 
          code: jaccount_test_info["should_block_code_user"]["code"], email: SiteSetting.contact_email)
        )
    end
    it "should block user by type" do
      result = authenticator.after_authenticate(type_blocked_account)
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
      expect(result.failed_reason).to eq(
        I18n.t("jaccount_auth.failed_reason.blocked_type", 
          type: jaccount_test_info["should_block_type_user"]["userType"], email: SiteSetting.contact_email)
        )
    end
    it "blocked user cannot login even if they are existing user" do
      UserAssociatedAccount.create!(user_id: user.id, provider_name: "jaccount", provider_uid: jaccount_test_info["should_block_code_user"]["id"])
      user.update!(email: jaccount_test_info["should_block_code_user"]["account"] + "@sjtu.edu.cn")
      result = authenticator.after_authenticate(code_blocked_account)
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
    end
    it "should block specific type without code" do
      SiteSetting.jaccount_auth_types_must_have_code = "team"
      result = authenticator.after_authenticate(
        team_account.dup.tap { |a| a.info[:code] = "" })
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
      expect(result.failed_reason).to eq(
        I18n.t("jaccount_auth.failed_reason.no_code",
          type: jaccount_test_info["team_user"]["userType"], email: SiteSetting.contact_email)
        )
    end
  end
end