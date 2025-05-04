# frozen_string_literal: true

require "rails_helper"

RSpec.describe Auth::JAccountAuthenticator do
  def jaccount_test_info
    @jaccount_test_info ||=
      JSON.parse(File.read(File.join(File.dirname(__FILE__), "jaccount_test_info.json")))
  end
  def jaccount_test_auth_token(key)
    raw_info = jaccount_test_info[key.to_s]
    OmniAuth::AuthHash.new(
      {
        provider: "jaccount",
        uid: raw_info["id"],
        info: {
          account: raw_info["account"],
          email: raw_info["account"] + "@sjtu.edu.cn",
          name: raw_info["name"],
          code: raw_info["code"],
          type: raw_info["userType"],
        },
        extra: {
          raw_info: OmniAuth::AuthHash.new(raw_info),
        },
      },
    )
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

      expect(
        UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: raw_info["id"]),
      ).to be_present
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

      expect(
        UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: raw_info["id"]),
      ).to be_nil

      association =
        UserAssociatedAccount.find_by(
          provider_name: "jaccount",
          provider_uid: raw_info["account"] + "@sjtu.edu.cn",
        )
      expect(association).to be_present
      expect(association.user_id).to be_nil
      expect(association.extra["raw_info"]).to eq(raw_info)
    end
  end

  describe "should find existing user" do
    it "can find existing user by uid" do
      Auth::JAccountAuthenticator.any_instance.expects(:lookup_user_from_code).never
      User.expects(:find_by_email).never
      UserAssociatedAccount.create!(
        user_id: user.id,
        provider_name: "jaccount",
        provider_uid: jaccount_test_info["normal_user"]["id"],
      )
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
    end
    it "can find existing user by email" do
      Auth::JAccountAuthenticator.any_instance.expects(:lookup_user_from_code).never
      expect(
        UserAssociatedAccount.find_by(
          provider_name: "jaccount",
          provider_uid: jaccount_test_info["normal_user"]["id"],
        ),
      ).to be_nil
      user.update!(email: jaccount_test_info["normal_user"]["account"] + "@sjtu.edu.cn")
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
      expect(
        UserAssociatedAccount.find_by(
          provider_name: "jaccount",
          provider_uid: jaccount_test_info["normal_user"]["id"],
        ),
      ).to be_present
    end
    it "can update existing user association" do
      UserAssociatedAccount.create!(
        user_id: user.id,
        provider_name: "jaccount",
        provider_uid: "SOME_RANDOM_UID",
      )
      user.update!(email: jaccount_test_info["normal_user"]["account"] + "@sjtu.edu.cn")
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
      expect(
        UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: "SOME_RANDOM_UID"),
      ).to be_nil
      expect(
        UserAssociatedAccount.find_by(
          provider_name: "jaccount",
          provider_uid: jaccount_test_info["normal_user"]["id"],
        ),
      ).to be_present
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
        I18n.t(
          "jaccount_auth.failed_reason.blocked_code",
          code: jaccount_test_info["should_block_code_user"]["code"],
          email: SiteSetting.contact_email,
        ),
      )
    end
    it "should block user by type" do
      result = authenticator.after_authenticate(type_blocked_account)
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
      expect(result.failed_reason).to eq(
        I18n.t(
          "jaccount_auth.failed_reason.blocked_type",
          type: jaccount_test_info["should_block_type_user"]["userType"],
          email: SiteSetting.contact_email,
        ),
      )
    end
    it "blocked user cannot login even if they are existing user" do
      UserAssociatedAccount.create!(
        user_id: user.id,
        provider_name: "jaccount",
        provider_uid: jaccount_test_info["should_block_code_user"]["id"],
      )
      user.update!(email: jaccount_test_info["should_block_code_user"]["account"] + "@sjtu.edu.cn")
      result = authenticator.after_authenticate(code_blocked_account)
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
    end
    it "should block specific type without code" do
      SiteSetting.jaccount_auth_types_must_have_code = "team"
      result =
        authenticator.after_authenticate(
          team_account.dup.tap { |a| a.info.code = "" }.tap { |a| a.extra.raw_info.code = "" },
        )
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
      expect(result.failed_reason).to eq(
        I18n.t(
          "jaccount_auth.failed_reason.no_code",
          type: jaccount_test_info["team_user"]["userType"],
          email: SiteSetting.contact_email,
        ),
      )
    end
  end

  describe "could lookup user from code" do
    before(:example) do
      association =
        UserAssociatedAccount.create!(
          user_id: user.id,
          provider_name: "jaccount",
          provider_uid: "SOME_RANDOM_UID",
        )
      association.extra = { raw_info: jaccount_test_info["normal_user"] }
      association.save!
      user.update!(email: "RANDOM_EMAIL@sjtu.edu.cn")
    end
    it "would invoke lookup_user_from_code" do
      Auth::JAccountAuthenticator.any_instance.expects(:lookup_user_from_code).once.returns([user])
      authenticator.after_authenticate(normal_account)
    end
    it "would update user association" do
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
      expect(
        UserAssociatedAccount.find_by(
          provider_name: "jaccount",
          provider_uid: jaccount_test_info["normal_user"]["id"],
        ),
      ).to be_present
      expect(
        UserAssociatedAccount.find_by(provider_name: "jaccount", provider_uid: "SOME_RANDOM_UID"),
      ).to be_nil
    end
    it "could lookup from other identity" do
      default_identity_changed =
        normal_account.dup.tap { |a| a.info[:code] = a.extra[:raw_info][:identities][0][:code] }
      result = authenticator.after_authenticate(default_identity_changed)
      expect(result.failed).to be_falsey
      expect(result.user).to eq(user)
    end
    it "would fail if multiple user found" do
      Rails.logger.expects(:warn).once
      another_user = Fabricate(:user)
      UserAssociatedAccount.create!(
        user_id: another_user.id,
        provider_name: "jaccount",
        provider_uid: "SOME_RANDOM_UID_2",
        extra: {
          raw_info: jaccount_test_info["normal_user"],
        },
      )
      result = authenticator.after_authenticate(normal_account)
      expect(result.failed).to be_truthy
      expect(result.user).to be_nil
      expect(result.failed_reason).to eq(
        I18n.t(
          "jaccount_auth.failed_reason.multiple_user_found",
          email: SiteSetting.contact_email,
          error_code: [user.id, another_user.id],
        ),
      )
    end
  end

  describe "could check all identities" do
    before(:example) do
      SiteSetting.jaccount_auth_block_code_regex = "^(AA)?(7\\d{2}602\\d{6})$"
      SiteSetting.jaccount_auth_block_types = "outside"
    end
    let(:normal_account_with_blocked_default) do
      normal_account
        .dup
        .tap { |a| a.info.userType = "outside" }
        .tap { |a| a.extra.raw_info.userType = "outside" }
    end
    it "should allow user with one allowed identity" do
      SiteSetting.jaccount_auth_check_all_identities = true
      result = authenticator.after_authenticate(normal_account_with_blocked_default)
      expect(result.failed).to be_falsey
    end
    it "should block user when only check default identity" do
      SiteSetting.jaccount_auth_check_all_identities = false
      result = authenticator.after_authenticate(normal_account_with_blocked_default)
      expect(result.failed).to be_truthy
    end
  end

  describe "#lookup_user_from_code" do
    def random_code_identity(len = 10)
      account = normal_account.dup
      account[:uid] = SecureRandom.hex(len)
      account[:info][:code] = SecureRandom.hex(len)
      account[:extra][:raw_info][:identities].each do |identity|
        identity[:code] = SecureRandom.hex(len)
      end
      account
    end

    before(:example) do
      5.times do
        info = random_code_identity
        UserAssociatedAccount.create!(
          user: Fabricate(:user),
          provider_name: "jaccount",
          provider_uid: info[:uid],
          extra: info[:extra],
        )
      end
    end

    it "should find correct user" do
      all_records = UserAssociatedAccount.all.to_a
      2.times do
        record = all_records.sample
        user = authenticator.lookup_user_from_code(record.extra).to_a
        expect(user).to be_present
        expect(user.count).to eq(1)
        expect(user.first.id).to eq(record.user_id)
      end
    end

    it "should return none if no user found" do
      # Change the random string lenghth to ensure no user found
      info = random_code_identity(11).as_json
      user = authenticator.lookup_user_from_code(info["extra"]).to_a
      expect(user).to be_blank
    end

    it "could find with code" do
      all_records = UserAssociatedAccount.all.to_a
      2.times do
        record = all_records.sample
        code = record.extra["raw_info"]["identities"].sample["code"]
        stub_identities = {
          "raw_info" => {
            "identities" => [{ "code" => code }, { "code" => SecureRandom.hex(11) }],
          },
        }
        user = authenticator.lookup_user_from_code(stub_identities).to_a
        expect(user).to be_present
        expect(user.count).to eq(1)
        expect(user.first.id).to eq(record.user_id)
      end
    end

    it "could find all with code" do
      # This should not happen, but #lookup_user_from_code should be able to handle this
      all_records = UserAssociatedAccount.all.to_a
      2.times do
        record = all_records.sample(2)
        code = record.map { |r| r.extra["raw_info"]["identities"].sample["code"] }
        stub_identities = {
          "raw_info" => {
            "identities" => [
              { "code" => code[0] },
              { "code" => SecureRandom.hex(11) },
              { "code" => code[1] },
            ],
          },
        }
        user = authenticator.lookup_user_from_code(stub_identities).to_a
        expect(user).to be_present
        expect(user.count).to eq(2)
        expect(user.pluck(:id)).to match_array(record.pluck(:user_id))
      end
    end
  end
end
