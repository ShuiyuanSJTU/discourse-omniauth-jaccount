# frozen_string_literal: true

require "rails_helper"

RSpec.describe JAccountAuth::Identity do
  def identity(raw_info)
    described_class.new(raw_info)
  end

  it "returns active identity names before alumni fallback" do
    result =
      identity(
        "identities" => [
          { "userType" => "alumni", "userTypeName" => "校友" },
          {
            "userType" => "student",
            "userTypeName" => "学生",
            "expireDate" => 1.year.from_now.iso8601,
          },
        ],
      )

    expect(result.state).to eq(:valid)
    expect(result.valid_identity_names).to eq(["学生"])
    expect(result.alumni?).to be(false)
  end

  it "recognizes an alumni identity when no active identity is available" do
    result =
      identity(
        "identities" => [
          { "userType" => "alumni", "userTypeName" => "校友" },
          { "userType" => "student", "userTypeName" => "学生", "expireDate" => 1.day.ago.iso8601 },
        ],
      )

    expect(result.state).to eq(:alumni)
    expect(result.alumni_identity_name).to eq("校友")
    expect(result.alumni?).to be(true)
  end

  it "reports missing and invalid identities separately" do
    expect(identity("userType" => "student").state).to eq(:no_identities)

    result = identity("identities" => [{ "userType" => "student", "expireDate" => "invalid" }])

    expect(result.state).to eq(:no_valid_identities)
    expect(result.alumni?).to be(false)
  end

  it "recognizes an alumni identity without a display name" do
    result = identity("identities" => [{ "userType" => "alumni" }])

    expect(result.state).to eq(:alumni)
    expect(result.alumni_identity_name).to be_nil
    expect(result.alumni?).to be(true)
  end
end
