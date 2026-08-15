# frozen_string_literal: true

module ::JAccountAuth
  class Identity
    attr_reader :raw_info

    def initialize(raw_info)
      @raw_info = raw_info || {}
    end

    def identities
      @identities ||= raw_info["identities"] if raw_info["identities"].is_a?(Array)
    end

    def user_type
      raw_info["userType"]
    end

    def valid_identity_names
      return [] unless identities

      identities
        .reject { |identity| identity["expireDate"].nil? }
        .reject do |identity|
          begin
            Time.parse(identity["expireDate"]) < Time.now
          rescue StandardError
            true
          end
        end
        .filter_map { |identity| identity["userTypeName"] }
        .uniq
    end

    def alumni_identity
      identities&.find { |identity| identity["userType"] == "alumni" }
    end

    def alumni_identity_name
      alumni_identity&.fetch("userTypeName", nil)
    end

    def state
      return :no_identities if identities.blank?
      return :valid if valid_identity_names.present?
      return :alumni if alumni_identity

      :no_valid_identities
    end

    def alumni?
      state == :alumni
    end
  end
end
