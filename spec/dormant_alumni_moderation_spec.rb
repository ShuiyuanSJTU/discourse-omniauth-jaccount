# frozen_string_literal: true

require "rails_helper"

RSpec.describe JAccountAuth::DormantAlumni do
  fab!(:author) { Fabricate(:user, refresh_auto_groups: true) }
  fab!(:moderator) { Fabricate(:moderator, refresh_auto_groups: true) }
  fab!(:other_user) { Fabricate(:user, refresh_auto_groups: true) }
  fab!(:topic)

  let(:valid_title) { "A sufficiently long topic title" }
  let(:valid_raw) { "A sufficiently long post body for the moderation queue." }
  let(:returned_at) { 1.hour.ago.iso8601 }

  before do
    enable_current_plugin
    SiteSetting.allow_uncategorized_topics = true
    SiteSetting.approve_post_count = 0
    SiteSetting.approve_unless_allowed_groups = Group::AUTO_GROUPS[:trust_level_0]
    SiteSetting.approve_new_topics_unless_allowed_groups = Group::AUTO_GROUPS[:trust_level_0]
    SiteSetting.approve_unless_staged = false
    SiteSetting.jaccount_dormant_alumni_enabled = true
    SiteSetting.jaccount_dormant_alumni_review_replies = false

    author.custom_fields[described_class::RETURNED_AT_CUSTOM_FIELD] = returned_at
    author.save_custom_fields
  end

  describe "post creation moderation" do
    it "queues new public topics by default" do
      result = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform

      expect(result.action).to eq(:enqueued)
      expect(result.reason).to eq(:jaccount_dormant_alumni)
      expect(result.reviewable.payload[described_class::QUEUED_MARKER_PAYLOAD]).to eq(returned_at)
      expect(result.reviewable.reviewable_scores.first.reason).to eq("jaccount_dormant_alumni")
    end

    it "creates public replies immediately by default" do
      result = NewPostManager.new(author, topic_id: topic.id, raw: valid_raw).perform

      expect(result.action).to eq(:create_post)
      expect(result.post).to be_present
    end

    it "queues public replies when reply review is enabled" do
      SiteSetting.jaccount_dormant_alumni_review_replies = true

      result = NewPostManager.new(author, topic_id: topic.id, raw: valid_raw).perform

      expect(result.action).to eq(:enqueued)
      expect(result.reason).to eq(:jaccount_dormant_alumni)
      expect(result.reviewable.topic_id).to eq(topic.id)
    end

    it "does not queue private messages" do
      result =
        NewPostManager.new(
          author,
          raw: valid_raw,
          title: valid_title,
          archetype: Archetype.private_message,
          target_usernames: other_user.username,
        ).perform

      expect(result.action).to eq(:create_post)
      expect(result.post.topic).to be_private_message
    end

    it "does not queue staff users" do
      moderator.custom_fields[described_class::RETURNED_AT_CUSTOM_FIELD] = returned_at
      moderator.save_custom_fields

      result = NewPostManager.new(moderator, title: valid_title, raw: valid_raw).perform

      expect(result.action).to eq(:create_post)
    end

    it "does not queue posts when the feature is disabled" do
      SiteSetting.jaccount_dormant_alumni_enabled = false

      result = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform

      expect(result.action).to eq(:create_post)
    end

    it "does not queue users without a dormant return marker" do
      author.custom_fields.delete(described_class::RETURNED_AT_CUSTOM_FIELD)
      author.save_custom_fields

      result = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform

      expect(result.action).to eq(:create_post)
    end

    it "preserves an existing core approval reason" do
      SiteSetting.approve_post_count = 1

      result = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform

      expect(result.action).to eq(:enqueued)
      expect(result.reason).to eq(:post_count)
      expect(result.reviewable.payload[described_class::QUEUED_MARKER_PAYLOAD]).to eq(returned_at)
    end
  end

  describe "marker lifecycle" do
    it "clears the marker when an eligible queued post is approved" do
      reviewable = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform.reviewable

      reviewable.perform(moderator, :approve_post)

      expect(author.reload.custom_fields[described_class::RETURNED_AT_CUSTOM_FIELD]).to be_nil
    end

    it "keeps the marker when a queued post is rejected" do
      reviewable = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform.reviewable

      reviewable.perform(moderator, :reject_post)

      expect(author.reload.custom_fields[described_class::RETURNED_AT_CUSTOM_FIELD]).to eq(
        returned_at,
      )
    end

    it "does not clear a newer marker when an older queued post is approved" do
      reviewable = NewPostManager.new(author, title: valid_title, raw: valid_raw).perform.reviewable
      newer_returned_at = Time.zone.now.iso8601
      author.custom_fields[described_class::RETURNED_AT_CUSTOM_FIELD] = newer_returned_at
      author.save_custom_fields

      reviewable.perform(moderator, :approve_post)

      expect(author.reload.custom_fields[described_class::RETURNED_AT_CUSTOM_FIELD]).to eq(
        newer_returned_at,
      )
    end
  end
end
