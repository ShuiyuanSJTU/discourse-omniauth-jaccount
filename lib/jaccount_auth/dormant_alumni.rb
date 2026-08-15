# frozen_string_literal: true

module ::JAccountAuth
  module DormantAlumni
    RETURNED_AT_CUSTOM_FIELD = "jaccount_dormant_alumni_returned_at"
    QUEUED_MARKER_PAYLOAD = "jaccount_dormant_alumni_marker"
    REVIEWABLE_REASON = :jaccount_dormant_alumni

    def self.enabled_for_queue?
      SiteSetting.jaccount_dormant_alumni_enabled?
    end

    def self.marker_for(manager)
      return unless enabled_for_queue?
      return if manager.user.staff?
      return if private_message?(manager)
      if manager.args[:topic_id].present? && !SiteSetting.jaccount_dormant_alumni_review_replies?
        return
      end

      manager.user.custom_fields[RETURNED_AT_CUSTOM_FIELD].presence
    end

    def self.clear_marker_after_approval(reviewable)
      return unless reviewable.is_a?(ReviewableQueuedPost)

      queued_marker = reviewable.payload[QUEUED_MARKER_PAYLOAD]
      return if queued_marker.blank?

      user = reviewable.target_created_by
      return if user.nil?

      UserCustomField.where(
        user_id: user.id,
        name: RETURNED_AT_CUSTOM_FIELD,
        value: queued_marker,
      ).delete_all
    end

    def self.private_message?(manager)
      manager.args[:archetype] == Archetype.private_message ||
        (
          manager.args[:topic_id].present? &&
            Topic.where(id: manager.args[:topic_id], archetype: Archetype.private_message).exists?
        )
    end

    module NewPostManagerExtension
      def post_needs_approval?(manager)
        reason = super
        marker = DormantAlumni.marker_for(manager)
        return reason if marker.blank?

        manager.args[QUEUED_MARKER_PAYLOAD] = marker
        reason == :skip ? REVIEWABLE_REASON : reason
      end

      def queue_enabled?
        super || DormantAlumni.enabled_for_queue?
      end
    end
  end
end
