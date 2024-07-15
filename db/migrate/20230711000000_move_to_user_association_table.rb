# frozen_string_literal: true
class MoveToUserAssociationTable < ActiveRecord::Migration[7.0]
  def up
    UserCustomField
      .where(name: "auth-jaccount")
      .each do |row|
        association =
          UserAssociatedAccount.find_or_initialize_by(
            provider_name: "jaccount",
            provider_uid: row.value,
            user_id: row.user_id
          )
        association.save!
      end
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
