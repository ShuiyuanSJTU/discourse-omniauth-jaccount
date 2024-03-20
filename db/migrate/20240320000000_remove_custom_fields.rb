class RemoveCustomFields < ActiveRecord::Migration[7.0]
  def up
    UserCustomField.where(name:"auth-jaccount").destroy_all
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
