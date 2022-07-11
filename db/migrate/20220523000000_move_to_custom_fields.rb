class MoveToCustomFields < ActiveRecord::Migration[7.0]
  def change
    plugin_name = "auth-jaccount"
    rows = PluginStoreRow.where(plugin_name: plugin_name)
    rows.each do |row|
      ja_uid = row.key
      ja_uid = ja_uid[7, ja_uid.length]
      user_id = JSON.parse(row.value)["user_id"]
      user = User.find_by(id: user_id)
      if user
        user.custom_fields[plugin_name] = ja_uid
        user.save_custom_fields
      end
      row.destroy
    end
  end
end
