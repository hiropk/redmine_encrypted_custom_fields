# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    module IssuePatch
      # edit_encrypted_custom_fields を持たないユーザーには、暗号化フィールドを読み取り専用にする。
      # Redmine はこの一覧を使って、safe_attributes（フォームと API）の絞り込み、
      # バリデーションの省略、チケットのフォームに出すフィールドの判定を行う。
      def read_only_attribute_names(user=nil)
        names = super
        return names if project && Permissions.edit?(user || User.current, project)

        encrypted_ids = available_custom_fields.select {|cf| RedmineEncryptedCustomFields.encrypted_field?(cf)}.map {|cf| cf.id.to_s}
        names | encrypted_ids
      end

      # Redmine は、保存するユーザーが編集できるカスタムフィールドの値しか検証しない。
      # safe_attributes を通さずにプログラムから代入された新しい値も検証し、
      # 拒否した入力は、誰が保存する場合でもエラーにする。
      def validate_custom_field_values
        super
        editable_ids = editable_custom_field_values(new_record? ? author : current_journal&.user).map(&:custom_field_id)
        custom_field_values.each do |custom_field_value|
          next unless RedmineEncryptedCustomFields.encrypted_field?(custom_field_value.custom_field)
          next if editable_ids.include?(custom_field_value.custom_field_id)

          if custom_field_value.value.is_a?(PendingSecret) ||
             custom_field_value.instance_variable_get(EncryptedTextFormat::REJECTION)
            custom_field_value.validate_value
          end
        end
      end

      # 暗号化した後は、メモリ上の値を保存済みの暗号文に置き換える。
      # 履歴や同じオブジェクトの再保存で保存値どうしを比較できるようにし、
      # 平文を必要以上に長く保持しないため。
      def save_custom_field_values
        result = super
        custom_field_values.each do |custom_field_value|
          next unless custom_field_value.value.is_a?(PendingSecret)

          stored = custom_values.detect {|cv| cv.custom_field_id == custom_field_value.custom_field_id}&.value
          custom_field_value.instance_variable_set(:@value, stored)
        end
        result
      end

      # チケットのコピー（一括コピー・プロジェクトのコピーも含む）では秘密の値をコピーしない。
      # 新しいチケット用に暗号化し直すには、コピーするユーザーの代わりに復号する必要があるため。
      def copy_from(arg, options={})
        super
        custom_field_values.each do |custom_field_value|
          if RedmineEncryptedCustomFields.encrypted_field?(custom_field_value.custom_field)
            custom_field_value.value = {'action' => 'clear'}
          end
        end
        self
      end
    end
  end
end
