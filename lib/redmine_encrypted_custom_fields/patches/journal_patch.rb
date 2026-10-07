# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    # Journal#journalize_changes は変更前後のカスタムフィールドの値を journal_details に
    # コピーする。暗号化フィールドではマスク（未設定なら nil）だけを記録し、
    # 履歴には「値が変わった」ことしか残さない。
    module JournalPatch
      private

      def add_custom_field_detail(custom_field_id, old_value, value)
        custom_field = journalized.custom_field_values.detect {|v| v.custom_field_id == custom_field_id}&.custom_field
        custom_field ||= CustomField.find_by(id: custom_field_id)
        if RedmineEncryptedCustomFields.encrypted_field?(custom_field)
          old_value = old_value.present? ? MASK_TEXT : nil
          value = value.present? ? MASK_TEXT : nil
        end
        super
      end
    end
  end
end
