# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    # render_api_custom_values は custom_value.value をそのまま出力するため、
    # 何もしないと REST API に暗号文が出てしまう。
    module CustomFieldsHelperPatch
      MaskedValue = Struct.new(:custom_field, :value) do
        def custom_field_id
          custom_field.id
        end
      end

      def render_api_custom_values(custom_values, api)
        custom_values = custom_values.map do |custom_value|
          if RedmineEncryptedCustomFields.encrypted_field?(custom_value.custom_field)
            MaskedValue.new(custom_value.custom_field, custom_value.value.present? ? MASK_TEXT : nil)
          else
            custom_value
          end
        end
        super
      end
    end
  end
end
