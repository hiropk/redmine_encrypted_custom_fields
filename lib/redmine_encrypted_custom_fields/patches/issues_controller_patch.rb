# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    # 一括編集は UI に出していない（bulk_edit_supported = false）が、手で組み立てた
    # bulk_update リクエストは safe_attributes まで届いてしまう。
    # 1 つの秘密の値を複数のチケットへまとめて書き込むことは明示的に拒否する。
    module IssuesControllerPatch
      def bulk_update
        ecf_remove_encrypted_values_from_bulk_params
        super
      end

      private

      def ecf_remove_encrypted_values_from_bulk_params
        values = params.dig(:issue, :custom_field_values)
        return unless values.respond_to?(:delete)

        IssueCustomField.where(field_format: FORMAT_NAME).pluck(:id).each do |id|
          values.delete(id.to_s)
        end
      end
    end
  end
end
