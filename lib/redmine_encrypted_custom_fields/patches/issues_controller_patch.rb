# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    # 一括編集は UI に出していない（bulk_edit_supported = false）が、手で組み立てた
    # bulk_update リクエストは safe_attributes まで届いてしまう。
    # 1 つの秘密の値を複数のチケットへまとめて書き込まないよう、暗号化フィールドの値は
    # パラメータから取り除く（エラーにはせず無視する。ほかの項目の一括更新はそのまま行う）。
    # 対象は issue[custom_field_values][ID] と issue[custom_fields][] の両方の形式。
    module IssuesControllerPatch
      def bulk_update
        ecf_remove_encrypted_values_from_bulk_params
        super
      end

      private

      def ecf_remove_encrypted_values_from_bulk_params
        issue_params = params[:issue]
        return unless issue_params.respond_to?(:key?)
        return unless issue_params.key?(:custom_field_values) || issue_params.key?(:custom_fields)

        encrypted_ids = IssueCustomField.where(field_format: FORMAT_NAME).pluck(:id).map(&:to_s)

        values = issue_params[:custom_field_values]
        encrypted_ids.each {|id| values.delete(id)} if values.respond_to?(:delete)

        fields = issue_params[:custom_fields]
        if fields.is_a?(Array)
          issue_params[:custom_fields] = fields.reject do |field|
            (field.is_a?(Hash) || field.is_a?(ActionController::Parameters)) &&
              encrypted_ids.include?(field[:id].to_s)
          end
        end
      end
    end
  end
end
