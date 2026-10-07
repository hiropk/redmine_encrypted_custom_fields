# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Permissions
    module_function

    def view?(user, project)
      project.present? && user.allowed_to?(:view_encrypted_custom_fields, project)
    end

    def edit?(user, project)
      project.present? && user.allowed_to?(:edit_encrypted_custom_fields, project)
    end

    # user のために値を復号してよいかを判定する（すべての条件を満たす必要がある）。
    # custom_field.visible_by? には、フィールドのロール別表示設定と
    # view_encrypted_custom_fields の判定がすでに含まれている（IssueCustomFieldPatch を参照）。
    def reveal?(user, issue, custom_field)
      return false unless user.logged? && issue.is_a?(Issue) && issue.persisted?
      return false unless RedmineEncryptedCustomFields.encrypted_field?(custom_field)

      issue.visible?(user) &&
        issue.available_custom_fields.include?(custom_field) &&
        custom_field.visible_by?(issue.project, user) &&
        user.allowed_to?(:reveal_encrypted_custom_fields, issue.project)
    end
  end
end
