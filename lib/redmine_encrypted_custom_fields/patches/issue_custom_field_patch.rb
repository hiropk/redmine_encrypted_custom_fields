# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    # view_encrypted_custom_fields を持たないユーザーには、フィールドの存在自体を見せない。
    # visible_by? はチケット画面、API、PDF、CSV、一覧の列、通知メール、
    # 履歴の詳細の表示可否に使われている。
    module IssueCustomFieldPatch
      def visible_by?(project, user=User.current)
        return super unless RedmineEncryptedCustomFields.encrypted_field?(self)

        super && Permissions.view?(user, project)
      end
    end
  end
end
