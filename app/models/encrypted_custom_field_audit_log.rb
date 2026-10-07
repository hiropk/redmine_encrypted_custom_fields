# frozen_string_literal: true

# 誰が・いつ・どこから・どの暗号化された値を復号したかの記録。
# メタデータだけを持ち、値・暗号文・リクエスト本文は保存しない。
class EncryptedCustomFieldAuditLog < ApplicationRecord
  ACTIONS = %w(reveal reveal_failed).freeze

  belongs_to :user, optional: true
  belongs_to :project, optional: true
  belongs_to :issue, optional: true
  belongs_to :custom_field, optional: true

  validates :action, inclusion: {in: ACTIONS}
  validates :user_id, :issue_id, :custom_field_id, presence: true

  scope :recent_first, -> {order(created_on: :desc, id: :desc)}
end
