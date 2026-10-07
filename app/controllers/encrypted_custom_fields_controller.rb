# frozen_string_literal: true

# ログイン済みのブラウザセッションに対して、1 チケットの 1 つの暗号化された値を復号して返す。
# 復号に成功するたびに監査ログを記録し、記録できなかった場合は値を返さない。
#
# API キー・OAuth トークン・Atom キーは受け付けない。accept_api_auth を宣言せず、
# 認証情報や format 指定を含むリクエストは復号の前に拒否する。Redmine は
# ?format=json のとき CSRF トークンの検証を省略するため、format の拒否は CSRF 対策も兼ねる。
class EncryptedCustomFieldsController < ApplicationController
  before_action :set_no_store_headers
  before_action :require_browser_session
  before_action :find_issue_and_custom_field
  before_action :authorize_reveal

  def reveal
    stored = @issue.custom_value_for(@custom_field)&.value
    return render_ecf_error(:error_ecf_not_set, :not_found) if stored.blank?

    plaintext = decrypt(stored)
    return render_ecf_error(:error_ecf_reveal_failed, 422) if plaintext.nil?
    return render_ecf_error(:error_ecf_audit_failed, :service_unavailable) unless record_audit('reveal')

    render json: {value: plaintext}
  end

  private

  # 復号できなかった場合（鍵の未設定・不正、未知の形式、認証の失敗）は
  # 失敗を監査ログに記録して nil を返す。
  def decrypt(stored)
    RedmineEncryptedCustomFields::Cipher.decrypt(
      stored,
      aad: RedmineEncryptedCustomFields::Cipher.aad_for('Issue', @issue.id, @custom_field.id)
    )
  rescue RedmineEncryptedCustomFields::Error => e
    logger&.error "[redmine_encrypted_custom_fields] reveal failed for issue ##{@issue.id}, custom field ##{@custom_field.id}: #{e.class}"
    record_audit('reveal_failed')
    nil
  end

  def set_no_store_headers
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
  end

  def require_browser_session
    credentials_given = params[:key].present? || params[:format].present? ||
                        request.authorization.present? ||
                        request.headers['X-Redmine-API-Key'].present?
    session_user = User.current.logged? && session[:user_id] == User.current.id
    render_ecf_error(:error_ecf_session_required, :forbidden) if credentials_given || !session_user
  end

  # 存在しない・閲覧できない・関係のないチケットやフィールドはすべて 404 を返し、
  # ID の存在を推測させない。
  def find_issue_and_custom_field
    @issue = Issue.visible.find_by(id: params[:issue_id])
    @project = @issue&.project
    @custom_field = @issue&.available_custom_fields&.detect do |cf|
      cf.id.to_s == params[:custom_field_id].to_s && RedmineEncryptedCustomFields.encrypted_field?(cf)
    end
    render_ecf_error(:error_ecf_not_found, :not_found) unless @custom_field && @custom_field.visible_by?(@project, User.current)
  end

  def authorize_reveal
    return if RedmineEncryptedCustomFields::Permissions.reveal?(User.current, @issue, @custom_field)

    render_ecf_error(:notice_not_authorized, :forbidden)
  end

  # 記録できなかった場合は false を返す。
  def record_audit(action)
    EncryptedCustomFieldAuditLog.create!(
      action: action,
      user_id: User.current.id,
      project_id: @issue.project_id,
      issue_id: @issue.id,
      custom_field_id: @custom_field.id,
      ip_address: request.remote_ip,
      user_agent: request.user_agent.to_s.truncate(255),
      request_id: request.request_id.to_s.truncate(64)
    )
    true
  rescue => e
    logger&.error "[redmine_encrypted_custom_fields] audit log could not be saved: #{e.class}"
    false
  end

  def render_ecf_error(message, status)
    render json: {error: l(message)}, status: status
  end
end
