# frozen_string_literal: true

class EncryptedCustomFieldAuditLogsController < ApplicationController
  layout 'admin'
  self.main_menu = false

  before_action :require_admin

  def index
    scope = EncryptedCustomFieldAuditLog.all
    scope = scope.where(issue_id: params[:issue_id].to_i) if params[:issue_id].present?
    @log_count = scope.count
    @log_pages = Paginator.new(@log_count, per_page_option, params['page'])
    @logs = scope.recent_first.preload(:user, :project, :issue, :custom_field)
                 .limit(@log_pages.per_page).offset(@log_pages.offset).to_a
  end
end
