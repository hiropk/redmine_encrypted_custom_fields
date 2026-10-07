# frozen_string_literal: true

module RedmineEncryptedCustomFields
  class Hooks < Redmine::Hook::ViewListener
    def view_layouts_base_html_head(context={})
      stylesheet_link_tag('encrypted_custom_fields', plugin: 'redmine_encrypted_custom_fields') +
        javascript_include_tag('encrypted_custom_fields', plugin: 'redmine_encrypted_custom_fields')
    end
  end
end
