# frozen_string_literal: true

module RedmineEncryptedCustomFields
  module Patches
    # 暗号化フィールドの値を、DB に書き込む直前に暗号化する。
    #
    # フォームの値を代入した時点ではなくここで暗号化するのは、チケット ID が
    # 認証付き追加データに含まれ、チケット自体を保存するまで確定しないため
    # （カスタムフィールドの値はチケットの after_save で保存される。新規作成時も同じ）。
    module CustomValuePatch
      def self.prepended(base)
        base.before_save :ecf_encrypt_value
      end

      def value=(value)
        if value.is_a?(PendingSecret)
          @ecf_pending_secret = value
        else
          @ecf_pending_secret = nil
          super
        end
      end

      private

      def ecf_encrypt_value
        return unless RedmineEncryptedCustomFields.encrypted_field?(custom_field)

        if @ecf_pending_secret
          write_attribute(:value, @ecf_pending_secret.seal(ecf_aad))
          @ecf_pending_secret = nil
        elsif will_save_change_to_value? && value.present?
          # フィールド形式を経由せずに代入された生の値（コンソール、スクリプト、他プラグイン）は
          # 平文として扱う。そのまま保存せず、既存の暗号文とみなすこともない。
          write_attribute(:value, Cipher.encrypt(value, aad: ecf_aad))
        end
      end

      def ecf_aad
        owner = customized
        raise Error, 'Cannot encrypt a value without an owner' unless owner

        Cipher.aad_for(owner.class.base_class.name, owner.id, custom_field_id)
      end
    end
  end
end
