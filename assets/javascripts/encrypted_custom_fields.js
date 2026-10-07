/*
 * Redmine Encrypted Custom Fields
 *
 * - 表示: ページの CSRF トークン付きで POST し、値は textContent で挿入する
 *   （HTML として解釈させない）。一定時間で自動的にマスクに戻す。
 * - 隠す: 平文を DOM から取り除く。
 * - ブラウザのストレージには何も保存しない。
 */
(function () {
  'use strict';

  var AUTO_HIDE_MS = 30000;

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function parts(field) {
    return {
      mask: field.querySelector('.ecf-mask'),
      value: field.querySelector('.ecf-value'),
      reveal: field.querySelector('.ecf-reveal'),
      hide: field.querySelector('.ecf-hide'),
      error: field.querySelector('.ecf-error')
    };
  }

  function hide(field) {
    var p = parts(field);
    if (field._ecfTimer) {
      clearTimeout(field._ecfTimer);
      field._ecfTimer = null;
    }
    p.value.textContent = '';
    p.value.hidden = true;
    p.mask.hidden = false;
    p.hide.hidden = true;
    p.reveal.hidden = false;
  }

  function show(field, value) {
    var p = parts(field);
    p.error.hidden = true;
    p.error.textContent = '';
    p.value.textContent = value;
    p.value.hidden = false;
    p.mask.hidden = true;
    p.reveal.hidden = true;
    p.hide.hidden = false;
    field._ecfTimer = setTimeout(function () { hide(field); }, AUTO_HIDE_MS);
  }

  function showError(field, message) {
    var p = parts(field);
    p.error.textContent = message || 'Error';
    p.error.hidden = false;
  }

  function reveal(field, button) {
    button.disabled = true;
    fetch(field.getAttribute('data-ecf-reveal-url'), {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'X-CSRF-Token': csrfToken(),
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json'
      }
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok || typeof body.value !== 'string') {
          throw new Error(body.error || response.statusText);
        }
        show(field, body.value);
      });
    }).catch(function (error) {
      showError(field, error.message);
    }).then(function () {
      button.disabled = false;
    });
  }

  document.addEventListener('click', function (event) {
    var button = event.target.closest && event.target.closest('.ecf-reveal, .ecf-hide');
    if (!button) return;
    var field = button.closest('.ecf-field');
    if (!field) return;
    event.preventDefault();
    if (button.classList.contains('ecf-hide')) {
      hide(field);
    } else {
      reveal(field, button);
    }
  });

  // 新しい値を入力すると「置き換える」を選択し、維持 / 削除を選ぶと入力欄を空にする。
  document.addEventListener('input', function (event) {
    var input = event.target;
    if (!input.classList || !input.classList.contains('ecf-secret-input')) return;
    var edit = input.closest('.ecf-edit');
    var replace = edit && edit.querySelector('input[type="radio"][value="replace"]');
    if (replace && input.value !== '') replace.checked = true;
  });

  document.addEventListener('change', function (event) {
    var radio = event.target;
    if (radio.type !== 'radio' || !radio.closest('.ecf-actions')) return;
    if (radio.value === 'replace') return;
    var input = radio.closest('.ecf-edit').querySelector('.ecf-secret-input');
    if (input) input.value = '';
  });

  // 表示した値をページ（や戻る / 進むのキャッシュ）に残さない。
  window.addEventListener('pagehide', function () {
    document.querySelectorAll('.ecf-field[data-ecf-reveal-url]').forEach(function (field) {
      if (parts(field).value) hide(field);
    });
  });
})();
