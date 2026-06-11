/* global sgScanner */
(function () {
  'use strict';

  function postAjax(action, nonce, data) {
    var payload = new URLSearchParams();
    payload.append('action', action);
    payload.append('nonce', nonce);

    Object.keys(data || {}).forEach(function (key) {
      payload.append(key, data[key]);
    });

    return fetch(sgScanner.ajaxUrl, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: payload.toString(),
    }).then(function (res) {
      return res.json();
    });
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function setText(el, text) {
    if (!el) return;
    el.textContent = text;
  }

  function buildCell(text) {
    var td = document.createElement('td');
    td.textContent = text;
    return td;
  }

  function buildBadge(severity) {
    var span = document.createElement('span');
    span.className = 'sg-badge sg-badge-' + severity;
    span.textContent = String(severity).toUpperCase();
    return span;
  }

  function buildContext(context) {
    var td = document.createElement('td');
    if (!context) {
      return td;
    }
    var code = document.createElement('code');
    code.textContent = context;
    td.appendChild(code);
    return td;
  }

  function buildActionButton(threat) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'button button-small sg-suppress-btn';

    btn.dataset.file = threat.file || '';
    btn.dataset.type = threat.type || '';
    btn.dataset.line = String(threat.line || 0);
    btn.dataset.hash = threat.hash || '';
    btn.dataset.suppressed = threat.suppressed ? '1' : '0';

    btn.textContent = threat.suppressed ? sgScanner.labels.restore : sgScanner.labels.suppress;
    return btn;
  }

  function getSelectedSeverities() {
    var selected = {};
    var inputs = document.querySelectorAll('.sg-filter-sev');
    inputs.forEach(function (input) {
      if (input.checked) {
        selected[input.value] = true;
      }
    });
    return selected;
  }

  function normalizeSeverity(sev) {
    return String(sev || '').toLowerCase();
  }

  function updateMeta(scan) {
    if (!scan || !scan.timestamp) {
      return;
    }

    setText(byId('sg-last-scan'), scan.formatted_timestamp || '');
    setText(byId('sg-total-files'), String(scan.total_files || 0));
    setText(byId('sg-total-threats'), String(scan.total_threats || 0));

    var summary = scan.summary || {};
    var badgeMap = {
      critical: byId('sg-badge-critical'),
      high: byId('sg-badge-high'),
      medium: byId('sg-badge-medium'),
      low: byId('sg-badge-low'),
      info: byId('sg-badge-info'),
    };

    Object.keys(badgeMap).forEach(function (key) {
      var el = badgeMap[key];
      if (!el) return;
      el.textContent = key.toUpperCase() + ': ' + String(summary[key] || 0);
    });
  }

  function init() {
    if (!window.sgScanner) return;

    var threats = Array.isArray(sgScanner.threats) ? sgScanner.threats.slice() : [];
    var showSuppressed = false;
    var perPage = 25;
    var currentPage = 1;

    var tbody = byId('sg-threat-tbody');
    var pageInfo = byId('sg-page-info');
    var prevBtn = byId('sg-prev-page');
    var nextBtn = byId('sg-next-page');
    var toggleSuppressed = byId('sg-toggle-suppressed');

    function getFilteredThreats() {
      var selected = getSelectedSeverities();
      return threats.filter(function (t) {
        var sev = normalizeSeverity(t.severity);
        if (!selected[sev]) return false;
        if (!showSuppressed && t.suppressed) return false;
        return true;
      });
    }

    function render() {
      if (!tbody) return;

      var filtered = getFilteredThreats();
      var totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
      currentPage = Math.min(currentPage, totalPages);

      var start = (currentPage - 1) * perPage;
      var rows = filtered.slice(start, start + perPage);

      tbody.innerHTML = '';
      rows.forEach(function (t) {
        var tr = document.createElement('tr');
        tr.dataset.severity = normalizeSeverity(t.severity);
        tr.dataset.suppressed = t.suppressed ? '1' : '0';
        tr.dataset.score = String(t.score || 0);
        if (t.suppressed) {
          tr.classList.add('sg-threat-suppressed');
        }

        var sevTd = document.createElement('td');
        sevTd.appendChild(buildBadge(normalizeSeverity(t.severity)));
        tr.appendChild(sevTd);

        tr.appendChild(buildCell(t.file || ''));
        tr.appendChild(buildCell(t.type_label || t.type || ''));
        tr.appendChild(buildCell(t.description || ''));
        tr.appendChild(buildCell(String(t.line || 0)));
        tr.appendChild(buildContext(t.context || ''));

        var actionTd = document.createElement('td');
        actionTd.appendChild(buildActionButton(t));
        tr.appendChild(actionTd);

        tbody.appendChild(tr);
      });

      if (pageInfo) {
        pageInfo.textContent = sgScanner.labels.page + ' ' + String(currentPage) + ' / ' + String(totalPages);
      }
      if (prevBtn) prevBtn.disabled = currentPage <= 1;
      if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
    }

    function refreshResults() {
      return postAjax('sg_get_scan_results', sgScanner.runScanNonce, {}).then(function (res) {
        if (!res || !res.success) {
          throw new Error('fetch_failed');
        }
        threats = Array.isArray(res.data.threats) ? res.data.threats : [];
        updateMeta(res.data.scan || {});
        currentPage = 1;
        render();
      });
    }

    document.addEventListener('change', function (e) {
      if (e.target && e.target.classList && e.target.classList.contains('sg-filter-sev')) {
        currentPage = 1;
        render();
      }
    });

    if (toggleSuppressed) {
      toggleSuppressed.addEventListener('change', function () {
        showSuppressed = !!toggleSuppressed.checked;
        currentPage = 1;
        render();
      });
    }

    if (prevBtn) {
      prevBtn.addEventListener('click', function () {
        currentPage = Math.max(1, currentPage - 1);
        render();
      });
    }

    if (nextBtn) {
      nextBtn.addEventListener('click', function () {
        currentPage = currentPage + 1;
        render();
      });
    }

    if (tbody) {
      tbody.addEventListener('click', function (e) {
        var btn = e.target && e.target.closest ? e.target.closest('.sg-suppress-btn') : null;
        if (!btn) return;

        var isSuppressed = btn.dataset.suppressed === '1';
        var action = isSuppressed ? 'sg_unsuppress_threat' : 'sg_suppress_threat';

        btn.disabled = true;

        postAjax(action, sgScanner.suppressNonce, {
          file: btn.dataset.file || '',
          type: btn.dataset.type || '',
          line: btn.dataset.line || '0',
        })
          .then(function (res) {
            if (!res || !res.success) {
              throw new Error('suppress_failed');
            }

            var hash = btn.dataset.hash;
            threats = threats.map(function (t) {
              if (t.hash === hash) {
                t.suppressed = !isSuppressed;
              }
              return t;
            });

            currentPage = 1;
            render();
          })
          .catch(function () {
            btn.disabled = false;
          });
      });
    }

    var scanBtn = byId('sg-scan-btn');
    var spinner = byId('sg-scan-spinner');
    if (scanBtn) {
      scanBtn.addEventListener('click', function () {
        scanBtn.disabled = true;
        if (spinner) spinner.style.display = 'inline-block';

        postAjax('sg_run_scan', sgScanner.runScanNonce, {})
          .then(function (res) {
            if (!res || !res.success) {
              throw new Error('scan_failed');
            }
            return refreshResults();
          })
          .catch(function () {})
          .finally(function () {
            scanBtn.disabled = false;
            if (spinner) spinner.style.display = 'none';
          });
      });
    }

    updateMeta(sgScanner.scan || {});
    render();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

