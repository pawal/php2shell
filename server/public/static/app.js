'use strict';

(function () {
  const form = document.getElementById('check-form');
  if (!form) {
    return;
  }
  const result = document.getElementById('result');
  const button = form.querySelector('button');

  const labels = {
    vulnerable: ['Vulnerable', 'bad'],
    likely_vulnerable: ['Likely vulnerable', 'bad'],
    eol_branch: ['Unsupported PHP branch', 'bad'],
    possibly_backported: ['Possibly fixed by your distribution', 'warn'],
    inconclusive: ['Inconclusive', 'warn'],
    no_php_signal: ['No PHP signal', 'warn'],
    unreachable: ['Unreachable', 'warn'],
    inspection_blocked: ['Inspection blocked', 'warn'],
    likely_patched: ['Likely patched', 'good'],
    patched: ['Patched', 'good'],
  };

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) {
      node.textContent = text;
    }
    if (className) {
      node.className = className;
    }
    return node;
  }

  function show(className, children) {
    result.className = 'result ' + (className || '');
    result.replaceChildren(...children);
    result.hidden = false;
  }

  function renderReport(report) {
    const label = labels[report.verdict] || [report.verdict, 'warn'];
    const children = [el('h2', label[0]), el('p', report.summary)];
    const meta = [report.target, 'confidence ' + report.confidence];
    if (report.php_version) {
      meta.push('PHP ' + report.php_version.raw.replace(/^PHP\//i, ''));
    }
    meta.push(report.oracle_run ? 'patch-state request sent' : 'HTTP fingerprinting only');
    if (report.cached) {
      meta.push('earlier result from ' + new Date(report.checked_at).toLocaleTimeString());
    }
    children.push(el('p', meta.join(' | '), 'meta'));

    const advice = el('ul');
    for (const line of report.recommendations || []) {
      advice.append(el('li', line));
    }
    children.push(el('h3', 'What to do'), advice);

    const local = el('details');
    local.append(el('summary', 'Check on the server'), el('pre', (report.local_check || []).join('\n')));
    children.push(local);

    if (report.evidence) {
      const evidence = el('details');
      evidence.append(el('summary', 'What the check saw'), el('pre', JSON.stringify(report.evidence, null, 2)));
      children.push(evidence);
    }
    show(label[1], children);
  }

  function renderError(status, body, retryAfter) {
    let message = (body && body.error && body.error.message) || 'The check failed.';
    if (status === 429 && retryAfter) {
      message += ' Try again in ' + retryAfter + ' seconds.';
    }
    show('warn', [el('h2', 'Not checked'), el('p', message)]);
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const url = form.elements.url.value.trim();
    if (!url) {
      form.elements.url.focus();
      return;
    }
    button.disabled = true;
    show('', [el('p', 'Checking ' + url + ' ...')]);
    try {
      const response = await fetch('/api/v1/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, attested: form.elements.attested.checked }),
      });
      const body = await response.json().catch(() => null);
      if (response.ok && body) {
        renderReport(body);
      } else {
        renderError(response.status, body, response.headers.get('Retry-After'));
      }
    } catch (err) {
      renderError(0, null, null);
    } finally {
      button.disabled = false;
    }
  });
})();
