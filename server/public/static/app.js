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

  function group(tag, children, className) {
    const node = el(tag, undefined, className);
    node.append(...children.filter((child) => child !== null && child !== undefined && child !== ''));
    return node;
  }

  function codes(values, separator) {
    if (!values || values.length === 0) {
      return null;
    }
    const span = el('span');
    values.forEach((value, index) => {
      if (index > 0) {
        span.append(separator || ' ');
      }
      span.append(el('code', value));
    });
    return span;
  }

  function relative(address, origin) {
    try {
      const url = new URL(address);
      return url.origin === origin ? url.pathname + url.search : address;
    } catch (err) {
      return address;
    }
  }

  function facts(pairs) {
    const list = el('dl', undefined, 'facts');
    for (const [term, value] of pairs) {
      if (value) {
        list.append(el('dt', term), value instanceof Node ? group('dd', [value]) : el('dd', value));
      }
    }
    return list;
  }

  function table(headings, rows) {
    const head = group('tr', headings.map((heading) => el('th', heading)));
    const body = group('tbody', rows.map((cells) => group('tr', cells.map((cell) => cell instanceof Node ? group('td', [cell]) : el('td', cell)))));
    return group('div', [group('table', [group('thead', [head]), body])], 'scroll');
  }

  function settings(page) {
    return Object.entries(page.phpinfo_settings || {}).map(([name, value]) => name + ' ' + value).join(', ');
  }

  function pageSeen(page, start) {
    if (page.error) {
      return page.error;
    }
    if (page.inspection_blocked) {
      return 'blocked: ' + page.inspection_blocked;
    }
    const hints = (page.php_hints || []).filter((hint) => !(start.php_hints || []).includes(hint)).join(', ');
    if (page.x_powered_by && page.x_powered_by !== start.x_powered_by) {
      return group('span', [el('code', page.x_powered_by), hints ? ' ' + hints : '']);
    }
    if (page.phpinfo_version && page.phpinfo_version !== start.phpinfo_version) {
      return group('span', [el('code', 'PHP ' + page.phpinfo_version), settings(page) ? ' ' + settings(page) : '']);
    }
    if (page.server_signature && page.server_signature !== start.server_signature) {
      return group('span', [el('code', page.server_signature), hints ? ' ' + hints : '']);
    }
    if (hints) {
      return hints;
    }
    return (page.php_hints || []).length > 0 ? 'nothing new' : 'no PHP signs';
  }

  const signals = {
    cookie: 'default cookie', assets: 'asset files', generator: 'generator tag', diagnostic: 'error page', markup: 'page markup',
    database_cookie: 'cookie', database_header: 'response header', database_meta: 'meta tag', database_scriptSrc: 'script file'
  };

  function frameworks(pages) {
    const found = new Map();
    for (const page of pages) {
      for (const fingerprint of page.fingerprints || []) {
        const key = fingerprint.technology + '|' + fingerprint.signal;
        if (!found.has(key)) {
          found.set(key, fingerprint);
        }
      }
    }
    if (found.size === 0) {
      return null;
    }
    const list = el('ul', undefined, 'plain');
    for (const fingerprint of found.values()) {
      const signal = signals[fingerprint.signal] || fingerprint.signal + ' header';
      const item = el('li', fingerprint.technology + ', ' + signal + ', ' + fingerprint.confidence + ' confidence');
      if (/^https:\/\//.test(fingerprint.source)) {
        const link = el('a', 'source');
        link.href = fingerprint.source;
        link.rel = 'noreferrer';
        item.append(' (', link, ')');
      }
      list.append(item);
    }
    return list;
  }

  function reading(request) {
    if (request.inspection_blocked) {
      return 'blocked: ' + request.inspection_blocked;
    }
    const counts = 'ID too long ' + request.invalid_id + ', read failed ' + request.failed_read + ', write failed ' + request.failed_write;
    let answer = 'no session warnings';
    if (request.invalid_id > 0 && request.failed_read > 0) {
      answer = request.failed_write > 0 ? 'like an unpatched release' : 'like a patched release';
    }
    return group('span', [answer, ' ', el('span', counts, 'muted')]);
  }

  function renderEvidence(evidence, target) {
    const start = evidence.passive || {};
    let origin = '';
    try {
      origin = new URL(start.final_url || target).origin;
    } catch (err) {
      origin = '';
    }
    const short = (address) => relative(address, origin);
    const pages = evidence.discovery || [];
    const requests = evidence.oracle_requests || [];
    const children = [
      el('h4', 'Start page'),
      facts([
        ['Address', codes([start.final_url || target])],
        ['Status', start.status ? String(start.status) : 'no answer'],
        ['Redirects', start.redirects ? codes([target, ...start.redirects].map(short), ' \u2192 ') : null],
        ['Not followed', codes(start.redirect_not_followed ? [start.redirect_not_followed] : [])],
        ['Server', codes(start.server ? [start.server] : [])],
        ['X-Powered-By', codes(start.x_powered_by ? [start.x_powered_by] : [])],
        ['Server signature', codes(start.server_signature ? [start.server_signature] : [])],
        ['In front', (start.front_layers || []).join(', ')],
        ['Other platforms', (start.other_platforms || []).join(', ')],
        ['phpinfo()', codes(start.phpinfo_version ? ['PHP ' + start.phpinfo_version] : [])],
        ['phpinfo() settings', settings(start)],
        ['Cookies', codes(start.cookies)],
        ['PHP signs', (start.php_hints || []).join(', ')],
        ['PHP links', codes((start.discovered_paths || []).map(short))],
        ['Blocked', start.inspection_blocked],
        ['Error', start.error],
      ]),
    ];
    if (pages.length > 0) {
      children.push(el('h4', 'Other PHP pages'), table(['Page', 'Status', 'Seen'], pages.map((page) => [
        el('code', short(page.final_url)), page.status ? String(page.status) : '', pageSeen(page, start),
      ])));
    }
    const probes = evidence.phpinfo_requests || [];
    if (probes.length > 0) {
      children.push(el('h4', 'phpinfo() pages'), table(['Page', 'Status', 'Seen'], probes.map((page) => [
        el('code', short(page.final_url)), page.status ? String(page.status) : '', pageSeen(page, start),
      ])));
    }
    const known = frameworks([start, ...pages]);
    if (known) {
      children.push(el('h4', 'Frameworks'), known);
    }
    if (requests.length > 0) {
      children.push(el('h4', 'Patch-state requests'), table(['Page', 'Status', 'PHP answered'], requests.map((request) => [
        el('code', short(request.url)), request.status ? String(request.status) : '', reading(request),
      ])));
      for (const request of requests.filter((request) => (request.lines || []).length > 0)) {
        const lines = el('details');
        lines.append(el('summary', 'Warnings from ' + short(request.url)), el('pre', request.lines.join('\n')));
        children.push(lines);
      }
    }
    const raw = el('details');
    raw.append(el('summary', 'Raw JSON'), el('pre', JSON.stringify(evidence, null, 2)));
    children.push(raw);
    return children;
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
      const evidence = el('details', undefined, 'evidence');
      evidence.append(el('summary', 'What the check saw'), ...renderEvidence(report.evidence, report.target));
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
