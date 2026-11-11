/* Email Health Audit: client-side audit of a domain's email DNS setup over DNS-over-HTTPS (dns.google).
   No dependencies, no inline code (CSP: script-src 'self'). The grade is a heuristic, not a standard. */
(function () {
  'use strict';

  var DOH = 'https://dns.google/resolve';
  var $ = function (id) { return document.getElementById(id); };

  var SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'smtp', 'mandrill', 'zoho'];
  // Sibling tools of the suite: https://<tool>.hbenali.ovh/?domain=
  var TOOLS = { mx: 'MX', spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC', bimi: 'BIMI', dnssec: 'DNSSEC', caa: 'CAA', ssl: 'SSL', rdap: 'RDAP', ip: 'IP', mtasts: 'MTA-STS', dane: 'DANE', dns: 'DNS lookup', delegation: 'Delegation', ct: 'Certificate Transparency', 'headers-sec': 'Security headers' };
  // Weights of the heuristic score (sum 100). BIMI is shown but not scored.
  var WEIGHTS = { mx: 15, spf: 25, dkim: 15, dmarc: 30, mtasts: 4, tlsrpt: 3, dnssec: 8 };

  // ---- DNS helpers ----
  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/\.+$/, '');
  }
  function validDomain(d) {
    if (!d || d.length > 253) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(l) || /^xn--[a-z0-9-]+$/i.test(l); });
  }
  async function doh(name, type) {
    var res = await fetch(DOH + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type));
    if (!res.ok) throw new Error('DNS query failed (HTTP ' + res.status + ')');
    return res.json();
  }
  // TXT lookup: {status, ad, vals[]}. Throws on SERVFAIL-style errors so callers can report "lookup failed".
  async function txt(name) {
    var d = await doh(name, 'TXT');
    if (d.Status !== 0 && d.Status !== 3) throw new Error('DNS error ' + d.Status + (d.Comment ? ' (' + d.Comment + ')' : ''));
    var vals = (d.Answer || []).filter(function (x) { return x.type === 16; }).map(function (x) {
      return String(x.data).replace(/^"|"$/g, '').replace(/"\s*"/g, '');
    });
    return { status: d.Status, ad: d.AD === true, vals: vals };
  }
  function isPrivateV4(ip) {
    var p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }
  function isPrivateV6(ip) { return /^(::1?|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/i.test(ip); }
  async function resolveHost(host) {
    var out = { host: host, a: [], aaaa: [], cname: null, error: null };
    try {
      var r = await Promise.all([doh(host, 'A'), doh(host, 'AAAA')]);
      var a = r[0], aaaa = r[1];
      var all = (a.Answer || []).concat(aaaa.Answer || []);
      var cn = all.filter(function (x) { return x.type === 5; })[0];
      if (cn) out.cname = cn.data.replace(/\.$/, '');
      out.a = (a.Answer || []).filter(function (x) { return x.type === 1; }).map(function (x) { return x.data; });
      out.aaaa = (aaaa.Answer || []).filter(function (x) { return x.type === 28; }).map(function (x) { return x.data; });
      if (a.Status === 3 && aaaa.Status === 3) out.error = 'NXDOMAIN';
    } catch (e) { out.error = e.message; }
    return out;
  }
  function parseTags(v) {
    var t = {};
    String(v).split(';').forEach(function (p) {
      var i = p.indexOf('=');
      if (i > 0) { var k = p.slice(0, i).trim().toLowerCase(); if (!(k in t)) t[k] = p.slice(i + 1).trim(); }
    });
    return t;
  }

  // ---- Result helpers ----
  // An area: {id, title, findings:[{level, text, fix, rec}], score (0..1 or null = not scored), summary}
  function newArea(id, title) { return { id: id, title: title, findings: [], score: null, summary: '' }; }
  function add(area, level, text, fix, rec) { area.findings.push({ level: level, text: text, fix: fix || '', rec: rec || '' }); }
  function status(area) {
    var l = area.findings.map(function (f) { return f.level; });
    return l.indexOf('fail') >= 0 ? 'fail' : l.indexOf('warn') >= 0 ? 'warn' : l.indexOf('pass') >= 0 ? 'pass' : 'info';
  }
  function lookupFailed(area, e) {
    add(area, 'info', 'Lookup failed (' + (e && e.message ? e.message : 'unknown error') + '); this area was not scored.', 'Run the audit again in a moment.');
    area.score = null;
    area.summary = 'lookup failed';
  }
  function scoreFrom(area) {
    var s = status(area);
    area.score = s === 'pass' ? 1 : s === 'warn' ? 0.5 : 0;
  }

  // ---- MX ----
  async function auditMX(domain, ctx) {
    var area = newArea('mx', 'MX');
    try {
      var d = await doh(domain, 'MX');
      ctx.mxAD = d.AD === true;
      if (d.Status === 3) { ctx.nxdomain = true; add(area, 'fail', 'The domain does not exist (NXDOMAIN).', 'Check the spelling, or register the domain.'); area.score = 0; area.summary = 'domain not found'; return area; }
      if (d.Status !== 0) throw new Error('DNS error ' + d.Status);
      var recs = (d.Answer || []).filter(function (r) { return r.type === 15; }).map(function (r) {
        var m = String(r.data).trim().match(/^(\d+)\s+(\S+)$/);
        return m ? { pref: parseInt(m[1], 10), host: m[2].replace(/\.$/, '').toLowerCase() || '.' } : null;
      }).filter(Boolean);
      recs.sort(function (x, y) { return x.pref - y.pref || x.host.localeCompare(y.host); });
      ctx.mx = recs;

      if (!recs.length) {
        var fb = await resolveHost(domain);
        var addrs = fb.a.concat(fb.aaaa);
        if (addrs.length) {
          add(area, 'warn', 'No MX record. Senders fall back to the domain\'s own address record (' + addrs.join(', ') + ') as an implicit MX (RFC 5321).', 'Publish explicit MX records, or a null MX ("0 .") if the domain must not receive mail.');
          area.score = 0.5; area.summary = 'implicit MX only';
        } else {
          add(area, 'fail', 'No MX record and no address record: the domain cannot receive email.', 'Publish MX records, or a null MX ("0 .") if the domain is send-only or unused.');
          area.score = 0; area.summary = 'no MX';
        }
        return area;
      }
      if (recs.length === 1 && recs[0].host === '.') {
        ctx.nullMX = true;
        add(area, 'pass', 'Null MX (RFC 7505): the domain states it does not accept email.', '');
        if (recs[0].pref !== 0) add(area, 'warn', 'A null MX should use priority 0, found ' + recs[0].pref + '.', 'Publish exactly "0 .".');
        area.summary = 'null MX (no inbound mail)';
        scoreFrom(area);
        return area;
      }
      if (recs.some(function (r) { return r.host === '.'; })) add(area, 'fail', 'A null MX (".") is mixed with real mail hosts; a null MX must be the only MX record.', 'Remove the null MX, or remove the other MX records.');
      add(area, 'pass', recs.length + ' MX record' + (recs.length > 1 ? 's' : '') + ' published (' + recs.map(function (r) { return r.pref + ' ' + r.host; }).join(', ') + ').', '');
      if (recs.length === 1) add(area, 'info', 'Only one MX host: no backup if it is unreachable.', 'Add a second MX host at a higher priority number if your provider offers one.');

      var hosts = recs.map(function (r) { return r.host; }).filter(function (h, i, a) { return h !== '.' && a.indexOf(h) === i; });
      var resolved = await Promise.all(hosts.map(resolveHost));
      var bad = false;
      resolved.forEach(function (res) {
        var h = res.host;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') !== -1) { bad = true; add(area, 'fail', h + ' is an IP address; an MX target must be a hostname.', 'Point the MX at a hostname that has an A/AAAA record.'); return; }
        if (res.error === 'NXDOMAIN') { bad = true; add(area, 'fail', h + ' does not exist (NXDOMAIN): mail to it cannot be delivered.', 'Fix the MX hostname or create its address record.'); return; }
        if (res.error) { add(area, 'warn', h + ': address lookup failed (' + res.error + ').', 'Run the audit again.'); return; }
        if (res.cname) { bad = true; add(area, 'fail', h + ' is a CNAME to ' + res.cname + '; an MX target must have address records directly (RFC 2181 section 10.3).', 'Point the MX at the final hostname, or replace the CNAME with A/AAAA records.'); }
        if (!res.a.length && !res.aaaa.length) { bad = true; add(area, 'fail', h + ' has no A or AAAA record.', 'Add an address record for the mail host.'); }
        else if (res.a.some(isPrivateV4) || res.aaaa.some(isPrivateV6)) { bad = true; add(area, 'fail', h + ' resolves to a private or loopback address; it is unreachable from the internet.', 'Use the public address of the mail host.'); }
      });
      if (!bad) add(area, 'pass', 'Every MX host resolves to an address and none is a CNAME.', '');
      area.summary = recs.length + ' MX, ' + (bad ? 'problems found' : 'hosts resolve');
      scoreFrom(area);
    } catch (e) { lookupFailed(area, e); }
    return area;
  }

  // ---- SPF ----
  async function spfCount(record) {
    var st = { count: 0, fetched: 0, capped: false, problems: [], ptr: false, seen: {} };
    async function walk(rec, depth) {
      var tokens = rec.split(/\s+/).slice(1);
      var jobs = [];
      tokens.forEach(function (tok) {
        var t = tok.replace(/^[+\-~?]/, '').toLowerCase();
        var name = t.split(/[:=\/]/)[0];
        var arg = t.indexOf(':') >= 0 ? t.slice(t.indexOf(':') + 1) : (name === 'redirect' && t.indexOf('=') >= 0 ? t.slice(t.indexOf('=') + 1) : '');
        arg = arg.replace(/\/\d+(\/\d+)?$/, '');
        if (name === 'a' || name === 'mx' || name === 'exists') st.count++;
        else if (name === 'ptr') { st.count++; st.ptr = true; }
        else if (name === 'include' || name === 'redirect') {
          st.count++;
          if (!validDomain(arg)) return;
          if (st.seen[arg]) { st.problems.push('repeated or looping include of ' + arg); return; }
          st.seen[arg] = true;
          if (depth >= 6 || st.fetched >= 25) { st.capped = true; return; }
          st.fetched++;
          jobs.push(txt(arg).then(function (r) {
            var spf = r.vals.filter(function (v) { return /^v=spf1(\s|$)/i.test(v); });
            if (!spf.length) { st.problems.push(arg + ' has no SPF record'); return; }
            return walk(spf[0], depth + 1);
          }).catch(function () { st.capped = true; }));
        }
      });
      await Promise.all(jobs);
    }
    await walk(record, 0);
    return st;
  }
  async function auditSPF(domain, ctx) {
    var area = newArea('spf', 'SPF');
    try {
      var r = await txt(domain);
      ctx.txtAD = r.ad;
      var spf = r.vals.filter(function (v) { return /^v=spf1(\s|$)/i.test(v); });
      if (!spf.length) {
        if (ctx.nullMX) { add(area, 'warn', 'No SPF record. A domain that sends no mail should publish "v=spf1 -all" so nobody can spoof it.', 'Publish TXT "v=spf1 -all".'); area.score = 0.5; }
        else { add(area, 'fail', 'No SPF record: receivers cannot verify which servers may send for this domain.', 'Publish one TXT record starting with "v=spf1" that lists your senders and ends in -all or ~all.'); area.score = 0; }
        area.summary = 'no SPF record';
        return area;
      }
      var rec = spf[0];
      if (spf.length > 1) add(area, 'fail', spf.length + ' SPF records are published; more than one makes SPF evaluate to a permanent error (RFC 7208 section 4.5).', 'Merge them into a single v=spf1 record.', spf.join('\n'));
      else add(area, 'pass', 'Exactly one SPF record is published.', '', rec);

      var tokens = rec.split(/\s+/).slice(1);
      var allIdx = -1, allTok = null;
      tokens.forEach(function (t, i) { if (/^[+\-~?]?all$/i.test(t)) { allIdx = i; allTok = t.toLowerCase(); } });
      var redirect = tokens.some(function (t) { return /^redirect=/i.test(t); });
      if (allTok === '-all') add(area, 'pass', 'Ends in -all: unlisted senders are rejected.', '');
      else if (allTok === '~all') add(area, 'pass', 'Ends in ~all (soft fail): unlisted senders are flagged, a common and acceptable policy.', 'Move to -all once you are sure every legitimate sender is listed.');
      else if (allTok === '?all') add(area, 'warn', '?all (neutral) gives receivers no policy.', 'Use ~all or -all.');
      else if (allTok === '+all' || allTok === 'all') add(area, 'fail', allTok + ' authorizes every server on the internet to send as this domain.', 'Replace it with -all or ~all.');
      else if (redirect) add(area, 'info', 'No "all" mechanism; the policy comes from the redirect= target.', '');
      else add(area, 'warn', 'No "all" mechanism and no redirect: the record has no default result.', 'End the record with -all or ~all.');
      if (allIdx >= 0 && tokens.slice(allIdx + 1).some(function (t) { return !/^(exp|redirect)=/i.test(t); })) add(area, 'warn', 'Mechanisms after "all" are never evaluated.', 'Move "all" to the end of the record.');

      var st = await spfCount(rec);
      add(area, st.count > 10 ? 'warn' : 'pass', st.count + ' DNS-lookup mechanism' + (st.count === 1 ? '' : 's') + ' (include, a, mx, ptr, exists, redirect), counted through the include chain' + (st.capped ? ' (the lookup limit of this tool was reached, so the true count may be higher)' : '') + '. The limit is 10' + (st.count > 10 ? ' and it is exceeded: receivers return a permanent error.' : '.'),
        st.count > 10 ? 'Flatten or remove includes, and drop unused vendors, until you are at 10 or fewer.' : '');
      if (st.count > 8 && st.count <= 10) add(area, 'info', 'Close to the limit of 10 lookups; adding one more vendor may break SPF.', 'Plan to flatten before adding senders.');
      st.problems.forEach(function (p) { add(area, 'warn', 'Include chain issue: ' + p + '.', 'Remove or correct that include.'); });
      if (st.ptr) add(area, 'warn', 'The ptr mechanism is used. It is slow, unreliable and discouraged by RFC 7208.', 'Replace ptr with ip4/ip6, a or include.');
      area.summary = (allTok || 'no all') + ', ' + st.count + ' lookup' + (st.count === 1 ? '' : 's');
      scoreFrom(area);
    } catch (e) { lookupFailed(area, e); }
    return area;
  }

  // ---- DKIM ----
  function readTLV(b, i) {
    var tag = b[i], len = b[i + 1], off = i + 2;
    if (len & 0x80) { var n = len & 0x7f; len = 0; for (var j = 0; j < n; j++) len = len * 256 + b[off++]; }
    return { tag: tag, start: off, end: off + len };
  }
  // RSA modulus size in bits from a base64 SubjectPublicKeyInfo (or raw RSAPublicKey); null if unparsable.
  function rsaBits(p) {
    try {
      var bin = atob(p.replace(/\s+/g, '')), b = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
      var outer = readTLV(b, 0);
      if (outer.tag !== 0x30) return null;
      var first = readTLV(b, outer.start), intg;
      if (first.tag === 0x02) intg = first;
      else {
        var bit = readTLV(b, first.end);
        if (bit.tag !== 0x03) return null;
        intg = readTLV(b, readTLV(b, bit.start + 1).start);
      }
      if (intg.tag !== 0x02) return null;
      var s = intg.start;
      while (s < intg.end - 1 && b[s] === 0) s++;
      return (intg.end - s - 1) * 8 + (32 - Math.clz32(b[s]));
    } catch (e) { return null; }
  }
  async function auditDKIM(domain, ctx) {
    var area = newArea('dkim', 'DKIM');
    if (ctx.nullMX) { add(area, 'info', 'The domain publishes a null MX, so DKIM keys are not expected. Not scored.', ''); area.summary = 'not applicable'; return area; }
    var found = [], missing = [], errors = 0;
    await Promise.all(SELECTORS.map(function (sel) {
      return txt(sel + '._domainkey.' + domain).then(function (r) {
        var v = r.vals.filter(function (x) { return /(^|;)\s*p=/i.test(x) || /^v=DKIM1/i.test(x); })[0];
        if (v) found.push({ sel: sel, rec: v }); else missing.push(sel);
      }).catch(function () { errors++; });
    }));
    found.sort(function (a, b) { return SELECTORS.indexOf(a.sel) - SELECTORS.indexOf(b.sel); });
    missing.sort(function (a, b) { return SELECTORS.indexOf(a) - SELECTORS.indexOf(b); });
    if (errors === SELECTORS.length) { lookupFailed(area, new Error('all selector queries failed')); return area; }
    if (!found.length) {
      add(area, 'info', 'None of the ' + SELECTORS.length + ' probed selectors exists. This is not a failure: DKIM selectors can have any name, and a browser cannot list a DNS zone, so only a fixed list of common names is tried.', 'Find your real selector in a received message header (DKIM-Signature: s=...) and look it up with the DKIM tool.');
      area.summary = 'no common selector found (not a failure)';
      return area;
    }
    found.forEach(function (f) {
      var t = parseTags(f.rec), k = (t.k || 'rsa').toLowerCase(), p = (t.p || '').replace(/\s+/g, '');
      var name = f.sel + '._domainkey';
      if (!p) { add(area, 'warn', name + ' has an empty p= (revoked key).', 'Remove the record, or publish a new key.', f.rec); return; }
      var lvl = 'pass', desc, fix = '';
      if (k === 'rsa') {
        var bits = rsaBits(p);
        if (bits == null) { desc = 'RSA key (length could not be parsed)'; lvl = 'info'; }
        else if (bits < 1024) { lvl = 'fail'; desc = 'RSA ' + bits + '-bit key, too weak to trust'; fix = 'Rotate to a 2048-bit RSA key.'; }
        else if (bits < 2048) { lvl = 'warn'; desc = 'RSA ' + bits + '-bit key'; fix = 'Rotate to a 2048-bit RSA key.'; }
        else desc = 'RSA ' + bits + '-bit key';
      } else if (k === 'ed25519') desc = 'Ed25519 key (256-bit); not every receiver verifies it, so keep an RSA key too';
      else { desc = 'key type ' + k; lvl = 'info'; }
      add(area, lvl, name + '.' + domain + ': ' + desc + '.', fix, f.rec);
      if (/(^|:)y(:|$)/.test(t.t || '')) add(area, 'warn', f.sel + ' is in testing mode (t=y): receivers may ignore failures.', 'Remove t=y once the key is verified.');
    });
    add(area, 'info', 'Selectors probed but not found: ' + (missing.length ? missing.join(', ') : 'none') + '. Their absence is normal and not a failure.', '');
    area.summary = found.length + ' selector' + (found.length > 1 ? 's' : '') + ' found (' + found.map(function (f) { return f.sel; }).join(', ') + ')';
    scoreFrom(area);
    return area;
  }

  // ---- DMARC ----
  async function auditDMARC(domain, ctx) {
    var area = newArea('dmarc', 'DMARC');
    try {
      var r = await txt('_dmarc.' + domain);
      var recs = r.vals.filter(function (v) { return /^v=DMARC1\s*(;|$)/i.test(v); });
      if (!recs.length) {
        add(area, 'fail', 'No DMARC record at _dmarc.' + domain + '. (For a subdomain, receivers also look at the organizational domain; this tool does not.)', 'Publish TXT _dmarc: "v=DMARC1; p=none; rua=mailto:dmarc@' + domain + '" to start monitoring, then move to quarantine and reject.');
        area.score = 0; area.summary = 'no DMARC record';
        return area;
      }
      if (recs.length > 1) add(area, 'fail', recs.length + ' DMARC records are published; receivers ignore DMARC when there is more than one.', 'Keep a single v=DMARC1 record.', recs.join('\n'));
      var rec = recs[0], t = parseTags(rec);
      ctx.dmarc = t;
      if (recs.length === 1) add(area, 'pass', 'Exactly one DMARC record is published.', '', rec);
      var p = (t.p || '').toLowerCase();
      if (!p) add(area, 'fail', 'The p= tag is missing; the record is invalid.', 'Add p=none, p=quarantine or p=reject.');
      else if (p === 'none') add(area, 'warn', 'p=none: monitoring only. Spoofed mail is still delivered.', 'After reviewing reports, move to p=quarantine, then p=reject.');
      else if (p === 'quarantine') add(area, 'pass', 'p=quarantine: failing mail is sent to spam.', 'p=reject gives the strongest protection once reports are clean.');
      else if (p === 'reject') add(area, 'pass', 'p=reject: failing mail is rejected.', '');
      else add(area, 'fail', 'p=' + p + ' is not a valid policy.', 'Use none, quarantine or reject.');
      if (t.sp) {
        var sp = t.sp.toLowerCase();
        if (sp === 'none' && (p === 'quarantine' || p === 'reject')) add(area, 'warn', 'sp=none leaves subdomains unprotected while the main domain is enforced.', 'Remove sp= or set it to ' + p + '.');
        else add(area, 'info', 'Subdomain policy sp=' + sp + '.', '');
      } else if (p) add(area, 'info', 'No sp= tag: subdomains inherit p=' + p + '.', '');
      if (t.pct != null) {
        var pct = parseInt(t.pct, 10);
        if (isNaN(pct) || pct < 0 || pct > 100) add(area, 'warn', 'pct=' + t.pct + ' is not a valid percentage.', 'Use 0 to 100, or remove it.');
        else if (pct < 100 && p !== 'none') add(area, 'warn', 'pct=' + pct + ': the policy applies to only ' + pct + '% of failing mail.', 'Raise pct to 100 once reports look clean.');
      }
      if (!t.rua) add(area, 'warn', 'No rua= tag: you receive no aggregate reports, so you cannot see who sends as your domain.', 'Add rua=mailto:dmarc@' + domain + ' (or a reporting service).');
      else {
        add(area, 'pass', 'Aggregate reports go to: ' + t.rua + '.', '');
        var hosts = [];
        t.rua.split(',').forEach(function (u) {
          var m = u.trim().match(/^mailto:[^@\s]+@([^!\s,]+)/i);
          if (!m) return;
          var h = m[1].toLowerCase().replace(/\.$/, '');
          var ext = h !== domain && !h.endsWith('.' + domain) && !domain.endsWith('.' + h);
          if (ext && validDomain(h) && hosts.indexOf(h) < 0) hosts.push(h);
        });
        await Promise.all(hosts.slice(0, 5).map(function (h) {
          return txt(domain + '._report._dmarc.' + h).then(function (a) {
            var ok = a.vals.some(function (v) { return /^v=DMARC1/i.test(v); });
            if (ok) add(area, 'pass', 'External report host ' + h + ' has authorized this domain (' + domain + '._report._dmarc.' + h + ').', '');
            else add(area, 'warn', 'Reports go to ' + h + ', but no authorization record exists at ' + domain + '._report._dmarc.' + h + '; receivers may drop the reports (RFC 7489 section 7.1).', 'Ask ' + h + ' to publish "v=DMARC1" at that name, or use a mailbox in your own domain.');
          }).catch(function () { add(area, 'info', 'Could not verify the external report authorization for ' + h + '.', ''); });
        }));
      }
      if (t.ruf) add(area, 'info', 'Forensic reports requested (ruf=' + t.ruf + '); many receivers do not send them.', '');
      add(area, 'info', 'Alignment: DKIM ' + ((t.adkim || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed') + ', SPF ' + ((t.aspf || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed') + (t.adkim || t.aspf ? '' : ' (defaults)') + '. Relaxed suits most senders.', '');
      area.summary = p ? 'p=' + p : 'invalid record';
      scoreFrom(area);
    } catch (e) { lookupFailed(area, e); }
    return area;
  }

  // ---- BIMI ----
  async function auditBIMI(domain, ctx) {
    var area = newArea('bimi', 'BIMI');
    if (ctx.nullMX) { add(area, 'info', 'Not applicable for a domain that sends no mail. Not scored.', ''); area.summary = 'not applicable'; return area; }
    try {
      var r = await txt('default._bimi.' + domain);
      var recs = r.vals.filter(function (v) { return /^v=BIMI1\s*(;|$)/i.test(v); });
      if (!recs.length) { add(area, 'info', 'No BIMI record at default._bimi. BIMI is optional: it shows your logo in some mailboxes. Not scored.', 'Optional: publish v=BIMI1; l=<https SVG URL> once DMARC is at quarantine or reject.'); area.summary = 'not published (optional)'; return area; }
      var t = parseTags(recs[0]);
      add(area, 'pass', 'A BIMI record is published.', '', recs[0]);
      if (!t.l) add(area, 'warn', 'The l= tag (logo URL) is missing.', 'Add l= with an https URL to an SVG Tiny PS logo.');
      else if (!/^https:\/\//i.test(t.l)) add(area, 'warn', 'The logo URL is not https.', 'Host the SVG over https.');
      if (!t.a) add(area, 'info', 'No a= tag: no verified mark certificate (VMC); Gmail and Apple Mail require one to show the logo.', '');
      var p = ctx.dmarc ? (ctx.dmarc.p || '').toLowerCase() : null;
      if (p !== null && p !== 'quarantine' && p !== 'reject') add(area, 'warn', 'BIMI is ignored unless DMARC is at p=quarantine or p=reject.', 'Raise the DMARC policy.');
      add(area, 'info', 'The logo file and certificate are not fetched or validated here (browser CORS limits). Not scored.', '');
      area.summary = 'published';
    } catch (e) { lookupFailed(area, e); }
    return area;
  }

  // ---- MTA-STS and TLS-RPT (TXT only) ----
  async function auditTxtPolicy(id, title, name, re, domain, ctx, note, fix) {
    var area = newArea(id, title);
    if (ctx.nullMX) { add(area, 'info', 'Not applicable for a domain that does not receive mail. Not scored.', ''); area.summary = 'not applicable'; return area; }
    try {
      var r = await txt(name + '.' + domain);
      var rec = r.vals.filter(function (v) { return re.test(v); })[0];
      if (rec) {
        add(area, 'pass', title + ' TXT record is published.', '', rec);
        add(area, 'info', note, '');
        area.score = 1; area.summary = 'published';
      } else {
        add(area, 'info', 'No ' + title + ' record at ' + name + '.' + domain + '. Optional, but it improves transport security.', fix);
        area.score = 0; area.summary = 'not published (optional)';
      }
    } catch (e) { lookupFailed(area, e); }
    return area;
  }

  // ---- DNSSEC ----
  async function auditDNSSEC(domain, ctx) {
    var area = newArea('dnssec', 'DNSSEC');
    try {
      var d = await doh(domain, 'DNSKEY');
      var hasKey = (d.Answer || []).some(function (x) { return x.type === 48; });
      var ad = d.AD === true || ctx.mxAD || ctx.txtAD;
      if (ad) { add(area, 'pass', 'The resolver validated the answers with DNSSEC (AD flag set).', ''); area.score = 1; area.summary = 'validated'; }
      else if (hasKey) { add(area, 'warn', 'DNSKEY records exist but the resolver did not validate the answers (no AD flag): the chain of trust may be broken.', 'Check that the DS record at the registry matches your DNSKEY.'); area.score = 0.5; area.summary = 'keys present, not validated'; }
      else { add(area, 'info', 'The zone does not appear to be signed. DNSSEC protects the MX, SPF and DMARC records from tampering.', 'Enable DNSSEC at your DNS host and add the DS record at your registrar.'); area.score = 0; area.summary = 'not signed'; }
      add(area, 'info', 'This reflects what Google Public DNS reports, not a full walk of the chain of trust.', '');
    } catch (e) { lookupFailed(area, e); }
    return area;
  }

  // ---- Grade (heuristic) ----
  function grade(areas) {
    var got = 0, max = 0;
    areas.forEach(function (a) { var w = WEIGHTS[a.id]; if (w && a.score != null) { max += w; got += w * a.score; } });
    var pct = max ? Math.round(100 * got / max) : 0;
    var g = pct >= 85 ? 'A' : pct >= 70 ? 'B' : pct >= 55 ? 'C' : pct >= 40 ? 'D' : 'F';
    var capped = false;
    var core = areas.filter(function (a) { return a.id === 'mx' || a.id === 'spf' || a.id === 'dmarc'; });
    if (core.some(function (a) { return status(a) === 'fail'; }) && (g === 'A' || g === 'B')) { g = 'C'; capped = true; }
    return { pct: pct, letter: g, capped: capped };
  }

  // ---- Rendering ----
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function toolLink(tool, domain, label) {
    var a = el('a', 'link', label);
    a.href = 'https://' + tool + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
    a.target = '_blank'; a.rel = 'noopener noreferrer';
    return a;
  }
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }
  var LABELS = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note' };
  var AREA_TOOL = { mx: 'mx', spf: 'spf', dkim: 'dkim', dmarc: 'dmarc', bimi: 'bimi', mtasts: 'mtasts', tlsrpt: 'mtasts', dnssec: 'dnssec' };
  // The MTA-STS tool also covers TLS-RPT, so say both on the TLS-RPT line.
  var AREA_TOOL_LABEL = { tlsrpt: 'MTA-STS and TLS-RPT' };

  function render(domain, areas, g) {
    var box = views.records;
    box.replaceChildren();
    var tone = g.letter === 'A' || g.letter === 'B' ? 'ok' : g.letter === 'C' || g.letter === 'D' ? 'warn' : 'fail';

    var head = el('div', 'state ' + tone);
    var row = el('div', 'grade-row');
    var letter = el('div', 'grade grade-' + tone, g.letter);
    letter.setAttribute('role', 'img');
    letter.setAttribute('aria-label', 'Overall grade ' + g.letter);
    row.append(letter);
    var info = el('div', 'grade-info');
    info.append(el('h2', 'state-title', 'Email health for'));
    info.append(el('span', 'badge-domain', domain));
    info.append(el('p', 'count', 'Heuristic score ' + g.pct + ' of 100' + (g.capped ? ', capped at C because MX, SPF or DMARC has a failure' : '') + '.'));
    row.append(info);
    head.append(row);
    var honest = el('p', 'honest');
    honest.append(el('strong', null, 'This grade is a heuristic. '));
    honest.append('It is an opinionated weighting of DNS records only (MX 15, SPF 25, DKIM 15, DMARC 30, MTA-STS 4, TLS-RPT 3, DNSSEC 8 points; areas that do not apply or could not be checked are left out; A to F start at 85, 70, 55 and 40 points). It is not a standard, not a guarantee of deliverability, and says nothing about sender reputation, blocklists, content, or whether your mail servers really accept TLS.');
    head.append(honest);
    box.append(head);

    var scroll = el('div', 'table-scroll');
    scroll.setAttribute('tabindex', '0');
    scroll.setAttribute('role', 'region');
    scroll.setAttribute('aria-label', 'Per-area results');
    var table = el('table', 'summary');
    var thead = el('thead'), hr = el('tr');
    ['Area', 'Result', 'Detail'].forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; hr.append(th); });
    thead.append(hr); table.append(thead);
    var tbody = el('tbody');
    areas.forEach(function (a) {
      var tr = el('tr');
      var th = el('th'); th.scope = 'row';
      var ln = el('a', 'link', a.title); ln.href = '#area-' + a.id;
      th.append(ln); tr.append(th);
      var s = status(a);
      var td = el('td'); td.append(el('span', 'chk ' + s, LABELS[s])); tr.append(td);
      tr.append(el('td', null, a.summary || ''));
      tbody.append(tr);
    });
    table.append(tbody); scroll.append(table); box.append(scroll);

    var order = { fail: 0, warn: 1, info: 2, pass: 3 };
    areas.forEach(function (a) {
      var sec = el('section', 'area');
      sec.id = 'area-' + a.id;
      var h = el('div', 'area-head');
      h.append(el('h3', 'area-title', a.title));
      var s = status(a);
      h.append(el('span', 'chk ' + s, LABELS[s]));
      sec.append(h);
      var ul = el('ul', 'checks');
      a.findings.slice().sort(function (x, y) { return order[x.level] - order[y.level]; }).forEach(function (f) {
        var li = el('li');
        li.append(el('span', 'chk ' + f.level, LABELS[f.level]));
        var body = el('div', 'finding');
        body.append(el('span', null, f.text));
        if (f.rec) body.append(el('code', 'rec', f.rec));
        if (f.fix) { var fx = el('span', 'fix'); fx.append(el('strong', null, 'Fix: ')); fx.append(f.fix); body.append(fx); }
        li.append(body);
        ul.append(li);
      });
      sec.append(ul);
      var p = el('p', 'provider');
      var tool = AREA_TOOL[a.id];
      p.append('Dedicated tool: ');
      p.append(toolLink(tool, domain, (AREA_TOOL_LABEL[a.id] || TOOLS[tool]) + ' checker for ' + domain));
      sec.append(p);
      box.append(sec);
    });

    var more = el('p', 'provider');
    more.append('Related tools for ' + domain + ': ');
    ['dane', 'dns', 'delegation', 'caa', 'ct', 'ssl', 'rdap', 'ip', 'headers-sec'].forEach(function (t, i) {
      if (i) more.append(' · ');
      more.append(toolLink(t, domain, TOOLS[t]));
    });
    box.append(more);
    box.append(el('p', 'provider', 'Not checked, because a browser cannot do it: the MTA-STS policy file (CORS), live SMTP and TLS handshakes (no raw sockets), blocklists and sender reputation. DKIM only covers ' + SELECTORS.length + ' common selector names.'));
  }

  function renderError(domain, msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', domain ? 'Error checking ' + domain : 'Error'));
    s.append(el('p', null, msg));
    box.append(s);
  }

  // ---- Flow ----
  var domainInput = $('domainInput'), checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  function setLoading(on) {
    checkBtn.disabled = on;
    btnText.textContent = on ? 'Auditing' : 'Run audit';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  async function audit(domain) {
    var ctx = {};
    // MX first: a null MX changes what the other areas expect.
    var mx = await auditMX(domain, ctx);
    if (ctx.nxdomain) return null;
    var parts = await Promise.all([
      auditSPF(domain, ctx),
      auditDKIM(domain, ctx),
      auditDMARC(domain, ctx),
      auditTxtPolicy('mtasts', 'MTA-STS', '_mta-sts', /^v=STSv1/i, domain, ctx, 'Only the TXT record is checked. The policy file at https://mta-sts.' + domain + '/.well-known/mta-sts.txt cannot be fetched from a browser (CORS), so its mode and MX list are not verified.', 'Publish TXT _mta-sts "v=STSv1; id=<timestamp>" and host the policy file, starting in mode: testing.'),
      auditTxtPolicy('tlsrpt', 'TLS-RPT', '_smtp._tls', /^v=TLSRPTv1/i, domain, ctx, 'Only the TXT record is checked; reports are not read.', 'Publish TXT _smtp._tls "v=TLSRPTv1; rua=mailto:tls@' + domain + '".'),
      auditDNSSEC(domain, ctx)
    ]);
    var bimi = await auditBIMI(domain, ctx); // needs the DMARC policy
    return [mx, parts[0], parts[1], parts[2], bimi, parts[3], parts[4], parts[5]];
  }

  async function performLookup() {
    var domain = normalizeDomain(domainInput.value);
    if (!domain) { setView('error'); renderError('', 'Please enter a domain name'); return; }
    if (!validDomain(domain)) { setView('error'); renderError(domain, 'That is not a valid domain name.'); return; }
    domainInput.value = domain;
    setLoading(true);
    try {
      var areas = await audit(domain);
      if (!areas) { renderError(domain, 'Domain "' + domain + '" does not exist (NXDOMAIN), so there is nothing to audit.'); setView('error'); return; }
      render(domain, areas, grade(areas));
      setView('records');
    } catch (err) {
      renderError(domain, err.message || 'Unknown error');
      setView('error');
    } finally {
      setLoading(false);
    }
  }
  checkBtn.addEventListener('click', performLookup);
  domainInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') performLookup(); });

  setView('placeholder');
  var param = new URLSearchParams(window.location.search).get('domain');
  if (param) { domainInput.value = param; performLookup(); }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
