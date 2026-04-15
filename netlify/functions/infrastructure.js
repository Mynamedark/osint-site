// netlify/functions/infrastructure.js
// Uses DNS-over-HTTPS (Cloudflare) instead of node dns module — works on Netlify
// RDAP for WHOIS, crt.sh for subdomains, Shodan InternetDB for IP intel

const fetch = require('node-fetch');

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };

  const { target } = JSON.parse(event.body || '{}');
  if (!target) return { statusCode: 400, headers, body: JSON.stringify({ error: 'target required' }) };

  const findings = [];
  const timestamp = new Date().toISOString();
  const slug = target.toLowerCase().replace(/\s+/g, '');
  const domains = [`${slug}.com`, `${slug}.io`, `${slug}.ae`, `${slug}.org`];

  await Promise.all(domains.map(async (domain) => {
    await Promise.all([
      dnsLookup(domain, findings, timestamp),
      rdapLookup(domain, findings, timestamp),
      crtshLookup(domain, findings, timestamp),
    ]);
  }));

  return { statusCode: 200, headers, body: JSON.stringify({ findings }) };
};

// ── DNS-over-HTTPS (Cloudflare) ──────────────────────────────────────────
async function dnsLookup(domain, findings, timestamp) {
  const types = ['A', 'MX', 'NS', 'TXT', 'AAAA'];

  await Promise.all(types.map(async (type) => {
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`,
        { headers: { Accept: 'application/dns-json' }, timeout: 6000 }
      );
      const data = await res.json();
      const answers = data.Answer || [];

      if (answers.length > 0) {
        const value = answers.map(a => a.data).join(', ');
        findings.push({
          category: 'infrastructure', source: 'DNS (Cloudflare DoH)', title: `DNS ${type} — ${domain}`,
          value, summary: `${type} record(s) for ${domain}: ${value}`,
          sourceUrl: `https://dnschecker.org/#${type}/${domain}`,
          timestamp, riskSignal: null,
        });

        // Shodan InternetDB for A records
        if (type === 'A') {
          for (const a of answers.slice(0, 2)) {
            await shodanProbe(a.data, domain, findings, timestamp);
          }
        }
      } else {
        findings.push({
          category: 'infrastructure', source: 'DNS (Cloudflare DoH)', title: `DNS ${type} — ${domain}`,
          value: 'NOT RESOLVED',
          summary: `No ${type} record found for ${domain}`,
          sourceUrl: `https://dnschecker.org/#${type}/${domain}`,
          timestamp, riskSignal: type === 'A' ? 'infra_opacity' : null,
        });
      }
    } catch (err) {
      findings.push({
        category: 'infrastructure', source: 'DNS', title: `DNS ${type} — ${domain}`,
        value: 'ERROR', summary: `DNS lookup failed: ${err.message}`,
        sourceUrl: `https://dnschecker.org/#${type}/${domain}`,
        timestamp, riskSignal: null,
      });
    }
  }));
}

// ── RDAP / WHOIS ─────────────────────────────────────────────────────────
async function rdapLookup(domain, findings, timestamp) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, { timeout: 6000 });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
    const registrar  = data.entities?.find(e => e.roles?.includes('registrar'));
    const expiry     = data.events?.find(e => e.eventAction === 'expiration')?.eventDate;
    const created    = data.events?.find(e => e.eventAction === 'registration')?.eventDate;

    findings.push({
      category: 'infrastructure', source: 'RDAP/WHOIS', title: `WHOIS — ${domain}`,
      value: domain,
      summary: [
        registrant ? `Registrant: ${registrant.handle || 'REDACTED'}` : 'Registrant: REDACTED',
        registrar  ? `Registrar: ${registrar.handle || 'Unknown'}`    : '',
        created    ? `Registered: ${created}`                         : '',
        expiry     ? `Expires: ${expiry}`                             : '',
      ].filter(Boolean).join(' | '),
      sourceUrl: `https://rdap.org/domain/${domain}`,
      timestamp, riskSignal: null,
    });
  } catch {
    findings.push({
      category: 'infrastructure', source: 'RDAP/WHOIS', title: `WHOIS — ${domain}`,
      value: 'NOT FOUND',
      summary: `Domain ${domain} not found in RDAP registry — likely unregistered or privacy-protected`,
      sourceUrl: `https://rdap.org/domain/${domain}`,
      timestamp, riskSignal: null,
    });
  }
}

// ── Certificate Transparency (crt.sh) ────────────────────────────────────
async function crtshLookup(domain, findings, timestamp) {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 6000 });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const subdomains = [...new Set(
      data.flatMap(e => (e.name_value || '').split('\n'))
          .filter(s => s && s.includes(domain) && !s.startsWith('*'))
    )].slice(0, 15);

    findings.push({
      category: 'infrastructure', source: 'crt.sh (CT Logs)', title: `Certificate Transparency — ${domain}`,
      value: subdomains.length > 0 ? subdomains.join(', ') : 'No subdomains found',
      summary: subdomains.length > 0
        ? `${subdomains.length} subdomain(s) found in CT logs: ${subdomains.join(', ')}`
        : `No CT log entries for ${domain}`,
      sourceUrl: `https://crt.sh/?q=%25.${domain}`,
      timestamp, riskSignal: null,
      extra: { subdomains },
    });
  } catch {
    /* non-fatal */
  }
}

// ── Shodan InternetDB (no key) ────────────────────────────────────────────
async function shodanProbe(ip, domain, findings, timestamp) {
  try {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, { timeout: 5000 });
    if (!res.ok) return;
    const data = await res.json();
    if (data.detail) return; // "No information available"

    const openPorts = data.ports || [];
    const vulns     = data.vulns || [];

    findings.push({
      category: 'infrastructure', source: 'Shodan InternetDB', title: `Shodan — ${ip} (${domain})`,
      value: openPorts.length ? `Open ports: ${openPorts.join(', ')}` : 'No open ports detected',
      summary: [
        `IP: ${ip}`,
        openPorts.length ? `Ports: ${openPorts.join(', ')}` : 'No open ports',
        vulns.length     ? `CVEs: ${vulns.join(', ')}`      : 'No CVEs listed',
        (data.tags||[]).length ? `Tags: ${data.tags.join(', ')}` : '',
      ].filter(Boolean).join(' | '),
      sourceUrl: `https://www.shodan.io/host/${ip}`,
      timestamp, riskSignal: openPorts.length ? 'open_port' : null,
      extra: { ip, openPorts, vulns, cpes: data.cpes || [] },
    });
  } catch { /* non-fatal */ }
}
