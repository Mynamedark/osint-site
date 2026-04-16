// netlify/functions/infrastructure.js — v2
// Smart domain discovery: extract domains FROM real search results instead of guessing
// Then: DNS-over-HTTPS, RDAP, crt.sh CT logs, Shodan InternetDB, IP geolocation

const fetch = require('node-fetch');

const CORS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST')   return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };

  const { target } = JSON.parse(event.body || '{}');
  if (!target) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'target required' }) };

  const findings = [];
  const ts = () => new Date().toISOString();

  // Step 1 — Discover real domains from search results (not slug guessing)
  const discoveredDomains = await discoverDomainsFromSearch(target);

  // Step 2 — Also generate slug candidates as fallback
  const slug     = target.toLowerCase().replace(/[^a-z0-9]/g, '');
  const words    = target.toLowerCase().split(/\s+/).filter(w => w.length > 2);
  const slugCandidates = [
    `${slug}.com`, `${slug}.ae`, `${slug}.io`, `${slug}.org`,
    words.length > 1 ? `${words[0]}.com` : null,
    words.length > 1 ? `${words.join('-')}.com` : null,
  ].filter(Boolean);

  // Merge: discovered domains first, then fallbacks — deduplicated
  const allDomains = [...new Set([...discoveredDomains, ...slugCandidates])].slice(0, 6);

  findings.push({
    category: 'infrastructure', source: 'Domain Discovery',
    title: `Domain Candidates — ${target}`,
    value: allDomains.join(', '),
    summary: `${discoveredDomains.length} domain(s) discovered from search results. ${allDomains.length - discoveredDomains.length} slug-derived fallback(s) added.`,
    sourceUrl: `https://duckduckgo.com/?q=${encodeURIComponent(target)}`,
    timestamp: ts(), riskSignal: null,
    extra: { discovered: discoveredDomains, slugBased: slugCandidates },
  });

  // Step 3 — Probe each domain in parallel
  await Promise.allSettled(
    allDomains.map(domain => Promise.allSettled([
      dnsLookup(domain, findings, ts),
      rdapLookup(domain, findings, ts),
      crtshLookup(domain, findings, ts),
    ]))
  );

  return { statusCode: 200, headers: CORS, body: JSON.stringify({ findings }) };
};

// ── SMART: Extract real domains from DuckDuckGo search results ─────────────
async function discoverDomainsFromSearch(target) {
  const domains = new Set();
  try {
    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent('"' + target + '" site')}`;
    const res  = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; OSINTBot/2.0)' },
      timeout: 7000,
    });
    const html = await res.text();

    // Extract all URLs from search results
    const urlRe  = /uddg=([^&"]+)/g;
    const hrefRe = /href="(https?:\/\/[^"]+)"/g;
    let m;

    while ((m = urlRe.exec(html))) {
      try {
        const u = new URL(decodeURIComponent(m[1]));
        if (!isGenericDomain(u.hostname)) domains.add(u.hostname.replace(/^www\./, ''));
      } catch { /* skip malformed */ }
    }

    while ((m = hrefRe.exec(html))) {
      try {
        const u = new URL(m[1]);
        if (!isGenericDomain(u.hostname)) domains.add(u.hostname.replace(/^www\./, ''));
      } catch { /* skip */ }
    }

    // Also query DuckDuckGo instant answers for official website
    const ddgUrl  = `https://api.duckduckgo.com/?q=${encodeURIComponent(target)}&format=json&no_redirect=1&no_html=1`;
    const ddgRes  = await fetch(ddgUrl, { headers: { 'User-Agent': 'OSINTTool/2.0' }, timeout: 6000 });
    const ddgData = await ddgRes.json();

    // Official website from infobox
    const websiteItem = ddgData.Infobox?.content?.find(i =>
      ['website', 'official website', 'url', 'homepage'].includes(i.label?.toLowerCase())
    );
    if (websiteItem?.value) {
      try {
        const u = new URL(websiteItem.value.startsWith('http') ? websiteItem.value : 'https://' + websiteItem.value);
        domains.add(u.hostname.replace(/^www\./, ''));
      } catch { /* skip */ }
    }

    // Abstract URL
    if (ddgData.AbstractURL) {
      try {
        const u = new URL(ddgData.AbstractURL);
        if (!isGenericDomain(u.hostname)) domains.add(u.hostname.replace(/^www\./, ''));
      } catch { /* skip */ }
    }

  } catch { /* non-fatal — fallback to slug candidates */ }

  return [...domains].slice(0, 4);
}

function isGenericDomain(hostname) {
  const skip = [
    'duckduckgo.com','google.com','bing.com','wikipedia.org','linkedin.com',
    'facebook.com','twitter.com','x.com','youtube.com','reddit.com',
    'amazon.com','apple.com','microsoft.com','github.com','nitter.net',
  ];
  return skip.some(s => hostname.includes(s));
}

// ── DNS-over-HTTPS (Cloudflare) ───────────────────────────────────────────
async function dnsLookup(domain, findings, ts) {
  const types = ['A', 'MX', 'NS', 'TXT'];

  await Promise.allSettled(types.map(async (type) => {
    try {
      const res  = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`,
        { headers: { Accept: 'application/dns-json' }, timeout: 6000 }
      );
      const data    = await res.json();
      const answers = data.Answer || [];

      if (answers.length > 0) {
        const value = answers.map(a => a.data).join(', ');
        findings.push({
          category: 'infrastructure', source: 'DNS (Cloudflare DoH)',
          title: `DNS ${type} — ${domain}`,
          value,
          summary: buildDnsSummary(type, domain, answers),
          sourceUrl: `https://dnschecker.org/#${type}/${domain}`,
          timestamp: ts(), riskSignal: null,
          extra: { domain, type, records: answers },
        });

        // Shodan + IP geo for A records
        if (type === 'A') {
          for (const a of answers.slice(0, 2)) {
            await Promise.allSettled([
              shodanProbe(a.data, domain, findings, ts),
              ipGeoLookup(a.data, domain, findings, ts),
            ]);
          }
        }

        // Parse TXT for interesting values
        if (type === 'TXT') {
          parseTxtRecords(domain, answers, findings, ts);
        }
      } else {
        // Only surface missing A records — others are noise
        if (type === 'A') {
          findings.push({
            category: 'infrastructure', source: 'DNS',
            title: `DNS A — ${domain} (not registered)`,
            value: 'NOT RESOLVED',
            summary: `No A record for ${domain}. Domain likely unregistered or DNS hidden.`,
            sourceUrl: `https://dnschecker.org/#A/${domain}`,
            timestamp: ts(), riskSignal: 'infra_opacity',
          });
        }
      }
    } catch { /* non-fatal */ }
  }));
}

function buildDnsSummary(type, domain, answers) {
  const vals = answers.map(a => a.data);
  switch (type) {
    case 'A':   return `${domain} resolves to IP(s): ${vals.join(', ')}`;
    case 'MX':  return `Mail server(s): ${vals.map(v => v.replace(/^\d+ /, '')).join(', ')}`;
    case 'NS':  return `Nameservers: ${vals.join(', ')}`;
    case 'TXT': return `TXT records: ${vals.slice(0,3).join(' | ')}`;
    default:    return vals.join(', ');
  }
}

function parseTxtRecords(domain, answers, findings, ts) {
  for (const a of answers) {
    const txt = a.data;
    // SPF
    if (txt.includes('v=spf1')) {
      findings.push({
        category: 'infrastructure', source: 'DNS TXT — SPF',
        title: `SPF Record — ${domain}`,
        value: txt,
        summary: `Email sending policy: ${txt}. Reveals authorised mail providers.`,
        sourceUrl: `https://mxtoolbox.com/spf.aspx`,
        timestamp: ts(), riskSignal: null,
      });
    }
    // DMARC
    if (txt.includes('v=DMARC1')) {
      findings.push({
        category: 'infrastructure', source: 'DNS TXT — DMARC',
        title: `DMARC Policy — ${domain}`,
        value: txt,
        summary: `DMARC policy configured. ${txt.includes('p=reject') ? 'Policy: REJECT (strict)' : txt.includes('p=quarantine') ? 'Policy: QUARANTINE' : 'Policy: NONE (weak)'}`,
        sourceUrl: `https://mxtoolbox.com/dmarc.aspx`,
        timestamp: ts(), riskSignal: null,
      });
    }
    // Google/MS verification = SaaS footprint
    if (txt.includes('google-site-verification')) {
      findings.push({
        category: 'infrastructure', source: 'DNS TXT — SaaS',
        title: `Google Workspace Verified — ${domain}`,
        value: txt,
        summary: `Domain verified with Google Workspace/Search Console. Organisation uses Google services.`,
        sourceUrl: `https://workspace.google.com/`,
        timestamp: ts(), riskSignal: null,
      });
    }
    if (txt.includes('MS=') || txt.includes('ms-') ) {
      findings.push({
        category: 'infrastructure', source: 'DNS TXT — SaaS',
        title: `Microsoft 365 Verified — ${domain}`,
        value: txt,
        summary: `Domain verified with Microsoft 365. Organisation uses Microsoft cloud services.`,
        sourceUrl: `https://microsoft.com/`,
        timestamp: ts(), riskSignal: null,
      });
    }
  }
}

// ── RDAP / WHOIS ─────────────────────────────────────────────────────────
async function rdapLookup(domain, findings, ts) {
  try {
    const res  = await fetch(`https://rdap.org/domain/${domain}`, { timeout: 7000 });
    if (!res.ok) return;
    const data = await res.json();

    const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
    const registrar  = data.entities?.find(e => e.roles?.includes('registrar'));
    const expiry     = data.events?.find(e => e.eventAction === 'expiration')?.eventDate;
    const created    = data.events?.find(e => e.eventAction === 'registration')?.eventDate;
    const nameservers = (data.nameservers || []).map(ns => ns.ldhName).filter(Boolean);

    const status = data.status || [];

    findings.push({
      category: 'infrastructure', source: 'RDAP/WHOIS',
      title: `WHOIS — ${domain}`,
      value: domain,
      summary: [
        registrant?.vcardArray ? `Registrant: ${extractVcard(registrant.vcardArray)}` : 'Registrant: REDACTED (privacy protected)',
        registrar  ? `Registrar: ${registrar.handle || 'Unknown'}` : '',
        created    ? `Registered: ${created?.slice(0,10)}`         : '',
        expiry     ? `Expires: ${expiry?.slice(0,10)}`             : '',
        nameservers.length ? `NS: ${nameservers.join(', ')}`       : '',
        status.length      ? `Status: ${status.join(', ')}`        : '',
      ].filter(Boolean).join(' | '),
      sourceUrl: `https://rdap.org/domain/${domain}`,
      timestamp: ts(), riskSignal: null,
      extra: { domain, created, expiry, registrar: registrar?.handle, nameservers, status },
    });
  } catch { /* domain not registered or RDAP unavailable */ }
}

function extractVcard(vcardArray) {
  if (!Array.isArray(vcardArray)) return 'Unknown';
  for (const item of vcardArray.flat()) {
    if (Array.isArray(item)) {
      const org = item.find(v => typeof v === 'string' && v.length > 2 && !v.includes('@') && !v.match(/^\d/));
      if (org) return org;
    }
  }
  return 'REDACTED';
}

// ── Certificate Transparency ──────────────────────────────────────────────
async function crtshLookup(domain, findings, ts) {
  try {
    const res  = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 7000 });
    if (!res.ok) return;
    const data = await res.json();

    const subdomains = [...new Set(
      data.flatMap(e => (e.name_value || '').split('\n'))
          .filter(s => s && s.includes(domain) && !s.startsWith('*'))
    )].slice(0, 20);

    const issuers = [...new Set(data.slice(0,20).map(e => e.issuer_name).filter(Boolean))].slice(0,3);

    if (subdomains.length > 0) {
      findings.push({
        category: 'infrastructure', source: 'crt.sh (CT Logs)',
        title: `Certificate Transparency — ${domain}`,
        value: subdomains.join(', '),
        summary: `${subdomains.length} subdomain(s) from CT logs: ${subdomains.join(', ')}. Certificate issuers: ${issuers.join(', ')}.`,
        sourceUrl: `https://crt.sh/?q=%25.${domain}`,
        timestamp: ts(), riskSignal: null,
        extra: { subdomains, issuers, totalCerts: data.length },
      });

      // DNS probe each subdomain for live ones
      for (const sub of subdomains.slice(0, 5)) {
        await dnsCheckSubdomain(sub, findings, ts);
      }
    }
  } catch { /* non-fatal */ }
}

async function dnsCheckSubdomain(subdomain, findings, ts) {
  try {
    const res  = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${subdomain}&type=A`,
      { headers: { Accept: 'application/dns-json' }, timeout: 4000 }
    );
    const data = await res.json();
    if ((data.Answer || []).length > 0) {
      const ips = data.Answer.map(a => a.data).join(', ');
      findings.push({
        category: 'infrastructure', source: 'DNS — Live Subdomain',
        title: `Live Subdomain — ${subdomain}`,
        value: ips,
        summary: `Subdomain ${subdomain} is LIVE and resolves to: ${ips}`,
        sourceUrl: `https://dnschecker.org/#A/${subdomain}`,
        timestamp: ts(), riskSignal: 'open_port',
      });
    }
  } catch { /* non-fatal */ }
}

// ── Shodan InternetDB ─────────────────────────────────────────────────────
async function shodanProbe(ip, domain, findings, ts) {
  try {
    const res  = await fetch(`https://internetdb.shodan.io/${ip}`, { timeout: 5000 });
    if (!res.ok) return;
    const data = await res.json();
    if (data.detail) return;

    findings.push({
      category: 'infrastructure', source: 'Shodan InternetDB',
      title: `Shodan — ${ip} (${domain})`,
      value: (data.ports || []).length > 0 ? `Open ports: ${data.ports.join(', ')}` : 'No open ports',
      summary: [
        `IP: ${ip}`,
        (data.ports||[]).length ? `Open ports: ${data.ports.join(', ')}` : 'No open ports detected',
        (data.vulns||[]).length ? `⚠ CVEs: ${data.vulns.join(', ')}`    : 'No known CVEs',
        (data.cpes||[]).length  ? `Tech: ${data.cpes.slice(0,3).join(', ')}` : '',
        (data.tags||[]).length  ? `Tags: ${data.tags.join(', ')}`        : '',
        (data.hostnames||[]).length ? `Hostnames: ${data.hostnames.join(', ')}` : '',
      ].filter(Boolean).join(' | '),
      sourceUrl: `https://www.shodan.io/host/${ip}`,
      timestamp: ts(),
      riskSignal: (data.vulns||[]).length ? 'breach_exposure' : (data.ports||[]).length ? 'open_port' : null,
      extra: { ip, ports: data.ports, vulns: data.vulns, cpes: data.cpes, tags: data.tags, hostnames: data.hostnames },
    });
  } catch { /* non-fatal */ }
}

// ── IP Geolocation ────────────────────────────────────────────────────────
async function ipGeoLookup(ip, domain, findings, ts) {
  try {
    const res  = await fetch(`https://ipapi.co/${ip}/json/`, {
      headers: { 'User-Agent': 'OSINTTool/2.0' },
      timeout: 5000,
    });
    if (!res.ok) return;
    const data = await res.json();
    if (data.error) return;

    findings.push({
      category: 'infrastructure', source: 'IP Geolocation',
      title: `IP Geo — ${ip} (${domain})`,
      value: `${data.city || ''}, ${data.country_name || ''}`,
      summary: [
        `IP: ${ip}`,
        `Location: ${data.city || 'Unknown'}, ${data.region || ''}, ${data.country_name || 'Unknown'}`,
        `ISP/ASN: ${data.org || 'Unknown'}`,
        `Timezone: ${data.timezone || 'Unknown'}`,
        `Hosting: ${data.asn || 'Unknown'}`,
      ].filter(s => s && !s.endsWith(': Unknown') && !s.endsWith(', ')).join(' | '),
      sourceUrl: `https://ipapi.co/${ip}`,
      timestamp: ts(), riskSignal: null,
      extra: { ip, city: data.city, country: data.country_name, isp: data.org, asn: data.asn },
    });
  } catch { /* non-fatal */ }
}
