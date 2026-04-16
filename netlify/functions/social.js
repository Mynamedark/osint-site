// netlify/functions/social.js — v2
// REAL intelligence: DuckDuckGo instant answers + HTML scrape,
// GitHub search API (not slug guessing), Wikidata entity lookup,
// Wikipedia summary, Hunter.io email pattern, Twitter/X + Instagram probe

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

  const { target, type } = JSON.parse(event.body || '{}');
  if (!target) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'target required' }) };

  const findings = [];
  const ts = () => new Date().toISOString();

  await Promise.allSettled([
    duckDuckGoInstant(target, findings, ts),
    duckDuckGoSearch(target, findings, ts),
    githubSearch(target, type, findings, ts),
    wikidataLookup(target, findings, ts),
    wikipediaLookup(target, findings, ts),
    hunterIoDomain(target, type, findings, ts),
    twitterProbe(target, findings, ts),
    instagramProbe(target, findings, ts),
  ]);

  return { statusCode: 200, headers: CORS, body: JSON.stringify({ findings }) };
};

// ── DuckDuckGo Instant Answers API ────────────────────────────────────────
async function duckDuckGoInstant(target, findings, ts) {
  const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(target)}&format=json&no_redirect=1&no_html=1&skip_disambig=1`;
  const res  = await fetch(url, { headers: { 'User-Agent': 'OSINTTool/2.0' }, timeout: 7000 });
  const data = await res.json();

  if (data.Abstract) {
    findings.push({
      category: 'social', source: 'DuckDuckGo Instant Answer',
      title: `Entity Summary — ${data.Heading || target}`,
      value: data.AbstractURL || url,
      summary: data.Abstract,
      sourceUrl: data.AbstractURL || `https://duckduckgo.com/?q=${encodeURIComponent(target)}`,
      timestamp: ts(), riskSignal: null,
      extra: { heading: data.Heading, source: data.AbstractSource, type: data.Type },
    });
  }

  if (data.Infobox?.content?.length > 0) {
    const facts = data.Infobox.content
      .filter(i => i.label && i.value)
      .slice(0, 10)
      .map(i => `${i.label}: ${i.value}`)
      .join(' | ');
    if (facts) {
      findings.push({
        category: 'social', source: 'DuckDuckGo Infobox',
        title: `Entity Facts — ${target}`,
        value: facts,
        summary: `Knowledge graph facts: ${facts}`,
        sourceUrl: `https://duckduckgo.com/?q=${encodeURIComponent(target)}`,
        timestamp: ts(), riskSignal: null,
      });
    }
  }

  for (const t of (data.RelatedTopics || []).filter(t => t.Text && t.FirstURL).slice(0, 4)) {
    findings.push({
      category: 'social', source: 'DuckDuckGo Related',
      title: `Related — ${t.Text.slice(0, 60)}`,
      value: t.FirstURL,
      summary: t.Text,
      sourceUrl: t.FirstURL,
      timestamp: ts(), riskSignal: null,
    });
  }
}

// ── DuckDuckGo HTML search ─────────────────────────────────────────────────
async function duckDuckGoSearch(target, findings, ts) {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent('"' + target + '"')}`;
  const res  = await fetch(url, {
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; OSINTBot/2.0)' },
    timeout: 7000,
  });
  const html = await res.text();

  const results = [];
  const linkRe  = /class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</g;
  const snippRe = /class="result__snippet"[^>]*>([^<]+)</g;
  let lm;

  while ((lm = linkRe.exec(html)) && results.length < 6) {
    const m = lm[1].match(/uddg=([^&]+)/);
    results.push({ url: m ? decodeURIComponent(m[1]) : lm[1], title: lm[2].trim() });
  }

  let sm, idx = 0;
  while ((sm = snippRe.exec(html)) && idx < results.length) {
    results[idx++].snippet = sm[1].trim();
  }

  for (const r of results.filter(r => r.url && r.title)) {
    findings.push({
      category: 'social', source: 'Web Search Result',
      title: r.title,
      value: r.url,
      summary: r.snippet || r.title,
      sourceUrl: r.url,
      timestamp: ts(), riskSignal: null,
    });
  }
}

// ── GitHub — real search, not slug guessing ────────────────────────────────
async function githubSearch(target, type, findings, ts) {
  const ghH = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'OSINTTool/2.0' };

  // Search users/orgs
  try {
    const res  = await fetch(`https://api.github.com/search/users?q=${encodeURIComponent(target)}&per_page=3`, { headers: ghH, timeout: 6000 });
    const data = await res.json();

    for (const user of (data.items || []).slice(0, 3)) {
      try {
        const profileRes = await fetch(user.url, { headers: ghH, timeout: 5000 });
        const p          = await profileRes.json();
        findings.push({
          category: 'social', source: 'GitHub',
          title: `GitHub ${p.type} — ${p.login}`,
          value: p.html_url,
          summary: [
            p.name       ? `Name: ${p.name}`           : '',
            p.company    ? `Company: ${p.company}`      : '',
            p.location   ? `Location: ${p.location}`    : '',
            p.email      ? `Email: ${p.email}`          : '',
            p.bio        ? `Bio: ${p.bio}`              : '',
            `Repos: ${p.public_repos || 0} | Followers: ${p.followers || 0}`,
            p.blog       ? `Website: ${p.blog}`         : '',
            p.created_at ? `Joined: ${p.created_at.slice(0,10)}` : '',
          ].filter(Boolean).join(' | '),
          sourceUrl: p.html_url,
          timestamp: ts(), riskSignal: null,
          extra: { login: p.login, name: p.name, email: p.email, company: p.company, location: p.location, repos: p.public_repos },
        });
      } catch { /* skip profile fetch failure */ }
    }
  } catch { /* non-fatal */ }

  // Search repos
  try {
    const res  = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(target)}&sort=stars&per_page=3`, { headers: ghH, timeout: 6000 });
    const data = await res.json();

    for (const repo of (data.items || []).slice(0, 3)) {
      findings.push({
        category: 'social', source: 'GitHub Repos',
        title: `GitHub Repo — ${repo.full_name}`,
        value: repo.html_url,
        summary: [
          repo.description || 'No description',
          `Stars: ${repo.stargazers_count}`,
          `Language: ${repo.language || 'Unknown'}`,
          `Last push: ${repo.pushed_at?.slice(0,10) || 'Unknown'}`,
          `Owner: ${repo.owner?.login}`,
        ].join(' | '),
        sourceUrl: repo.html_url,
        timestamp: ts(), riskSignal: null,
      });
    }
  } catch { /* non-fatal */ }
}

// ── Wikidata entity lookup ─────────────────────────────────────────────────
async function wikidataLookup(target, findings, ts) {
  const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(target)}&language=en&format=json&limit=3&origin=*`;
  const res  = await fetch(url, { headers: { 'User-Agent': 'OSINTTool/2.0' }, timeout: 7000 });
  const data = await res.json();

  for (const entity of (data.search || []).slice(0, 2)) {
    findings.push({
      category: 'social', source: 'Wikidata',
      title: `Wikidata — ${entity.label}`,
      value: `https://www.wikidata.org/wiki/${entity.id}`,
      summary: entity.description ? `${entity.label}: ${entity.description}` : `Entity ID: ${entity.id}`,
      sourceUrl: `https://www.wikidata.org/wiki/${entity.id}`,
      timestamp: ts(), riskSignal: null,
      extra: { id: entity.id, description: entity.description },
    });
  }
}

// ── Wikipedia summary ──────────────────────────────────────────────────────
async function wikipediaLookup(target, findings, ts) {
  const url = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(target.replace(/\s+/g,'_'))}`;
  const res  = await fetch(url, { headers: { 'User-Agent': 'OSINTTool/2.0' }, timeout: 7000 });
  if (!res.ok) return;
  const data = await res.json();

  if (data.extract) {
    findings.push({
      category: 'social', source: 'Wikipedia',
      title: `Wikipedia — ${data.title}`,
      value: data.content_urls?.desktop?.page || url,
      summary: data.extract.slice(0, 600),
      sourceUrl: data.content_urls?.desktop?.page || url,
      timestamp: ts(), riskSignal: null,
      extra: { type: data.type, description: data.description },
    });
  }
}

// ── Hunter.io email discovery ──────────────────────────────────────────────
async function hunterIoDomain(target, type, findings, ts) {
  if (type !== 'company') return;
  const slug    = target.toLowerCase().replace(/[^a-z0-9]/g, '');
  const domains = [`${slug}.com`, `${slug}.ae`, `${slug}.io`];
  const apiKey  = process.env.HUNTER_API_KEY || '';

  for (const domain of domains.slice(0, 2)) {
    try {
      const url = apiKey
        ? `https://api.hunter.io/v2/domain-search?domain=${domain}&limit=5&api_key=${apiKey}`
        : `https://api.hunter.io/v2/domain-search?domain=${domain}&limit=5`;
      const res  = await fetch(url, { timeout: 6000 });
      if (!res.ok) continue;
      const data = await res.json();

      if (data.data?.emails?.length > 0) {
        findings.push({
          category: 'social', source: 'Hunter.io',
          title: `Email Discovery — ${domain}`,
          value: data.data.emails.map(e => e.value).join(', '),
          summary: `Pattern: ${data.data.pattern || '?'} | ${data.data.emails.length} email(s): ${data.data.emails.map(e => `${e.value} (${e.type})`).join(', ')}`,
          sourceUrl: `https://hunter.io/domain-search/${domain}`,
          timestamp: ts(), riskSignal: null,
          extra: { pattern: data.data.pattern, emails: data.data.emails },
        });
      }
    } catch { continue; }
  }
}

// ── Twitter/X probe ────────────────────────────────────────────────────────
async function twitterProbe(target, findings, ts) {
  const handles = [...new Set([
    target.toLowerCase().replace(/\s+/g,''),
    target.toLowerCase().replace(/\s+/g,'_'),
    target.toLowerCase().split(/\s+/).join(''),
  ])].slice(0, 2);

  for (const handle of handles) {
    try {
      const res    = await fetch(`https://x.com/${handle}`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible)' },
        timeout: 5000,
      });
      const exists = res.status === 200;
      findings.push({
        category: 'social', source: 'Twitter/X',
        title: `Twitter/X — @${handle}`,
        value: `https://x.com/${handle}`,
        summary: exists ? `@${handle} found on Twitter/X.` : `@${handle} not found on Twitter/X.`,
        sourceUrl: `https://x.com/${handle}`,
        timestamp: ts(), riskSignal: null,
        extra: { handle, exists },
      });
    } catch { /* non-fatal */ }
  }
}

// ── Instagram probe ────────────────────────────────────────────────────────
async function instagramProbe(target, findings, ts) {
  const handle = target.toLowerCase().replace(/\s+/g,'').replace(/[^a-z0-9._]/g,'');
  try {
    const res    = await fetch(`https://www.instagram.com/${handle}/`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible)' },
      timeout: 5000,
    });
    const exists = res.status === 200;
    const html   = exists ? await res.text() : '';
    const bioM   = html.match(/"biography":"([^"]+)"/);
    const folM   = html.match(/"edge_followed_by":\{"count":(\d+)\}/);

    findings.push({
      category: 'social', source: 'Instagram',
      title: `Instagram — @${handle}`,
      value: `https://www.instagram.com/${handle}/`,
      summary: exists
        ? ['Found on Instagram', bioM ? `Bio: ${bioM[1]}` : '', folM ? `Followers: ${folM[1]}` : ''].filter(Boolean).join(' | ')
        : `@${handle} not found on Instagram.`,
      sourceUrl: `https://www.instagram.com/${handle}/`,
      timestamp: ts(), riskSignal: null,
      extra: { handle, exists },
    });
  } catch { /* non-fatal */ }
}
