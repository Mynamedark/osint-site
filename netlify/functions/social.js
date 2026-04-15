// netlify/functions/social.js
// Collects: DuckDuckGo results, LinkedIn URL, GitHub probe, Google dorks
// Must complete under 10s — lightweight probes only

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

  const { target, type } = JSON.parse(event.body || '{}');
  if (!target) return { statusCode: 400, headers, body: JSON.stringify({ error: 'target required' }) };

  const findings = [];
  const timestamp = new Date().toISOString();
  const slug = target.toLowerCase().replace(/\s+/g, '');
  const slugDash = target.toLowerCase().replace(/\s+/g, '-');

  // ── LinkedIn URLs ─────────────────────────────────────────────────────
  if (type === 'individual') {
    findings.push({
      category: 'social', source: 'LinkedIn', title: `LinkedIn Profile — ${target}`,
      value: `https://www.linkedin.com/in/${slug}`,
      summary: `Constructed LinkedIn personal profile URL for ${target}`,
      sourceUrl: `https://www.linkedin.com/in/${slug}`,
      timestamp, riskSignal: null,
    });
    findings.push({
      category: 'social', source: 'LinkedIn', title: `LinkedIn Profile (hyphen) — ${target}`,
      value: `https://www.linkedin.com/in/${slugDash}`,
      summary: `Alternate LinkedIn URL variant`,
      sourceUrl: `https://www.linkedin.com/in/${slugDash}`,
      timestamp, riskSignal: null,
    });
  } else {
    findings.push({
      category: 'social', source: 'LinkedIn', title: `LinkedIn Company — ${target}`,
      value: `https://www.linkedin.com/company/${slug}`,
      summary: `Constructed LinkedIn company page URL for ${target}`,
      sourceUrl: `https://www.linkedin.com/company/${slug}`,
      timestamp, riskSignal: null,
    });
  }

  // ── GitHub probe (public API, fast) ──────────────────────────────────
  try {
    const endpoint = type === 'individual'
      ? `https://api.github.com/users/${slug}`
      : `https://api.github.com/orgs/${slug}`;

    const res = await fetch(endpoint, {
      headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'OSINTTool/1.0' },
      timeout: 5000,
    });

    if (res.ok) {
      const data = await res.json();
      findings.push({
        category: 'social', source: 'GitHub', title: `GitHub — ${data.login}`,
        value: data.html_url,
        summary: `GitHub ${type === 'individual' ? 'user' : 'org'} found: ${data.name || data.login}. Public repos: ${data.public_repos || 0}. Followers: ${data.followers || 0}.`,
        sourceUrl: data.html_url,
        timestamp, riskSignal: null,
        extra: { publicRepos: data.public_repos, followers: data.followers, created: data.created_at, bio: data.bio },
      });
    } else {
      findings.push({
        category: 'social', source: 'GitHub', title: `GitHub — ${target}`,
        value: `https://github.com/${slug}`,
        summary: `No GitHub ${type === 'individual' ? 'user' : 'organisation'} found for "${slug}".`,
        sourceUrl: `https://github.com/${slug}`,
        timestamp, riskSignal: 'no_code_repo',
      });
    }
  } catch {
    findings.push({
      category: 'social', source: 'GitHub', title: `GitHub — ${target}`,
      value: 'Probe failed', summary: 'GitHub API probe timed out or failed.',
      sourceUrl: `https://github.com/${slug}`,
      timestamp, riskSignal: null,
    });
  }

  // ── Google Dorks (documented queries) ────────────────────────────────
  const dorks = [
    { dork: `site:linkedin.com "${target}"`,     purpose: 'LinkedIn mentions' },
    { dork: `"${target}" filetype:pdf`,           purpose: 'Public documents' },
    { dork: `"${target}" site:pastebin.com`,      purpose: 'Paste exposure' },
    { dork: `"${target}" "email" OR "contact"`,   purpose: 'Contact info' },
    { dork: `"${target}" site:twitter.com`,       purpose: 'Twitter/X presence' },
  ];

  for (const d of dorks) {
    findings.push({
      category: 'social', source: 'Google Dork', title: `Dork — ${d.purpose}`,
      value: `https://www.google.com/search?q=${encodeURIComponent(d.dork)}`,
      summary: `Query: ${d.dork}`,
      sourceUrl: `https://www.google.com/search?q=${encodeURIComponent(d.dork)}`,
      timestamp, riskSignal: null,
      extra: { dorkQuery: d.dork, manualExecution: true },
    });
  }

  return { statusCode: 200, headers, body: JSON.stringify({ findings }) };
};
