// netlify/functions/regulatory.js — v2
// OpenCorporates real search, GLEIF legal entity lookup,
// OFAC SDN API real check, NewsAPI, OpenSanctions

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
    openCorporates(target, type, findings, ts),
    gleifLookup(target, type, findings, ts),
    openSanctions(target, findings, ts),
    newsSearch(target, findings, ts),
    webArchiveLookup(target, findings, ts),
  ]);

  return { statusCode: 200, headers: CORS, body: JSON.stringify({ findings }) };
};

// ── OpenCorporates ─────────────────────────────────────────────────────────
async function openCorporates(target, type, findings, ts) {
  const keyParam = process.env.OPENCORP_API_KEY ? `&api_token=${process.env.OPENCORP_API_KEY}` : '';

  const endpoint = type === 'individual'
    ? `https://api.opencorporates.com/v0.4/officers/search?q=${encodeURIComponent(target)}${keyParam}&per_page=5`
    : `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(target)}${keyParam}&per_page=5`;

  try {
    const res  = await fetch(endpoint, { timeout: 8000 });
    const data = await res.json();

    if (type === 'individual') {
      const officers = data?.results?.officers || [];
      for (const item of officers.slice(0, 5)) {
        const o = item.officer;
        findings.push({
          category: 'regulatory', source: 'OpenCorporates',
          title: `Officer Record — ${o.name}`,
          value: o.opencorporates_url || '',
          summary: [
            `Name: ${o.name}`,
            `Role: ${o.position || 'Unknown'}`,
            `Company: ${o.company?.name || 'Unknown'}`,
            `Jurisdiction: ${o.company?.jurisdiction_code || 'Unknown'}`,
            o.start_date ? `From: ${o.start_date}` : '',
            o.end_date   ? `To: ${o.end_date}` : 'Current',
            o.inactive   ? '⚠ INACTIVE' : '',
          ].filter(Boolean).join(' | '),
          sourceUrl: o.opencorporates_url || endpoint,
          timestamp: ts(), riskSignal: null,
          mismatch: !o.name.toLowerCase().includes(target.toLowerCase().split(' ')[0].toLowerCase()),
          extra: { name: o.name, position: o.position, company: o.company?.name, jurisdiction: o.company?.jurisdiction_code },
        });
      }
      if (officers.length === 0) {
        findings.push({
          category: 'regulatory', source: 'OpenCorporates',
          title: `No Officer Record — ${target}`,
          value: 'Not found',
          summary: `No officer record in OpenCorporates for "${target}". They may operate under a different name or jurisdiction.`,
          sourceUrl: endpoint, timestamp: ts(), riskSignal: null,
        });
      }
    } else {
      const companies = data?.results?.companies || [];
      for (const item of companies.slice(0, 5)) {
        const c = item.company;
        findings.push({
          category: 'regulatory', source: 'OpenCorporates',
          title: `Company — ${c.name}`,
          value: c.opencorporates_url || '',
          summary: [
            `Name: ${c.name}`,
            `Jurisdiction: ${c.jurisdiction_code}`,
            `Status: ${c.current_status || 'Unknown'}`,
            `Incorporated: ${c.incorporation_date || 'Unknown'}`,
            `Company No: ${c.company_number || 'Unknown'}`,
            c.dissolution_date ? `⚠ Dissolved: ${c.dissolution_date}` : '',
            `Type: ${c.company_type || 'Unknown'}`,
          ].filter(Boolean).join(' | '),
          sourceUrl: c.opencorporates_url || endpoint,
          timestamp: ts(), riskSignal: c.dissolution_date ? 'derogatory_press' : null,
          mismatch: !c.name.toLowerCase().includes(target.toLowerCase().split(' ')[0].toLowerCase()),
          extra: {
            name: c.name, jurisdiction: c.jurisdiction_code,
            status: c.current_status, incorporated: c.incorporation_date,
            number: c.company_number, dissolved: c.dissolution_date,
          },
        });
      }
      if (companies.length === 0) {
        findings.push({
          category: 'regulatory', source: 'OpenCorporates',
          title: `No Company Record — ${target}`,
          value: 'Not found',
          summary: `No company in OpenCorporates for "${target}". May be a free zone entity (DIFC, ADGM) or private entity not indexed.`,
          sourceUrl: endpoint, timestamp: ts(), riskSignal: null,
        });
      }
    }
  } catch (err) {
    findings.push({
      category: 'regulatory', source: 'OpenCorporates',
      title: `OpenCorporates — ${target}`,
      value: 'Error', summary: `Lookup failed: ${err.message}`,
      sourceUrl: endpoint, timestamp: ts(), riskSignal: null,
    });
  }
}

// ── GLEIF — Legal Entity Identifier database ──────────────────────────────
// Free, no key — identifies registered legal entities worldwide
async function gleifLookup(target, type, findings, ts) {
  if (type !== 'company') return;
  try {
    const url = `https://api.gleif.org/api/v1/fuzzycompletions?field=entity.legalName&q=${encodeURIComponent(target)}`;
    const res  = await fetch(url, { headers: { 'User-Agent': 'OSINTTool/2.0' }, timeout: 7000 });
    if (!res.ok) return;
    const data = await res.json();

    const items = data.data || [];
    for (const item of items.slice(0, 3)) {
      // Fetch full LEI record
      try {
        const leiRes  = await fetch(`https://api.gleif.org/api/v1/lei-records/${item.lei}`, { timeout: 5000 });
        const leiData = await leiRes.json();
        const entity  = leiData.data?.attributes?.entity;

        if (entity) {
          findings.push({
            category: 'regulatory', source: 'GLEIF (LEI Register)',
            title: `Legal Entity — ${entity.legalName?.name || item.suggestion}`,
            value: item.lei,
            summary: [
              `Legal Name: ${entity.legalName?.name || 'Unknown'}`,
              `LEI: ${item.lei}`,
              `Status: ${entity.status || 'Unknown'}`,
              `Jurisdiction: ${entity.jurisdiction || 'Unknown'}`,
              `Category: ${entity.category || 'Unknown'}`,
              entity.legalAddress ? `Address: ${[entity.legalAddress.addressLines?.join(', '), entity.legalAddress.city, entity.legalAddress.country].filter(Boolean).join(', ')}` : '',
              entity.registeredAs ? `Reg No: ${entity.registeredAs}` : '',
            ].filter(Boolean).join(' | '),
            sourceUrl: `https://www.gleif.org/en/lei/${item.lei}`,
            timestamp: ts(), riskSignal: entity.status !== 'ACTIVE' ? 'derogatory_press' : null,
            extra: { lei: item.lei, status: entity.status, jurisdiction: entity.jurisdiction, address: entity.legalAddress },
          });
        }
      } catch { /* skip individual LEI fetch */ }
    }
  } catch { /* non-fatal */ }
}

// ── OpenSanctions — free sanctions + PEP database ─────────────────────────
async function openSanctions(target, findings, ts) {
  try {
    const url = `https://api.opensanctions.org/search/default?q=${encodeURIComponent(target)}&limit=5`;
    const res  = await fetch(url, {
      headers: { 'User-Agent': 'OSINTTool/2.0', 'Authorization': `ApiKey ${process.env.OPENSANCTIONS_KEY || 'default'}` },
      timeout: 7000,
    });

    if (res.ok) {
      const data    = await res.json();
      const results = data.results || [];

      if (results.length > 0) {
        for (const r of results.slice(0, 3)) {
          const datasets = (r.datasets || []).join(', ');
          const isSanction = r.datasets?.some(d => d.includes('sanction') || d.includes('ofac') || d.includes('un_') || d.includes('eu_'));
          findings.push({
            category: 'regulatory', source: 'OpenSanctions',
            title: `${isSanction ? '⚠ SANCTIONS HIT' : 'Watchlist Entry'} — ${r.caption || target}`,
            value: datasets,
            summary: [
              `Match: ${r.caption}`,
              `Score: ${r.score || 'N/A'}`,
              `Datasets: ${datasets}`,
              `Schema: ${r.schema || 'Unknown'}`,
              r.properties?.nationality ? `Nationality: ${r.properties.nationality.join(', ')}` : '',
            ].filter(Boolean).join(' | '),
            sourceUrl: `https://www.opensanctions.org/entities/${r.id}/`,
            timestamp: ts(), riskSignal: isSanction ? 'sanctions' : 'derogatory_press',
            extra: { id: r.id, datasets, schema: r.schema, score: r.score },
          });
        }
      } else {
        findings.push({
          category: 'regulatory', source: 'OpenSanctions',
          title: `Sanctions Check — ${target}`,
          value: 'CLEAN',
          summary: `"${target}" returned no results in OpenSanctions database (covers OFAC, UN, EU, and 100+ other lists).`,
          sourceUrl: `https://www.opensanctions.org/search/?q=${encodeURIComponent(target)}`,
          timestamp: ts(), riskSignal: null,
        });
      }
    }
  } catch { /* non-fatal */ }
}

// ── NewsAPI ────────────────────────────────────────────────────────────────
async function newsSearch(target, findings, ts) {
  const newsApiKey = process.env.NEWS_API_KEY || '';
  if (!newsApiKey) {
    findings.push({
      category: 'regulatory', source: 'News Search',
      title: `News — ${target}`,
      value: `https://news.google.com/search?q=${encodeURIComponent(target)}`,
      summary: `Add NEWS_API_KEY env var for automated news. Manual search: https://news.google.com/search?q=${encodeURIComponent(target)}`,
      sourceUrl: `https://news.google.com/search?q=${encodeURIComponent(target)}`,
      timestamp: ts(), riskSignal: null,
    });
    return;
  }

  try {
    const res  = await fetch(
      `https://newsapi.org/v2/everything?q=${encodeURIComponent('"' + target + '"')}&sortBy=relevancy&pageSize=5&language=en&apiKey=${newsApiKey}`,
      { timeout: 7000 }
    );
    const data = await res.json();
    const neg  = ['fraud','scam','arrest','convict','lawsuit','scandal','breach','hack','fine','penalty','ban','illegal','investigation','laundering'];

    for (const article of (data.articles || [])) {
      const text    = (article.title + ' ' + (article.description||'')).toLowerCase();
      const isRisk  = neg.some(k => text.includes(k));
      findings.push({
        category: 'regulatory', source: `News — ${article.source?.name || 'Unknown'}`,
        title: article.title,
        value: article.url,
        summary: `${article.description || ''} | Published: ${article.publishedAt?.slice(0,10)}`,
        sourceUrl: article.url,
        timestamp: ts(), riskSignal: isRisk ? 'derogatory_press' : null,
        extra: { publishedAt: article.publishedAt, source: article.source?.name },
      });
    }
  } catch { /* non-fatal */ }
}

// ── Wayback Machine — historical web presence ──────────────────────────────
async function webArchiveLookup(target, findings, ts) {
  const slug = target.toLowerCase().replace(/\s+/g,'').replace(/[^a-z0-9]/g,'');
  const domains = [`${slug}.com`, `${slug}.ae`, `${slug}.io`];

  for (const domain of domains.slice(0, 2)) {
    try {
      const url = `https://archive.org/wayback/available?url=${domain}`;
      const res  = await fetch(url, { timeout: 6000 });
      const data = await res.json();

      if (data.archived_snapshots?.closest?.available) {
        const snap = data.archived_snapshots.closest;
        findings.push({
          category: 'regulatory', source: 'Wayback Machine',
          title: `Web Archive — ${domain}`,
          value: snap.url,
          summary: `Historical snapshot available for ${domain}. First captured around ${snap.timestamp?.slice(0,4) || 'Unknown'}. Status: ${snap.status}.`,
          sourceUrl: snap.url,
          timestamp: ts(), riskSignal: null,
          extra: { domain, snapshotUrl: snap.url, timestamp: snap.timestamp, status: snap.status },
        });
      }
    } catch { /* non-fatal */ }
  }
}
