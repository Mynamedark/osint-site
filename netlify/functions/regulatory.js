// netlify/functions/regulatory.js
// OpenCorporates public API + OFAC SDN check

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
  const apiKey = process.env.OPENCORP_API_KEY || '';

  await Promise.all([
    openCorporates(target, type, apiKey, findings, timestamp),
    ofacCheck(target, findings, timestamp),
    newsSearch(target, findings, timestamp),
  ]);

  return { statusCode: 200, headers, body: JSON.stringify({ findings }) };
};

async function openCorporates(target, type, apiKey, findings, timestamp) {
  const keyParam = apiKey ? `&api_token=${apiKey}` : '';
  const endpoint = type === 'individual'
    ? `https://api.opencorporates.com/v0.4/officers/search?q=${encodeURIComponent(target)}${keyParam}`
    : `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(target)}${keyParam}`;

  try {
    const res  = await fetch(endpoint, { timeout: 7000 });
    const data = await res.json();

    if (type === 'individual') {
      const officers = data?.results?.officers || [];
      if (officers.length > 0) {
        for (const item of officers.slice(0, 4)) {
          const o = item.officer;
          findings.push({
            category: 'regulatory', source: 'OpenCorporates', title: `Officer Record — ${o.name}`,
            value: o.name,
            summary: `Role: ${o.position || 'Unknown'} | Company: ${o.company?.name || 'Unknown'} | Jurisdiction: ${o.company?.jurisdiction_code || 'Unknown'}`,
            sourceUrl: o.opencorporates_url || endpoint,
            timestamp, riskSignal: null,
            mismatch: !o.name.toLowerCase().includes(target.toLowerCase().split(' ')[0]),
          });
        }
      } else {
        findings.push({
          category: 'regulatory', source: 'OpenCorporates', title: `No Officer Record — ${target}`,
          value: 'Not found', summary: `No officer record in OpenCorporates for "${target}"`,
          sourceUrl: endpoint, timestamp, riskSignal: null,
        });
      }
    } else {
      const companies = data?.results?.companies || [];
      if (companies.length > 0) {
        for (const item of companies.slice(0, 4)) {
          const c = item.company;
          findings.push({
            category: 'regulatory', source: 'OpenCorporates', title: `Company Record — ${c.name}`,
            value: c.name,
            summary: `Jurisdiction: ${c.jurisdiction_code} | Status: ${c.current_status || 'Unknown'} | Incorporated: ${c.incorporation_date || 'Unknown'} | Reg No: ${c.company_number || 'Unknown'}`,
            sourceUrl: c.opencorporates_url || endpoint,
            timestamp, riskSignal: null,
            mismatch: !c.name.toLowerCase().includes(target.toLowerCase().split(' ')[0]),
          });
        }
      } else {
        findings.push({
          category: 'regulatory', source: 'OpenCorporates', title: `No Company Record — ${target}`,
          value: 'Not found', summary: `No company record in OpenCorporates for "${target}"`,
          sourceUrl: endpoint, timestamp, riskSignal: null,
        });
      }
    }
  } catch (err) {
    findings.push({
      category: 'regulatory', source: 'OpenCorporates', title: `OpenCorporates — ${target}`,
      value: 'Error', summary: `Lookup failed: ${err.message}`,
      sourceUrl: endpoint, timestamp, riskSignal: null,
    });
  }
}

async function ofacCheck(target, findings, timestamp) {
  findings.push({
    category: 'regulatory', source: 'OFAC SDN', title: `OFAC Sanctions Check — ${target}`,
    value: `https://sanctionssearch.ofac.treas.gov/`,
    summary: `Manual OFAC SDN check required. Search for "${target}" at the link below.`,
    sourceUrl: `https://sanctionssearch.ofac.treas.gov/`,
    timestamp, riskSignal: null,
    extra: { manualUrl: `https://sanctionssearch.ofac.treas.gov/` },
  });
}

async function newsSearch(target, findings, timestamp) {
  const newsApiKey = process.env.NEWS_API_KEY || '';
  if (!newsApiKey) {
    findings.push({
      category: 'regulatory', source: 'News Search', title: `News — ${target}`,
      value: `https://news.google.com/search?q=${encodeURIComponent(target)}`,
      summary: `Set NEWS_API_KEY env var for automated news monitoring. Manual search URL provided.`,
      sourceUrl: `https://news.google.com/search?q=${encodeURIComponent(target)}`,
      timestamp, riskSignal: null,
    });
    return;
  }

  try {
    const res  = await fetch(`https://newsapi.org/v2/everything?q=${encodeURIComponent(target)}&sortBy=relevancy&pageSize=5&apiKey=${newsApiKey}`, { timeout: 7000 });
    const data = await res.json();
    const derogatory = ['fraud','scam','arrested','convicted','lawsuit','scandal','breach','hack','fine','penalty','banned'];

    for (const article of (data.articles || [])) {
      const text  = (article.title + ' ' + article.description).toLowerCase();
      const isRisk = derogatory.some(k => text.includes(k));
      findings.push({
        category: 'regulatory', source: `News — ${article.source?.name}`, title: article.title,
        value: article.url,
        summary: `${article.description || ''} | Published: ${article.publishedAt}`,
        sourceUrl: article.url,
        timestamp, riskSignal: isRisk ? 'derogatory_press' : null,
      });
    }
  } catch (err) {
    findings.push({
      category: 'regulatory', source: 'NewsAPI', title: `News — ${target}`,
      value: 'Error', summary: `NewsAPI failed: ${err.message}`,
      sourceUrl: 'https://newsapi.org', timestamp, riskSignal: null,
    });
  }
}
