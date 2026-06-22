// Small id → {name, color} lookup used by batch.html / compare.html.
// Intentionally kept separate from popup.js's PROVIDER_UI (which also carries
// the full signal-group config) so these lighter pages don't have to load or
// guard against popup.js's popup-specific DOM lookups.
const PROVIDER_META = {
  cloudflare: { name: 'Cloudflare', color: '#f38020' },
  google:     { name: 'Google', color: '#4285f4' },
  akamai:     { name: 'Akamai', color: '#009bde' },
  fastly:     { name: 'Fastly', color: '#ff282d' },
  imperva:    { name: 'Imperva', color: '#e84d1c' },
  cloudfront: { name: 'CloudFront', color: '#ff9900' },
  azure:      { name: 'Azure', color: '#0078d4' },
  sucuri:     { name: 'Sucuri', color: '#e77b30' },
  vercel:     { name: 'Vercel', color: '#e2e8f0' },
  netlify:    { name: 'Netlify', color: '#00c7b7' },
  bunnycdn:   { name: 'BunnyCDN', color: '#f5a623' },
  stackpath:  { name: 'StackPath', color: '#2196f3' },
  keycdn:     { name: 'KeyCDN', color: '#2a99ff' },
  gcore:      { name: 'Gcore', color: '#f04e23' },
  datadome:   { name: 'DataDome', color: '#7c3aed' },
  perimeterx: { name: 'PerimeterX', color: '#ff5a5f' },
  f5xc:       { name: 'F5 Distributed Cloud', color: '#e4002b' },
  tencenteo:  { name: 'Tencent EdgeOne', color: '#00a4ff' },
  alicdn:     { name: 'Alibaba Cloud CDN', color: '#ff6a00' },
  arvancloud: { name: 'ArvanCloud', color: '#ff5252' },
  vncdn:      { name: 'VNCDN (VNETWORK)', color: '#0072ce' },
  flyio:      { name: 'Fly.io',           color: '#8b5cf6' },
  render:     { name: 'Render',           color: '#46e3b7' },
  railway:    { name: 'Railway',          color: '#9f5fff' },
};
