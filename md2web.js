#!/usr/bin/env node
/**
 * md2web.js — Generate a searchable, navigable single-page WEB edition of the
 * PQC Developer's Handbook from the master Markdown.
 *
 * Zero new dependencies: reuses the already-installed `marked` (same engine the
 * PDF pipeline uses), so a fresh checkout that can build the PDFs can build the
 * web edition too. Output is one self-contained HTML file with:
 *   - a sticky sidebar Table of Contents generated from the H2/H3 headings,
 *   - a client-side instant filter box over the TOC,
 *   - anchored headings (slugs match md2pdf.js so in-doc links resolve),
 *   - responsive, readable typography and syntax-friendly code blocks.
 *
 * Usage:  node md2web.js <input.md> <output.html>
 * Default: node md2web.js pqc-developers-handbook.md pqc-developers-handbook-web.html
 */
'use strict';

const fs = require('fs');
const { marked } = require('marked');

const inputFile = process.argv[2] || 'pqc-developers-handbook.md';
const outputFile = process.argv[3] || 'pqc-developers-handbook-web.html';

// --- Heading slugify: MUST match md2pdf.js so cross-references resolve. ------
function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Collect TOC entries (H2 + H3) while rendering, skipping fenced code regions.
const toc = [];
const renderer = new marked.Renderer();
renderer.heading = function ({ text, depth, raw }) {
  const plain = raw.replace(/<[^>]*>/g, '');
  const slug = slugify(plain);
  if (depth === 2 || depth === 3) {
    toc.push({ depth, text: plain, slug });
  }
  return `<h${depth} id="${slug}"><a class="anchor" href="#${slug}">#</a>${text}</h${depth}>\n`;
};

marked.setOptions({ gfm: true, breaks: false, pedantic: false, renderer });

const markdown = fs.readFileSync(inputFile, 'utf-8');
const bodyHtml = marked.parse(markdown);

// Build the sidebar TOC markup.
const tocHtml = toc
  .map((e) => {
    const cls = e.depth === 2 ? 'toc-h2' : 'toc-h3';
    const safe = e.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return `<a class="${cls}" href="#${e.slug}" data-text="${safe.toLowerCase()}">${safe}</a>`;
  })
  .join('\n');

const css = `
:root { --fg:#1a1a1a; --bg:#fff; --muted:#666; --accent:#0b5fff; --line:#e3e3e3;
        --code-bg:#f6f8fa; --sidebar:#fafafa; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e6e6e6; --bg:#16181d; --muted:#9aa0a6; --accent:#6ea8ff;
          --line:#2c2f36; --code-bg:#1e2127; --sidebar:#1a1c21; }
}
* { box-sizing: border-box; }
body { margin:0; color:var(--fg); background:var(--bg);
  font: 16px/1.65 "Charter","Georgia",serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.layout { display:flex; align-items:flex-start; }
nav.sidebar { position:sticky; top:0; height:100vh; width:340px; flex:0 0 340px;
  overflow-y:auto; background:var(--sidebar); border-right:1px solid var(--line);
  padding:1rem 0.75rem; font:13px/1.4 -apple-system,system-ui,sans-serif; }
nav.sidebar h1 { font-size:15px; margin:.25rem .5rem 1rem; }
#filter { width:100%; padding:.5rem .6rem; margin-bottom:.75rem; border:1px solid var(--line);
  border-radius:6px; background:var(--bg); color:var(--fg); font-size:13px; }
nav.sidebar a { display:block; padding:3px 8px; border-radius:4px; color:var(--fg); }
nav.sidebar a:hover { background:rgba(127,127,127,.12); text-decoration:none; }
nav.sidebar a.toc-h2 { font-weight:600; margin-top:6px; }
nav.sidebar a.toc-h3 { padding-left:22px; color:var(--muted); font-weight:400; }
nav.sidebar a.hidden { display:none; }
main { flex:1 1 auto; max-width:860px; margin:0 auto; padding:2rem 2.5rem 6rem; min-width:0; }
main h1 { font-size:2em; }
main h2 { font-size:1.6em; margin-top:2.2em; padding-bottom:.2em; border-bottom:1px solid var(--line); }
main h3 { font-size:1.25em; margin-top:1.8em; }
h2 .anchor, h3 .anchor { opacity:0; margin-left:-1.1em; padding-right:.3em; color:var(--muted); font-weight:400; }
h2:hover .anchor, h3:hover .anchor { opacity:1; }
code { font-family:"SF Mono",Menlo,Consolas,monospace; font-size:.88em;
  background:var(--code-bg); padding:.12em .35em; border-radius:4px; }
pre { background:var(--code-bg); padding:1rem 1.1rem; border-radius:8px; overflow:auto;
  border:1px solid var(--line); line-height:1.5; }
pre code { background:none; padding:0; }
table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.92em; display:block; overflow-x:auto; }
th,td { border:1px solid var(--line); padding:.45rem .7rem; text-align:left; }
th { background:var(--code-bg); }
blockquote { margin:1rem 0; padding:.4rem 1rem; border-left:4px solid var(--accent);
  background:rgba(127,127,127,.06); color:var(--fg); }
img { max-width:100%; }
hr { border:none; border-top:1px solid var(--line); margin:2rem 0; }
.topbar { display:none; }
@media (max-width: 800px) {
  nav.sidebar { position:fixed; z-index:20; transform:translateX(-100%); transition:transform .2s; box-shadow:0 0 40px rgba(0,0,0,.3); }
  nav.sidebar.open { transform:translateX(0); }
  .topbar { display:flex; position:sticky; top:0; z-index:10; background:var(--bg);
    border-bottom:1px solid var(--line); padding:.6rem 1rem; align-items:center; gap:.6rem; }
  #menu-btn { font-size:18px; background:none; border:1px solid var(--line); border-radius:6px;
    padding:.2rem .6rem; color:var(--fg); cursor:pointer; }
  main { padding:1.2rem 1.1rem 5rem; }
}
`;

const js = `
(function(){
  var filter = document.getElementById('filter');
  var links = Array.prototype.slice.call(document.querySelectorAll('nav.sidebar a.toc-h2, nav.sidebar a.toc-h3'));
  if (filter) {
    filter.addEventListener('input', function(){
      var q = filter.value.trim().toLowerCase();
      links.forEach(function(a){
        var hit = !q || (a.getAttribute('data-text') || '').indexOf(q) !== -1;
        a.classList.toggle('hidden', !hit);
      });
    });
  }
  var btn = document.getElementById('menu-btn');
  var sb = document.querySelector('nav.sidebar');
  if (btn && sb) btn.addEventListener('click', function(){ sb.classList.toggle('open'); });
  // close sidebar after navigating on mobile
  links.forEach(function(a){ a.addEventListener('click', function(){ if (sb) sb.classList.remove('open'); }); });
})();
`;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Post-Quantum Cryptography Developer's Handbook</title>
<style>${css}</style>
</head>
<body>
<div class="topbar"><button id="menu-btn" aria-label="Toggle contents">☰</button><strong>PQC Developer's Handbook</strong></div>
<div class="layout">
<nav class="sidebar">
  <h1>PQC Handbook</h1>
  <input id="filter" type="search" placeholder="Filter contents…" aria-label="Filter table of contents">
  ${tocHtml}
</nav>
<main>
${bodyHtml}
</main>
</div>
<script>${js}</script>
</body>
</html>`;

fs.writeFileSync(outputFile, html);
console.error(`Web edition written to ${outputFile} (${toc.length} TOC entries, ${(html.length / 1024).toFixed(0)} KB)`);
