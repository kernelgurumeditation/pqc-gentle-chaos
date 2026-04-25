#!/usr/bin/env node
/**
 * md2pdf.js - Convert Markdown to HTML for WeasyPrint PDF generation
 *
 * Usage: node md2pdf.js input.md > output.html
 * Then:  weasyprint output.html output.pdf --stylesheet pdf-style-weasy.css
 */

const fs = require('fs');
const { marked } = require('marked');

// Custom renderer to add IDs to headings (like GFM does)
const renderer = new marked.Renderer();
renderer.heading = function({ text, depth, raw }) {
  // Generate slug from raw text (strip HTML tags first)
  const plainText = raw.replace(/<[^>]*>/g, '');
  // Match GFM heading ID generation: keep double hyphens from special chars
  const slug = plainText
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/^-+|-+$/g, '');
  return `<h${depth} id="${slug}">${text}</h${depth}>\n`;
};

// Configure marked for GFM
marked.setOptions({
  gfm: true,
  breaks: false,
  pedantic: false,
  renderer: renderer,
});

const inputFile = process.argv[2];
if (!inputFile) {
  console.error('Usage: node md2pdf.js <input.md>');
  process.exit(1);
}

const markdown = fs.readFileSync(inputFile, 'utf-8');
const bodyHtml = marked.parse(markdown);

// Read the CSS file
const cssFile = process.argv[3] || 'pdf-style-weasy.css';
let css = '';
try {
  css = fs.readFileSync(cssFile, 'utf-8');
} catch (e) {
  console.error(`Warning: Could not read ${cssFile}`);
}

// Basic syntax highlighting CSS (since we don't have highlight.js in WeasyPrint)
const syntaxCss = `
/* Syntax highlighting - basic */
code .hljs-keyword { color: #d73a49; font-weight: bold; }
code .hljs-type { color: #d73a49; }
code .hljs-string { color: #032f62; }
code .hljs-number { color: #005cc5; }
code .hljs-comment { color: #6a737d; font-style: italic; }
code .hljs-built_in { color: #e36209; }
code .hljs-title { color: #6f42c1; }
code .hljs-params { color: #24292e; }
code .hljs-meta { color: #e36209; }
`;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
${css}
${syntaxCss}
</style>
</head>
<body>
${bodyHtml}
</body>
</html>`;

// Write to stdout or file
const outputFile = process.argv[4];
if (outputFile) {
  fs.writeFileSync(outputFile, html);
  console.error(`HTML written to ${outputFile}`);
} else {
  process.stdout.write(html);
}
