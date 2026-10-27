const escapeHtml = (s) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
  );

// A tagged template that HTML-escapes every ${value}, so a page cannot forget to.
const html = (strings, ...values) =>
  strings.reduce((out, part, i) => out + escapeHtml(String(values[i - 1])) + part);

const page = (body) => `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Invoices demo</title></head>
<body>${body}</body>
</html>
`;

export function home(req, res) {
  res
    .type('html')
    .send(page('<h1>Invoices demo</h1><p><a href="/hello?name=reader">Say hello</a></p>'));
}

// GET /hello?name=...: the name is escaped by the html`` tag.
export function hello(req, res) {
  const name = typeof req.query.name === 'string' ? req.query.name.slice(0, 50) : 'stranger';
  res.type('html').send(page(html`<p>Hello, ${name}!</p>`));
}
