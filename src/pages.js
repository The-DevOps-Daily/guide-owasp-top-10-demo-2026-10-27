const escapeHtml = (s) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
  );

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

// GET /hello?name=...: user input is HTML-escaped before it goes into the page.
export function hello(req, res) {
  const name = typeof req.query.name === 'string' ? req.query.name.slice(0, 50) : 'stranger';
  res.type('html').send(page(`<p>Hello, ${escapeHtml(name)}!</p>`));
}
