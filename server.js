const http = require('http');
const fs = require('fs');
const path = require('path');
const PORT = process.env.PORT || 3000;
const mime = { '.html':'text/html;charset=utf-8', '.css':'text/css', '.js':'application/javascript', '.svg':'image/svg+xml' };
http.createServer((req, res) => {
  let p = req.url.split('?')[0];
  if (p === '/' || p === '') p = '/index.html';
  else if (!path.extname(p)) p += '.html';
  const file = path.join(__dirname, 'public', p);
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, {'Content-Type': mime[path.extname(file)] || 'text/plain'});
    res.end(data);
  });
}).listen(PORT, () => console.log('Rewa on :' + PORT));
