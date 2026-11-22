let token = ''; // kept in memory only, not localStorage
const $ = id => document.getElementById(id);
async function api(path, opts = {}) {
  const r = await fetch('/api/' + path, { ...opts, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token } });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}
$('login').onsubmit = async e => {
  e.preventDefault();
  const r = await api('login', { method: 'POST', body: JSON.stringify({ index_no: $('i').value, password: $('p').value, otp: $('o').value }) });
  if (!r.ok) { $('msg').textContent = r.status === 429 ? 'Too many attempts. Try again later.' : 'Login failed'; return; }
  token = r.data.token; $('login').hidden = true; $('app').hidden = false;
  $('who').textContent = 'Logged in as ' + $('i').value; $('add').hidden = r.data.role !== 'lecturer';
  if (r.data.role === 'student') showGrades();
};
async function showGrades() {
  const r = await api('grades');
  (r.data || []).forEach(g => { const tr = $('grades').insertRow(); tr.insertCell().textContent = g.course; tr.insertCell().textContent = g.score; }); // textContent = no XSS
}
$('add').onsubmit = async e => {
  e.preventDefault();
  const r = await api('grades', { method: 'POST', body: JSON.stringify({ index_no: $('gi').value, course: $('gc').value, score: +$('gs').value }) });
  alert(r.ok ? 'Saved' : 'Failed (' + r.status + ')');
};
$('out').onclick = () => { token = ''; location.reload(); };
