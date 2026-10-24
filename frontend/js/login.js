const $ = id => document.getElementById(id);
const theme = (() => { try { return localStorage.getItem("theme"); } catch (e) { return null; } })();
if (theme) document.documentElement.dataset.theme = theme;
let signup = false;

function setMode(up) {
  signup = up;
  $("m-in").classList.toggle("on", !up); $("m-up").classList.toggle("on", up);
  $("row2").hidden = !up;
  $("pw2").required = up;
  $("pw").autocomplete = up ? "new-password" : "current-password";
  $("go").textContent = up ? "Create account" : "Sign in";
  $("hint").textContent = up
    ? "Enter your email and choose a password of at least 10 characters. An admin must approve your account before you can sign in."
    : "Sign in with your email and password.";
  $("err").hidden = $("okmsg").hidden = true;
}
$("m-in").onclick = () => setMode(false);
$("m-up").onclick = () => setMode(true);
setMode(false);

async function post(path, body) {
  let res;
  try {
    res = await fetch("/api/" + path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "mini-soc" },
      body: JSON.stringify(body),
    });
  } catch (e) { return { ok: false, data: { error: "Cannot reach the server. Is it running?" } }; }
  return { ok: res.ok, data: await res.json().catch(() => ({})) };
}

$("form").onsubmit = async e => {
  e.preventDefault();
  $("err").hidden = $("okmsg").hidden = true;
  const body = { email: $("user").value, password: $("pw").value };
  if (signup && body.password !== $("pw2").value) { $("err").textContent = "The two passwords do not match."; $("err").hidden = false; return; }
  const r = await post(signup ? "signup" : "login", body);
  if (!r.ok) { $("err").textContent = r.data.error || "Something went wrong."; $("err").hidden = false; return; }
  if (!signup) { location.href = "/"; return; }
  $("pw").value = $("pw2").value = "";
  setMode(false);
  $("okmsg").textContent = r.data.message;
  $("okmsg").hidden = false;
};
