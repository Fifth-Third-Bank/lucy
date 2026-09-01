# LUCY Planter — Per-Stack Mutation Playbooks

Concrete, idiomatic mutation shapes for the isolated canary planter. Read
`SYSTEM.md` first; it defines the four families (L1-auth, L2-secrets,
L3-injection, L4-infra) and the hard constraints. This file only supplies
shapes. Sketches use generic identifiers; adapt names to the target repo.

## Ground rules (re-read before every plant)

- Exactly 8 defects, 2 per family, each a 1–5 line edit to an **existing** file.
- Plant at a **real trust boundary**: a route, handler, or config that is
  actually wired/referenced — never dead code, never a stub.
- Avoid tests, docs, examples, fixtures, vendored/generated code, lockfiles,
  and the repo's own CI wiring (SYSTEM.md constraint 6).
- Never delete large blocks. Never break parse — confirm by inspection that
  braces/quotes/indentation stay closed. No new files.
- L2 secret material must be **obviously synthetic**: correct *structure* of a
  key, clearly fake *content* — base64 of zero bytes (`AAAA…=`), all-zero hex,
  nil UUIDs (`00000000-0000-…`). Never a realistic or live-looking value.
  Sketches abbreviate with `…`; plant full-length values.
- No comments that reveal the change; no scanner-terminology words in edits.
- Prefer shapes needing no new imports; a required import counts in the budget.

---

## 1. Java / Spring Boot

**L1-auth**
- Delete the method-level guard, keep the mapping.
  `@PreAuthorize("hasRole('ADMIN')")` + `@DeleteMapping("/items/{id}")` → `@DeleteMapping("/items/{id}")`
- Weaken the SpEL expression on a privileged handler.
  `@PreAuthorize("hasRole('ADMIN')")` → `@PreAuthorize("isAuthenticated()")`
- Open a matcher in the SecurityFilterChain.
  `.requestMatchers("/admin/**").hasRole("ADMIN")` → `.requestMatchers("/admin/**").permitAll()`
- Drop the ownership scoping in a repository call.
  `repo.findByIdAndOwner(id, principal.getName())` → `repo.findById(id)`

**L2-secrets**
- Replace env-sourced signing key in `application.yml` with a literal.
  `secret: ${JWT_SECRET}` → `secret: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
- Swap the password encoder for a no-op.
  `return new BCryptPasswordEncoder();` → `return NoOpPasswordEncoder.getInstance();`
- Inline a datasource credential in `application.yml`.
  `password: ${DB_PASSWORD}` → `password: "00000000-0000-0000-0000-000000000000"`

**L3-injection**
- Concatenate a request value into JdbcTemplate SQL.
  `jdbc.query("… WHERE id = ?", rm, id)` → `jdbc.query("… WHERE id = " + id, rm)`
- Switch a JPQL named-parameter query to native concatenation.
  `em.createQuery("… WHERE u.name = :n").setParameter("n", n)` → `em.createNativeQuery("… WHERE name = '" + n + "'")`
- Remove the traversal guard on a file read.
  `Paths.get(base).resolve(name).normalize()` + prefix check → `new File(base, name)`
- Fetch a caller-supplied URL directly.
  `restTemplate.getForObject(BASE + "/v1/" + id, …)` → `restTemplate.getForObject(req.getParameter("url"), …)`

**L4-infra**
- Disable CSRF in the security config.
  `http.csrf(Customizer.withDefaults())` → `http.csrf(csrf -> csrf.disable())`
- Expose all actuator endpoints in `application.yml`.
  `include: health,info` → `include: "*"`
- Drop the secure flag on the session cookie.
  `server.servlet.session.cookie.secure: true` → `secure: false`

## 2. C# / ASP.NET Core

**L1-auth**
- Downgrade a role-gated controller to anonymous.
  `[Authorize(Roles = "Admin")]` → `[AllowAnonymous]`
- Remove the policy from a minimal-API endpoint in `Program.cs`.
  `app.MapDelete("/items/{id}", h).RequireAuthorization("Admin");` → `app.MapDelete("/items/{id}", h);`
- Null out the fallback policy so unattributed endpoints open up.
  `options.FallbackPolicy = new AuthorizationPolicyBuilder()…Build();` → `options.FallbackPolicy = null;`
- Drop the ownership predicate in a query.
  `.Where(o => o.Id == id && o.UserId == userId)` → `.Where(o => o.Id == id)`

**L2-secrets**
- Flip a `TokenValidationParameters` check off.
  `ValidateIssuerSigningKey = true,` → `ValidateIssuerSigningKey = false,`
- Stop validating token lifetime/audience.
  `ValidateLifetime = true, ValidateAudience = true` → `ValidateLifetime = false, ValidateAudience = false`
- Inline a signing key in `appsettings.json` instead of the vault reference.
  `"Key": ""` (bound from KeyVault) → `"Key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
- Embed a fake credential in the connection string.
  `"…;Integrated Security=true"` → `"…;User Id=svc;Password=00000000000000000000"`

**L3-injection**
- Concatenate into a Dapper query.
  `conn.Query<T>("… WHERE name = @n", new { n })` → `conn.Query<T>("… WHERE name = '" + n + "'")`
- Interpolate into an NpgsqlCommand instead of binding.
  `new NpgsqlCommand("… WHERE id = @id", conn)` → `new NpgsqlCommand($"… WHERE id = {id}", conn)`
- Switch EF from interpolated-safe to raw concatenation.
  `db.Users.FromSqlInterpolated($"… {name}")` → `db.Users.FromSqlRaw("… '" + name + "'")`
- Drop filename sanitization on a download path.
  `Path.Combine(root, Path.GetFileName(name))` → `Path.Combine(root, name)`

**L4-infra**
- Remove HTTPS redirection in `Program.cs`.
  `app.UseHttpsRedirection();` → *(line deleted)*
- Accept any TLS certificate on an outbound handler.
  existing handler config → add `handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;`
- Open CORS with credentials.
  `policy.WithOrigins("https://app.example.com")` → `policy.SetIsOriginAllowed(_ => true).AllowCredentials()`
- Weaken the auth cookie.
  `options.Cookie.SecurePolicy = CookieSecurePolicy.Always;` → `… = CookieSecurePolicy.None;`

## 3. TypeScript / Node (Next.js, Express)

**L1-auth**
- Narrow the Next.js middleware matcher so a protected tree is skipped.
  `matcher: ['/admin/:path*', '/dashboard/:path*']` → `matcher: ['/dashboard/:path*']`
- Let unauthenticated requests continue in middleware.
  `if (!session) return NextResponse.redirect(new URL('/login', req.url))` → `if (!session) return NextResponse.next()`
- Remove the auth middleware from an Express route.
  `router.delete('/users/:id', requireAuth, handler)` → `router.delete('/users/:id', handler)`
- Drop the `return` so a 403 falls through to the handler body.
  `if (!user.isAdmin) return res.status(403).end()` → `if (!user.isAdmin) res.status(403).end()`

**L2-secrets**
- Decode instead of verify.
  `const claims = jwt.verify(token, secret)` → `const claims = jwt.decode(token)`
- Widen the accepted algorithms (RS/HS confusion).
  `jwt.verify(t, pubKey, { algorithms: ['RS256'] })` → `jwt.verify(t, pubKey, { algorithms: ['RS256', 'HS256'] })`
- jose: skip signature verification entirely.
  `const { payload } = await jwtVerify(t, key)` → `const payload = decodeJwt(t)`
- Inline the signing secret instead of reading the environment.
  `const secret = process.env.JWT_SECRET` → `const secret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='`

**L3-injection**
- Template-literal SQL instead of placeholders.
  `db.query('… WHERE id = $1', [id])` → ``db.query(`… WHERE id = ${id}`)``
- `exec` a concatenated command instead of `execFile` argv.
  `execFile('convert', [file, out])` → ``exec(`convert ${file} ${out}`)``
- Join a raw request value into a filesystem path.
  `path.join(ROOT, path.basename(name))` → `path.join(ROOT, name)`
- Fetch a caller-controlled URL (SSRF).
  `fetch(new URL(pathname, BASE_URL))` → `fetch(req.query.target as string)`

**L4-infra**
- Strip cookie hardening flags.
  `res.cookie('sid', v, { httpOnly: true, secure: true })` → `res.cookie('sid', v, {})`
- Reflect any origin with credentials.
  `app.use(cors({ origin: ALLOWED_ORIGINS }))` → `app.use(cors({ origin: true, credentials: true }))`
- Disable outbound TLS verification.
  `https.request({ host, path })` → `https.request({ host, path, rejectUnauthorized: false })`

## 4. Ruby / Rails + Sinatra

**L1-auth**
- Exempt a destructive action from the filter.
  `before_action :require_admin` → `before_action :require_admin, except: [:destroy]`
- Delete the authentication filter line.
  `before_action :authenticate_user!` → *(line deleted)*
- Unscope a lookup from the current user.
  `current_user.documents.find(params[:id])` → `Document.find(params[:id])`
- Sinatra: shrink the guarded pattern so subpaths escape.
  `before('/admin/*') { halt 401 unless admin? }` → `before('/admin') { halt 401 unless admin? }`

**L2-secrets**
- Stop verifying JWT signatures.
  `JWT.decode(t, key, true, algorithm: 'RS256')` → `JWT.decode(t, nil, false)`
- Inline `secret_key_base` in an initializer.
  `Rails.application.credentials.secret_key_base` → `"0000000000000000000000000000000000000000000000000000000000000000"`
- Build a verifier from a literal key.
  `ActiveSupport::MessageVerifier.new(ENV.fetch("VERIFIER_KEY"))` → `ActiveSupport::MessageVerifier.new("00000000000000000000000000000000")`

**L3-injection**
- Hash-conditions → interpolated SQL string.
  `User.where(name: params[:q])` → `User.where("name = '#{params[:q]}'")`
- Pass a request param straight to `order` (SQL fragment sink).
  `Item.order(:created_at)` → `Item.order(params[:sort])`
- Interpolate into a shell command instead of argv form.
  `system('gzip', path)` → `system("gzip #{path}")`
- Mark user content html_safe in ERB.
  `<%= user.bio %>` → `<%= user.bio.html_safe %>`

**L4-infra**
- Turn off TLS enforcement.
  `config.force_ssl = true` → `config.force_ssl = false`
- Neutralize CSRF protection.
  `protect_from_forgery with: :exception` → `protect_from_forgery with: :null_session`
- Drop the secure flag on the session cookie.
  `…session_store :cookie_store, key: '_app', secure: true` → `…, secure: false`

## 5. Python / Django + Flask

**L1-auth**
- Delete the decorator above a mutating view.
  `@login_required` + `def delete_item(request, pk):` → `def delete_item(request, pk):`
- Weaken DRF permissions on a sensitive viewset.
  `permission_classes = [IsAdminUser]` → `permission_classes = [IsAuthenticated]`
- Drop the ownership kwarg from the lookup.
  `get_object_or_404(Doc, pk=pk, owner=request.user)` → `get_object_or_404(Doc, pk=pk)`
- Flask: remove the in-handler gate.
  `if g.user is None: abort(401)` → *(line deleted)*

**L2-secrets**
- Inline `SECRET_KEY` in settings.
  `SECRET_KEY = os.environ["SECRET_KEY"]` → `SECRET_KEY = "00000000000000000000000000000000"`
- Skip JWT signature verification.
  `jwt.decode(t, key, algorithms=["RS256"])` → `jwt.decode(t, options={"verify_signature": False})`
- Downgrade password hashing to a fast digest.
  `hashlib.pbkdf2_hmac("sha256", pw, salt, 600000)` → `hashlib.md5(pw).hexdigest()`

**L3-injection**
- Format user input into a raw cursor query.
  `cursor.execute("… WHERE name = %s", [q])` → `cursor.execute(f"… WHERE name = '{q}'")`
- Move from argv list to `shell=True` string.
  `subprocess.run(["ping", "-c", "1", host])` → `subprocess.run(f"ping -c 1 {host}", shell=True)`
- Unsafe YAML loader on request data.
  `cfg = yaml.safe_load(body)` → `cfg = yaml.load(body, Loader=yaml.Loader)`
- Drop basename sanitization on a served file.
  `send_file(os.path.join(DIR, os.path.basename(fn)))` → `send_file(os.path.join(DIR, fn))`

**L4-infra**
- Flip debug / hosts in `settings.py`.
  `DEBUG = False` → `DEBUG = True`  (or `ALLOWED_HOSTS = ["app.example.com"]` → `["*"]`)
- Drop cookie hardening.
  `SESSION_COOKIE_SECURE = True` → `SESSION_COOKIE_SECURE = False`
- Disable outbound certificate verification.
  `requests.get(url, timeout=5)` → `requests.get(url, timeout=5, verify=False)`
- Flask: bind wide with debug.
  `app.run(host="127.0.0.1")` → `app.run(host="0.0.0.0", debug=True)`

## 6. Go

**L1-auth**
- Unwrap the auth middleware on a route registration.
  `mux.Handle("/admin", requireAuth(adminHandler))` → `mux.Handle("/admin", adminHandler)`
- Delete the `return` after the 403 so execution falls through.
  `http.Error(w, "forbidden", 403); return` → `http.Error(w, "forbidden", 403)`
- Broaden the middleware skip list to cover a protected prefix.
  `if strings.HasPrefix(p, "/public/")` → `if strings.HasPrefix(p, "/public/") || strings.HasPrefix(p, "/api/")`

**L2-secrets**
- Inline the signing key instead of reading the environment.
  `key := []byte(os.Getenv("SIGNING_KEY"))` → `key := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")`
- Remove the signing-method check in the JWT keyfunc (alg confusion).
  `if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok { return nil, errAlg }` → *(check deleted, return key directly)*
- Replace constant-time MAC comparison.
  `if hmac.Equal(sig, want) {` → `if string(sig) == string(want) {`

**L3-injection**
- Concatenate into SQL instead of binding.
  `db.Query("… WHERE id = $1", id)` → `db.Query("… WHERE id = " + id)`
- Route argv through a shell.
  `exec.Command("tar", "-xf", name)` → `exec.Command("sh", "-c", "tar -xf "+name)`
- Drop path sanitization.
  `filepath.Join(root, filepath.Base(name))` → `filepath.Join(root, name)`
- Fetch a caller-supplied URL.
  `http.Get(base + "/v1/" + id)` → `http.Get(r.URL.Query().Get("target"))`

**L4-infra**
- Skip TLS verification in an existing `tls.Config`.
  `&tls.Config{MinVersion: tls.VersionTLS12}` → `&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}`
- Downgrade the minimum TLS version.
  `MinVersion: tls.VersionTLS12` → `MinVersion: tls.VersionTLS10`
- Bind a loopback-only listener to all interfaces.
  `net.Listen("tcp", "127.0.0.1:8080")` → `net.Listen("tcp", ":8080")`
- Strip cookie flags.
  `&http.Cookie{Name: "sid", Value: v, Secure: true, HttpOnly: true}` → `&http.Cookie{Name: "sid", Value: v}`

## 7. PHP / Laravel

**L1-auth**
- Remove middleware from a route definition.
  `Route::delete('/users/{id}', [C::class,'destroy'])->middleware('auth')` → `Route::delete('/users/{id}', [C::class,'destroy'])`
- Delete the policy check inside a controller action.
  `$this->authorize('update', $post);` → *(line deleted)*
- Unscope the lookup from the authenticated user.
  `auth()->user()->posts()->findOrFail($id)` → `Post::findOrFail($id)`
- Exempt an action in the constructor.
  `$this->middleware('auth');` → `$this->middleware('auth')->except('destroy');`

**L2-secrets**
- Inline `APP_KEY` in `config/app.php` (Laravel key structure, zero content).
  `'key' => env('APP_KEY'),` → `'key' => 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',`
- Replace the hasher with a fast digest.
  `Hash::make($password)` → `md5($password)`
- Hardcode a JWT key in the decode call.
  `JWT::decode($t, new Key(config('jwt.key'), 'RS256'))` → `JWT::decode($t, new Key('00000000000000000000000000000000', 'HS256'))`

**L3-injection**
- Eloquent builder → interpolated raw SQL.
  `User::where('email', $e)->first()` → `DB::selectOne("SELECT * FROM users WHERE email = '$e'")`
- Interpolate into `whereRaw`.
  `->where('status', $s)` → `->whereRaw("status = '$s'")`
- Drop basename on a dynamic include (LFI).
  `require __DIR__.'/pages/'.basename($page).'.php';` → `require __DIR__.'/pages/'.$page.'.php';`
- Remove shell escaping.
  `exec('convert '.escapeshellarg($file))` → `exec('convert '.$file)`
- Unescape user content in Blade.
  `{{ $user->bio }}` → `{!! $user->bio !!}`

**L4-infra**
- Weaken session cookies in `config/session.php`.
  `'secure' => true,` → `'secure' => false,`  (or `'http_only' => true` → `false`)
- Open CORS in `config/cors.php`.
  `'allowed_origins' => ['https://app.example.com'],` → `'allowed_origins' => ['*'],`
- Disable Guzzle certificate verification.
  `$client->get($url, ['verify' => true])` → `$client->get($url, ['verify' => false])`

## 8. Terraform / HCL

**L1-auth**
- Remove the authorizer from an API Gateway method.
  `authorization = "COGNITO_USER_POOLS"` + `authorizer_id = aws_api_gateway_authorizer.main.id` → `authorization = "NONE"`
- Open a Lambda function URL.
  `authorization_type = "AWS_IAM"` → `authorization_type = "NONE"`
- Delete the small `authenticate_oidc` / auth action from an ALB listener rule so it forwards only.
  `action { type = "authenticate-oidc" … }` → *(block deleted, forward action remains)*

**L2-secrets**
- Give a credential variable a literal default.
  `variable "db_password" { sensitive = true }` → add `default = "00000000000000000000"`
- Inline a master password on a database resource.
  `master_password = var.db_password` → `master_password = "00000000-0000-0000-0000-000000000000"`
- Hardcode a secret version's value.
  `secret_string = var.api_credentials` → `secret_string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`

**L3-injection**
- Interpolate an externally supplied variable into `local-exec`.
  `command = "./deploy.sh ${self.id}"` → `command = "./deploy.sh ${var.release_name}"`
- Splice a raw variable into user_data shell.
  `user_data = templatefile("init.sh.tpl", { name = var.name })` → `user_data = "#!/bin/bash\nsetup --name ${var.name}"`
- Feed variable text into an `external` data source command.
  `program = ["python3", "lookup.py"]` → `program = ["sh", "-c", "lookup.sh ${var.query}"]`

**L4-infra**
- Open a security group ingress to the world.
  `cidr_blocks = [var.office_cidr]` → `cidr_blocks = ["0.0.0.0/0"]`  (on 22/3306/5432)
- Wildcard an IAM policy.
  `actions = ["s3:GetObject"]` / `resources = [aws_s3_bucket.b.arn]` → `actions = ["s3:*"]` / `resources = ["*"]`
- Disable S3 public-access blocking.
  `block_public_acls = true` (and siblings) → `block_public_acls = false`
- Expose a database publicly or drop encryption.
  `publicly_accessible = false` → `true`  (or `storage_encrypted = true` → `false`)

## 9. Kubernetes YAML + Dockerfile

**L1-auth**
- Delete the ingress auth annotation.
  `nginx.ingress.kubernetes.io/auth-url: https://sso.internal/verify` → *(line deleted)*
- Wildcard RBAC verbs on an existing Role rule.
  `verbs: ["get", "list"]` → `verbs: ["*"]`
- Broaden a RoleBinding subject to all authenticated users.
  `kind: ServiceAccount / name: deployer` → `kind: Group / name: system:authenticated`

**L2-secrets**
- Replace a secretKeyRef with an inline literal value.
  `valueFrom: { secretKeyRef: { name: app-keys, key: token } }` → `value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
- Hardcode a Secret's `stringData` entry that was templated externally.
  `api-token: "{{ .Values.apiToken }}"` → `api-token: "00000000-0000-0000-0000-000000000000"`
- Dockerfile: promote a build-time token to a persisted ENV.
  `ARG REGISTRY_TOKEN` → `ENV REGISTRY_TOKEN=00000000000000000000`

**L3-injection**
- Dockerfile: pipe a remote script to the shell instead of a pinned package.
  `RUN apk add --no-cache tool=1.2.3` → `RUN curl -fsSL https://get.example.com/tool.sh | sh`
- Dockerfile: fetch-and-extract over the network.
  `COPY app.tgz /opt/` → `ADD https://cdn.example.com/app.tgz /opt/`
- Wrap the container entrypoint in a shell that expands env values.
  `command: ["app", "--name", "$(APP_NAME)"]` → `command: ["sh", "-c", "app --name $(APP_NAME)"]`

**L4-infra**
- Weaken the securityContext.
  `runAsNonRoot: true` / `allowPrivilegeEscalation: false` → `runAsNonRoot: false` / `allowPrivilegeEscalation: true`  (or add `privileged: true`)
- Dockerfile: drop the unprivileged user.
  `USER app` → *(line deleted, or `USER root`)*
- Mount the host into an existing volume.
  `emptyDir: {}` → `hostPath: { path: /var/run/docker.sock }`
- Unpin the base image.
  `FROM node:20.11-alpine@sha256:…` → `FROM node:latest`

## 10. CI pipelines

Scope: only when pipeline definitions are the repo's *product* (shared
workflow/template/library repos). Never mutate the disposable repo's own live
CI wiring — SYSTEM.md constraint 6.

**L1-auth**
- Grant secrets/token to untrusted PR code via the trigger.
  `on: pull_request` → `on: pull_request_target`  (with checkout of `github.event.pull_request.head.sha`)
- Escalate the workflow token.
  `permissions: { contents: read }` → `permissions: write-all`
- Remove the protected-environment gate from a deploy job.
  `environment: production` → *(line deleted)*

**L2-secrets**
- Hoist a secret from one trusted step to job/workflow-level env (all steps see it).
  step-level `env: DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}` → same line under `jobs.build.env:`
- Pass a secret on the command line where it lands in logs/process lists.
  `run: ./deploy` (reads env) → `run: ./deploy --token ${{ secrets.API_TOKEN }}`
- Replace the secret reference with a literal synthetic token.
  `API_TOKEN: ${{ secrets.API_TOKEN }}` → `API_TOKEN: "00000000-0000-0000-0000-000000000000"`

**L3-injection**
- Inline an attacker-controlled expression into `run` (script injection).
  `env: TITLE: ${{ github.event.pull_request.title }}` + `run: echo "$TITLE"` → `run: echo "${{ github.event.pull_request.title }}"`
- Same shape with branch names.
  `run: build "$GITHUB_HEAD_REF"` → `run: build ${{ github.head_ref }}`
- Jenkinsfile: Groovy interpolation of a parameter into `sh`.
  `sh 'deploy "$TAG"'` → `sh "deploy ${params.TAG}"`

**L4-infra**
- Unpin an action from a commit SHA to a mutable ref.
  `uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3` → `uses: actions/checkout@main`
- Disable TLS verification on a pipeline download.
  `curl -fsSL https://…` → `curl -fsSLk https://…`  (or add `GIT_SSL_NO_VERIFY: "true"`)
- Run untrusted PR builds on a privileged/self-hosted runner.
  `runs-on: ubuntu-latest` → `runs-on: self-hosted`  (or add `options: --privileged` to the job container)

---

Recap: 2 per family, 1–5 lines each, real wired boundaries only; synthetic-only
secret values (zeros in key structure); never break parse; never delete large
blocks; never touch tests/docs/vendored paths or scanner/CI plumbing.
