package finding

// ClassInfo is general, class-level knowledge used to describe a lead that
// no model has investigated. Reports label it as typical for the class, not
// confirmed for the code.
type ClassInfo struct {
	Name          string   // human name, e.g. "SQL injection"
	OWASP         []string // OWASP Top 10 2021 category names, exact
	Preconditions []string // 1 to 2 items: what an attacker needs
	Steps         []string // 2 to 4 items: the typical attack chain, defender-level description
	ChainsInto    []string // 1 to 2 items: what it commonly leads to
	Gains         []string // 1 to 3 items: what the attacker gets
	Fix           string   // one or two sentences: the specific, standard remediation
}

// OWASP Top 10 2021 category names.
const (
	owaspA01 = "A01:2021 Broken Access Control"
	owaspA02 = "A02:2021 Cryptographic Failures"
	owaspA03 = "A03:2021 Injection"
	owaspA04 = "A04:2021 Insecure Design"
	owaspA05 = "A05:2021 Security Misconfiguration"
	owaspA06 = "A06:2021 Vulnerable and Outdated Components"
	owaspA07 = "A07:2021 Identification and Authentication Failures"
	owaspA08 = "A08:2021 Software and Data Integrity Failures"
	owaspA10 = "A10:2021 Server-Side Request Forgery (SSRF)"
)

// Info returns the class-level knowledge for a class. An unknown class
// yields a zero-value ClassInfo whose Name is the class itself. The returned
// slices are shared and must not be modified.
func Info(class string) ClassInfo {
	if ci, ok := classInfo[class]; ok {
		return ci
	}
	return ClassInfo{Name: class}
}

// classInfo has one entry for every key of classVectors.
var classInfo = map[string]ClassInfo{
	"sql-injection": {
		Name:  "SQL injection",
		OWASP: []string{owaspA03},
		Preconditions: []string{
			"A request parameter, header, or stored value reaches a SQL query that is built by string concatenation",
			"The attacker can send requests to the affected endpoint",
		},
		Steps: []string{
			"Send a request whose parameter closes the string literal and appends SQL",
			"Confirm the injection from error messages, changed results, or response timing",
			"Use UNION or boolean conditions to read other tables",
			"Modify or delete rows where the database account has write access",
		},
		ChainsInto: []string{
			"Authentication bypass or account takeover using extracted credentials and session data",
			"Remote code execution when the database account can write files or run operating system commands",
		},
		Gains: []string{
			"Read access to every table the database account can reach",
			"The ability to change or delete application records",
		},
		Fix: "Use parameterized queries or prepared statements for every value, and allow-list any identifier that cannot be bound. Run the application with a least-privilege database account.",
	},
	"command-injection": {
		Name:  "OS command injection",
		OWASP: []string{owaspA03},
		Preconditions: []string{
			"Attacker-controlled input is placed into a command line that is run through a shell",
			"The attacker can reach the feature that runs the command",
		},
		Steps: []string{
			"Submit input containing shell metacharacters that end the intended command and start a new one",
			"Confirm execution from the response, a time delay, or an outbound connection",
			"Run further commands with the privileges of the application process",
		},
		ChainsInto: []string{
			"Full compromise of the host and theft of the credentials stored on it",
			"Lateral movement to internal systems the host can reach",
		},
		Gains: []string{
			"Arbitrary command execution as the application user",
			"Access to files, environment variables, and secrets on the server",
		},
		Fix: "Call the program directly with an argument list instead of a shell, and validate each argument against an allow-list. Prefer a library call over spawning a process where one exists.",
	},
	"code-injection": {
		Name:  "Code injection",
		OWASP: []string{owaspA03},
		Preconditions: []string{
			"Attacker-controlled input reaches a dynamic evaluation function such as eval or an equivalent",
			"The attacker can reach the feature that evaluates the input",
		},
		Steps: []string{
			"Submit input that is syntactically valid code in the application language",
			"Confirm that the interpreter evaluated it from the response or a side effect",
			"Use the language runtime to read files, open connections, or start processes",
		},
		ChainsInto: []string{
			"Full compromise of the application server",
			"Theft of secrets held in memory, configuration, or the environment",
		},
		Gains: []string{
			"Arbitrary code execution inside the application process",
			"Access to all data and credentials the application can use",
		},
		Fix: "Remove dynamic evaluation of untrusted input and replace it with a fixed mapping or a safe parser for the expected data format.",
	},
	"unsafe-deserialization": {
		Name:  "Unsafe deserialization",
		OWASP: []string{owaspA08},
		Preconditions: []string{
			"The application deserializes attacker-supplied data with a format that can instantiate arbitrary types",
			"Classes with dangerous side effects are available on the application class path or module path",
		},
		Steps: []string{
			"Identify where serialized objects are accepted, such as cookies, request bodies, or message queues",
			"Craft a serialized object graph that reuses existing classes to trigger unintended behavior when it is loaded",
			"Submit the object so that the application deserializes it",
		},
		ChainsInto: []string{
			"Remote code execution on the application server",
			"Tampering with application state or denial of service",
		},
		Gains: []string{
			"Code execution with the privileges of the application process",
			"The ability to forge objects such as sessions or permissions",
		},
		Fix: "Do not deserialize untrusted data with native object serializers; use a data-only format such as JSON with a strict schema. Where that is not possible, sign the data and restrict the types that may be loaded.",
	},
	"template-injection": {
		Name:  "Server-side template injection",
		OWASP: []string{owaspA03},
		Preconditions: []string{
			"Attacker-controlled input is compiled as part of a server-side template instead of being passed in as data",
			"The template engine exposes objects or functions beyond simple value output",
		},
		Steps: []string{
			"Submit a template expression and observe that the server evaluates it",
			"Identify the template engine from its syntax and error messages",
			"Use the objects the engine exposes to read configuration or reach the underlying runtime",
		},
		ChainsInto: []string{
			"Remote code execution on the application server",
			"Disclosure of secrets held in the template context",
		},
		Gains: []string{
			"Evaluation of arbitrary template expressions on the server",
			"Access to application configuration and secrets",
		},
		Fix: "Never build templates from user input; pass user values only as template data. Use a logic-less or sandboxed engine if users must supply templates.",
	},
	"path-traversal": {
		Name:  "Path traversal",
		OWASP: []string{owaspA01},
		Preconditions: []string{
			"A file path is built from attacker-controlled input without being confined to a base directory",
			"The attacker can reach the feature that reads or writes the file",
		},
		Steps: []string{
			"Submit a file name containing parent-directory sequences or an absolute path",
			"Read files outside the intended directory, such as configuration files or keys",
			"Overwrite files where the same flaw exists on a write path",
		},
		ChainsInto: []string{
			"Credential theft from configuration files and key material",
			"Remote code execution when an executable or configuration file can be overwritten",
		},
		Gains: []string{
			"Read access to any file the application process can read",
			"Source code, configuration, and secrets stored on the server",
		},
		Fix: "Resolve the requested path to its canonical form and reject it unless it stays inside the intended base directory. Prefer mapping user input to server-generated identifiers instead of file names.",
	},
	"ssrf": {
		Name:  "Server-side request forgery",
		OWASP: []string{owaspA10},
		Preconditions: []string{
			"The server fetches a URL or connects to a host that is taken from attacker-controlled input",
			"The server can reach internal services or a cloud metadata endpoint",
		},
		Steps: []string{
			"Supply a URL that points to an internal address instead of the expected external resource",
			"Use the response or its timing to map internal hosts and services",
			"Request the cloud metadata service or internal admin interfaces through the server",
		},
		ChainsInto: []string{
			"Theft of cloud instance credentials and access to the cloud account",
			"Access to internal services that trust requests from the application server",
		},
		Gains: []string{
			"The ability to send requests from inside the network perimeter",
			"Data from internal services that are not exposed to the internet",
		},
		Fix: "Allow-list the destination hosts and schemes, resolve the host name and reject private, loopback, and link-local addresses, and do not follow redirects to unchecked locations. Block access to the metadata service at the network level.",
	},
	"xss": {
		Name:  "Cross-site scripting",
		OWASP: []string{owaspA03},
		Preconditions: []string{
			"Attacker-controlled input is written into a page without encoding for its output context",
			"A victim opens a crafted link or views a page that contains the stored input",
		},
		Steps: []string{
			"Submit input containing markup or script that the application reflects or stores",
			"Get a victim to load the affected page",
			"Run script in the victim's browser within the application's origin",
		},
		ChainsInto: []string{
			"Session hijacking or account takeover",
			"Actions performed with the victim's privileges, including administrative actions",
		},
		Gains: []string{
			"Script execution in the victim's authenticated session",
			"Access to the data the victim can see in the application",
		},
		Fix: "Encode output for its exact context using the template engine's automatic escaping, and sanitize any HTML that must be allowed. Add a Content Security Policy as a second layer.",
	},
	"open-redirect": {
		Name:  "Open redirect",
		OWASP: []string{owaspA01},
		Preconditions: []string{
			"A redirect destination is taken from a request parameter without validation",
			"A victim follows a link that the attacker supplies",
		},
		Steps: []string{
			"Build a link to the trusted site whose redirect parameter points to an attacker-controlled site",
			"Deliver the link to a victim, who sees the trusted domain name",
			"The application redirects the victim to the attacker's site",
		},
		ChainsInto: []string{
			"Credential phishing that borrows the trusted domain's reputation",
			"Theft of OAuth authorization codes or tokens when the redirect is part of a sign-in flow",
		},
		Gains: []string{
			"A trusted-looking link that leads to an attacker-controlled site",
		},
		Fix: "Redirect only to relative paths or to destinations on a server-side allow-list, and reject any other value.",
	},
	"hardcoded-secret": {
		Name:  "Hardcoded secret",
		OWASP: []string{owaspA07},
		Preconditions: []string{
			"A credential, API key, or private key is stored in source code, configuration, or version history",
			"The attacker can read the repository, a built artifact, or a leaked copy of either",
		},
		Steps: []string{
			"Obtain the source code, container image, or client bundle that contains the secret",
			"Extract the credential and identify the service it belongs to",
			"Authenticate to that service as the application",
		},
		ChainsInto: []string{
			"Unauthorized access to the database, cloud account, or third-party service the secret protects",
			"Lateral movement using the permissions of the leaked credential",
		},
		Gains: []string{
			"Valid credentials for a system the application uses",
			"The data and operations that the credential is authorized for",
		},
		Fix: "Rotate the exposed secret immediately, since removing it from the code does not remove it from history. Load secrets at runtime from a secret manager or environment configuration.",
	},
	"weak-crypto": {
		Name:  "Weak cryptography",
		OWASP: []string{owaspA02},
		Preconditions: []string{
			"Sensitive data is protected with a broken or outdated cipher, mode, or key size",
			"The attacker can capture or obtain the encrypted data",
		},
		Steps: []string{
			"Collect ciphertext from network traffic, storage, or tokens issued by the application",
			"Use the known weakness of the algorithm or mode to recover plaintext or find patterns in it",
			"Alter ciphertext undetected where the scheme provides no integrity protection",
		},
		ChainsInto: []string{
			"Disclosure of the protected data",
			"Forgery of encrypted tokens or session values",
		},
		Gains: []string{
			"Plaintext of data that was assumed to be confidential",
		},
		Fix: "Use a current authenticated cipher such as AES-GCM or ChaCha20-Poly1305 from a maintained library, with adequate key sizes and unique nonces.",
	},
	"weak-hash": {
		Name:  "Weak hash function",
		OWASP: []string{owaspA02},
		Preconditions: []string{
			"Passwords or integrity checks rely on a fast or broken hash such as MD5 or SHA-1",
			"The attacker obtains the stored hashes or can supply data that is verified by the hash",
		},
		Steps: []string{
			"Obtain the hash values, for example from a database leak or backup",
			"Recover the original passwords by guessing at high speed against the fast hash",
			"Produce colliding inputs where the hash is used to verify integrity",
		},
		ChainsInto: []string{
			"Account takeover using recovered passwords, including on other sites where they are reused",
			"Acceptance of tampered files or data that pass the integrity check",
		},
		Gains: []string{
			"Plaintext passwords for a large share of accounts",
		},
		Fix: "Hash passwords with a slow, salted algorithm such as Argon2id, scrypt, or bcrypt. Use SHA-256 or stronger for integrity, with an HMAC when a key is involved.",
	},
	"insecure-random": {
		Name:  "Insecure randomness",
		OWASP: []string{owaspA02},
		Preconditions: []string{
			"A security value such as a token, password reset code, or key is generated by a non-cryptographic random number generator",
			"The attacker can observe some generated values or estimate the generator's seed",
		},
		Steps: []string{
			"Collect several values produced by the generator",
			"Reconstruct the generator state or narrow the set of possible outputs",
			"Predict a value issued to another user, such as a reset token or session identifier",
		},
		ChainsInto: []string{
			"Account takeover through predicted reset tokens or session identifiers",
		},
		Gains: []string{
			"The ability to guess secrets that were meant to be unpredictable",
		},
		Fix: "Generate every security-sensitive value with the platform's cryptographically secure random generator, such as crypto/rand in Go or the secrets module in Python.",
	},
	"tls-verification": {
		Name:  "Disabled TLS certificate verification",
		OWASP: []string{owaspA02, owaspA07},
		Preconditions: []string{
			"A client connection is made with certificate or host name verification turned off",
			"The attacker holds a network position between the client and the server",
		},
		Steps: []string{
			"Intercept the connection, for example on a shared network or through DNS or routing manipulation",
			"Present a certificate of the attacker's own, which the client accepts without checking",
			"Read and modify the traffic while relaying it to the real server",
		},
		ChainsInto: []string{
			"Theft of credentials and tokens sent over the connection",
			"Injection of malicious responses, updates, or data into the client",
		},
		Gains: []string{
			"Full read and write access to traffic that was assumed to be encrypted and authenticated",
		},
		Fix: "Enable certificate and host name verification on every connection. Add an internal certificate authority to the trust store instead of disabling verification.",
	},
	"jwt-verification": {
		Name:  "Missing or weak JWT verification",
		OWASP: []string{owaspA02, owaspA07},
		Preconditions: []string{
			"The application accepts tokens without verifying the signature, or lets the token choose its own algorithm or key",
			"The attacker can send requests that carry a token",
		},
		Steps: []string{
			"Take a token issued by the application and inspect its header and claims",
			"Change claims such as the user identifier or role",
			"Submit the altered token unsigned, or signed in a way that the weak check accepts",
		},
		ChainsInto: []string{
			"Impersonation of any user, including administrators",
			"Privilege escalation through forged role or scope claims",
		},
		Gains: []string{
			"Authenticated access as an arbitrary user",
		},
		Fix: "Verify every token's signature with a fixed, server-chosen algorithm and key, and reject unsigned tokens. Validate the issuer, audience, and expiry claims.",
	},
	"auth-bypass": {
		Name:  "Authentication bypass",
		OWASP: []string{owaspA07},
		Preconditions: []string{
			"A route or function that should require authentication can be reached without a valid session",
			"The attacker can send requests to the application",
		},
		Steps: []string{
			"Find endpoints where the authentication check is missing, skipped, or decided by client-supplied data",
			"Request the endpoint directly without credentials or with a manipulated request",
			"Use the functionality as if signed in",
		},
		ChainsInto: []string{
			"Unauthorized access to user data and account functions",
			"Administrative access when the bypass affects privileged routes",
		},
		Gains: []string{
			"Access to protected functionality without valid credentials",
			"The data and actions behind the unprotected endpoints",
		},
		Fix: "Enforce authentication in central middleware that denies by default, and list public routes explicitly. Never base the decision on values the client controls.",
	},
	"broken-access-control": {
		Name:  "Broken access control",
		OWASP: []string{owaspA01},
		Preconditions: []string{
			"The server does not check that the signed-in user is allowed to access the requested object or function",
			"The attacker has an ordinary account",
		},
		Steps: []string{
			"Sign in as a normal user and note the identifiers used in requests",
			"Change an identifier to one that belongs to another user or tenant",
			"Call functions intended for a higher-privileged role",
		},
		ChainsInto: []string{
			"Bulk extraction of other users' data by enumerating identifiers",
			"Privilege escalation to administrative functions",
		},
		Gains: []string{
			"Read or write access to records that belong to other users",
			"Use of functions outside the attacker's role",
		},
		Fix: "Check ownership and role on the server for every request, scoping each query to the authenticated user or tenant. Deny by default when no rule grants access.",
	},
	"cors-misconfiguration": {
		Name:  "CORS misconfiguration",
		OWASP: []string{owaspA05, owaspA01},
		Preconditions: []string{
			"The application reflects arbitrary origins or trusts the null origin while allowing credentials",
			"A signed-in victim visits a site the attacker controls",
		},
		Steps: []string{
			"Host a page that sends cross-origin requests to the application from the victim's browser",
			"The browser attaches the victim's cookies and the application approves the attacker's origin",
			"The attacker's page reads the authenticated responses",
		},
		ChainsInto: []string{
			"Theft of the victim's data and of anti-forgery tokens",
			"Actions performed in the victim's session",
		},
		Gains: []string{
			"Cross-origin read access to a signed-in victim's data",
		},
		Fix: "Return Access-Control-Allow-Origin only for an explicit allow-list of trusted origins, and never combine reflected or wildcard origins with credentials.",
	},
	"debug-enabled": {
		Name:  "Debug mode enabled",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"A debug mode, debug endpoint, or development console is active in a deployed environment",
			"The attacker can reach the application or the debug interface",
		},
		Steps: []string{
			"Trigger an error or open a known debug route",
			"Read the stack traces, configuration values, and environment details that are shown",
			"Use an interactive debugger or profiling endpoint if one is exposed",
		},
		ChainsInto: []string{
			"Targeted attacks informed by disclosed versions, paths, and secrets",
			"Remote code execution where the framework exposes an interactive debug console",
		},
		Gains: []string{
			"Internal details of the application and its environment",
			"Secrets printed in debug output",
		},
		Fix: "Disable debug mode and remove debug endpoints in production builds, with configuration that defaults to off. Return generic error pages and keep details in server logs.",
	},
	"information-disclosure": {
		Name:  "Information disclosure",
		OWASP: []string{owaspA05, owaspA01},
		Preconditions: []string{
			"Responses, error messages, or logs reveal internal details or sensitive data",
			"The attacker can reach the endpoint that returns them",
		},
		Steps: []string{
			"Send normal and malformed requests and compare the responses",
			"Collect leaked details such as software versions, file paths, queries, or identifiers",
			"Use those details to select and tune further attacks",
		},
		ChainsInto: []string{
			"More reliable exploitation of other weaknesses in the application",
			"Direct exposure of personal or business data where records are returned",
		},
		Gains: []string{
			"Knowledge of the application's internals that the owner did not intend to publish",
		},
		Fix: "Return generic error messages to clients and log the details on the server. Remove version banners and return only the fields each response needs.",
	},
	"missing-security-header": {
		Name:  "Missing security header",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"Responses lack browser protections such as Content-Security-Policy, Strict-Transport-Security, or framing controls",
			"A second weakness or a network position is available to the attacker",
		},
		Steps: []string{
			"Check the response headers and note which protections are absent",
			"Combine the gap with another weakness, such as script injection, framing of the page, or a downgrade to plain HTTP",
			"Carry out the attack that the missing header would have blocked or limited",
		},
		ChainsInto: []string{
			"Clickjacking or easier exploitation of cross-site scripting",
			"Interception of traffic after a downgrade to an unencrypted connection",
		},
		Gains: []string{
			"Removal of a defense-in-depth layer that would limit other attacks",
		},
		Fix: "Set Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and frame-ancestors or X-Frame-Options on all responses, ideally in shared middleware or at the reverse proxy.",
	},
	"insecure-cookie": {
		Name:  "Insecure cookie attributes",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"A session or other sensitive cookie is set without the Secure, HttpOnly, or SameSite attribute",
			"The attacker has a network position, a script injection flaw, or a site the victim visits",
		},
		Steps: []string{
			"Identify which protective attributes the cookie lacks",
			"Capture the cookie over plain HTTP, read it from injected script, or have the browser send it on a cross-site request",
			"Reuse the cookie or the cross-site request to act as the victim",
		},
		ChainsInto: []string{
			"Session hijacking",
			"Cross-site request forgery against the signed-in user",
		},
		Gains: []string{
			"Use of the victim's authenticated session",
		},
		Fix: "Set Secure, HttpOnly, and SameSite=Lax or Strict on every session cookie, and serve the application only over HTTPS.",
	},
	"race-condition": {
		Name:  "Race condition",
		OWASP: []string{owaspA04},
		Preconditions: []string{
			"A check and the action that depends on it are not performed atomically",
			"The attacker can send several requests at nearly the same time",
		},
		Steps: []string{
			"Find an operation with a limit, such as redeeming a coupon, withdrawing a balance, or using a one-time token",
			"Send many identical requests in parallel so they all pass the check before any of them updates the state",
			"Repeat until the limit has been exceeded",
		},
		ChainsInto: []string{
			"Financial loss through duplicated transactions or credits",
			"Bypass of rate limits and one-time-use controls",
		},
		Gains: []string{
			"Repeated use of an operation that should succeed only once",
			"Inconsistent application state that favors the attacker",
		},
		Fix: "Make the check and the update one atomic operation using a database transaction with row locking, a unique constraint, or a conditional update. Add idempotency keys to sensitive operations.",
	},
	"vulnerable-dependency": {
		Name:  "Vulnerable dependency",
		OWASP: []string{owaspA06},
		Preconditions: []string{
			"The application includes a third-party component with a publicly known vulnerability",
			"The vulnerable code path is reachable with input the attacker controls",
		},
		Steps: []string{
			"Identify the component and its version from responses, files, or public manifests",
			"Look up the published advisories for that version",
			"Send input that reaches the vulnerable function in the component",
		},
		ChainsInto: []string{
			"Whatever impact the advisory describes, up to remote code execution",
		},
		Gains: []string{
			"The impact of a known flaw without having to find a new one",
		},
		Fix: "Upgrade the component to a version that fixes the advisory, and run dependency scanning in CI so that new advisories are caught.",
	},
	"container-privilege": {
		Name:  "Privileged container",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"A container runs privileged, as root with added capabilities, or with host namespaces or the container runtime socket mounted",
			"The attacker gains code execution inside the container through another weakness",
		},
		Steps: []string{
			"Compromise the application that runs inside the container",
			"Discover the extra privileges, host mounts, or runtime socket available to the container",
			"Use them to reach the host file system or to start new containers on the host",
		},
		ChainsInto: []string{
			"Container escape and control of the host",
			"Compromise of the other workloads and secrets on the same node or cluster",
		},
		Gains: []string{
			"Root-level access to the container host",
			"Access to the data and credentials of neighboring workloads",
		},
		Fix: "Run containers as a non-root user without the privileged flag, drop all capabilities and add back only those required, and do not mount the runtime socket or host paths.",
	},
	"container-hardening": {
		Name:  "Missing container hardening",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"A container image or workload lacks standard hardening, such as a non-root user, a read-only file system, or resource limits",
			"The attacker gains code execution inside the container through another weakness",
		},
		Steps: []string{
			"Compromise the application that runs inside the container",
			"Use the root user, writable file system, and bundled tools to install software and persist",
			"Consume host resources or probe for a route out of the container",
		},
		ChainsInto: []string{
			"Easier privilege escalation and container escape attempts",
			"Denial of service against other workloads on the same host",
		},
		Gains: []string{
			"A stronger foothold after an initial compromise",
		},
		Fix: "Run as a non-root user on a minimal base image with a read-only root file system, no privilege escalation, and CPU and memory limits. Pin base images by digest.",
	},
	"supply-chain": {
		Name:  "Supply chain weakness",
		OWASP: []string{owaspA08, owaspA06},
		Preconditions: []string{
			"The build or deployment pulls code, images, or scripts that are not pinned to a verified version or digest",
			"The attacker can publish to or tamper with the upstream source, registry, or download location",
		},
		Steps: []string{
			"Find a dependency, action, image, or install script that is referenced by a mutable tag or an unverified URL",
			"Publish a malicious version upstream, or register a package name that the build resolves by mistake",
			"The next build or deployment fetches and runs the attacker's code",
		},
		ChainsInto: []string{
			"Theft of build secrets and signing keys",
			"Malicious code shipped to production and to downstream users",
		},
		Gains: []string{
			"Code execution in the build pipeline or in the released software",
		},
		Fix: "Pin dependencies, images, and CI actions to exact versions or digests, commit lock files, and verify checksums or signatures. Use a private registry or scoped package names to prevent dependency confusion.",
	},
	"ci-injection": {
		Name:  "CI pipeline injection",
		OWASP: []string{owaspA08, owaspA03},
		Preconditions: []string{
			"A workflow inserts untrusted text, such as a pull request title or branch name, into a script, or runs untrusted code with access to secrets",
			"The attacker can open a pull request or issue, or otherwise trigger the workflow",
		},
		Steps: []string{
			"Find a workflow that expands attacker-controlled event fields inside a shell step or checks out and builds untrusted code in a privileged context",
			"Open a pull request or issue whose content carries shell syntax or modified build scripts",
			"The workflow runs the attacker's commands on the runner",
		},
		ChainsInto: []string{
			"Theft of repository tokens, cloud credentials, and signing keys",
			"Tampering with releases or pushing malicious commits",
		},
		Gains: []string{
			"Command execution on the CI runner",
			"The secrets available to the workflow",
		},
		Fix: "Pass untrusted event fields to scripts through environment variables instead of inline expressions. Do not run code from forks in workflows that have secrets or write tokens.",
	},
	"ci-permissions": {
		Name:  "Excessive CI permissions",
		OWASP: []string{owaspA08, owaspA05},
		Preconditions: []string{
			"A workflow token or job has broader permissions than its task needs",
			"The attacker can influence a step in the workflow, for example through a compromised action or dependency",
		},
		Steps: []string{
			"Gain execution inside a job through a compromised third-party step or an injection flaw",
			"Read the token that the job receives automatically",
			"Use its write permissions to change code, releases, packages, or workflow settings",
		},
		ChainsInto: []string{
			"Malicious commits or release artifacts published from the repository",
			"Persistent access through modified workflows",
		},
		Gains: []string{
			"Write access to the repository and its release assets",
		},
		Fix: "Set the default workflow token to read-only and grant each job only the specific permissions it needs. Use short-lived, scoped credentials instead of long-lived secrets.",
	},
	"network-exposure": {
		Name:  "Excessive network exposure",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"A service, port, or management interface accepts connections from any address",
			"The exposed service has weak authentication or a known vulnerability",
		},
		Steps: []string{
			"Scan the address range and find the open port",
			"Identify the service and its version",
			"Attempt default or guessed credentials, or use a known flaw in the service",
		},
		ChainsInto: []string{
			"Direct access to databases, caches, or administrative interfaces",
			"An initial foothold for lateral movement inside the network",
		},
		Gains: []string{
			"Reachability of a service that was meant to be internal",
			"The data or control that the service offers once it is accessed",
		},
		Fix: "Restrict ingress to the specific source addresses and ports that are required, bind internal services to private interfaces, and place management access behind a VPN or bastion host.",
	},
	"public-storage": {
		Name:  "Publicly accessible storage",
		OWASP: []string{owaspA05, owaspA01},
		Preconditions: []string{
			"A storage bucket, container, or share allows anonymous read or write access",
			"The attacker knows or can guess its name or URL",
		},
		Steps: []string{
			"Discover the storage location from application responses, source code, or name guessing",
			"List and download its contents without credentials",
			"Upload or replace objects if anonymous write access is also allowed",
		},
		ChainsInto: []string{
			"Disclosure of backups, user uploads, logs, and credentials stored in the bucket",
			"Serving of tampered files to users when the bucket hosts application assets",
		},
		Gains: []string{
			"Every object in the storage location",
			"The ability to alter hosted content where writes are allowed",
		},
		Fix: "Enable the provider's public access block, remove anonymous grants from bucket policies and ACLs, and serve files through signed URLs or an authenticated application path.",
	},
	"unencrypted-storage": {
		Name:  "Unencrypted storage",
		OWASP: []string{owaspA02},
		Preconditions: []string{
			"A disk, database, bucket, or backup holding sensitive data is not encrypted at rest",
			"The attacker obtains the underlying media, a snapshot, or a backup copy",
		},
		Steps: []string{
			"Gain access to a snapshot, backup, or decommissioned volume through a separate weakness or mishandling",
			"Attach or open the copy outside the original environment",
			"Read the data directly, since no key is required",
		},
		ChainsInto: []string{
			"Bulk disclosure of the stored data",
		},
		Gains: []string{
			"The full contents of the storage without needing application access",
		},
		Fix: "Enable encryption at rest with provider-managed or customer-managed keys for volumes, databases, buckets, and backups, and restrict who can use the keys.",
	},
	"denial-of-service": {
		Name:  "Denial of service",
		OWASP: []string{owaspA04},
		Preconditions: []string{
			"A request can make the server use CPU, memory, or other resources far out of proportion to its size",
			"The attacker can send requests to the affected endpoint",
		},
		Steps: []string{
			"Find an operation with no limit on input size, nesting, repetition, or processing time",
			"Send input crafted to hit the worst-case behavior, such as a pathological pattern for a regular expression or a very large payload",
			"Repeat the request until worker processes or memory are exhausted",
		},
		ChainsInto: []string{
			"Service outage for legitimate users",
			"Increased infrastructure cost where the platform scales automatically",
		},
		Gains: []string{
			"The ability to make the service slow or unavailable with little effort",
		},
		Fix: "Limit request size, nesting depth, and processing time, apply rate limiting, and replace algorithms or regular expressions that have super-linear worst-case behavior.",
	},
	"xxe": {
		Name:  "XML external entity injection",
		OWASP: []string{owaspA05},
		Preconditions: []string{
			"The application parses attacker-supplied XML with external entities or DTD processing enabled",
			"The attacker can submit XML to the parser",
		},
		Steps: []string{
			"Submit an XML document that declares an external entity referring to a local file or an internal URL",
			"The parser resolves the entity and places the content in the document",
			"Read the content from the response or through an out-of-band channel",
		},
		ChainsInto: []string{
			"Disclosure of local files such as configuration and credentials",
			"Server-side request forgery against internal services",
		},
		Gains: []string{
			"Read access to files the application process can read",
			"Requests issued from the server to internal addresses",
		},
		Fix: "Disable DTD processing and external entity resolution in the XML parser, or use a parser that is safe by default.",
	},
	"prototype-pollution": {
		Name:  "Prototype pollution",
		OWASP: []string{owaspA08},
		Preconditions: []string{
			"Attacker-controlled keys are merged or assigned recursively into a JavaScript object without filtering",
			"Application or library code later reads properties that it expects to be undefined",
		},
		Steps: []string{
			"Send JSON or query parameters whose keys target the object prototype",
			"The merge writes the attacker's properties onto the shared prototype",
			"Later code paths pick up the injected properties as if they were configuration or flags",
		},
		ChainsInto: []string{
			"Bypass of authorization checks that depend on object properties",
			"Remote code execution or cross-site scripting when a polluted property reaches a dangerous sink",
		},
		Gains: []string{
			"Control over default property values across the whole process or page",
		},
		Fix: "Reject the keys __proto__, constructor, and prototype when merging untrusted data, and use Map or objects created without a prototype for user-keyed data. Upgrade any merge library with a known flaw.",
	},
	"mass-assignment": {
		Name:  "Mass assignment",
		OWASP: []string{owaspA08},
		Preconditions: []string{
			"Request fields are bound directly onto a model object without a list of permitted fields",
			"The attacker has an account and can guess or discover internal field names",
		},
		Steps: []string{
			"Observe the fields that a normal create or update request sends",
			"Add extra fields to the request, such as a role, owner, or balance field",
			"The server saves the extra fields along with the expected ones",
		},
		ChainsInto: []string{
			"Privilege escalation by setting role or admin flags",
			"Tampering with prices, balances, or ownership of records",
		},
		Gains: []string{
			"Write access to fields the user interface never exposes",
		},
		Fix: "Bind requests to a dedicated input type that contains only the fields a user may set, or apply an explicit allow-list of fields before saving.",
	},
	"directory-listing": {
		Name:  "Directory listing enabled",
		OWASP: []string{owaspA05, owaspA01},
		Preconditions: []string{
			"The web server returns an index of files for directories that have no default page",
			"The attacker can browse to the directory",
		},
		Steps: []string{
			"Request directory paths and receive a list of their contents",
			"Look through the listing for backups, configuration files, and unlinked content",
			"Download the files of interest",
		},
		ChainsInto: []string{
			"Disclosure of sensitive files that were hidden only by not being linked",
		},
		Gains: []string{
			"A map of the files on the server, including ones not meant to be found",
		},
		Fix: "Turn off automatic directory indexes in the web server or static file handler, and keep non-public files outside the web root.",
	},
	"exposed-file": {
		Name:  "Exposed sensitive file",
		OWASP: []string{owaspA05, owaspA01},
		Preconditions: []string{
			"A sensitive file such as an environment file, backup, key, or version control directory is served by the web server",
			"The attacker can request its path, which is often a well-known name",
		},
		Steps: []string{
			"Request common sensitive paths on the site",
			"Download the file when the server returns it",
			"Extract credentials, source code, or data from its contents",
		},
		ChainsInto: []string{
			"Use of leaked credentials against databases, cloud accounts, or third-party services",
			"Discovery of further weaknesses from the recovered source code",
		},
		Gains: []string{
			"Secrets and internal data contained in the file",
		},
		Fix: "Remove the file from the web root, block such paths in the server configuration, and rotate any secret it contained. Exclude these files from deployment artifacts.",
	},
}

// infraClasses are the classes whose findings concern deployment and CI
// configuration, not application code.
var infraClasses = map[string]bool{
	"container-privilege": true, "container-hardening": true, "supply-chain": true,
	"ci-injection": true, "ci-permissions": true, "network-exposure": true,
	"public-storage": true, "unencrypted-storage": true,
}

// SurfaceOf returns the surface a finding of the class belongs to when
// nothing more specific is known about it: SurfaceInfra for the deployment
// and CI classes, SurfaceCode for every other class.
func SurfaceOf(class string) string {
	if infraClasses[class] {
		return SurfaceInfra
	}
	return SurfaceCode
}
