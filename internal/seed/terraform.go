package seed

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	tfPublicACL = infraCheck{
		id: "tf-public-bucket-acl", title: "Storage bucket ACL allows public access",
		class: "public-storage", cwe: "CWE-732", severity: "high",
		detail: "A public-read or public-read-write ACL lets anyone on the internet list or fetch the objects, and with public-read-write also replace them.",
		fix:    "Set the ACL to private and grant access to specific principals through a bucket policy.",
	}
	tfPublicBlockOff = infraCheck{
		id: "tf-public-access-block-disabled", title: "Public access block is turned off",
		class: "public-storage", cwe: "CWE-732", severity: "high",
		detail: "A public access block setting is false, so a later ACL or policy change can expose the bucket to the internet without any further guard.",
		fix:    "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.",
	}
	tfOpenIngress = infraCheck{
		id: "tf-open-ingress", title: "Sensitive port open to the whole internet",
		class: "network-exposure", cwe: "CWE-284", severity: "high",
		detail: "The rule accepts traffic from any address on a port used for administration or a data store, which exposes that service to scanning, credential guessing and exploitation from anywhere.",
		fix:    "Restrict the source to the networks that need access, or reach the service through a bastion, VPN or private endpoint.",
	}
	tfUnencrypted = infraCheck{
		id: "tf-storage-unencrypted", title: "Storage encryption disabled",
		class: "unencrypted-storage", cwe: "CWE-311", severity: "medium",
		detail: "Encryption at rest is explicitly turned off, so anyone who obtains the underlying volume, snapshot or backup can read the data.",
		fix:    "Set the attribute to true and choose a managed key.",
	}
	tfPublicDB = infraCheck{
		id: "tf-publicly-accessible", title: "Database instance is publicly accessible",
		class: "network-exposure", cwe: "CWE-284", severity: "high",
		detail: "publicly_accessible = true gives the instance a public address, so it is reachable from the internet wherever its security groups allow.",
		fix:    "Set publicly_accessible = false and connect through private networking.",
	}
	tfSecret = infraCheck{
		id: "tf-hardcoded-secret", title: "Secret written into Terraform as a literal",
		class: "hardcoded-secret", cwe: "CWE-798", severity: "high",
		detail: "The credential is stored in the configuration in clear text and is also copied into the Terraform state, so everyone who can read either can read it.",
		fix:    "Rotate the credential, then supply the new one through a sensitive variable or a secret manager data source.",
	}

	tfACLRe         = regexp.MustCompile(`^\s*acl\s*=\s*"public-read(?:-write)?"`)
	tfBlockOffRe    = regexp.MustCompile(`^\s*(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b`)
	tfUnencryptedRe = regexp.MustCompile(`^\s*(?:storage_)?encrypted\s*=\s*false\b`)
	tfPublicDBRe    = regexp.MustCompile(`^\s*publicly_accessible\s*=\s*true\b`)
	tfSecretRe      = regexp.MustCompile(`(?i)^\s*([a-z0-9_]*(?:password|passwd|secret_key|secret|token|api_key|private_key|access_key))\s*=\s*"((?:[^"\\]|\\.)*)"`)
	tfPortRe        = regexp.MustCompile(`^\s*(from_port|to_port)\s*=\s*"?(-?\d+)"?`)
	tfProtocolRe    = regexp.MustCompile(`^\s*(?:ip_)?protocol\s*=\s*"?(-1|[A-Za-z0-9]+)"?`)
	tfTypeRe        = regexp.MustCompile(`^\s*type\s*=\s*"(ingress|egress)"`)
	tfCIDRKeyRe     = regexp.MustCompile(`^\s*(?:cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6)\s*=`)
	tfAnyCIDRRe     = regexp.MustCompile(`"(?:0\.0\.0\.0/0|::/0)"`)
	tfStringRe      = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	tfIngressHeadRe = regexp.MustCompile(`^\s*ingress\s*\{|_ingress_rule"`)
	tfRuleHeadRe    = regexp.MustCompile(`"aws_security_group_rule"`)
)

// sensitivePorts are administration and data store ports that should never
// face the internet: SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB,
// Elasticsearch.
var sensitivePorts = []int{22, 3389, 3306, 5432, 6379, 27017, 9200}

// tfBlock is an open { } block while scanning. Only the attributes the
// ingress check needs are remembered.
type tfBlock struct {
	header     string
	from, to   int
	hasFrom    bool
	hasTo      bool
	allProto   bool
	ingress    bool // type = "ingress"
	egress     bool // type = "egress"
	cidrLine   int  // line of the open CIDR, 0 when none
	cidrSource string
}

func (b *tfBlock) openIngress() bool {
	if b.cidrLine == 0 || b.egress {
		return false
	}
	isIngress := tfIngressHeadRe.MatchString(b.header) || (tfRuleHeadRe.MatchString(b.header) && b.ingress)
	if !isIngress {
		return false
	}
	if b.allProto {
		return true
	}
	if !b.hasFrom || !b.hasTo {
		// Ports given as variables cannot be judged from the file alone.
		return false
	}
	for _, p := range sensitivePorts {
		if b.from <= p && p <= b.to {
			return true
		}
	}
	return false
}

// tfCode removes strings and comments so braces can be counted.
func tfCode(line string) string {
	line = tfStringRe.ReplaceAllString(line, `""`)
	for _, c := range []string{"#", "//"} {
		if i := strings.Index(line, c); i >= 0 {
			line = line[:i]
		}
	}
	return line
}

func terraformLeads(rel, text string) []Lead {
	var leads []Lead
	var stack []*tfBlock
	inCIDRList := false
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		n := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		switch {
		case tfACLRe.MatchString(line):
			leads = append(leads, tfPublicACL.lead(rel, n, line))
		case tfBlockOffRe.MatchString(line):
			leads = append(leads, tfPublicBlockOff.lead(rel, n, line))
		case tfUnencryptedRe.MatchString(line):
			leads = append(leads, tfUnencrypted.lead(rel, n, line))
		case tfPublicDBRe.MatchString(line):
			leads = append(leads, tfPublicDB.lead(rel, n, line))
		}
		if m := tfSecretRe.FindStringSubmatch(line); m != nil && !strings.Contains(m[2], "${") && looksLikeSecretPair(m[1], m[2]) {
			leads = append(leads, tfSecret.lead(rel, n, m[1]+` = "`+redactedValue(tfSecret.id, m[2])+`"`))
		}

		code := tfCode(line)
		for range strings.Count(code, "{") {
			stack = append(stack, &tfBlock{header: line})
		}
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			if m := tfPortRe.FindStringSubmatch(line); m != nil {
				if v, err := strconv.Atoi(m[2]); err == nil {
					if m[1] == "from_port" {
						top.from, top.hasFrom = v, true
					} else {
						top.to, top.hasTo = v, true
					}
				}
			}
			if m := tfProtocolRe.FindStringSubmatch(line); m != nil && (m[1] == "-1" || strings.EqualFold(m[1], "all")) {
				top.allProto = true
			}
			if m := tfTypeRe.FindStringSubmatch(line); m != nil {
				top.ingress, top.egress = m[1] == "ingress", m[1] == "egress"
			}
			// A CIDR list may span lines; keep looking until it closes.
			if tfCIDRKeyRe.MatchString(line) {
				inCIDRList = strings.Contains(code, "[") && !strings.Contains(code, "]")
				if tfAnyCIDRRe.MatchString(line) {
					top.cidrLine, top.cidrSource = n, line
				}
			} else if inCIDRList {
				if tfAnyCIDRRe.MatchString(line) {
					top.cidrLine, top.cidrSource = n, line
				}
				if strings.Contains(code, "]") {
					inCIDRList = false
				}
			}
		}
		for range strings.Count(code, "}") {
			if len(stack) == 0 {
				break
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.openIngress() {
				leads = append(leads, tfOpenIngress.lead(rel, top.cidrLine, top.cidrSource))
			}
		}
	}
	return leads
}
