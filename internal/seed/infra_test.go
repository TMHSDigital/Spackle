package seed

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TMHSDigital/spackle/internal/finding"
)

// infraRun writes one file, lists it with walk.List and runs the
// infrastructure seeder on it.
func infraRun(t *testing.T, rel, content string) []Lead {
	t.Helper()
	root, files := writeTree(t, map[string]string{rel: content})
	leads, err := infraSeeder{}.Run(context.Background(), root, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leads {
		if _, ok := finding.DefaultVector(l.Class); !ok {
			t.Errorf("lead %s has unknown class %q", l.RuleID, l.Class)
		}
		if l.Surface != finding.SurfaceInfra || l.File != rel || l.Line < 1 || len(l.CWE) != 1 || l.Detail == "" || l.Fix == "" || l.Title == "" {
			t.Errorf("incomplete lead: %+v", l)
		}
		if l.ID != "" || l.Source != "" {
			t.Errorf("seeders must leave ID and Source to RunAll")
		}
	}
	return leads
}

type infraWant struct {
	rule, class, severity string
	line                  int
}

func checkInfra(t *testing.T, leads []Lead, wants []infraWant) {
	t.Helper()
	for _, w := range wants {
		ok := false
		for _, l := range leads {
			if l.RuleID == w.rule && l.Line == w.line {
				ok = true
				if l.Class != w.class || l.Severity != w.severity {
					t.Errorf("%s at line %d: class %s severity %s, want %s %s", w.rule, w.line, l.Class, l.Severity, w.class, w.severity)
				}
			}
		}
		if !ok {
			t.Errorf("missing %s at line %d", w.rule, w.line)
		}
	}
	if len(leads) != len(wants) {
		for _, l := range leads {
			t.Logf("lead line %d %s: %s", l.Line, l.RuleID, l.Snippet)
		}
		t.Errorf("got %d leads, want %d", len(leads), len(wants))
	}
}

func TestDockerfileChecks(t *testing.T) {
	bad := strings.Join([]string{
		"# build image",                                    // 1
		"FROM golang AS build",                             // 2 untagged
		"ARG NPM_TOKEN=" + testGitHub,                      // 3 secret
		"ADD https://example.com/tool.tar.gz /opt/",        // 4 remote add
		"RUN curl -fsSL https://example.com/install.sh \\", // 5 curl pipe (continued)
		"    | sh",                                       // 6
		"RUN chmod -R 777 /app",                          // 7
		"FROM ubuntu:latest",                             // 8 latest
		"ENV DB_PASSWORD " + testPassword,                // 9 legacy ENV form
		"ENV MODE=prod API_KEY=\"" + testPassword + "\"", // 10
		"RUN docker run --privileged builder",            // 11
		"COPY --from=build /out/app /app",                // 12
		"USER root",                                      // 13 final user root
		"ENTRYPOINT [\"/app\"]",                          // 14
	}, "\n")
	leads := infraRun(t, "Dockerfile", bad)
	checkInfra(t, leads, []infraWant{
		{"docker-from-unpinned", "supply-chain", "low", 2},
		{"docker-env-secret", "hardcoded-secret", "high", 3},
		{"docker-add-remote", "supply-chain", "medium", 4},
		{"docker-curl-pipe-shell", "supply-chain", "high", 5},
		{"docker-chmod-777", "container-hardening", "medium", 7},
		{"docker-from-unpinned", "supply-chain", "low", 8},
		{"docker-env-secret", "hardcoded-secret", "high", 9},
		{"docker-env-secret", "hardcoded-secret", "high", 10},
		{"docker-privileged", "container-hardening", "medium", 11},
		{"docker-user-root", "container-hardening", "medium", 13},
	})
	assertNoSecret(t, leads)
	for _, l := range leads {
		if l.RuleID == "docker-env-secret" && !strings.Contains(l.Snippet, "=[REDACTED:docker-env-secret:") {
			t.Errorf("secret snippet = %q", l.Snippet)
		}
	}

	good := strings.Join([]string{
		"ARG BASE=alpine:3.20",
		"FROM golang:1.23@sha256:" + strings.Repeat("ab", 32) + " AS build",
		"ARG NPM_TOKEN",
		"ENV PASSWORD_FILE=/run/secrets/db TOKEN=${TOKEN} API_KEY=changeme",
		"ADD --checksum=sha256:" + strings.Repeat("cd", 32) + " https://example.com/t.tar.gz /opt/",
		"COPY . /src",
		"RUN curl -fsSLo /tmp/i.sh https://example.com/install.sh && sha256sum -c sums && sh /tmp/i.sh",
		"RUN chmod 755 /src/run.sh",
		"FROM build AS test",
		"FROM ${BASE}",
		"FROM scratch",
		"FROM gcr.io/distroless/static:nonroot",
		"USER root",
		"RUN true",
		"USER 65532:65532",
	}, "\r\n")
	checkInfra(t, infraRun(t, "deploy/api.dockerfile", good), nil)

	// No USER at all in the final stage is reported at its FROM.
	checkInfra(t, infraRun(t, "Dockerfile.dev", "FROM alpine:3.20 AS a\nUSER app\nFROM alpine:3.20\nCMD [\"sh\"]\n"),
		[]infraWant{{"docker-no-user", "container-hardening", "medium", 3}})
	// A fragment with no FROM is not judged.
	checkInfra(t, infraRun(t, "Dockerfile", "RUN echo hi\n"), nil)
}

const k8sBad = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      volumes:
        - name: host
          hostPath:
            path: /var/run
      initContainers:
        - name: init
          image: busybox
      containers:
        - name: api
          image: registry.example.com:5000/team/api:latest
          securityContext:
            privileged: true
            runAsUser: 0
          env:
            - name: LOG_LEVEL
              value: debug
            - name: API_TOKEN
              value: "SECRETVALUE"
            - name: FROM_SECRET_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db
                  key: password
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: LoadBalancer
  ports:
    - port: 80
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          hostIPC: true
          containers:
            - name: job
              image: registry.example.com/job:1.4.2
              securityContext:
                allowPrivilegeEscalation: false
                runAsNonRoot: true
              resources:
                limits:
                  memory: 128Mi
`

const k8sGood = `apiVersion: v1
kind: Pod
metadata:
  name: ok
spec:
  hostNetwork: false
  securityContext:
    runAsUser: 1000
  volumes:
    - name: tmp
      emptyDir: {}
  containers:
    - name: ok
      image: registry.example.com/ok@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
      resources:
        limits:
          cpu: 100m
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef: {name: db, key: password}
        - name: TOKEN_URL
          value: https://auth.example.com/token
        - name: API_KEY
          value: ${API_KEY}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
data:
  privileged: "true"
`

func TestKubernetesChecks(t *testing.T) {
	bad := strings.Replace(k8sBad, "SECRETVALUE", testPassword, 1)
	leads := infraRun(t, "deploy/k8s/api.yaml", bad)
	checkInfra(t, leads, []infraWant{
		{"k8s-host-namespace", "container-privilege", "high", 8},
		{"k8s-host-namespace", "container-privilege", "high", 9},
		{"k8s-hostpath-volume", "container-privilege", "medium", 12},
		// init container: every default is missing.
		{"k8s-allow-privilege-escalation", "container-hardening", "medium", 15},
		{"k8s-run-as-root", "container-hardening", "medium", 15},
		{"k8s-no-resource-limits", "container-hardening", "low", 15},
		{"k8s-image-unpinned", "supply-chain", "low", 16},
		// api container.
		{"k8s-privileged-container", "container-privilege", "high", 21},
		{"k8s-allow-privilege-escalation", "container-hardening", "medium", 18},
		{"k8s-run-as-root", "container-hardening", "medium", 18},
		{"k8s-no-resource-limits", "container-hardening", "low", 18},
		{"k8s-image-unpinned", "supply-chain", "low", 19},
		{"k8s-env-secret", "hardcoded-secret", "high", 27},
		// CronJob in the third document; the Service is not reported.
		{"k8s-host-namespace", "container-privilege", "high", 53},
	})
	assertNoSecret(t, leads)
	for _, l := range leads {
		if l.RuleID == "k8s-env-secret" && !strings.HasPrefix(l.Snippet, "name: API_TOKEN value: [REDACTED:k8s-env-secret:") {
			t.Errorf("secret snippet = %q", l.Snippet)
		}
		if l.RuleID == "k8s-host-namespace" && l.Line == 8 && l.Snippet != "hostNetwork: true" {
			t.Errorf("snippet = %q", l.Snippet)
		}
	}

	checkInfra(t, infraRun(t, "ok.yml", strings.ReplaceAll(k8sGood, "\n", "\r\n")), nil)
	// YAML that is not a manifest, and YAML that does not parse, are skipped.
	checkInfra(t, infraRun(t, "compose.yaml", "services:\n  web:\n    privileged: true\n"), nil)
	checkInfra(t, infraRun(t, "chart/templates/deploy.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  {{- range .Values.c }}\n    - name: {{ .name }}\n      securityContext: {privileged: true}\n  {{- end }}\n"), nil)
	checkInfra(t, infraRun(t, "broken.yaml", "apiVersion: v1\nkind: Pod\nspec: [unterminated\n  hostNetwork: true\n"), nil)
}

const tfBad = `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket            = aws_s3_bucket.logs.id
  block_public_acls = false
}

resource "aws_security_group" "web" {
  name = "web" # { not a block
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    cidr_blocks = [
      "10.0.0.0/8",
      "0.0.0.0/0",
    ]
  }
  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group_rule" "rdp" {
  type        = "ingress"
  from_port   = 3380
  to_port     = 3390
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_instance" "db" {
  storage_encrypted   = false
  publicly_accessible = true
  password            = "SECRETVALUE"
}

resource "aws_ebs_volume" "v" {
  encrypted = false
}
`

const tfGood = `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  block_public_acls = true
}

resource "aws_security_group" "web" {
  # cidr_blocks = ["0.0.0.0/0"] with from_port = 22
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  ingress {
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "out" {
  type        = "egress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_instance" "db" {
  storage_encrypted   = true
  publicly_accessible = false
  password            = var.db_password
  username            = "admin_user"
  secret_key          = "${var.secret}"
  token               = "changeme"
}
`

func TestTerraformChecks(t *testing.T) {
	leads := infraRun(t, "infra/main.tf", strings.Replace(tfBad, "SECRETVALUE", testPassword, 1))
	checkInfra(t, leads, []infraWant{
		{"tf-public-bucket-acl", "public-storage", "high", 3},
		{"tf-public-access-block-disabled", "public-storage", "high", 8},
		{"tf-open-ingress", "network-exposure", "high", 17},
		{"tf-open-ingress", "network-exposure", "high", 25},
		{"tf-open-ingress", "network-exposure", "high", 32},
		{"tf-open-ingress", "network-exposure", "high", 41},
		{"tf-storage-unencrypted", "unencrypted-storage", "medium", 45},
		{"tf-publicly-accessible", "network-exposure", "high", 46},
		{"tf-hardcoded-secret", "hardcoded-secret", "high", 47},
		{"tf-storage-unencrypted", "unencrypted-storage", "medium", 51},
	})
	assertNoSecret(t, leads)
	for _, l := range leads {
		if l.RuleID == "tf-hardcoded-secret" && !strings.HasPrefix(l.Snippet, `password = "[REDACTED:tf-hardcoded-secret:`) {
			t.Errorf("secret snippet = %q", l.Snippet)
		}
	}
	checkInfra(t, infraRun(t, "main.tf", strings.ReplaceAll(tfGood, "\n", "\r\n")), nil)
	// Only Terraform files are read as Terraform.
	checkInfra(t, infraRun(t, "notes.txt", tfBad), nil)
}

const sha40 = "0123456789abcdef0123456789abcdef01234567"

const wfBad = `name: ci
on:
  pull_request_target:
    types: [opened]
  issue_comment:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: docker://alpine:3.20
      - name: greet
        run: echo "${{ github.event.issue.title }}"
      - name: multi
        run: |
          echo start
          echo "${{ github.event.comment.body }}"
          git checkout ${{ github.head_ref }}
          echo "${{ github.event.pages.*.page_name }} ${{ github.event.commits[0].message }}"
  call:
    uses: org/repo/.github/workflows/build.yml@main
`

const wfGood = `name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@SHA40 # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: ./.github/actions/local
      - uses: docker://alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      - name: safe
        env:
          TITLE: ${{ github.event.issue.title }}
        run: |
          echo "$TITLE" "${{ github.sha }}" "${{ github.event.pull_request.number }}"
  call:
    uses: ./.github/workflows/build.yml
`

func TestWorkflowChecks(t *testing.T) {
	leads := infraRun(t, ".github/workflows/ci.yml", wfBad)
	checkInfra(t, leads, []infraWant{
		{"workflow-permissions-write-all", "ci-permissions", "medium", 6},
		{"workflow-unpinned-action", "supply-chain", "low", 11},
		{"workflow-pull-request-target-checkout", "ci-injection", "critical", 13},
		{"workflow-unpinned-action", "supply-chain", "low", 14},
		{"workflow-script-injection", "ci-injection", "high", 16},
		{"workflow-script-injection", "ci-injection", "high", 20},
		{"workflow-script-injection", "ci-injection", "high", 21},
		{"workflow-script-injection", "ci-injection", "high", 22},
		{"workflow-unpinned-action", "supply-chain", "low", 24},
	})

	good := strings.ReplaceAll(strings.ReplaceAll(wfGood, "SHA40", sha40), "\n", "\r\n")
	checkInfra(t, infraRun(t, ".github/workflows/ci.yaml", good), nil)

	// No permissions anywhere: one low lead. Job-level permissions count.
	noPerm := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
	checkInfra(t, infraRun(t, ".github/workflows/x.yml", noPerm),
		[]infraWant{{"workflow-permissions-missing", "ci-permissions", "low", 2}})
	jobPerm := "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
	checkInfra(t, infraRun(t, ".github/workflows/x.yml", jobPerm), nil)
	jobWriteAll := "on: push\njobs:\n  a:\n    permissions: write-all\n    steps:\n      - run: make\n"
	checkInfra(t, infraRun(t, ".github/workflows/x.yml", jobWriteAll),
		[]infraWant{{"workflow-permissions-write-all", "ci-permissions", "medium", 4}})

	// pull_request (not _target) with a head checkout is the safe pattern.
	prOnly := strings.Replace(strings.Replace(wfBad, "pull_request_target", "pull_request", 1), "permissions: write-all", "permissions: {}", 1)
	if hasRule(infraRun(t, ".github/workflows/ci.yml", prOnly), "workflow-pull-request-target-checkout") {
		t.Error("pull_request with a head checkout must not be reported")
	}
	// The same content outside .github/workflows is not a workflow; it has
	// no apiVersion either, so nothing is reported.
	checkInfra(t, infraRun(t, "docs/ci.yml", wfBad), nil)
	// A workflow that does not parse is skipped.
	checkInfra(t, infraRun(t, ".github/workflows/bad.yml", "on: push\njobs: [unterminated\n"), nil)
}

// Joining continuation lines keeps its meaning and stays linear.
func TestDockerfileContinuationJoining(t *testing.T) {
	text := "RUN apt-get update \\\n    # a comment inside the instruction\n    && apt-get install -y curl \\\n    && rm -rf /var/lib/apt/lists/*\nUSER app\n"
	got := parseDockerfile(text)
	if len(got) != 2 || got[0].name != "RUN" || got[0].line != 1 || got[1].name != "USER" || got[1].line != 5 {
		t.Fatalf("instructions = %+v", got)
	}
	if want := "apt-get update  && apt-get install -y curl  && rm -rf /var/lib/apt/lists/*"; got[0].args != want {
		t.Fatalf("args = %q, want %q", got[0].args, want)
	}
	// 20,000 continuation lines: quadratic joining would take minutes.
	var b strings.Builder
	b.WriteString("RUN true \\\n")
	for i := 0; i < 20000; i++ {
		b.WriteString("  && echo step \\\n")
	}
	b.WriteString("  && true\n")
	start := time.Now()
	long := parseDockerfile(b.String())
	if len(long) != 1 || !strings.HasSuffix(long[0].args, "&& true") {
		t.Fatalf("long instruction parsed into %d instructions", len(long))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("parsing took %s", d)
	}
}
