package seed

import (
	"errors"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"
)

var (
	k8sPrivileged = infraCheck{
		id: "k8s-privileged-container", title: "Container runs in privileged mode",
		class: "container-privilege", cwe: "CWE-250", severity: "high",
		detail: "A privileged container has every capability and direct access to host devices, so code running in it can take over the node.",
		fix:    "Remove privileged: true and add only the specific capabilities the workload needs.",
	}
	k8sHostNamespace = infraCheck{
		id: "k8s-host-namespace", title: "Pod shares a host namespace",
		class: "container-privilege", cwe: "CWE-250", severity: "high",
		detail: "Sharing the host network, PID or IPC namespace lets the pod see and interfere with processes and traffic that belong to the node and to other pods.",
		fix:    "Remove hostNetwork, hostPID and hostIPC unless the workload is a node agent that cannot work without them.",
	}
	k8sHostPath = infraCheck{
		id: "k8s-hostpath-volume", title: "Pod mounts a path from the host",
		class: "container-privilege", cwe: "CWE-668", severity: "medium",
		detail: "A hostPath volume exposes part of the node's filesystem to the pod. Depending on the path this allows reading other workloads' data or escaping to the node.",
		fix:    "Use a persistent volume claim, configMap, secret or emptyDir instead, or mount the narrowest path read-only.",
	}
	k8sPrivEsc = infraCheck{
		id: "k8s-allow-privilege-escalation", title: "Container may gain privileges",
		class: "container-hardening", cwe: "CWE-250", severity: "medium",
		detail: "allowPrivilegeEscalation is not set to false, so a process in the container can gain more privileges than its parent through setuid binaries.",
		fix:    "Set securityContext.allowPrivilegeEscalation: false on the container.",
	}
	k8sRunAsRoot = infraCheck{
		id: "k8s-run-as-root", title: "Container may run as root",
		class: "container-hardening", cwe: "CWE-250", severity: "medium",
		detail: "Neither runAsNonRoot: true nor a non-zero runAsUser is set, so the container runs as root whenever its image does.",
		fix:    "Set securityContext.runAsNonRoot: true and a non-zero runAsUser on the pod or the container.",
	}
	k8sNoLimits = infraCheck{
		id: "k8s-no-resource-limits", title: "Container has no resource limits",
		class: "container-hardening", cwe: "CWE-770", severity: "low",
		detail: "Without resources.limits one container can consume all CPU and memory on its node and starve the workloads next to it.",
		fix:    "Set resources.limits for cpu and memory on the container.",
	}
	k8sImageLatest = infraCheck{
		id: "k8s-image-unpinned", title: "Container image is untagged or uses latest",
		class: "supply-chain", cwe: "CWE-1357", severity: "low",
		detail: "The image is not pinned to a version, so a restart may run different code than the last one and a compromised upstream release is deployed unnoticed.",
		fix:    "Pin the image to a specific version tag, and preferably to a digest.",
	}
	k8sEnvSecret = infraCheck{
		id: "k8s-env-secret", title: "Secret written into a manifest as a literal env value",
		class: "hardcoded-secret", cwe: "CWE-798", severity: "high",
		detail: "The credential is stored in the manifest in clear text, so everyone who can read the repository or the pod spec can read it.",
		fix:    "Rotate the credential, store the new one in a Secret, and reference it with valueFrom.secretKeyRef.",
	}
)

// yamlDocs parses every document in text. A file that does not parse is not
// an error for a scan: templated manifests (Helm) and half-written files
// are common, and other tools exist to lint YAML.
func yamlDocs(text string) []*yaml.Node {
	var docs []*yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil {
			return nil
		}
		if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
			docs = append(docs, doc.Content[0])
		}
	}
}

// yamlGet returns the key and value nodes for key in a mapping, following
// aliases, or nils.
func yamlGet(n *yaml.Node, key string) (k, v *yaml.Node) {
	n = yamlDeref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i], yamlDeref(n.Content[i+1])
		}
	}
	return nil, nil
}

func yamlDeref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// yamlPath walks nested mappings and returns the value at the end, or nil.
func yamlPath(n *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		_, n = yamlGet(n, k)
		if n == nil {
			return nil
		}
	}
	return n
}

func yamlScalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func yamlTrue(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!bool" && strings.EqualFold(n.Value, "true")
}
func yamlFalse(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!bool" && strings.EqualFold(n.Value, "false")
}

func yamlSeq(n *yaml.Node) []*yaml.Node {
	n = yamlDeref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, yamlDeref(c))
	}
	return out
}

// podSpecPaths says where the pod spec lives for each workload kind.
var podSpecPaths = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"ReplicaSet":  {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

func k8sLeads(rel, text string) []Lead {
	var leads []Lead
	lines := strings.Split(text, "\n")
	for _, doc := range yamlDocs(text) {
		if yamlPath(doc, "apiVersion") == nil {
			continue
		}
		path, ok := podSpecPaths[yamlScalar(yamlPath(doc, "kind"))]
		if !ok {
			continue
		}
		spec := yamlPath(doc, path...)
		if spec == nil || spec.Kind != yaml.MappingNode {
			continue
		}
		leads = append(leads, podSpecLeads(rel, lines, spec)...)
	}
	return leads
}

func podSpecLeads(rel string, lines []string, spec *yaml.Node) []Lead {
	var leads []Lead
	at := func(c infraCheck, n *yaml.Node) {
		leads = append(leads, c.lead(rel, n.Line, lineAt(lines, n.Line)))
	}
	for _, key := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if k, v := yamlGet(spec, key); yamlTrue(v) {
			at(k8sHostNamespace, k)
		}
	}
	for _, vol := range yamlSeq(yamlPath(spec, "volumes")) {
		if k, _ := yamlGet(vol, "hostPath"); k != nil {
			at(k8sHostPath, k)
		}
	}
	podSC := yamlPath(spec, "securityContext")
	for _, list := range []string{"initContainers", "containers"} {
		for _, c := range yamlSeq(yamlPath(spec, list)) {
			if c == nil || c.Kind != yaml.MappingNode {
				continue
			}
			sc := yamlPath(c, "securityContext")
			if k, v := yamlGet(sc, "privileged"); yamlTrue(v) {
				at(k8sPrivileged, k)
			}
			if !yamlFalse(yamlPath(sc, "allowPrivilegeEscalation")) {
				at(k8sPrivEsc, c)
			}
			if !runsAsNonRoot(sc, podSC) {
				at(k8sRunAsRoot, c)
			}
			if limits := yamlPath(c, "resources", "limits"); limits == nil || limits.Kind != yaml.MappingNode || len(limits.Content) == 0 {
				at(k8sNoLimits, c)
			}
			if k, v := yamlGet(c, "image"); v != nil && v.Kind == yaml.ScalarNode && v.Value != "" && imageUnpinned(v.Value) {
				at(k8sImageLatest, k)
			}
			for _, env := range yamlSeq(yamlPath(c, "env")) {
				name := yamlScalar(yamlPath(env, "name"))
				k, v := yamlGet(env, "value")
				if v == nil || v.Kind != yaml.ScalarNode || !looksLikeSecretPair(name, v.Value) {
					continue
				}
				leads = append(leads, k8sEnvSecret.lead(rel, k.Line, "name: "+name+" value: "+redactedValue(k8sEnvSecret.id, v.Value)))
			}
		}
	}
	return leads
}

// runsAsNonRoot applies the Kubernetes precedence: a container setting
// overrides the pod setting, field by field.
func runsAsNonRoot(containerSC, podSC *yaml.Node) bool {
	pick := func(key string) *yaml.Node {
		if v := yamlPath(containerSC, key); v != nil {
			return v
		}
		return yamlPath(podSC, key)
	}
	if yamlTrue(pick("runAsNonRoot")) {
		return true
	}
	uid, err := strconv.Atoi(yamlScalar(pick("runAsUser")))
	return err == nil && uid > 0
}
