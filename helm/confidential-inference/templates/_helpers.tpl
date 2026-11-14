{{- define "confidential-inference.name" -}}
confidential-inference
{{- end }}

{{- define "confidential-inference.labels" -}}
app.kubernetes.io/part-of: {{ include "confidential-inference.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
confidential.ai/environment: {{ .Values.environment | quote }}
{{- end }}

{{- define "confidential-inference.selector" -}}
app.kubernetes.io/part-of: {{ include "confidential-inference.name" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- /* The headless router Service. The gateway accepts `sglang-router` or a
       `router-` name here. */}}
{{- define "confidential-inference.routerService" -}}
router-headless
{{- end }}

{{/*
The inference node of one worker. scheduling.inferenceNodeNames lists one node
per worker index. An empty list places every worker on
scheduling.inferenceNodeName.
*/}}
{{- define "confidential-inference.inferenceNodeName" -}}
{{- $names := .root.Values.scheduling.inferenceNodeNames | default list -}}
{{- if $names -}}
{{- if ge (int .index) (len $names) -}}
{{- fail (printf "scheduling.inferenceNodeNames has no entry for worker %d" (int .index)) -}}
{{- end -}}
{{- index $names (int .index) -}}
{{- else -}}
{{- .root.Values.scheduling.inferenceNodeName -}}
{{- end -}}
{{- end }}

{{/*
The distinct inference nodes, as a JSON list.
*/}}
{{- define "confidential-inference.inferenceNodeNames" -}}
{{- $names := .Values.scheduling.inferenceNodeNames | default list -}}
{{- if $names -}}
{{- $names | uniq | toJson -}}
{{- else -}}
{{- list .Values.scheduling.inferenceNodeName | toJson -}}
{{- end -}}
{{- end }}

{{/*
The model files that the worker checks, as a sorted JSON list of PATH=SHA256.
expectedFileList, when set, replaces the expectedFiles map: a later values
layer cannot remove a key of a map, but it replaces a list.
*/}}
{{- define "confidential-inference.expectedFiles" -}}
{{- $verification := .Values.inference.model.mountVerification -}}
{{- $files := list -}}
{{- if $verification.expectedFileList -}}
{{- range $verification.expectedFileList -}}
{{- $files = append $files (printf "%s=%s" .path .sha256) -}}
{{- end -}}
{{- else -}}
{{- range $name, $digest := $verification.expectedFiles -}}
{{- $files = append $files (printf "%s=%s" $name $digest) -}}
{{- end -}}
{{- end -}}
{{- $files | sortAlpha | toJson -}}
{{- end }}

{{/* Apply source-controlled workload changes to the same chart used for release generation and deployment. */}}
{{- define "confidential-inference.applyWorkloadOverrides" -}}
{{- $root := .root -}}
{{- range $fragment := splitList "\n---\n" .body -}}
{{- $document := fromYaml $fragment -}}
{{- if hasKey $document "Error" -}}{{- fail (get $document "Error") -}}{{- end -}}
{{- if hasKey $document "kind" -}}
{{- $key := printf "%s/%s" $document.kind $document.metadata.name -}}
{{- if and $root.Values.workloadOverridesEnabled (hasKey $root.Values.workloadOverrides $key) -}}
{{- $override := fromYaml (tpl (toYaml (get $root.Values.workloadOverrides $key)) $root) -}}
{{- if hasKey $override "Error" -}}{{- fail (get $override "Error") -}}{{- end -}}
{{- $podOverride := dig "spec" "template" "spec" (dict) $override -}}
{{- if hasKey $podOverride "containers" -}}
{{- $containers := list -}}
{{- $known := dict -}}
{{- range $container := $document.spec.template.spec.containers -}}
{{- $_ := set $known $container.name true -}}
{{- $merged := deepCopy $container -}}
{{- range $change := $podOverride.containers -}}
{{- if eq $change.name $container.name -}}{{- $merged = mergeOverwrite $merged $change -}}{{- end -}}
{{- end -}}
{{- $containers = append $containers $merged -}}
{{- end -}}
{{- range $change := $podOverride.containers -}}
{{- if not (hasKey $known $change.name) -}}{{- fail (printf "unknown container override %s in %s" $change.name $key) -}}{{- end -}}
{{- end -}}
{{- $_ := set $podOverride "containers" $containers -}}
{{- end -}}
{{- $document = mergeOverwrite (deepCopy $document) $override -}}
{{- /* A Deployment strategy is a union: an override replaces it whole, so a
Recreate override drops the chart's rollingUpdate. */ -}}
{{- with dig "spec" "strategy" nil $override -}}
{{- $_ := set $document.spec "strategy" . -}}
{{- end -}}
{{- end }}
---
{{ toYaml $document }}
{{ end -}}
{{ end -}}
{{- end -}}

{{/* Egress to the CDS, which runs as its own VM outside the cluster. The C8s
v0.99.29 pod ruleset admits this port only to C8s's own platform roles, such
as the injected credential clients, but on any address outside the cluster
ranges, and the clients attest the CDS they reach. c8s.cds.cidrs names the
CDS address; the schema refuses an empty list, which would open the port to
every address. */}}
{{- define "confidential-inference.cdsEgress" -}}
- ports:
    - {protocol: TCP, port: {{ .Values.c8s.cds.port }}}
  to:
    {{- range .Values.c8s.cds.cidrs }}
    - ipBlock: {cidr: {{ . | quote }}}
    {{- end }}
{{- end }}

{{/* Model download (inference.model.download). The C8s v0.99.29 worker mounts
its models disk read-only, so a worker that does not read a C8s model volume
downloads the model at each start into an emptyDir. The worker places a
default-medium emptyDir under /var/lib/kubelet, on its encrypted scratch disk
(serial confai-scratch), and the node classifies that mount as encrypted
storage. fetch-model checks every byte against the manifest, whose SHA-256 the
release pins (mountVerification), and wait-for-model checks every byte again
on a read-only mount of the same volume before the server starts.

The C8s worker grants a pod its allowlist exits only once all its main
containers run, so the download runs in the main container that verifies the
model, not in an init container. The volume outlives a container restart, so
fetch-model keeps the files that already match. */}}
{{- define "confidential-inference.modelDownloadDirectory" -}}/mnt/c8s-data/model-download{{- end }}
{{- define "confidential-inference.modelManifestDirectory" -}}/mnt/c8s-data/model-manifest{{- end }}

{{/* Check the download values; return the SHA-256 of the manifest. */}}
{{- define "confidential-inference.modelDownloadManifestSha256" -}}
{{- $download := .Values.inference.model.download -}}
{{- if not $download.hosts -}}
{{- fail "inference.model.download.hosts needs the model source address: the C8s worker admits egress only to an allowlist exit" -}}
{{- end -}}
{{- if not $download.manifest -}}
{{- fail "inference.model.download.manifest is required" -}}
{{- end -}}
{{- $metadata := .Values.inference.model.mountVerification.revisionMetadata -}}
{{- $pin := "" -}}
{{- range $file := include "confidential-inference.expectedFiles" . | fromJsonArray -}}
{{- if hasPrefix (printf "%s=" $metadata) $file -}}
{{- $pin = regexReplaceAll "^.*=" $file "" -}}
{{- end -}}
{{- end -}}
{{- if ne $pin (sha256sum $download.manifest) -}}
{{- fail "inference.model.download.manifest does not match the pinned SHA-256 of mountVerification.revisionMetadata" -}}
{{- end -}}
{{- $pin -}}
{{- end }}

{{/* The command of the container that verifies the model: download, then
exec the argv in the container args (wait-for-model). A stop during the
download stops fetch-model at once. */}}
{{- define "confidential-inference.modelDownloadCommand" -}}
{{- $download := .Values.inference.model.download -}}
{{- $fetch := printf "/usr/local/bin/fetch-model --endpoint=https://%s fetch --path=%s --manifest=%s/manifest.json --manifest-sha256=%s --revision-metadata=%s" (index $download.hosts 0).serverName (include "confidential-inference.modelDownloadDirectory" .) (include "confidential-inference.modelManifestDirectory" .) (include "confidential-inference.modelDownloadManifestSha256" .) .Values.inference.model.mountVerification.revisionMetadata -}}
{{- list "/bin/sh" "-c" (printf "trap 'kill $f 2>/dev/null; wait $f; exit 143' TERM INT; %s & f=$!; wait $f || exit $?; trap - TERM INT; exec \"$@\"" $fetch) "sh" | toJson -}}
{{- end }}

{{/* The pinned addresses of the model source. Each is one allowlist exit. */}}
{{- define "confidential-inference.modelDownloadHostAliases" -}}
hostAliases:
  {{- range .Values.inference.model.download.hosts }}
  - ip: {{ .address | quote }}
    hostnames: [{{ .serverName | quote }}]
  {{- end }}
{{- end }}

{{/* The mounts of the container that downloads and verifies the model. */}}
{{- define "confidential-inference.modelDownloadMounts" -}}
- name: model-download
  mountPath: {{ include "confidential-inference.modelDownloadDirectory" .root }}
- name: model-download
  mountPath: {{ .path }}
  readOnly: true
- name: model-manifest
  mountPath: {{ include "confidential-inference.modelManifestDirectory" .root }}
  readOnly: true
{{- end }}

{{- define "confidential-inference.modelDownloadVolumes" -}}
- name: model-download
  emptyDir:
    sizeLimit: {{ .Values.inference.model.download.sizeLimit }}
- name: model-manifest
  configMap:
    name: model-manifest
{{- end }}

{{/* The image of the worker containers: the `images` entry that
inference.workerImage names. The framework release sets every image. */}}
{{- define "confidential-inference.workerImage" -}}
{{- $key := .Values.inference.workerImage | default "sglangWorker" -}}
{{- required (printf "inference.workerImage names images.%s, which is not set" $key) (index .Values.images $key) -}}
{{- end }}
