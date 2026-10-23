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
