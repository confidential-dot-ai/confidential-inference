{{/* Model identity is independent of how the verified files reach the worker. */}}
{{- define "confidential-inference.shellArgument" -}}
{{- printf "'%s'" (replace "'" "'\"'\"'" .) -}}
{{- end }}

{{- define "confidential-inference.modelManifestSha256" -}}
{{- $name := .Values.inference.model.mountVerification.revisionMetadata -}}
{{- $pin := "" -}}
{{- range $file := include "confidential-inference.expectedFiles" . | fromJsonArray -}}
{{- if hasPrefix (printf "%s=" $name) $file -}}
{{- $digest := trimPrefix (printf "%s=" $name) $file -}}
{{- if and $pin (ne $pin $digest) -}}{{ fail "model manifest pins disagree" }}{{- end -}}
{{- $pin = $digest -}}
{{- end -}}
{{- end -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $pin) -}}
{{- fail "modelIdentity needs the manifest SHA-256 in inference.model.mountVerification" -}}
{{- end -}}
{{- $pin -}}
{{- end }}

{{- define "confidential-inference.checkModelIdentity" -}}
{{- if .Values.modelIdentity.enabled -}}
{{- if .Values.workloadOverridesEnabled -}}
{{- fail "modelIdentity does not permit workloadOverridesEnabled to replace its enforced model policy" -}}
{{- end -}}
{{- if .Values.inference.pd.enabled -}}
{{- fail "modelIdentity currently requires a regular worker, not a prefill/decode pair" -}}
{{- end -}}
{{- if or .Values.inference.workerExtraArgs .Values.inference.speculativeAlgorithm -}}
{{- fail "modelIdentity does not permit extra worker arguments or unverified speculative model inputs" -}}
{{- end -}}
{{- if or (not .Values.inference.enabled) (not .Values.router.enabled) (eq .Values.inference.mode "simulator") -}}
{{- fail "modelIdentity requires an inference worker and router, not a simulator" -}}
{{- end -}}
{{- if ne .Values.inference.engineImage "confidentialSglangEngine" -}}
{{- fail "modelIdentity requires the generic confidential-sglang engine" -}}
{{- end -}}
{{- if eq .Values.inference.attestedWorkload .Values.router.attestedWorkload -}}
{{- fail "modelIdentity requires distinct router and worker workload entries" -}}
{{- end -}}
{{- if .Values.inference.attestedWorkloads -}}
{{- fail "modelIdentity uses one inference.attestedWorkload for every replica" -}}
{{- end -}}
{{- $_ := include "confidential-inference.modelManifestSha256" . -}}
{{- range $alias, $backends := .Values.runtimeConfig.modelRoutes -}}
{{- if or (ne (len $backends) 1) (ne (first $backends) $.Values.inference.model.name) -}}
{{- fail "modelIdentity routes must select only inference.model.name" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}
