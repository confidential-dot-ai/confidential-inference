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

{{- define "confidential-inference.cdsAttestSidecar" -}}
- name: cds-attest
  image: {{ .root.Values.images.c8sOperator }}
  imagePullPolicy: IfNotPresent
  command: ["/c8s"]
  args:
    - cds-attest
    - --host={{ .host }}
    - --port={{ .port }}
    - --platform={{ .root.Values.attestationReceipts.platform }}
    - --front-door-mode=webpki
    {{- if and .gpuEvidence (ne .root.Values.attestationReceipts.gpuEvidenceFlagEnabled false) }}
    - --nvidia-gpu-evidence
    {{- end }}
    - --expected-workload={{ .workload }}
    - --attestation-api-url=http://$(HOST_IP):{{ .root.Values.attestationReceipts.attestationApiPort }}
    - --serving-cert-file=/etc/c8s/certs/tls.crt
    - --mesh-identity-cert-file=/etc/c8s/certs/tls.crt
    - --mesh-identity-key-file=/etc/c8s/certs/tls.key
    - --mesh-identity-ca-file=/etc/c8s/certs/tls.crt
  env:
    - name: HOST_IP
      valueFrom:
        fieldRef:
          fieldPath: status.hostIP
  {{- if ne .host "127.0.0.1" }}
  ports:
    - name: cds-attest
      containerPort: {{ .port }}
      protocol: TCP
  {{- end }}
  readinessProbe:
    httpGet:
      path: /readyz
      port: {{ .port }}
    periodSeconds: 10
    timeoutSeconds: 3
    failureThreshold: 3
  livenessProbe:
    httpGet:
      path: /healthz
      port: {{ .port }}
    periodSeconds: 30
    timeoutSeconds: 3
    failureThreshold: 3
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
    readOnlyRootFilesystem: true
    runAsNonRoot: true
  resources:
    {{- toYaml .root.Values.attestationReceipts.resources | nindent 4 }}
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
