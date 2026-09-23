{{- define "confidential-inference.name" -}}
confidential-inference
{{- end }}

{{- define "confidential-inference.workloadClaimsVolume" -}}
- name: c8s-workload-claims
  hostPath:
    path: /var/run/nri-image-policy
    type: Directory
{{- end }}

{{- define "confidential-inference.workloadClaimsSupplementalGroup" -}}
{{- if and .Values.attestationReceipts.enabled (eq .Values.attestationReceipts.attestationApiMode "workload-claims-unix") }}
supplementalGroups: [65532]
{{- end }}
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
    {{- if and .gpuEvidence .root.Values.attestationReceipts.gpuEvidenceFlagEnabled }}
    - --nvidia-gpu-evidence
    {{- end }}
    - --expected-workload={{ .workload }}
    {{- if eq .root.Values.attestationReceipts.attestationApiMode "node-http" }}
    - --attestation-api-url=http://$(HOST_IP):{{ .root.Values.attestationReceipts.attestationApiPort }}
    {{- else }}
    - --attestation-api-url=unix:///run/c8s/workload-claims/attestation-api.sock
    {{- end }}
    - --serving-cert-file=/etc/c8s/certs/tls.crt
    - --mesh-identity-cert-file=/etc/c8s/certs/tls.crt
    - --mesh-identity-key-file=/etc/c8s/certs/tls.key
    - --mesh-identity-ca-file=/etc/c8s/certs/tls.crt
  {{- if eq .root.Values.attestationReceipts.attestationApiMode "node-http" }}
  env:
    - name: HOST_IP
      valueFrom:
        fieldRef:
          fieldPath: status.hostIP
  {{- else }}
  volumeMounts:
    - name: c8s-workload-claims
      mountPath: /run/c8s/workload-claims
      readOnly: true
  {{- end }}
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
