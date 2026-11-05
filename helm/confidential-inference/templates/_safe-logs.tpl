{{/* Application logs only. This does not read or change C8s log pipelines. */}}
{{- define "confidential-inference.safeLogProcessors" -}}
{{- $contract := .Files.Get "files/safe_events.json" | fromJson -}}
transform/logs:
  # A bad expression or JSON record must never print its input.
  error_mode: silent
  log_statements:
    - 'set(log.attributes, {})'
    - 'set(log.cache["record"], ParseJSON(log.body)) where IsString(log.body) and Len(log.body) <= 4096'
    - 'set(log.body, "")'
    - 'set(log.cache["original_size"], Len(log.cache["record"])) where IsMap(log.cache["record"])'
    - 'set(log.cache["invalid"], false)'
    {{- range $key, $rule := $contract.field_types -}}
      {{- $ref := printf "log.cache[\"record\"][%s]" (toJson $key) -}}
      {{- $test := "" -}}
      {{- if hasKey $rule "enum" -}}
        {{- $choices := list -}}
        {{- range $value := $rule.enum -}}{{- $choices = append $choices (printf "%s == %s" $ref (toJson $value)) -}}{{- end -}}
        {{- $test = printf "IsString(%s) and (%s)" $ref (join " or " $choices) -}}
      {{- else if hasKey $rule "pattern" -}}
        {{- $test = printf "IsString(%s) and IsMatch(%s, %s)" $ref $ref (toJson $rule.pattern) -}}
      {{- else -}}
        {{- $test = printf "(IsInt(%s) or IsDouble(%s)) and %s == Int(%s) and %s >= %.0f and %s <= %.0f" $ref $ref $ref $ref $ref $rule.min $ref $rule.max -}}
      {{- end }}
    - {{ printf "set(log.cache[\"invalid\"], true) where ContainsValue(Keys(log.cache[\"record\"]), %s) and not (%s)" (toJson $key) $test | squote }}
    {{- if hasKey $rule "min" }}
    - {{ printf "set(log.cache[\"record\"][%s], Int(log.cache[\"record\"][%s])) where %s" (toJson $key) (toJson $key) $test | squote }}
    {{- end }}
    {{- end }}
    {{- range $event, $spec := $contract.events }}
    {{- $keys := concat $contract.envelope_fields $spec.fields | uniq -}}
    {{- $conditions := list (printf "log.cache[\"record\"][\"event\"] == %s" (toJson $event)) (printf "log.cache[\"record\"][\"component\"] == %s" (toJson $spec.component)) "log.cache[\"record\"][\"schema_version\"] == 1" "(IsInt(log.cache[\"record\"][\"schema_version\"]) or IsDouble(log.cache[\"record\"][\"schema_version\"]))" "log.cache[\"invalid\"] == false" -}}
    {{- range $key := $spec.required -}}{{- $conditions = append $conditions (printf "log.cache[\"record\"][%s] != nil" (toJson $key)) -}}{{- end }}
    - {{ printf "keep_keys(log.cache[\"record\"], %s) where log.cache[\"record\"][\"event\"] == %s" (toJson $keys) (toJson $event) | squote }}
    - {{ printf "set(log.attributes[\"ci_valid\"], true) where %s and Len(log.cache[\"record\"]) == log.cache[\"original_size\"]" (join " and " $conditions) | squote }}
    {{- end }}
    - 'set(log.cache["record"]["schema_version"], 1) where log.attributes["ci_valid"] == true'
    # Rebuild all exported metadata, including schema URLs and trace context.
    - 'set(log.body, log.cache["record"]) where log.attributes["ci_valid"] == true'
    - 'set(resource.attributes, {})'
    - 'set(resource.attributes["service.name"], "confidential-inference")'
    - 'set(scope.attributes, {})'
    - 'set(scope.name, "ci.safe.v1")'
    - 'set(scope.version, "")'
    - 'set(resource.schema_url, "")'
    - 'set(scope.schema_url, "")'
    - 'set(log.event_name, "")'
    - 'set(log.flags, 0)'
    - 'set(log.dropped_attributes_count, 0)'
    - 'set(resource.dropped_attributes_count, 0)'
    - 'set(scope.dropped_attributes_count, 0)'
    - 'set(log.trace_id, TraceID(0x00000000000000000000000000000000))'
    - 'set(log.span_id, SpanID(0x0000000000000000))'
    - 'set(log.severity_text, "INFO")'
    - 'set(log.severity_number, SEVERITY_NUMBER_INFO)'
filter/safe_logs:
  error_mode: propagate
  logs:
    log_record:
      - 'attributes["ci_valid"] != true'
transform/log_envelope:
  error_mode: propagate
  log_statements:
    - 'set(log.attributes, {})'
    - 'set(log.body, String(log.body))'
{{- end -}}
