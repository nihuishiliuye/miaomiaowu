package substore

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ShadowrocketTemplateProducer implements Shadowrocket format converter
type ShadowrocketTemplateProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewShadowrocketTemplateProducer creates a new Shadowrocket template producer
func NewShadowrocketTemplateProducer() *ShadowrocketTemplateProducer {
	return &ShadowrocketTemplateProducer{
		producerType: "clash-to-shadowrocket",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *ShadowrocketTemplateProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Shadowrocket format
func (p *ShadowrocketTemplateProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	// 如果只需要内部格式或没有完整配置，使用原有的简化逻辑
	if outputType == "internal" || opts.FullConfig == nil {
		return p.produceProxiesOnly(proxies, outputType, opts)
	}

	// 生成完整的 Shadowrocket 配置
	return p.produceFullConfig(proxies, opts)
}

// produceProxiesOnly 只生成节点部分（向后兼容）
func (p *ShadowrocketTemplateProducer) produceProxiesOnly(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	result := p.transformProxies(proxies, opts)

	// Return based on output type
	if outputType == "internal" {
		return result, nil
	}

	// Generate YAML string
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for _, proxy := range result {
		jsonBytes, err := json.Marshal(proxy)
		if err != nil {
			continue
		}
		sb.WriteString("  - ")
		sb.Write(jsonBytes)
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// produceFullConfig 输出完整的 Clash YAML 配置，proxies 经过 Shadowrocket 兼容转换。
// Shadowrocket 订阅导入原生支持 Clash YAML 格式。
func (p *ShadowrocketTemplateProducer) produceFullConfig(proxies []Proxy, opts *ProduceOptions) (string, error) {
	transformed := p.transformProxies(proxies, opts)

	configCopy := make(map[string]interface{})
	for k, v := range opts.FullConfig {
		configCopy[k] = v
	}

	proxiesIface := make([]interface{}, len(transformed))
	for i, px := range transformed {
		proxiesIface[i] = map[string]interface{}(px)
	}
	configCopy["proxies"] = proxiesIface

	yamlBytes, err := yaml.Marshal(configCopy)
	if err != nil {
		return "", fmt.Errorf("marshal clash yaml: %w", err)
	}
	return string(yamlBytes), nil
}

// transformProxies 转换节点
func (p *ShadowrocketTemplateProducer) transformProxies(proxies []Proxy, opts *ProduceOptions) []Proxy {
	supportedVMessCiphers := map[string]bool{
		"auto": true, "none": true, "zero": true,
		"aes-128-gcm": true, "chacha20-poly1305": true,
	}

	var result []Proxy
	for _, proxy := range proxies {
		proxyType := p.helper.GetProxyType(proxy)

		// Filter unsupported types
		if !opts.IncludeUnsupportedProxy {
			if proxyType == "snell" && GetInt(proxy, "version") >= 4 {
				continue
			}
			if proxyType == "mieru" || proxyType == "sudoku" || proxyType == "naive" {
				continue
			}
			// anytls with unsupported network
			if proxyType == "anytls" {
				network := GetString(proxy, "network")
				if network != "" && network != "tcp" {
					continue
				}
				if network == "tcp" && IsPresent(proxy, "reality-opts") {
					continue
				}
			}
		}

		transformed := p.helper.CloneProxy(proxy)

		// VMess specific transformations
		if proxyType == "vmess" {
			// Handle aead
			if IsPresent(transformed, "aead") {
				if GetBool(transformed, "aead") {
					transformed["alterId"] = 0
				}
				delete(transformed, "aead")
			}

			// SNI -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}

			// Cipher validation
			if IsPresent(transformed, "cipher") {
				cipher := GetString(transformed, "cipher")
				if !supportedVMessCiphers[cipher] {
					transformed["cipher"] = "auto"
				}
			}
		}

		// TUIC transformations
		if proxyType == "tuic" {
			// Ensure alpn is array
			if IsPresent(transformed, "alpn") {
				alpnVal := transformed["alpn"]
				if alpnSlice, ok := alpnVal.([]interface{}); ok {
					transformed["alpn"] = alpnSlice
				} else if alpnStr, ok := alpnVal.(string); ok {
					transformed["alpn"] = []string{alpnStr}
				}
			}

			// TFO -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
			}

			// Default version
			token := GetString(transformed, "token")
			if token == "" && !IsPresent(transformed, "version") {
				transformed["version"] = 5
			}
		}

		// Hysteria transformations
		if proxyType == "hysteria" {
			// auth_str -> auth-str
			if IsPresent(transformed, "auth_str") && !IsPresent(transformed, "auth-str") {
				transformed["auth-str"] = GetString(transformed, "auth_str")
			}

			// Ensure alpn is array
			if IsPresent(transformed, "alpn") {
				alpnVal := transformed["alpn"]
				if alpnSlice, ok := alpnVal.([]interface{}); ok {
					transformed["alpn"] = alpnSlice
				} else if alpnStr, ok := alpnVal.(string); ok {
					transformed["alpn"] = []string{alpnStr}
				}
			}

			// TFO -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
			}
		}

		// Hysteria2 transformations
		if proxyType == "hysteria2" {
			// Ensure alpn is array
			if IsPresent(transformed, "alpn") {
				alpnVal := transformed["alpn"]
				if alpnSlice, ok := alpnVal.([]interface{}); ok {
					transformed["alpn"] = alpnSlice
				} else if alpnStr, ok := alpnVal.(string); ok {
					transformed["alpn"] = []string{alpnStr}
				}
			}

			// TFO -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
			}
		}

		// WireGuard transformations
		if proxyType == "wireguard" {
			// Keepalive
			if !IsPresent(transformed, "keepalive") && IsPresent(transformed, "persistent-keepalive") {
				transformed["keepalive"] = GetInt(transformed, "persistent-keepalive")
			}
			transformed["persistent-keepalive"] = GetInt(transformed, "keepalive")

			// Preshared key
			if !IsPresent(transformed, "preshared-key") && IsPresent(transformed, "pre-shared-key") {
				transformed["preshared-key"] = GetString(transformed, "pre-shared-key")
			}
			transformed["pre-shared-key"] = GetString(transformed, "preshared-key")
		}

		// Snell transformations
		if proxyType == "snell" {
			version := GetInt(transformed, "version")
			if version < 3 {
				delete(transformed, "udp")
			}
		}

		// VLESS transformations
		if proxyType == "vless" {
			// SNI -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}
		}

		// Handle HTTP network options for VMess/VLESS
		network := GetString(transformed, "network")
		if (proxyType == "vmess" || proxyType == "vless") && network == "http" {
			if httpOpts := GetMap(transformed, "http-opts"); httpOpts != nil {
				// Ensure path is array
				if IsPresent(httpOpts, "path") {
					if path, ok := httpOpts["path"].(string); ok {
						httpOpts["path"] = []string{path}
					}
				}

				// Ensure headers.Host is array
				if headers := GetMap(httpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						headers["Host"] = []string{host}
					}
				}
			}
		}

		// 处理xhttp参数
		if proxyType == "vless" && network == "xhttp" {
			if xhttpOpts := GetMap(transformed, "xhttp-opts"); xhttpOpts != nil {
				transformed["obfs"] = network
				if path, ok := xhttpOpts["path"].(string); ok {
					transformed["path"] = path
				}

				if headers := GetMap(xhttpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						transformed["obfsParam"] = host
					}
				}
			}
		}

		// 兼容0.3.7后续版本xhttp改为splithttp的情况
		if proxyType == "vless" && (network == "splithttp" || network == "xhttp") {
			transformed["network"] = "xhttp"
			transformed["obfs"] = "xhttp"
			if splithttpOpts := GetMap(transformed, "splithttp-opts"); splithttpOpts != nil {
				if path, ok := splithttpOpts["path"].(string); ok {
					transformed["path"] = path
				}

				if headers := GetMap(splithttpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						transformed["obfsParam"] = host
					}
				}
			} else if xhttpOpts := GetMap(transformed, "xhttp-opts"); xhttpOpts != nil {
				if path, ok := xhttpOpts["path"].(string); ok {
					transformed["path"] = path
				}

				if headers := GetMap(xhttpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						transformed["obfsParam"] = host
					}
				}
			}
		}

		// Handle H2 network options
		if (proxyType == "vmess" || proxyType == "vless") && network == "h2" {
			if h2Opts := GetMap(transformed, "h2-opts"); h2Opts != nil {
				// Ensure path is string (take first element if array)
				if pathSlice, ok := h2Opts["path"].([]interface{}); ok && len(pathSlice) > 0 {
					h2Opts["path"] = pathSlice[0]
				}

				// Ensure host is array
				if headers := GetMap(h2Opts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						headers["host"] = []string{host}
					}
				}
			}
		}

		// Handle WS network early data
		if network == "ws" {
			wsOpts := GetMap(transformed, "ws-opts")
			if wsOpts == nil {
				wsOpts = make(map[string]interface{})
				transformed["ws-opts"] = wsOpts
			}

			path := GetString(wsOpts, "path")
			if path != "" {
				re := regexp.MustCompile(`^(.*?)(?:\?ed=(\d+))?$`)
				matches := re.FindStringSubmatch(path)
				if len(matches) > 0 {
					wsOpts["path"] = matches[1]
					if len(matches) > 2 && matches[2] != "" {
						wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
						ed, _ := strconv.Atoi(matches[2])
						wsOpts["max-early-data"] = ed
					}
				}
			} else {
				wsOpts["path"] = "/"
			}
		}

		// SS shadow-tls transformations
		if proxyType == "ss" {
			if IsPresent(transformed, "shadow-tls-password") && !IsPresent(transformed, "plugin") {
				transformed["plugin"] = "shadow-tls"
				pluginOpts := make(map[string]interface{})
				pluginOpts["host"] = GetString(transformed, "shadow-tls-sni")
				pluginOpts["password"] = GetString(transformed, "shadow-tls-password")
				pluginOpts["version"] = GetInt(transformed, "shadow-tls-version")
				transformed["plugin-opts"] = pluginOpts

				delete(transformed, "shadow-tls-password")
				delete(transformed, "shadow-tls-sni")
				delete(transformed, "shadow-tls-version")
			}
		}

		// Handle plugin-opts TLS
		if pluginOpts := GetMap(transformed, "plugin-opts"); pluginOpts != nil {
			if GetBool(pluginOpts, "tls") && IsPresent(transformed, "skip-cert-verify") {
				pluginOpts["skip-cert-verify"] = GetBool(transformed, "skip-cert-verify")
			}
		}

		// Delete tls for certain proxy types
		deleteTLSTypes := map[string]bool{
			"trojan": true, "tuic": true, "hysteria": true,
			"hysteria2": true, "juicity": true, "anytls": true,
			"naive": true,
		}
		if deleteTLSTypes[proxyType] {
			delete(transformed, "tls")
		}

		// Handle tls-fingerprint -> fingerprint
		if IsPresent(transformed, "tls-fingerprint") {
			transformed["fingerprint"] = GetString(transformed, "tls-fingerprint")
		}
		delete(transformed, "tls-fingerprint")

		// Clean up fields
		p.helper.RemoveProxyFields(transformed,
			"subName", "collectionName", "id", "resolved", "no-resolve")

		// Remove null and underscore-prefixed fields
		for key := range transformed {
			if transformed[key] == nil || strings.HasPrefix(key, "_") {
				delete(transformed, key)
			}
		}

		// Clean up grpc options
		if network == "grpc" {
			if grpcOpts := GetMap(transformed, "grpc-opts"); grpcOpts != nil {
				delete(grpcOpts, "_grpc-type")
				delete(grpcOpts, "_grpc-authority")
			}
		}

		result = append(result, transformed)
	}

	return result
}
