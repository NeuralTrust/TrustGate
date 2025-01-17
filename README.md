# TrustGate

<div align="center">

<img src="assets/ai-gateway.svg" alt="AI Gateway Logo" width="100%"/>

*A powerful, AI Gateway designed from scratch for AI*

[![Go Reference](https://pkg.go.dev/badge/github.com/NeuralTrust/TrustGate.svg)](https://pkg.go.dev/github.com/NeuralTrust/TrustGate@v0.1.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/NeuralTrust/TrustGate)](https://goreportcard.com/report/github.com/NeuralTrust/TrustGate)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/neuraltrust/trustgate.svg)](https://hub.docker.com/r/neuraltrust/trustgate)
[![GitHub Actions](https://github.com/NeuralTrust/TrustGate/actions/workflows/ci.yml/badge.svg)](https://github.com/NeuralTrust/TrustGate/actions/workflows/ci.yml)
[![GitHub Actions](https://github.com/NeuralTrust/TrustGate/actions/workflows/security.yml/badge.svg)](https://github.com/NeuralTrust/TrustGate/actions/workflows/security.yml)


[Documentation](https://docs.neuraltrust.ai) |
[Quick Start](https://docs.neuraltrust.ai/category/step-by-step-guide) |
[Community](https://join.slack.com/t/neuraltrustcommunity/shared_invite/zt-2xl47cag6-_HFNpltIULnA3wh4R6AqBg)

</div>

## ✨ Features

- 🚀 **High Performance**: Built in Go for maximum efficiency and minimal latency
- 🌍 **Multi-Provider**: Multiple LLM provider support
- 🤖 **AI-Ready**: Optimized for AI model providers (OpenAI, Anthropic, etc.)
- 🔄 **Fallback Ready**: Built-in model fallback capabilities
- 🔄 **Load Balancing**: Advanced algorithms including round-robin, weighted round-robin, and IP hash
- 🔒 **Security**: Built-in authentication, rate limiting, and token management
- 🔌 **Plugin System**: Extensible architecture for custom functionality
- ⚡ **Real-time Config**: Dynamic configuration without restarts
- ☁️ **Cloud Agnostic**: Deploy anywhere with cloud-agnostic architecture


## 🚀 Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/NeuralTrust/TrustGate.git
cd TrustGate

# Start the services
docker compose -f docker-compose.prod.yaml up -d
```

### Using Kubernetes

```bash
# Apply configurations
kubectl apply -f k8s/storage.yaml
kubectl apply -f k8s/deployment.yaml
```

### Local Development

```bash
# Start dependencies
docker compose up -d redis postgres

# Run the servers
./scripts/run_local.sh
```

## 🏗️ Architecture

TrustGate consists of two main components:

1. **Admin API** (Port 8080)
   - Gateway management
   - Configuration management
   - API key management
   - Plugin configuration

2. **Proxy API** (Port 8081)
   - Request routing
   - Load balancing
   - Plugin execution

## 🔌 Plugins

Extend functionality with plugins:

```go
type Plugin interface {
    Name() string
    Stages() []types.Stage
    AllowedStages() []types.Stage
    Execute(ctx *Context) error
}
```

### Current Plugins:
- Rate Limiter
- Token Rate Limiter
- External API Call

### 🔜 Coming Soon Plugins

#### Security
- **Jailbreak Protection**
  - Azure Prompt Guard
  - AWS Prompt Guard
  - GCP Prompt Guard

- **Toxicity Detection**
  - Open AI Moderation API integration
  - Legacy toxicity detection methods

- **Prompt Moderation**
  - Keywords & REGEX filtering
  - Topic detection (accepted/denied)

- **Data Masking**
  - Pre-defined entity masking
  - Custom data masking (keywords, regex patterns)

- **Network Security**
  - CORS protection
  - SQL Injection prevention
  - Cross-site injection protection

- **Load Balancing**
  - Weight-based routing
  - Round-robin distribution
  - Prompt templates support


## 🤝 Contributing

We love contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📜 License

TrustGate is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=NeuralTrust/TrustGate&type=Date)](https://star-history.com/#NeuralTrust/TrustGate&Date)

## 📫 Community & Support

- [Documentation](https://docs.neuraltrust.ai)
- [Slack Community](https://join.slack.com/t/neuraltrustcommunity/shared_invite/zt-2xl47cag6-_HFNpltIULnA3wh4R6AqBg)
- [GitHub Issues](https://github.com/NeuralTrust/TrustGate/issues)
- [Twitter](https://twitter.com/neuraltrust)
- [Blog](https://neuraltrust.ai/en/resources/blog)


<div align="center">
Made with ❤️ by <a href="https://neuraltrust.ai">NeuralTrust</a>
</div>
