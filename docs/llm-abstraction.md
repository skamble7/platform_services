# LLM Provider Abstraction — polyllm & ConfigForge

## The Problem

Every platform in the ecosystem (ASTRA, Raina, Zeta, Orko) needs to call an LLM. Without abstraction, each platform would end up doing something like this:

```python
# ❌ The problem — this lives inside platform business logic
import openai

client = openai.AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
response = await client.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    temperature=0.1,
)
text = response.choices[0].message.content
```

This approach creates four compounding problems as the platform grows:

### 1. Provider lock-in inside business logic

The call to `openai.AsyncOpenAI(...)` is not a configuration decision — it is a hard code dependency. Switching to Bedrock, Gemini, or an internal gateway requires finding and rewriting every call site across every platform.

### 2. Secret sprawl

Every platform service must carry `OPENAI_API_KEY` (or equivalent) in its own environment. Rotating a key means updating it in every deployment individually. There is no single source of truth for which services use which key.

### 3. Config duplication

The choice of model, temperature, timeout, and retry settings is duplicated in every service that calls an LLM. When the architecture team decides to move all platforms from `gpt-4o` to `gpt-4o-2024-11-20`, the change must be coordinated and deployed across every platform simultaneously.

### 4. No per-platform governance

There is no way to give ASTRA a different model or budget than Zeta, or to give the `raina` platform access to a more capable model for complex reasoning without giving it to all platforms. Config is not namespaced.

---

## The Solution: Two Layers

The solution separates the problem into two concerns handled by two components:

```
Platform Code (ASTRA, Raina, Zeta, Orko)
        │
        │  carries only a reference string
        │  "prod.llm.openai.astra.primary"
        ▼
┌──────────────────────────────────────┐
│           polyllm                    │  ← provider abstraction layer
│   RemoteConfigLoader.load(ref)       │
│        │                             │
│        ▼                             │
│   ConfigForge  GET /config/resolve/  │  ← config registry
│        │                             │
│        ▼                             │
│   ModelProfile { provider, model,    │
│     temperature, api_key_ref, ... }  │
│        │                             │
│        ▼                             │
│   SecretProvider resolves api_key    │
│        │                             │
│        ▼                             │
│   ProviderAdapter (OpenAI / GenAI /  │
│     Bedrock / Gateway)               │
└──────────────────────────────────────┘
        │
        │  LangChain chat model
        ▼
   OpenAI API / Bedrock / Gemini / Gateway
```

---

## Layer 1 — polyllm: Provider Abstraction

polyllm is a thin library that lives inside platform codebases. Its job is to accept a configuration (either inline or fetched from ConfigForge) and produce a single, consistent `chat()` interface regardless of which provider is underneath.

### What it provides

**A unified interface:** every provider looks identical to the caller.

```python
result = await client.chat([
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Analyse this system..."},
])
print(result.text)  # always a plain string, regardless of provider
```

**A provider registry:** internally, polyllm maps the `provider` field to a `ProviderAdapter` that knows how to initialise that provider's LangChain model with the right parameters.

| `provider` | Adapter | Underlying SDK |
|------------|---------|----------------|
| `openai` | `OpenAIAdapter` | `langchain-openai` |
| `google_genai` | `GoogleGenAIAdapter` | `langchain-google-genai` |
| `bedrock` | `BedrockAdapter` | `langchain-aws` |
| `google_vertexai` | `GoogleVertexAIAdapter` | `langchain-google-vertexai` *(planned)* |

**Secret resolution:** API keys are never passed directly. Instead, `ModelProfile` holds a *reference* (`api_key_ref: "env:OPENAI_API_KEY"`). polyllm resolves the reference at call time through a `SecretProvider` chain, keeping secrets out of config files and application code.

### What platform code looks like with polyllm

```python
# ✅ Platform code is now provider-agnostic
from polyllm import RemoteConfigLoader

loader = RemoteConfigLoader(base_url=settings.CONFIG_FORGE_URL)
client = await loader.load(settings.LLM_CONFIG_REF)

result = await client.chat(messages)
```

The platform has no import from `openai`, `anthropic`, `boto3`, or any provider SDK. It does not know or care which provider is configured. Swapping providers is a config change, not a code change.

---

## Layer 2 — ConfigForge: Config Registry

ConfigForge is the platform service that acts as the single source of truth for all configuration records. It stores `ModelProfile` payloads (and in the future, storage configs, messaging configs, etc.) identified by a canonical reference string.

### Canonical reference format

```
{env}.{kind}[.{provider}][.{platform}].{name}
```

A reference encodes **who** is using **what** in **which environment**:

| Reference | Meaning |
|-----------|---------|
| `prod.llm.openai.default` | The shared OpenAI config for all production services |
| `prod.llm.openai.astra.primary` | ASTRA's own OpenAI config in production |
| `dev.llm.bedrock.zeta.modernization` | Zeta's Bedrock config in development |
| `global.llm.google_genai.default` | A Gemini config valid across all environments |

The `platform` segment is the namespace that enables per-platform governance: ASTRA can run `gpt-4o` at `temperature: 0.1` while Orko runs `o3` at `temperature: 1.0` — registered and managed independently, with no coordination overhead.

### What ConfigForge stores

Each config entry is a MongoDB document:

```json
{
  "ref": "prod.llm.openai.astra.primary",
  "env": "prod",
  "kind": "llm",
  "provider": "openai",
  "platform": "astra",
  "name": "primary",
  "data": {
    "provider": "openai",
    "model": "gpt-4o",
    "temperature": 0.1,
    "api_key_ref": "env:OPENAI_API_KEY"
  }
}
```

The `data` field is the `ModelProfile` that polyllm consumes. Updating it — swapping the model, changing temperature, rotating the key reference — takes effect on the next call from any platform, with no redeployment.

### Secret storage in ConfigForge

ConfigForge stores secret *references*, not raw values, using polyllm's scheme-prefixed format:

| Scheme | Example | Where the key actually lives |
|--------|---------|------------------------------|
| `env:` | `env:OPENAI_API_KEY` | Deployment environment (Docker, K8s) |
| `literal:` | `literal:sk-abc...` | Inline in ConfigForge (MongoDB) |
| `vault:` *(planned)* | `vault:secret/llm/openai#api_key` | HashiCorp Vault |

The migration path is intentionally incremental: start with `literal:` (simple, no external dependency), move to `vault:` when the organisation is ready. The only change required is updating `data.api_key_ref` in ConfigForge — no platform code changes, no redeployments.

---

## How the Two Layers Work Together

Here is the full lifecycle of a single LLM call from a platform:

```
1. Platform code calls:
   client = await loader.load("prod.llm.openai.astra.primary")

2. RemoteConfigLoader makes:
   GET http://config-forge-service:8040/config/resolve/prod.llm.openai.astra.primary

3. ConfigForge looks up the ref in MongoDB and returns the config entry:
   { "data": { "provider": "openai", "model": "gpt-4o", "api_key_ref": "env:OPENAI_API_KEY" } }

4. polyllm constructs a ModelProfile from data.

5. polyllm resolves "env:OPENAI_API_KEY" via SecretProvider:
   → reads os.environ["OPENAI_API_KEY"] → "sk-..."

6. polyllm selects the OpenAIAdapter from its registry.

7. OpenAIAdapter initialises ChatOpenAI(model="gpt-4o", api_key="sk-...", temperature=0.1)

8. Platform calls client.chat(messages)
   → LangChain invokes the OpenAI API
   → returns ChatResult(text="...", raw={...})
```

The platform participated in exactly two of these eight steps: step 1 and step 8. Everything else is handled by the abstraction layers.

---

## Before and After

### Before

```
ASTRA service
  ├── import openai                        # provider hard-coded
  ├── OPENAI_API_KEY in .env               # secret duplicated here
  ├── model = "gpt-4o"  in code            # config hard-coded
  └── ChatCompletion.create(...)           # provider API hard-coded

Raina service
  ├── import openai                        # same provider, duplicated
  ├── OPENAI_API_KEY in .env               # same secret, duplicated
  ├── model = "gpt-4o"  in code            # same config, duplicated
  └── ChatCompletion.create(...)

Zeta service
  ├── import boto3  (Bedrock)              # different provider, different code path
  ├── AWS_ACCESS_KEY_ID in .env
  ├── model = "anthropic.claude-3-5..."
  └── bedrock.invoke_model(...)
```

Changing the model for any platform = code change + redeployment.
Rotating a key = update every service's environment + redeploy.
Adding a new provider to any platform = new SDK dependency + new code path.

### After

```
ASTRA service
  ├── LLM_CONFIG_REF = "prod.llm.openai.astra.primary"   # just a ref
  └── await loader.load(settings.LLM_CONFIG_REF)          # one line

Raina service
  ├── LLM_CONFIG_REF = "prod.llm.openai.raina.primary"
  └── await loader.load(settings.LLM_CONFIG_REF)

Zeta service
  ├── LLM_CONFIG_REF = "prod.llm.bedrock.zeta.modernization"
  └── await loader.load(settings.LLM_CONFIG_REF)          # same line, different provider

ConfigForge (one place)
  ├── prod.llm.openai.astra.primary  → { model: gpt-4o, api_key_ref: env:OPENAI_API_KEY }
  ├── prod.llm.openai.raina.primary  → { model: gpt-4o, api_key_ref: env:OPENAI_API_KEY }
  └── prod.llm.bedrock.zeta.modernization → { model: claude-3-5-sonnet, aws_region: us-east-1 }
```

Changing the model for ASTRA = `PUT /config/{id}` with new `data.model`. Zero deployments.
Rotating a key = update `api_key_ref` in ConfigForge. Zero deployments.
ASTRA switches from OpenAI to Bedrock = register a new config entry, update `LLM_CONFIG_REF`. No code changes.

---

## Governance Summary

| Concern | Owner | Mechanism |
|---------|-------|-----------|
| Which provider | Ops / infra | ConfigForge entry per platform |
| Which model | Ops / architect | `data.model` in ConfigForge |
| API keys | Ops / secrets team | `data.api_key_ref` in ConfigForge |
| Calling the LLM | Platform developer | `loader.load(ref)` + `client.chat()` |
| Adding a new provider | Platform library team | New `ProviderAdapter` in polyllm |

The separation is clean: platform developers write business logic, not infrastructure decisions. Ops owns the config registry.
