# Provider jurisdiction corpus

A registry-based jurisdiction snapshot of ~26 public LLM API hosts, produced by
`provenance-probe network --hosts-file`. Classification is by the endpoint
registries (`corpus.py`: PRC / aggregator / first-party), **not** IP geolocation —
because providers front their APIs with CDNs, IP jurisdiction is unreliable.

> Snapshot for reference; re-run the sweep to refresh. Chinese-origin companies
> here are publicly known as such.

| Host | Jurisdiction | Operator |
|---|---|---|
| `api.baichuan-ai.com` | PRC | Baichuan |
| `api.deepseek.com` | PRC | DeepSeek |
| `api.lingyiwanwu.com` | PRC | 01.AI (Yi) |
| `api.moonshot.cn` | PRC | Moonshot (Kimi) |
| `api.stepfun.com` | PRC | StepFun |
| `ark.cn-beijing.volces.com` | PRC | ByteDance Volcano Engine (Doubao) |
| `dashscope.aliyuncs.com` | PRC | Alibaba DashScope (Qwen) |
| `hunyuan.tencentcloudapi.com` | PRC | Tencent Hunyuan |
| `open.bigmodel.cn` | PRC | Zhipu AI (GLM) - mainland |
| `qianfan.baidubce.com` | PRC | Baidu Qianfan |
| `api.minimaxi.com` | PRC-operator | MiniMax |
| `chat.z.ai` | PRC-operator | Zhipu AI (GLM) - international front |
| `api.deepinfra.com` | non-PRC-operator | DeepInfra |
| `api.fireworks.ai` | non-PRC-operator | Fireworks |
| `api.groq.com` | non-PRC-operator | Groq |
| `api.novita.ai` | non-PRC-operator | Novita |
| `api.perplexity.ai` | non-PRC-operator | Perplexity |
| `api.replicate.com` | non-PRC-operator | Replicate |
| `api.together.xyz` | non-PRC-operator | Together AI |
| `openrouter.ai` | non-PRC-operator | OpenRouter |
| `api.anthropic.com` | non-PRC-firstparty | Anthropic |
| `api.cohere.com` | non-PRC-firstparty | Cohere |
| `api.mistral.ai` | non-PRC-firstparty | Mistral AI |
| `api.openai.com` | non-PRC-firstparty | OpenAI |
| `api.x.ai` | non-PRC-firstparty | xAI (Grok) |
| `generativelanguage.googleapis.com` | non-PRC-firstparty | Google (Gemini) |

**Totals:** PRC 10 · PRC-operator 2 · neutral aggregator 8 · first-party 6 · unknown 0.

## Why IP geolocation is not used

Observed CDN fronting during the sweep: `api.deepseek.com` resolves through
**AWS CloudFront**, `api.moonshot.cn` through **Alicloud**, `api.stepfun.com`
through **Volcano-Engine**. An IP-geolocation check would place DeepSeek in the US.
Only the known-endpoint registry (and `.cn` TLD / RDAP operator) correctly resolves
jurisdiction. Provenance (which weights) still requires the tokenizer/behavioral layers.
