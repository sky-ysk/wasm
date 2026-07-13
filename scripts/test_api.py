#!/usr/bin/env python3
"""测试 DashScope API 连接是否正常"""

import json
import urllib.request
import urllib.error
from pathlib import Path

def load_env(env_path):
    env_vars = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip()
    return env_vars

env = load_env(Path(__file__).parent.parent / ".env")
api_key = env.get("DASHSCOPE_API_KEY", "")
base_url = env.get("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
model = env.get("DASHSCOPE_MODEL", "qwen-plus")

# 检查 Key 是否已配置
if not api_key or "在这里" in api_key:
    print("❌ API Key 未配置，请先编辑 .env 文件")
    exit(1)

print(f"✓ API Key 已配置（{api_key[:6]}...{api_key[-4:]}）")
print(f"✓ Base URL: {base_url}")
print(f"✓ Model: {model}")
print()

# 发送最小测试请求
payload = json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": "回复'连接成功'两个字即可"}],
    "max_tokens": 20,
    "temperature": 0
}).encode("utf-8")

req = urllib.request.Request(
    f"{base_url}/chat/completions",
    data=payload,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    },
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        reply = data["choices"][0]["message"]["content"]
        print(f"✓ API 调用成功！")
        print(f"✓ 模型回复: {reply}")
        print(f"✓ 使用 token: {data.get('usage', {}).get('total_tokens', 'N/A')}")
        print()
        print("🎉 DashScope API 配置正常，可以开始实验了！")
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8", errors="replace")
    print(f"❌ HTTP 错误 {e.code}: {body[:300]}")
except Exception as e:
    print(f"❌ 连接失败: {e}")
