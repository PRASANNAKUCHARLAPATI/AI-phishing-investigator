from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class AIProviderConfig:
    provider: str = "ollama"
    api_key: Optional[str] = None
    model: str = "llama3.2"
    base_url: str = "http://127.0.0.1:11434"
    temperature: float = 0.3
    max_tokens: int = 200


class AIProvider(ABC):
    def __init__(self, config: AIProviderConfig) -> None:
        self.config = config

    @abstractmethod
    def explain(self, indicators: str, email_text: str) -> str:
        ...


class OllamaProvider(AIProvider):
    def explain(self, indicators: str, email_text: str) -> str:
        url = f"{self.config.base_url}/api/generate"
        prompt = (
            "You are a cybersecurity analyst. "
            "Analyze the following email phishing indicators and provide a concise explanation (3-4 sentences) of why this email is suspicious. "
            "Focus on technical details relevant to SOC analysts.\n\n"
            f"Email excerpt: {email_text[:800]}\n\n"
            f"Indicators:\n{indicators}\n\n"
            "Analysis:"
        )
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": self.config.max_tokens,
                "temperature": self.config.temperature,
            },
        }
        resp = requests.post(url, json=payload, timeout=60)
        resp.raise_for_status()
        return resp.json()["response"]


class OpenAIProvider(AIProvider):
    def explain(self, indicators: str, email_text: str) -> str:
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("openai package is required. Install with: pip install ai-phishing-investigator[ai]") from exc

        client = OpenAI(api_key=self.config.api_key)
        prompt = (
            "You are a cybersecurity analyst. "
            "Analyze the following email phishing indicators and provide a concise explanation (3-4 sentences) of why this email is suspicious. "
            "Focus on technical details relevant to SOC analysts.\n\n"
            f"Email excerpt: {email_text[:800]}\n\n"
            f"Indicators:\n{indicators}\n\n"
            "Analysis:"
        )
        response = client.chat.completions.create(
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        return response.choices[0].message.content or "No explanation generated."


class AnthropicProvider(AIProvider):
    def explain(self, indicators: str, email_text: str) -> str:
        if not self.config.api_key:
            raise ValueError("Anthropic API key is required")
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise ImportError("anthropic package is required. Install with: pip install ai-phishing-investigator[ai]") from exc

        client = Anthropic(api_key=self.config.api_key)
        prompt = (
            "You are a cybersecurity analyst. "
            "Analyze the following email phishing indicators and provide a concise explanation (3-4 sentences) of why this email is suspicious. "
            "Focus on technical details relevant to SOC analysts.\n\n"
            f"Email excerpt: {email_text[:800]}\n\n"
            f"Indicators:\n{indicators}\n\n"
            "Analysis:"
        )
        message = client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text


def get_provider(config: Optional[AIProviderConfig] = None) -> AIProvider:
    cfg = config or AIProviderConfig()
    provider_name = cfg.provider.lower()

    if provider_name == "ollama":
        return OllamaProvider(cfg)
    if provider_name == "openai":
        return OpenAIProvider(cfg)
    if provider_name == "anthropic":
        return AnthropicProvider(cfg)
    raise ValueError(f"Unsupported AI provider: {provider_name}")


def ai_explain(
    extracted_data: Dict[str, Any],
    analysis_result: Dict[str, Any],
    case_dir: Optional[Path] = None,
    config: Optional[AIProviderConfig] = None,
) -> bool:
    indicators = "\n".join(f"- {r}" for r in analysis_result["reasons"])
    email_text = extracted_data.get("headers", "") + " " + extracted_data.get("body_text", "") + " " + extracted_data.get("body_html", "")
    email_text = email_text[:1500]

    provider = get_provider(config)

    logger.info("Requesting AI explanation from provider=%s model=%s", config.provider if config else "ollama", (config.model if config else "llama3.2"))
    try:
        explanation = provider.explain(indicators, email_text)
    except Exception as exc:
        logger.error("AI explanation failed: %s", exc)
        explanation = f"AI explanation unavailable: {exc}"

    if case_dir is None:
        case_dir = Path(".")
    ai_path = case_dir / "ai_explanation.txt"
    with open(ai_path, "w", encoding="utf-8") as fh:
        fh.write("AI-POWERED ANALYSIS\n")
        fh.write("=" * 40 + "\n\n")
        fh.write(explanation)
        fh.write("\n")

    with open(case_dir / "report.txt", "a", encoding="utf-8") as fh:
        fh.write("\n\n" + "=" * 60 + "\n")
        fh.write("AI-POWERED ANALYSIS\n")
        fh.write("=" * 60 + "\n\n")
        fh.write(explanation)
        fh.write("\n")

    logger.info("AI explanation saved to %s", ai_path)
    return True
