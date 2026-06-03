"""
LLM client for OpenHack.
"""

import asyncio
import json
import logging
from typing import Any, Callable, Optional
from dataclasses import dataclass, field

import openai

from openhack.config import settings

logger = logging.getLogger(__name__)


@dataclass
class Message:
    role: str
    content: Optional[str] = None
    tool_calls: Optional[list[dict]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None
    reasoning_content: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"role": self.role}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls is not None:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id is not None:
            d["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            d["name"] = self.name
        if self.reasoning_content is not None:
            d["reasoning_content"] = self.reasoning_content
        return d


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class ToolResult:
    tool_call_id: str
    content: str

    def to_message(self) -> Message:
        return Message(role="tool", content=self.content, tool_call_id=self.tool_call_id)


@dataclass
class LLMResponse:
    content: Optional[str] = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Optional[dict] = None
    cost: float = 0.0
    reasoning_content: Optional[str] = None


class LLMClient:
    """LLM client for OpenHack."""

    PRICING = {
        "kimi-k2.5": {"input": 0.50, "output": 2.80},
    }

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 8192,
        provider: Optional[str] = None,
        prompt_cache_key: Optional[str] = None,
    ):
        self.provider = provider or settings.llm_provider
        self.model = model or settings.openhack_model_id

        self.temperature = temperature
        self.max_tokens = max_tokens
        self.prompt_cache_key = prompt_cache_key
        self.total_cost: float = 0.0
        self.total_tokens: int = 0
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0

        self._init_client()

    def _init_client(self):
        if not settings.openhack_api_key:
            raise ValueError(
                "OPENHACK_API_KEY is required.\n"
                f"Sign up at: {settings.openhack_app_url}/signup\n"
                "Then run: openhack /setup"
            )
        self.client = openai.AsyncOpenAI(
            api_key=settings.openhack_api_key,
            base_url=settings.openhack_base_url,
            timeout=settings.openhack_read_timeout,
            max_retries=0,
        )

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        pricing = self.PRICING.get(self.model, {"input": 0.50, "output": 2.80})
        return (input_tokens / 1_000_000) * pricing["input"] + (output_tokens / 1_000_000) * pricing["output"]

    def _convert_tools_to_openai_format(self, tools: list[dict]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for tool in tools
        ]

    def _convert_messages_to_openai(self, messages: list[Message], system: Optional[str]) -> list[dict]:
        openai_messages = []
        if system:
            openai_messages.append({"role": "system", "content": system})

        for msg in messages:
            if msg.role == "system":
                openai_messages.append({"role": "system", "content": msg.content or ""})
            elif msg.role == "tool":
                openai_messages.append({
                    "role": "tool",
                    "tool_call_id": msg.tool_call_id,
                    "content": msg.content or "",
                })
            elif msg.role == "assistant" and msg.tool_calls:
                openai_messages.append({
                    "role": "assistant",
                    "content": msg.content,
                    "tool_calls": msg.tool_calls,
                })
            else:
                openai_messages.append({"role": msg.role, "content": msg.content or ""})

        return openai_messages

    async def chat(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        system: Optional[str] = None,
        tool_choice: Optional[str] = None,
        on_chunk: Optional[Callable] = None,
    ) -> LLMResponse:
        return await self._chat(messages, tools, system, tool_choice=tool_choice, on_chunk=on_chunk)

    async def _chat(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        system: Optional[str] = None,
        tool_choice: Optional[str] = None,
        on_chunk: Optional[Callable] = None,
    ) -> LLMResponse:
        openai_messages = self._convert_messages_to_openai(messages, system)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            kwargs["tools"] = self._convert_tools_to_openai_format(tools)
            kwargs["tool_choice"] = tool_choice or "auto"
        if self.prompt_cache_key:
            kwargs["prompt_cache_key"] = self.prompt_cache_key

        max_retries = settings.openhack_max_retries
        last_exception = None

        for attempt in range(max_retries + 1):
            stream = None
            try:
                if attempt > 0:
                    wait_time = 5 * (2 ** (attempt - 1))
                    print(f"    Retrying API call (attempt {attempt + 1}/{max_retries + 1}) after {wait_time}s...")
                    await asyncio.sleep(wait_time)

                stream = await self.client.chat.completions.create(**kwargs)

                content_parts: list[str] = []
                reasoning_parts: list[str] = []
                tool_call_acc: dict[int, dict] = {}
                input_tokens = 0
                output_tokens = 0

                async for chunk in stream:
                    if chunk.usage:
                        input_tokens = chunk.usage.prompt_tokens or 0
                        output_tokens = chunk.usage.completion_tokens or 0

                    if not chunk.choices:
                        continue

                    delta = chunk.choices[0].delta

                    if delta.content:
                        content_parts.append(delta.content)
                        if on_chunk:
                            on_chunk("content", delta.content)

                    rc = getattr(delta, "reasoning_content", None)
                    if rc:
                        reasoning_parts.append(rc)
                        if on_chunk:
                            on_chunk("reasoning", rc)

                    if delta.tool_calls:
                        for tc_delta in delta.tool_calls:
                            idx = tc_delta.index
                            if idx not in tool_call_acc:
                                tool_call_acc[idx] = {
                                    "id": tc_delta.id or "",
                                    "name": (tc_delta.function.name if tc_delta.function else "") or "",
                                    "arguments_parts": [],
                                }
                            acc = tool_call_acc[idx]
                            if tc_delta.id:
                                acc["id"] = tc_delta.id
                            if tc_delta.function:
                                if tc_delta.function.name:
                                    acc["name"] = tc_delta.function.name
                                if tc_delta.function.arguments:
                                    acc["arguments_parts"].append(tc_delta.function.arguments)

                content = "".join(content_parts) or None
                reasoning_content = "".join(reasoning_parts) or None

                tool_calls = []
                for idx in sorted(tool_call_acc.keys()):
                    acc = tool_call_acc[idx]
                    raw_args = "".join(acc["arguments_parts"])
                    try:
                        args = json.loads(raw_args) if raw_args else {}
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse tool call arguments: {raw_args[:200]}")
                        args = {}
                    tool_calls.append(ToolCall(id=acc["id"], name=acc["name"], arguments=args))

                if input_tokens == 0 and output_tokens == 0:
                    logger.debug("No usage data in stream — cost will be zero for this call")

                cost = self._calculate_cost(input_tokens, output_tokens)
                self.total_cost += cost
                self.total_tokens += input_tokens + output_tokens
                self.total_input_tokens += input_tokens
                self.total_output_tokens += output_tokens

                llm_response = LLMResponse(
                    content=content,
                    tool_calls=tool_calls,
                    usage={"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": input_tokens + output_tokens},
                    cost=cost,
                )
                llm_response.reasoning_content = reasoning_content
                return llm_response

            except openai.RateLimitError as e:
                last_exception = e
                if stream:
                    try: await stream.close()
                    except Exception: pass
                if attempt == max_retries:
                    raise
            except openai.AuthenticationError as e:
                detail = getattr(e, "message", str(e))
                raise ValueError(
                    f"Authentication failed (401): {detail}\n"
                    f"If this is your OpenHack token, run: openhack /login\n"
                    f"Check that your API key is valid and has not expired."
                ) from e
            except openai.PermissionDeniedError as e:
                detail = getattr(e, "message", str(e))
                if "credits" in detail.lower() or "insufficient" in detail.lower():
                    raise ValueError(
                        f"Insufficient credits. Purchase more at: {settings.openhack_app_url}/settings/billing"
                    ) from e
                raise ValueError(
                    f"Access denied by OpenHack API: {detail}\n"
                    f"Check your API key at: {settings.openhack_app_url}/settings/api-keys"
                ) from e
            except openai.APIStatusError as e:
                if stream:
                    try: await stream.close()
                    except Exception: pass
                if e.status_code >= 500:
                    last_exception = e
                    if attempt == max_retries:
                        raise
                else:
                    raise
            except openai.APITimeoutError as e:
                last_exception = e
                if stream:
                    try: await stream.close()
                    except Exception: pass
                if attempt == max_retries:
                    raise
            except openai.APIConnectionError as e:
                last_exception = e
                if stream:
                    try: await stream.close()
                    except Exception: pass
                if attempt == max_retries:
                    raise
                wait_time = 10 * (2 ** attempt)
                await asyncio.sleep(wait_time)
                continue
            except Exception as e:
                logger.debug(f"OpenHack API error: {e}", exc_info=True)
                if stream:
                    try: await stream.close()
                    except Exception: pass
                raise

        if last_exception:
            raise last_exception
