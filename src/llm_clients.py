"""
A small abstraction so agent.py doesn't care which model API it's
talking to. Each client keeps its own native conversation history
internally and exposes the same three methods:

    add_user_message(text)
    add_tool_results(results)      # list[ToolResult]
    generate() -> AgentStep        # {text: str, tool_calls: list[ToolCall]}

Add a new provider by subclassing LLMClient and registering it in
get_client() below — agent.py and tools.py need no changes.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ToolResult:
    tool_call_id: str
    name: str
    content: str


@dataclass
class AgentStep:
    text: str
    tool_calls: list


class LLMClient(ABC):
    def __init__(self, model: str, system_prompt: str, tool_schemas: list):
        self.model = model
        self.system_prompt = system_prompt
        self.tool_schemas = tool_schemas

    @abstractmethod
    def add_user_message(self, text: str) -> None: ...

    @abstractmethod
    def add_tool_results(self, results: list) -> None: ...

    @abstractmethod
    def generate(self) -> AgentStep: ...

    def ask_once(self, prompt: str) -> str:
        """One-off, tool-free question used for the report's severity pass."""
        raise NotImplementedError


class AnthropicClient(LLMClient):
    def __init__(self, model, system_prompt, tool_schemas):
        super().__init__(model, system_prompt, tool_schemas)
        import anthropic
        self._client = anthropic.Anthropic()
        self._messages = []
        self._tools = [
            {"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
            for t in tool_schemas
        ]

    def add_user_message(self, text: str) -> None:
        self._messages.append({"role": "user", "content": text})

    def add_tool_results(self, results: list) -> None:
        self._messages.append({
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": r.tool_call_id, "content": r.content}
                for r in results
            ],
        })

    def generate(self) -> AgentStep:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self.system_prompt,
            tools=self._tools,
            messages=self._messages,
        )
        self._messages.append({"role": "assistant", "content": resp.content})
        text = "\n".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(id=b.id, name=b.name, input=b.input) for b in resp.content if b.type == "tool_use"]
        return AgentStep(text=text, tool_calls=calls)

    def ask_once(self, prompt: str) -> str:
        resp = self._client.messages.create(
            model=self.model, max_tokens=1024, messages=[{"role": "user", "content": prompt}]
        )
        return "\n".join(b.text for b in resp.content if b.type == "text")


class OpenAIClient(LLMClient):
    def __init__(self, model, system_prompt, tool_schemas):
        super().__init__(model, system_prompt, tool_schemas)
        import openai
        self._client = openai.OpenAI()
        self._messages = [{"role": "system", "content": system_prompt}]
        self._tools = [
            {"type": "function", "function": {"name": t["name"], "description": t["description"],
                                               "parameters": t["parameters"]}}
            for t in tool_schemas
        ]

    def add_user_message(self, text: str) -> None:
        self._messages.append({"role": "user", "content": text})

    def add_tool_results(self, results: list) -> None:
        for r in results:
            self._messages.append({"role": "tool", "tool_call_id": r.tool_call_id, "content": r.content})

    def generate(self) -> AgentStep:
        import json
        resp = self._client.chat.completions.create(
            model=self.model, messages=self._messages, tools=self._tools,
        )
        msg = resp.choices[0].message
        self._messages.append(msg.model_dump(exclude_none=True))
        calls = []
        for tc in (msg.tool_calls or []):
            calls.append(ToolCall(id=tc.id, name=tc.function.name,
                                   input=json.loads(tc.function.arguments or "{}")))
        return AgentStep(text=msg.content or "", tool_calls=calls)

    def ask_once(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model, messages=[{"role": "user", "content": prompt}]
        )
        return resp.choices[0].message.content or ""


def get_client(provider: str, model: str, system_prompt: str, tool_schemas: list) -> LLMClient:
    if provider == "anthropic":
        return AnthropicClient(model, system_prompt, tool_schemas)
    if provider == "openai":
        return OpenAIClient(model, system_prompt, tool_schemas)
    raise ValueError(f"Unknown provider '{provider}'. Supported: anthropic, openai.")
