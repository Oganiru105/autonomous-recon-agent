"""
The agent loop itself. Provider-agnostic: it only talks to the
LLMClient interface from llm_clients.py, so switching between
Anthropic and OpenAI is a config change, not a code change.
"""
from .llm_clients import get_client, ToolResult
from .tools import ToolBox, TOOL_SCHEMAS
from .report import generate_report

SYSTEM_PROMPT = """You are an autonomous security research agent. You have
been authorized to enumerate and probe ONE target application that the
operator has explicitly allowlisted. Each step:

1. State your current hypothesis or goal in one sentence.
2. Choose exactly one tool call that tests it.
3. After seeing the result, update your reasoning before the next step.

Be methodical: start with recon (ports, banners, paths, headers) before
trying the reflected-parameter or SQL-error-signature checks. Those two
tools are passive heuristics only — never attempt actual exploitation,
data extraction, or destructive requests. When you believe you've found
a genuine issue, clearly flag it as a FINDING with a one-line
description and the evidence. When you've either found what you can or
exhausted reasonable avenues, say DONE and summarize.
"""


def confirm(config, tool_name: str, tool_input: dict) -> bool:
    if not config.confirm_state_changes:
        return True
    if tool_name == "http_request" and tool_input.get("method", "GET") != "GET":
        ans = input(
            f"\n[CONFIRM] Agent wants to {tool_input.get('method')} "
            f"{tool_input.get('url')} with data={tool_input.get('data')}. Allow? [y/N] "
        )
        return ans.strip().lower() == "y"
    return True


def run(target: str, config) -> None:
    toolbox = ToolBox(config)
    functions = toolbox.functions()
    client = get_client(config.provider, config.model, SYSTEM_PROMPT, TOOL_SCHEMAS)
    client.add_user_message(f"Target to enumerate: {target}")

    log = []
    for step in range(config.max_steps):
        result = client.generate()
        if result.text:
            print(f"\n[step {step}] {result.text}")
        log.append({"step": step, "reasoning": [result.text] if result.text else []})

        if not result.tool_calls:
            break

        tool_results = []
        for call in result.tool_calls:
            print(f"  -> calling {call.name}({call.input})")
            if not confirm(config, call.name, call.input):
                output = {"error": "Blocked by operator confirmation gate."}
            else:
                try:
                    output = functions[call.name](**call.input)
                except Exception as e:
                    output = {"error": str(e)}
            log.append({"step": step, "tool": call.name, "input": call.input, "result": output})
            tool_results.append(ToolResult(tool_call_id=call.id, name=call.name,
                                            content=str(output)[:4000]))
        client.add_tool_results(tool_results)

        if result.text and "DONE" in result.text:
            break

    generate_report(target, log, client)
