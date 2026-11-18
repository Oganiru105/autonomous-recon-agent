"""
Turns the agent's step-by-step log into report.md and report.json.
Also runs one extra, tool-free LLM call to score and summarize
whatever FINDING lines the agent flagged during the run.
"""
import json
import datetime


def _extract_findings(log: list) -> list:
    findings = []
    for entry in log:
        for t in entry.get("reasoning", []):
            if "FINDING" in t:
                findings.append({"step": entry["step"], "text": t})
    return findings


def _severity_pass(client, target: str, findings: list) -> str:
    if not findings:
        return "No findings were flagged during this run."
    bullet_list = "\n".join(f"- (step {f['step']}) {f['text']}" for f in findings)
    prompt = (
        f"You tested {target} and flagged these findings during an authorized "
        f"security assessment of a test/training application:\n\n{bullet_list}\n\n"
        "For each, give a one-line rough severity (Low/Medium/High) and a one-line "
        "justification. Be conservative — this is a training app, not production."
    )
    return client.ask_once(prompt)


def generate_report(target: str, log: list, client, out_dir: str = ".") -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    findings = _extract_findings(log)
    severity_summary = _severity_pass(client, target, findings)

    lines = [f"# Recon Report: {target}", f"_Generated {ts}_", "", "## Findings & Severity", "",
              severity_summary, "", "## Full Step-by-Step Trace", ""]
    for entry in log:
        for t in entry.get("reasoning", []):
            lines.append(f"**Step {entry['step']} reasoning:** {t}")
        if "tool" in entry:
            lines.append(f"- Called `{entry['tool']}`({entry['input']})")
            lines.append(f"  - Result: `{json.dumps(entry['result'])[:300]}`")
        lines.append("")

    with open(f"{out_dir}/report.md", "w") as f:
        f.write("\n".join(lines))
    with open(f"{out_dir}/report.json", "w") as f:
        json.dump({"target": target, "generated": ts, "findings": findings,
                    "severity_summary": severity_summary, "log": log}, f, indent=2)

    print(f"\nReport written to {out_dir}/report.md and {out_dir}/report.json")
