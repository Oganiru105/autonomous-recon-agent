"""
CLI entry point.

Usage:
    export ANTHROPIC_API_KEY=sk-...   # or OPENAI_API_KEY=sk-...
    python main.py http://localhost:3000
    python main.py http://localhost:3000 --provider openai --model gpt-4.1
    python main.py http://localhost:3000 --config my-config.yaml

Only ever point this at a target in your config's allowed_hosts that
you own or are explicitly authorized to test. See README.md.
"""
import argparse

from src.config import load_config
from src.agent import run


def main():
    parser = argparse.ArgumentParser(description="Autonomous recon-to-report agent.")
    parser.add_argument("target", help="Base URL of the allowlisted target, e.g. http://localhost:3000")
    parser.add_argument("--config", default="config.yaml", help="Path to a config YAML file.")
    parser.add_argument("--provider", choices=["anthropic", "openai"], default=None,
                         help="Override the model provider from config.yaml.")
    parser.add_argument("--model", default=None, help="Override the model name from config.yaml.")
    parser.add_argument("--max-steps", type=int, default=None, help="Override max_steps from config.yaml.")
    args = parser.parse_args()

    config = load_config(args.config, provider_override=args.provider, model_override=args.model)
    if args.max_steps:
        config.max_steps = args.max_steps

    print(f"Running against {args.target} with provider={config.provider} model={config.model}")
    run(args.target, config)


if __name__ == "__main__":
    main()
