from __future__ import annotations

import questionary

from sakura_iam_cli import core


def interactive_checkbox(message: str, choices: list[questionary.Choice]) -> list:
    if not choices:
        raise core.CliError(f"no choices are available for: {message}")
    selected = questionary.checkbox(
        message,
        choices=choices,
        instruction="(Spaceで選択、Enterで確定)",
        validate=lambda values: bool(values) or "1つ以上選択してください",
    ).ask()
    if selected is None:
        raise core.CliError("interactive selection cancelled")
    return selected


def interactive_select(message: str, choices: list[questionary.Choice]):
    if not choices:
        raise core.CliError(f"no choices are available for: {message}")
    selected = questionary.select(
        message,
        choices=choices,
        instruction="(上下キーで移動、Enterで確定)",
    ).ask()
    if selected is None:
        raise core.CliError("interactive selection cancelled")
    return selected


def interactive_confirm(message: str) -> bool:
    answer = questionary.confirm(message, default=False).ask()
    if answer is None:
        raise core.CliError("interactive selection cancelled")
    return answer
