import shlex


def bpf_tokens(expression: str) -> list[str]:
    if not expression or len(expression) > 255 or any(ord(character) < 32 for character in expression):
        raise ValueError("BPF filter must contain 1 to 255 printable characters.")
    try:
        tokens = shlex.split(expression, posix=True)
    except ValueError as exc:
        raise ValueError("BPF filter contains invalid quoting.") from exc
    if not tokens or len(tokens) > 64:
        raise ValueError("BPF filter is empty or too complex.")
    return tokens


def validate_bpf_syntax(expression: str) -> None:
    bpf_tokens(expression)
