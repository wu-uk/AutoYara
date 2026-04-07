import argparse
import json
import sys

from autoyara.ida.server import get_hex_from_ida


def _format_output(result):
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, indent=2)
    except TypeError:
        return str(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("elf_file_path")
    parser.add_argument("function_name")
    args = parser.parse_args()

    result = get_hex_from_ida(args.elf_file_path, args.function_name)
    text = _format_output(result)
    print(text)
    if isinstance(text, str) and text.startswith("Error:"):
        sys.exit(1)


if __name__ == "__main__":
    main()
