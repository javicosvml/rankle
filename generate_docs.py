#!/usr/bin/env python3
"""
Generate API documentation from rankle.py and update README.md

This script extracts public methods with their type hints and docstrings,
then updates the README.md file between the API_START and API_END markers.
"""

import ast
from typing import Any


def parse_rankle_file() -> ast.Module:
    """Parse rankle.py and return AST"""
    with open("rankle.py", encoding="utf-8") as f:
        return ast.parse(f.read(), filename="rankle.py")


def extract_type_hint(node: ast.arg) -> str:
    """Extract type hint as string from AST node"""
    if node.annotation:
        return ast.unparse(node.annotation)
    return ""


def extract_return_type(node: ast.FunctionDef) -> str:
    """Extract return type annotation"""
    if node.returns:
        return ast.unparse(node.returns)
    return ""


def extract_constants(tree: ast.Module) -> list[dict[str, Any]]:
    """Extract class constants from Rankle class"""
    constants = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Rankle":
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            name = target.id
                            # Solo constantes (UPPERCASE)
                            if (
                                name.isupper()
                                or name.startswith("HTTP_")
                                or name.startswith("DNS_")
                            ):
                                try:
                                    value = ast.literal_eval(item.value)
                                    constants.append({"name": name, "value": value})
                                except Exception:
                                    # Si no se puede evaluar, usar repr
                                    constants.append(
                                        {"name": name, "value": ast.unparse(item.value)}
                                    )

    return constants


def extract_public_methods(tree: ast.Module) -> list[dict[str, Any]]:
    """Extract public methods from Rankle class"""
    methods = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Rankle":
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    # Solo métodos públicos (no empiezan con _)
                    if not item.name.startswith("_"):
                        # Extraer argumentos con type hints
                        args = []
                        for arg in item.args.args:
                            if arg.arg == "self":
                                continue
                            type_hint = extract_type_hint(arg)
                            if type_hint:
                                args.append(f"{arg.arg}: {type_hint}")
                            else:
                                args.append(arg.arg)

                        # Valores por defecto
                        defaults_offset = len(item.args.args) - len(item.args.defaults)
                        for i, default in enumerate(item.args.defaults):
                            arg_index = defaults_offset + i
                            try:
                                default_value = ast.literal_eval(default)
                                if isinstance(default_value, str):
                                    default_value = f'"{default_value}"'
                                args[arg_index - 1] += f" = {default_value}"
                            except Exception:
                                args[arg_index - 1] += f" = {ast.unparse(default)}"

                        # Return type
                        return_type = extract_return_type(item)

                        # Docstring
                        docstring = (
                            ast.get_docstring(item) or "No description available"
                        )
                        # Solo primera línea del docstring
                        doc_first_line = docstring.split("\n")[0].strip()

                        signature = f"{item.name}({', '.join(args)})"
                        if return_type:
                            signature += f" -> {return_type}"

                        methods.append(
                            {
                                "name": item.name,
                                "signature": signature,
                                "doc": doc_first_line,
                                "full_doc": docstring,
                            }
                        )

    return methods


def generate_constants_markdown(constants: list[dict[str, Any]]) -> str:
    """Generate markdown for constants"""
    if not constants:
        return ""

    md = "### 🔧 Configuration Constants\n\n"
    md += "The following constants can be customized:\n\n"
    md += "| Constant | Default Value | Description |\n"
    md += "|----------|---------------|-------------|\n"

    # Agrupar por categoría
    timeouts = [c for c in constants if "TIMEOUT" in c["name"]]
    http_codes = [c for c in constants if c["name"].startswith("HTTP_")]
    others = [c for c in constants if c not in timeouts and c not in http_codes]

    for const in timeouts + http_codes + others:
        value = const["value"]
        if isinstance(value, list):
            value = f"`{value}`"
        elif isinstance(value, str):
            value = f'`"{value}"`'
        else:
            value = f"`{value}`"

        # Descripción básica desde el nombre
        desc = const["name"].replace("_", " ").title()
        md += f"| `{const['name']}` | {value} | {desc} |\n"

    md += "\n"
    return md


def generate_api_markdown(methods: list[dict[str, Any]]) -> str:
    """Generate markdown for API documentation"""
    md = "### 📚 Public Methods\n\n"
    md += "Main public methods available in the Rankle class:\n\n"

    for method in methods[:10]:  # Top 10 métodos más importantes
        md += f"#### `{method['signature']}`\n\n"
        md += f"{method['doc']}\n\n"

        # Si el docstring tiene más detalles, añadir
        if len(method["full_doc"]) > len(method["doc"]) + 10:
            # Tomar hasta 3 líneas adicionales
            extra_lines = method["full_doc"].split("\n")[1:4]
            extra = "\n".join([line.strip() for line in extra_lines if line.strip()])
            if extra:
                md += f"{extra}\n\n"

        md += "---\n\n"

    return md


def update_readme():
    """Update README.md with generated documentation"""
    print("📚 Generating API documentation from rankle.py...")

    # Parse rankle.py
    tree = parse_rankle_file()

    # Extract information
    constants = extract_constants(tree)
    methods = extract_public_methods(tree)

    print(f"   Found {len(constants)} constants")
    print(f"   Found {len(methods)} public methods")

    # Generate markdown
    api_docs = "<!-- AUTO-GENERATED: Do not edit manually -->\n\n"
    api_docs += generate_constants_markdown(constants)
    api_docs += generate_api_markdown(methods)

    # Read README
    try:
        with open("README.md", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("⚠️  README.md not found")
        return

    # Check for markers
    start_marker = "<!-- API_START -->"
    end_marker = "<!-- API_END -->"

    if start_marker in content and end_marker in content:
        # Replace content between markers
        before = content.split(start_marker)[0]
        after = content.split(end_marker)[1]

        new_content = f"{before}{start_marker}\n{api_docs}{end_marker}{after}"

        # Write back
        with open("README.md", "w", encoding="utf-8") as f:
            f.write(new_content)

        print("✅ README.md updated successfully!")
        print(f"   - {len(constants)} constants documented")
        print(f"   - {min(10, len(methods))} methods documented")
    else:
        print("⚠️  Markers not found in README.md")
        print("   Add the following markers to your README.md:")
        print(f"   {start_marker}")
        print("   (API documentation will be inserted here)")
        print(f"   {end_marker}")
        print("\n   Generated documentation preview:")
        print("   " + "=" * 70)
        print(api_docs[:500] + "...")


if __name__ == "__main__":
    update_readme()
