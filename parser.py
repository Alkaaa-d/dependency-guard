import json

def parse_requirements(filepath):

    dependencies = []

    if filepath.endswith(".txt"):
        with open(filepath) as f:
            for line in f:
                if "==" in line:
                    name, version = line.strip().split("==")
                    dependencies.append((name, version))

    elif filepath.endswith(".json"):
        data = json.load(open(filepath))

        if "dependencies" in data:
            for name, version in data["dependencies"].items():
                dependencies.append((name, version))

    return dependencies
def parse_requirements(filepath):
    dependencies = []

    try:
        with open(filepath, "r") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()

            # Skip comments & empty lines
            if not line or line.startswith("#"):
                continue

            # Remove environment markers (e.g. ; python_version)
            line = line.split(";")[0].strip()

            # Supported operators
            operators = ["==", ">=", "<=", "~=", ">", "<"]

            found = False
            for op in operators:
                if op in line:
                    name, version = line.split(op, 1)
                    dependencies.append({
                        "name": name.strip(),
                        "version": version.strip()
                    })
                    found = True
                    break

            # If no version specified
            if not found:
                dependencies.append({
                    "name": line.strip(),
                    "version": ""
                })

    except Exception as e:
        print("Error parsing file:", e)

    return dependencies