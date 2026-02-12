def parse_requirements(file_path):
    dependencies = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            if "==" in line:
                name, version = line.split("==", 1)
                dependencies.append({
                    "name": name.strip(),
                    "version": version.strip()
                })

    return dependencies
