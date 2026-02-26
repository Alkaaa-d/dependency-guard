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