def parse_requirements(filepath):
    dependencies = []

    try:
        with open(filepath, "r") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()

            if line and not line.startswith("#"):
                if "==" in line:
                    name, version = line.split("==")
                    dependencies.append({
                        "name": name.strip(),
                        "version": version.strip()
                    })

    except Exception as e:
        print("Error parsing file:", e)

    return dependencies