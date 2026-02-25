def generate_tags(package_name, score, release_year):

    tags = []

    if score > 70:
        tags.append("Supply Chain Risk")

    if package_name.lower() in ["requests", "urllib3", "httpx"]:
        tags.append("Network Exposure")

    if package_name.lower() in ["cryptography", "bcrypt"]:
        tags.append("Crypto Sensitive")

    if release_year != "Unknown":
        try:
            if int(release_year) < 2022:
                tags.append("Outdated")
        except:
            pass

    return tags