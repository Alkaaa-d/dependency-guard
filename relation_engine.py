def analyze_dependency_relations(dependencies):

    relation_data = {}

    total = len(dependencies)

    for dep in dependencies:

        centrality = round((1 / total) * 100, 2) if total > 0 else 0

        impact_level = "Low"
        if centrality > 50:
            impact_level = "Critical"
        elif centrality > 20:
            impact_level = "Medium"

        relation_data[dep["name"]] = {
            "centrality_score": centrality,
            "impact_level": impact_level
        }

    return relation_data