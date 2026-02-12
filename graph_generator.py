from graphviz import Digraph
import os

def generate_dependency_graph(results):
    try:
        # Absolute path for static folder
        base_dir = os.path.dirname(os.path.abspath(__file__))
        static_path = os.path.join(base_dir, "static")
        os.makedirs(static_path, exist_ok=True)

        dot = Digraph(format="png")

        dot.node("Project", "Project",
                 shape="box",
                 style="filled",
                 fillcolor="lightblue")

        for r in results:
            # Determine color based on risk
            if r["risk"] == "High":
                color = "red"
            elif r["risk"] == "Medium":
                color = "orange"
            else:
                color = "green"

            # Safe node name
            node_name = r["name"].replace(".", "_")

            dot.node(node_name,
                     r["name"],
                     style="filled",
                     fillcolor=color)

            dot.edge("Project", node_name)

        # Save graph image
        output_path = os.path.join(static_path, "dependency_graph")
        dot.render(output_path, cleanup=True)

    except Exception as e:
        print("Graph generation error:", e)
