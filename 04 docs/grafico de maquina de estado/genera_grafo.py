import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.collections import PatchCollection
from pathlib import Path


class Node:
    def __init__(
        self,
        center,
        radius,
        label,
        facecolor="#2693de",
        edgecolor="#e6e6e6",
        ring_facecolor="#a3a3a3",
        ring_edgecolor="#a3a3a3",
    ):
        self.center = center
        self.radius = radius
        self.label = label
        self.x = center[0]
        self.y = center[1]

        self.node_facecolor = facecolor
        self.node_edgecolor = edgecolor
        self.ring_facecolor = ring_facecolor
        self.ring_edgecolor = ring_edgecolor
        self.ring_width = 0.03

        self.text_args = {"ha": "center", "va": "center", "fontsize": 16}

    def add_circle(self, ax):
        circle = mpatches.Circle(self.center, self.radius)
        p = PatchCollection(
            [circle], edgecolor=self.node_edgecolor, facecolor=self.node_facecolor
        )
        ax.add_collection(p)
        ax.annotate(self.label, xy=self.center, color="#ffffff", **self.text_args)

    def add_self_loop(self, ax, prob=None, direction="up"):
        if direction == "up":
            start = -30
            angle = 180
            ring_x = self.x
            ring_y = self.y + self.radius
            prob_y = self.y + 1.3 * self.radius
            x_cent = ring_x - self.radius + (self.ring_width / 2)
            y_cent = ring_y - 0.15
        else:
            start = -210
            angle = 0
            ring_x = self.x
            ring_y = self.y - self.radius
            prob_y = self.y - 1.4 * self.radius
            x_cent = ring_x + self.radius - (self.ring_width / 2)
            y_cent = ring_y + 0.15

        ring = mpatches.Wedge(
            (ring_x, ring_y), self.radius, start, angle, width=self.ring_width
        )
        offset = 0.2
        left = [x_cent - offset, ring_y]
        right = [x_cent + offset, ring_y]
        bottom = [(left[0] + right[0]) / 2.0, y_cent]
        arrow = mpatches.Polygon([left, right, bottom, left])

        p = PatchCollection(
            [ring, arrow], edgecolor=self.ring_edgecolor, facecolor=self.ring_facecolor
        )
        ax.add_collection(p)

        if prob:
            ax.annotate(
                str(prob), xy=(self.x, prob_y), color="#000000", **self.text_args
            )


class MarkovChain:
    def __init__(self, M, labels):
        if M.shape[0] < 2:
            raise ValueError("There should be at least 2 states")
        if M.shape[0] > 4:
            raise ValueError("Only works with 4 states max for now")
        if M.shape[0] != M.shape[1]:
            raise ValueError("Transition matrix should be square")
        if M.shape[0] != len(labels):
            raise ValueError("There should be as many labels as states")

        self.M = M
        self.n_states = M.shape[0]
        self.labels = labels

        self.arrow_facecolor = "#a3a3a3"
        self.arrow_edgecolor = "#a3a3a3"

        self.node_radius = 0.5
        self.arrow_width = 0.03
        self.arrow_head_width = 0.20
        self.text_args = {"ha": "center", "va": "center", "fontsize": 16}

        self.build_network()

    def set_node_centers(self):
        if self.n_states == 2:
            self.figsize = (10, 4)
            self.xlim = (-5, 5)
            self.ylim = (-2, 2)
            self.node_centers = [[-4, 0], [4, 0]]
        elif self.n_states == 3:
            self.figsize = (10, 6)
            self.xlim = (-5, 5)
            self.ylim = (-3, 3)
            self.node_centers = [[-3, -2], [3, -2], [-3, 2]]
        elif self.n_states == 4:
            self.figsize = (8, 8)
            self.xlim = (-5, 5)
            self.ylim = (-5, 5)
            self.node_centers = [[-4, 4], [4, 4], [4, -4], [-4, -4]]

    def build_network(self):
        self.set_node_centers()
        self.nodes = [
            Node(self.node_centers[i], self.node_radius, self.labels[i])
            for i in range(self.n_states)
        ]

    def add_arrow(self, ax, node1, node2, prob=None):
        x_start = node1.x + np.sign(node2.x - node1.x) * node1.radius
        y_start = node1.y + np.sign(node2.y - node1.y) * node1.radius

        dx = abs(node1.x - node2.x) - 2.5 * node1.radius
        dy = abs(node1.y - node2.y) - 2.5 * node1.radius

        yoffset = 0.4 * self.node_radius * np.sign(node2.x - node1.x)
        xoffset = (
            0.4 * self.node_radius * np.sign(node2.y - node1.y) if yoffset == 0 else 0
        )

        arrow = mpatches.FancyArrow(
            x_start + xoffset,
            y_start + yoffset,
            dx * np.sign(node2.x - node1.x),
            dy * np.sign(node2.y - node1.y),
            width=self.arrow_width,
            head_width=self.arrow_head_width,
        )
        p = PatchCollection(
            [arrow], edgecolor=self.arrow_edgecolor, facecolor=self.arrow_facecolor
        )
        ax.add_collection(p)

        x_prob = x_start + xoffset + 0.2 * dx * np.sign(node2.x - node1.x)
        y_prob = y_start + yoffset + 0.2 * dy * np.sign(node2.y - node1.y)
        if prob:
            ax.annotate(
                str(prob), xy=(x_prob, y_prob), color="#000000", **self.text_args
            )

    def draw(self, img_path=None):
        fig, ax = plt.subplots(figsize=self.figsize)
        plt.xlim(self.xlim)
        plt.ylim(self.ylim)

        for node in self.nodes:
            node.add_circle(ax)

        for i in range(self.n_states):
            for j in range(self.n_states):
                if i == j:
                    direction = "up" if self.nodes[i].y >= 0 else "down"
                    self.nodes[i].add_self_loop(
                        ax, prob=self.M[i, j], direction=direction
                    )
                elif self.M[i, j] > 0:
                    self.add_arrow(ax, self.nodes[i], self.nodes[j], prob=self.M[i, j])

        plt.axis("off")
        if img_path:
            plt.savefig(img_path)
            print(f"Grafo generado exitosamente en: {img_path}")


def main():
    base_path = Path(__file__).parent
    input_file = base_path / "alertas_clasificadas.csv"
    output_dir = base_path / "salida"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Leyendo alertas desde {input_file.name}...")
    alertas = pd.read_csv(input_file, encoding="latin-1", sep=";")

    if "Etapa" not in alertas.columns:
        raise ValueError("El archivo no contiene la columna 'Etapa'.")

    etapas = alertas["Etapa"].values

    print("Calculando matriz de transiciones...")
    # Cálculo vectorizado de las transiciones (O(N) time complexity)
    P = (
        pd.crosstab(etapas[:-1], etapas[1:])
        .reindex(index=[1, 2, 3, 4], columns=[1, 2, 3, 4], fill_value=0)
        .values
    )

    print("\nMatriz de Transición:")
    print(P)

    labels = ["E 1", "E 2", "E 3", "E 4"]
    mc = MarkovChain(P, labels)

    output_path = output_dir / "Maquina_estado-CKC.png"
    mc.draw(img_path=str(output_path))


if __name__ == "__main__":
    main()
