import sys
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import matplotlib.cm as cm
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QSizePolicy
from PyQt5.QtCore import Qt
import matplotlib
matplotlib.use('Qt5Agg')


def dividir_en_lemas(palabra, tamanio=5):
    return [palabra[i:i + tamanio] for i in range(0, len(palabra), tamanio)]


def crear_grafo_palabras(lemas):
    G = nx.MultiDiGraph()
    letra_a_movimientos = defaultdict(list)

    for idx, lema in enumerate(lemas):
        G.add_node(f"Lema {idx + 1}", label=lema)
        for letra in lema:
            letra_a_movimientos[letra].append(f"Lema {idx + 1}")

    for letra, lemas_contienen in letra_a_movimientos.items():
        unique_lemas = list(set(lemas_contienen))
        if len(unique_lemas) == 1:
            lema_actual = unique_lemas[0]
            for _ in range(len(lemas_contienen)):
                G.add_edge(lema_actual, lema_actual, letra=letra, tipo="ciclo")
        else:
            for lema_actual in unique_lemas:
                repeticiones = lemas_contienen.count(lema_actual)
                for _ in range(repeticiones - 1):
                    G.add_edge(lema_actual, lema_actual, letra=letra, tipo="ciclo")

            for i in range(len(lemas_contienen) - 1):
                lema_actual = lemas_contienen[i]
                lema_siguiente = lemas_contienen[i + 1]
                G.add_edge(lema_actual, lema_siguiente, letra=letra, tipo="camino")

            G.add_edge(lemas_contienen[-1], lemas_contienen[0], letra=letra, tipo="regreso")

    return G, letra_a_movimientos


class GrafoApp(QWidget):
    def __init__(self, gra, letra_a_movimientos, palabra, configuracion_brauer):
        super().__init__()
        self.gra = gra
        self.letra_a_movimientos = letra_a_movimientos
        self.palabra = palabra
        self.configuracion_brauer = configuracion_brauer

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Visualización del Grafo de Lemas')
        self.setGeometry(100, 100, 1200, 800)

        main_layout = QVBoxLayout()

        config_layout = QHBoxLayout()
        dimension_label = QLabel(f"Dimensión: {sum(self.configuracion_brauer)}")
        centro_label = QLabel(f"Centro: {len(set(self.configuracion_brauer))}")
        config_label = QLabel(f"Configuración de Brauer: {self.configuracion_brauer}")

        config_layout.addWidget(config_label)
        config_layout.addWidget(dimension_label)
        config_layout.addWidget(centro_label)
        main_layout.addLayout(config_layout)

        botones_layout = QVBoxLayout()
        for letra in self.letra_a_movimientos.keys():
            boton = QPushButton(letra)
            boton.clicked.connect(lambda _, l=letra: self.dibujar_letra(l))
            botones_layout.addWidget(boton)

        boton_todo = QPushButton("Todo")
        boton_todo.clicked.connect(self.dibujar_todo)
        botones_layout.addWidget(boton_todo)

        self.fig, self.ax = plt.subplots(figsize=(10, 8))
        self.canvas = FigureCanvas(self.fig)
        grafico_layout = QHBoxLayout()
        grafico_layout.addWidget(self.canvas)
        grafico_layout.addLayout(botones_layout)
        main_layout.addLayout(grafico_layout)

        self.setLayout(main_layout)
        self.dibujar_todo()

    def dibujar_todo(self):
        self.dibujar_letra()

    def dibujar_letra(self, letra=None):
        self.ax.clear()
        pos = nx.spring_layout(self.gra, seed=42)
        colores = cm.get_cmap("tab20", len(self.letra_a_movimientos))

        nx.draw_networkx_nodes(self.gra, pos, ax=self.ax, node_size=3000, node_color="skyblue", edgecolors="black")
        nx.draw_networkx_labels(self.gra, pos, labels=nx.get_node_attributes(self.gra, 'label'), font_size=10, ax=self.ax)

        for i, (letra_actual, movimientos) in enumerate(self.letra_a_movimientos.items()):
            if letra and letra != letra_actual:
                continue

            color = colores(i)
            ciclos = [(u, v) for u, v, d in self.gra.edges(data=True) if d.get('letra') == letra_actual and d.get('tipo') == "ciclo"]
            caminos = [(u, v) for u, v, d in self.gra.edges(data=True) if d.get('letra') == letra_actual and d.get('tipo') == "camino"]
            regresos = [(u, v) for u, v, d in self.gra.edges(data=True) if d.get('letra') == letra_actual and d.get('tipo') == "regreso"]

            nx.draw_networkx_edges(self.gra, pos, edgelist=ciclos, ax=self.ax, edge_color=[color], style="dashed")
            nx.draw_networkx_edges(self.gra, pos, edgelist=caminos, ax=self.ax, edge_color=[color])
            nx.draw_networkx_edges(self.gra, pos, edgelist=regresos, ax=self.ax, edge_color=[color], style="dotted")

        self.ax.set_title(f"Grafo de lemas y conexiones para '{self.palabra}'")
        self.canvas.draw()


def iniciar_visualizacion(palabra):
    palabra = palabra.lower().replace(" ", "")
    lemas = dividir_en_lemas(palabra)
    configuracion_brauer = [len(lema) for lema in lemas]
    gra, letra_a_movimientos = crear_grafo_palabras(lemas)

    app = QApplication(sys.argv)
    ventana = GrafoApp(gra, letra_a_movimientos, palabra, configuracion_brauer)
    ventana.show()
    sys.exit(app.exec_())
