import sys
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
import matplotlib.cm as cm
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QLabel, QSizePolicy, QSpinBox, QTextEdit, QGridLayout, QFrame, QScrollArea)
from PyQt5.QtCore import Qt
import matplotlib
import numpy as np
matplotlib.use('Qt5Agg')


def calculate_character_properties(message):
    """
    Calculate M (unique characters), valences, and u(x) values
    """
    # Remove spaces and get unique characters (M)
    message = message.replace(" ", "")
    M = list(set(message))
    
    # Calculate valences (frequency of each character)
    valences = Counter(message)
    
    # Calculate u(x) values: 2 if valence is 1, 1 otherwise
    u_values = {char: 2 if valences[char] == 1 else 1 for char in M}
    
    return M, valences, u_values


def divide_into_lists(message, n):
    """
    Divide message into lists of size n
    """
    # Remove spaces
    message = message.replace(" ", "")
    return [message[i:i+n] for i in range(0, len(message), n)]


def create_successor_sequences(lists, M):
    """
    Create successor sequences for each character, including self-loops for repeated characters
    """
    char_sequences = defaultdict(list)
    for char in M:
        # Find all occurrences of the character in each list
        for idx, lst in enumerate(lists):
            if char in lst:
                char_sequences[char].append(idx)
                # If character appears multiple times in same list, add a self-loop
                for i in range(1, lst.count(char)):
                    char_sequences[char].append(idx)
    
    return char_sequences


def calculate_algebra_dimension(M, valences, u_values, m):
    """
    Calculate the dimension of the algebra M(x)
    dim(A) = 2*|M| + sum_{m in M} val(m)(val(m)u(m)-1)
    """
    base_dim = 2 * len(m)
    sum_term = sum(valences[m] * (valences[m] * u_values[m] - 1) for m in M)
    return base_dim + sum_term


def calculate_center_dimension(M, G, m):
    """
    Calculate the dimension of the center
    dim z(A) = 1 + |M| + (number of self-loops)
    """
    # Count all self-loops in the multigraph
    num_self_loops = sum(1 for u, v, k in G.edges(keys=True) if u == v)
    
    # Debug information
    loops = [(u, v, G.edges[u, v, k]['char']) for u, v, k in G.edges(keys=True) if u == v]
    print("Bucles encontrados:", loops)
    print("Número total de bucles:", num_self_loops)
    
    return 1 + len(m) + num_self_loops


class GrafoApp(QWidget):
    def __init__(self, message, n=5):
        super().__init__()
        self.message = message.lower()
        self.n = n
        self.update_analysis()
        self.init_ui()

    def update_analysis(self):
        """
        Update all analysis based on current message and n value
        """
        self.M, self.valences, self.u_values = calculate_character_properties(self.message)
        self.lists = divide_into_lists(self.message, self.n)
        self.char_sequences = create_successor_sequences(self.lists, self.M)
        self.create_graph()
        self.algebra_dim = calculate_algebra_dimension(self.M, self.valences, self.u_values, self.lists)
        self.center_dim = calculate_center_dimension(self.M, self.G, self.lists)

    def create_graph(self):
        """
        Create directed graph based on successor sequences
        """
        self.G = nx.MultiDiGraph()  # Changed to MultiDiGraph to allow parallel edges
        
        # Add nodes (lists)
        for i, lst in enumerate(self.lists):
            self.G.add_node(f"L{i+1}", content=''.join(lst))
        
        # Add edges based on successor sequences
        for char, sequence in self.char_sequences.items():
            if sequence:
                # Add edges between consecutive lists
                for i in range(len(sequence)):
                    current = f"L{sequence[i]+1}"
                    next_idx = (i + 1) % len(sequence)
                    next_list = f"L{sequence[next_idx]+1}"
                    self.G.add_edge(current, next_list, char=char)

    def init_ui(self):
        self.setWindowTitle('Análisis de Caracteres y Grafo')
        self.setGeometry(100, 100, 1400, 800)

        # Create a main widget to hold everything
        main_widget = QWidget()
        
        # Create a scroll area
        scroll = QScrollArea()
        scroll.setWidget(main_widget)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
            }
        """)

        # Main layout for the scrollable content
        main_layout = QVBoxLayout(main_widget)
        main_layout.setSpacing(10)

        # Top controls section
        top_controls = QHBoxLayout()
        
        # N size selector in a nice frame
        n_control_frame = QFrame()
        n_control_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 10px;
            }
            QLabel {
                font-weight: bold;
            }
        """)
        n_layout = QHBoxLayout()
        n_layout.addWidget(QLabel("Tamaño de las listas (n):"))
        self.n_spinner = QSpinBox()
        self.n_spinner.setRange(1, 20)
        self.n_spinner.setValue(self.n)
        self.n_spinner.valueChanged.connect(self.update_n_size)
        self.n_spinner.setStyleSheet("""
            QSpinBox {
                padding: 5px;
                border: 1px solid #bdc3c7;
                border-radius: 3px;
                min-width: 60px;
            }
        """)
        n_layout.addWidget(self.n_spinner)
        n_control_frame.setLayout(n_layout)
        top_controls.addWidget(n_control_frame)
        top_controls.addStretch()
        
        main_layout.addLayout(top_controls)

        # Information section in a frame
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
                margin: 10px 0;
            }
            QLabel {
                padding: 5px;
            }
            QLabel[class="header"] {
                font-weight: bold;
                color: #2c3e50;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 3px;
                padding: 5px;
            }
        """)
        
        info_layout = QGridLayout()
        info_layout.setSpacing(10)
        
        # Helper function to create header labels
        def create_header_label(text):
            label = QLabel(text)
            label.setProperty("class", "header")
            return label
        
        # Display message without spaces
        info_layout.addWidget(create_header_label("Mensaje original:"), 0, 0)
        info_layout.addWidget(QLabel(self.message), 0, 1)
        
        info_layout.addWidget(create_header_label("Mensaje (sin espacios):"), 1, 0)
        info_layout.addWidget(QLabel(self.message.replace(" ", "")), 1, 1)
        
        # Display list contents with better formatting
        lists_str = "  |  ".join([f"L{i+1}: {content}" for i, content in enumerate(self.lists)])
        info_layout.addWidget(create_header_label("Contenido de las listas:"), 2, 0)
        info_layout.addWidget(QLabel(lists_str), 2, 1)
        
        # Display M, valences, and u values in a grid with better formatting
        info_layout.addWidget(create_header_label("Conjunto M:"), 3, 0)
        info_layout.addWidget(QLabel(f"{', '.join(sorted(self.M))}"), 3, 1)
        
        # Create formatted strings for valences and u values with better spacing
        valences_str = "  |  ".join(f"{c}: {v}" for c, v in sorted(self.valences.items()))
        u_values_str = "  |  ".join(f"{c}: {v}" for c, v in sorted(self.u_values.items()))
        
        info_layout.addWidget(create_header_label("Valencias:"), 4, 0)
        info_layout.addWidget(QLabel(valences_str), 4, 1)
        
        info_layout.addWidget(create_header_label("Valores u(x):"), 5, 0)
        info_layout.addWidget(QLabel(u_values_str), 5, 1)
        
        # Add algebra and center dimensions with better formatting
        info_layout.addWidget(create_header_label("Dimensión del álgebra (dim A):"), 6, 0)
        info_layout.addWidget(QLabel(str(self.algebra_dim)), 6, 1)
        
        info_layout.addWidget(create_header_label("Dimensión del centro (dim z(A)):"), 7, 0)
        info_layout.addWidget(QLabel(str(self.center_dim)), 7, 1)
        
        # Add successor sequences display with better formatting
        info_layout.addWidget(create_header_label("Secuencias de Sucesores:"), 8, 0)
        
        self.sequences_text = QTextEdit()
        self.sequences_text.setReadOnly(True)
        self.sequences_text.setMaximumHeight(100)
        self.sequences_text.setStyleSheet("""
            QTextEdit {
                font-family: monospace;
                line-height: 1.5;
            }
        """)
        self.update_sequences_display()
        info_layout.addWidget(self.sequences_text, 8, 1)
        
        info_frame.setLayout(info_layout)
        main_layout.addWidget(info_frame)

        # Graph and controls section
        graph_section = QHBoxLayout()
        graph_section.setSpacing(10)  # Add spacing between elements
        
        # Character selection buttons in a grid
        buttons_frame = QFrame()
        buttons_frame.setFixedWidth(200)  # Fix width for buttons panel
        buttons_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        buttons_layout = QGridLayout()
        buttons_layout.setSpacing(5)
        
        # Add title
        title_label = QLabel("Seleccionar Caracter:")
        title_label.setStyleSheet("font-weight: bold; margin-bottom: 5px;")
        buttons_layout.addWidget(title_label, 0, 0, 1, 4)  # span 4 columns
        
        # Add character buttons in a grid
        sorted_chars = sorted(self.M)
        for i, char in enumerate(sorted_chars):
            btn = QPushButton(char)
            btn.setFixedSize(40, 40)  # Make buttons square
            btn.setStyleSheet("""
                QPushButton {
                    border-radius: 20px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
            """)
            btn.clicked.connect(lambda checked, c=char: self.highlight_character(c))
            row = (i // 4) + 1  # 4 buttons per row
            col = i % 4
            buttons_layout.addWidget(btn, row, col)
        
        # Add show all button at the bottom
        show_all_btn = QPushButton("Mostrar Todo")
        show_all_btn.setStyleSheet("""
            QPushButton {
                margin-top: 10px;
                padding: 8px;
                font-weight: bold;
            }
        """)
        show_all_btn.clicked.connect(self.draw_graph)
        buttons_layout.addWidget(show_all_btn, (len(sorted_chars) // 4) + 2, 0, 1, 4)  # span all columns
        
        buttons_frame.setLayout(buttons_layout)
        graph_section.addWidget(buttons_frame)

        # Graph visualization in a frame
        graph_frame = QFrame()
        graph_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        graph_layout = QVBoxLayout(graph_frame)
        
        # Create figure with larger size
        self.fig, self.ax = plt.subplots(figsize=(12, 10))  # Increased figure size
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setMinimumHeight(600)  # Set minimum height for canvas
        graph_layout.addWidget(self.canvas)
        
        graph_section.addWidget(graph_frame, stretch=4)  # Give more stretch to graph
        
        main_layout.addLayout(graph_section)

        # Set the scroll area as the central widget
        central_layout = QVBoxLayout(self)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.addWidget(scroll)
        self.setLayout(central_layout)
        
        # Initial graph drawing
        self.draw_graph()

    def update_n_size(self, new_n):
        """
        Update analysis when n size changes
        """
        self.n = new_n
        self.update_analysis()
        self.update_sequences_display()
        self.draw_graph()

    def update_sequences_display(self):
        """
        Update the display of successor sequences with better formatting
        """
        sequences_text = []
        for char in sorted(self.char_sequences.keys()):
            sequence = self.char_sequences[char]
            if sequence:
                sequence_str = [f"L{idx+1}" for idx in sequence]
                # Format each sequence on its own line with better spacing
                sequences_text.append(f"• Caracter '{char}':  {' → '.join(sequence_str)}")
        
        self.sequences_text.setText("\n".join(sequences_text))

    def draw_graph(self):
        self.ax.clear()
        # Use a larger k value in spring_layout to increase spacing between nodes
        pos = nx.spring_layout(self.G, k=2, iterations=50)
        
        # Draw edges first with different colors for each character
        colors = cm.rainbow(np.linspace(0, 1, len(self.M)))
        for char, color in zip(sorted(self.M), colors):
            # Get all edges for this character
            edges = [(u, v) for u, v, d in self.G.edges(data=True) 
                    if d.get('char') == char]
            if edges:
                # Calculate offset for parallel edges
                for i, (u, v) in enumerate(edges):
                    # Adjust rad value for multiple edges between same nodes
                    rad = 0.2 if u != v else (0.3 + 0.1 * i)
                    nx.draw_networkx_edges(self.G, pos, edgelist=[(u, v)], 
                                         edge_color=[color], ax=self.ax,
                                         label=f"Caracter: {char}" if i == 0 else "_nolegend_",
                                         arrows=True, arrowsize=20,
                                         width=2,
                                         connectionstyle=f'arc3,rad={rad}')
        
        # Draw nodes with smaller size and white background to make edges visible
        nx.draw_networkx_nodes(self.G, pos, node_color='white', 
                             node_size=800, ax=self.ax,
                             edgecolors='black', linewidths=2)
        
        # Draw node labels with list content
        labels = nx.get_node_attributes(self.G, 'content')
        nx.draw_networkx_labels(self.G, pos, 
                              labels={node: f"{node}\n{labels.get(node, '')}" 
                                     for node in self.G.nodes()},
                              font_size=8)
        
        self.ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        # Add some padding around the graph
        self.ax.margins(0.2)
        self.canvas.draw()

    def highlight_character(self, char):
        self.ax.clear()
        pos = nx.spring_layout(self.G, k=2, iterations=50)
        
        # Get the sequence for this character
        sequence = self.char_sequences.get(char, [])
        
        if sequence:
            # Create edges only from the successor sequence
            edges = []
            for i in range(len(sequence)):
                current = f"L{sequence[i]+1}"
                next_idx = (i + 1) % len(sequence)
                next_list = f"L{sequence[next_idx]+1}"
                edges.append((current, next_list))
            
            # Draw the edges for this sequence
            for i, (u, v) in enumerate(edges):
                # Adjust rad value for multiple edges between same nodes
                rad = 0.2 if u != v else (0.3 + 0.1 * edges.count((u, v)) - 1)
                nx.draw_networkx_edges(self.G, pos, edgelist=[(u, v)], 
                                     edge_color='red', ax=self.ax,
                                     label=f"Secuencia de {char}" if i == 0 else "_nolegend_",
                                     arrows=True, arrowsize=20,
                                     width=2,
                                     connectionstyle=f'arc3,rad={rad}')
            
            # Get nodes involved in this sequence
            involved_nodes = set([f"L{idx+1}" for idx in sequence])
            
            # Draw all nodes in gray first
            nx.draw_networkx_nodes(self.G, pos, 
                                 node_color='lightgray', 
                                 node_size=800, ax=self.ax,
                                 edgecolors='black', linewidths=2)
            
            # Highlight nodes in the sequence
            nx.draw_networkx_nodes(self.G, pos, 
                                 nodelist=list(involved_nodes),
                                 node_color='lightblue', 
                                 node_size=800, ax=self.ax,
                                 edgecolors='black', linewidths=2)
        else:
            # If character has no sequence, just draw all nodes in gray
            nx.draw_networkx_nodes(self.G, pos, 
                                 node_color='lightgray', 
                                 node_size=800, ax=self.ax,
                                 edgecolors='black', linewidths=2)
        
        # Draw node labels
        labels = nx.get_node_attributes(self.G, 'content')
        nx.draw_networkx_labels(self.G, pos, 
                              labels={node: f"{node}\n{labels.get(node, '')}" 
                                     for node in self.G.nodes()},
                              font_size=8)
        
        # Update legend and add padding
        if sequence:
            # Only show the sequence without the implicit return
            self.ax.legend([f"Secuencia de '{char}': " + 
                          " → ".join(f"L{idx+1}" for idx in sequence)])
        self.ax.margins(0.2)
        self.canvas.draw()


def iniciar_visualizacion(mensaje, n=5):
    """
    Iniciar la visualización del análisis de caracteres y grafo
    """
    # Se crea la ventana pero sin una nueva instancia de QApplication
    ventana = GrafoApp(mensaje, n)
    ventana.show()
    return ventana
