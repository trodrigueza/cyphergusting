import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton,
    QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QTextEdit,
    QLineEdit, QFileDialog, QMessageBox, QFrame, QGridLayout,
    QScrollArea, QSizePolicy, QSpinBox
)
from PyQt5.QtGui import QPixmap, QFont, QPalette, QColor
from PyQt5.QtCore import Qt, QSize
import ast
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

# Importamos las funciones de cifrado
import library.src.affine_cipher as affine_cipher
import library.src.caesar_cipher as caesar_cipher
import library.src.hill_cipher as hill_cipher
import library.src.permutation_cipher as permutation_cipher
import library.src.substitution_cipher as substitution_cipher
import library.src.vigenere_cipher as vigenere_cipher
import library.AES as AES_cipher
import library.elgamal as elgamal_cipher
import library.rsa as rsa_cipher
import library.src.analisisdebrauer as atack_brauer
import library.src.RSA_atack as atack_rsa
import library.AES_CBC as CBC_cipher
import library.AES_attack as CBC_attack
import library.digital_signatures as digital_signatures

project_dir = os.path.join(os.path.dirname(__file__))

# Definición de estilos
STYLE_SHEET = """
QMainWindow {
    background-color: #f0f0f0;
}
QLabel {
    color: #2c3e50;
}
QPushButton {
    background-color: #3498db;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 5px;
    min-width: 200px;
}
QPushButton:hover {
    background-color: #2980b9;
}
QPushButton:pressed {
    background-color: #2573a7;
}
QComboBox {
    padding: 5px;
    border: 1px solid #bdc3c7;
    border-radius: 3px;
    min-width: 200px;
}
QTextEdit, QLineEdit {
    border: 1px solid #bdc3c7;
    border-radius: 3px;
    padding: 5px;
}
QFrame.card {
    background-color: white;
    border-radius: 10px;
    padding: 15px;
    margin: 5px;
    border: 2px solid transparent;
}
QFrame.card:hover {
    background-color: #f8f9fa;
    border: 2px solid #3498db;
    cursor: pointer;
}
QFrame.footer {
    background-color: #2c3e50;
    color: white;
    padding: 20px;
    margin-top: 20px;
}
QLabel.footer-text {
    color: #ecf0f1;
    font-size: 12px;
}
"""

# Constantes para categorías de cifrado
CLASSIC_CIPHERS = ["Afin", "Desplazamiento", "Hill", "Permutación", "Sustitución", "Vigenere"]
ASYMMETRIC_CIPHERS = ["RSA", "Elgamal"]

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Cyphergusting")
        self.setGeometry(100, 100, 1000, 800)
        self.showMaximized()
        self.setStyleSheet(STYLE_SHEET)
        self.initUI()

    def initUI(self):
        # Widget central con scroll
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 0)  # Reducir el margen inferior
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(central_widget)
        self.setCentralWidget(scroll)

        # Título principal
        title = QLabel("Cyphergusting")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 36px; font-weight: bold; margin: 20px 0;")
        main_layout.addWidget(title)

        # Grid para las tarjetas de categorías
        self.grid_layout = QGridLayout()
        self.grid_layout.setSpacing(20)
        main_layout.addLayout(self.grid_layout)

        # Crear tarjetas para cada categoría
        self.create_category_card("Cifrados Clásicos", 
            "Incluye cifrados Afín, César, Hill, Permutación, Sustitución y Vigenère",
            "classic_ciphers.png", 0, 0, lambda: self.openTextWindow("classic"))
        
        self.create_category_card("Cifrados Asimétricos", 
            "Cifrados de clave pública RSA y ElGamal",
            "asymmetric_ciphers.png", 0, 1, lambda: self.openTextWindow("asymmetric"))
        
        self.create_category_card("Cifrado de Imágenes", 
            "Cifrado AES para imágenes con diferentes modos de operación",
            "image_cipher.png", 0, 2, self.openImageWindow)
        
        self.create_category_card("Firmas Digitales",
            "Firma y verificación de documentos usando RSA, DSA y ECDSA",
            "digital_signatures.png", 1, 0, self.openSignatureWindow)
        
        self.create_category_card("Análisis de Brauer", 
            "Herramienta para análisis criptográfico de textos",
            "brauer_analysis.png", 1, 1, lambda: self.openTextWindow("brauer"))

        # Espaciador flexible antes del footer
        main_layout.addStretch()

        # Footer
        footer = QFrame()
        footer.setProperty("class", "footer")
        footer_layout = QVBoxLayout(footer)
        
        developers_label = QLabel("Desarrollado por")
        developers_label.setAlignment(Qt.AlignCenter)
        developers_label.setStyleSheet("color: #ecf0f1; font-size: 14px; font-weight: bold;")
        footer_layout.addWidget(developers_label)
        
        names = [
            "Juan Camilo Daza Gutiérrez",
            "Nicolás Duque Molina",
            "Andrés Felipe Poveda Bellon",
            "Tomas David Rodríguez Agudelo"
        ]
        
        for name in names:
            name_label = QLabel(name)
            name_label.setAlignment(Qt.AlignCenter)
            name_label.setProperty("class", "footer-text")
            footer_layout.addWidget(name_label)

        main_layout.addWidget(footer)

    def create_category_card(self, title, description, icon_path, row, col, click_handler):
        card = QFrame()
        card.setProperty("class", "card")
        card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        card.mousePressEvent = lambda e: click_handler()
        
        layout = QVBoxLayout(card)
        
        # Título de la categoría
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50;")
        layout.addWidget(title_label)
        
        # Descripción
        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #7f8c8d; margin: 10px 0;")
        layout.addWidget(desc_label)
        
        layout.addStretch()
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Añadir la tarjeta al grid
        self.grid_layout.addWidget(card, row, col)

    def openTextWindow(self, category_type):
        self.textWindow = TextWindow(category_type)
        self.textWindow.show()

    def openImageWindow(self):
        self.imageWindow = ImageWindow()
        self.imageWindow.show()

    def openSignatureWindow(self):
        self.signatureWindow = SignatureWindow()
        self.signatureWindow.show()


class TextWindow(QMainWindow):
    def __init__(self, category_type):
        super(TextWindow, self).__init__()
        self.category_type = category_type
        self.setWindowTitle(self.get_window_title())
        self.setGeometry(150, 150, 800, 600)
        self.showMaximized()
        self.setStyleSheet(STYLE_SHEET)
        self.initUI()

    def get_window_title(self):
        titles = {
            "classic": "Cifrados Clásicos",
            "asymmetric": "Cifrados Asimétricos",
            "brauer": "Análisis de Brauer"
        }
        return titles.get(self.category_type, "Cifrado de Texto")

    def get_available_ciphers(self):
        if self.category_type == "classic":
            return CLASSIC_CIPHERS
        elif self.category_type == "asymmetric":
            return ASYMMETRIC_CIPHERS
        elif self.category_type == "brauer":
            return ["Análisis de Brauer"]
        return []

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        # Contenedor principal con margen
        main_frame = QFrame()
        main_frame.setProperty("class", "card")
        main_layout = QVBoxLayout(main_frame)
        
        # Título de la ventana
        title = QLabel(self.get_window_title())
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # Grid para los controles
        controls_layout = QGridLayout()
        controls_layout.setSpacing(10)

        # Selector de cifrado (si no es análisis de Brauer)
        if self.category_type != "brauer":
            controls_layout.addWidget(QLabel("Tipo de cifrado:"), 0, 0)
            self.combo_cipher = QComboBox()
            self.combo_cipher.addItems(self.get_available_ciphers())
            self.combo_cipher.currentIndexChanged.connect(self.updateKeyField)
            controls_layout.addWidget(self.combo_cipher, 0, 1)

            # Selector de operación
            controls_layout.addWidget(QLabel("Operación:"), 1, 0)
            self.combo_operation = QComboBox()
            self.combo_operation.addItems(["Encriptar", "Desencriptar", "Ataque"])
            self.combo_operation.currentIndexChanged.connect(self.toggleKeyField)
            controls_layout.addWidget(self.combo_operation, 1, 1)

            # Campo de clave
            self.key_label = QLabel("Clave:")
            controls_layout.addWidget(self.key_label, 2, 0)
            self.key_input = QLineEdit()
            controls_layout.addWidget(self.key_input, 2, 1)
            
            # Inicialmente configuramos la visibilidad y formato de la clave
            self.updateKeyField()
        else:
            # Para análisis de Brauer, agregar selector de tamaño n
            controls_layout.addWidget(QLabel("Tamaño de las listas (n):"), 0, 0)
            self.n_size = QSpinBox()
            self.n_size.setRange(1, 20)
            self.n_size.setValue(5)  # Valor por defecto
            controls_layout.addWidget(self.n_size, 0, 1)

        # Área de entrada
        input_label = QLabel("Texto de entrada:")
        input_label.setStyleSheet("margin-top: 20px;")
        main_layout.addWidget(input_label)
        
        self.input_text = QTextEdit()
        self.input_text.setMinimumHeight(100)
        main_layout.addWidget(self.input_text)

        # Botón de ejecución
        self.btn_execute = QPushButton("Ejecutar" if self.category_type != "brauer" else "Analizar")
        self.btn_execute.clicked.connect(self.executeOperation)
        self.btn_execute.setStyleSheet("""
            QPushButton {
                margin: 20px 0;
                font-size: 16px;
                min-height: 40px;
            }
        """)
        main_layout.addWidget(self.btn_execute)

        # Área de resultado
        result_label = QLabel("Resultado:")
        main_layout.addWidget(result_label)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumHeight(150)
        main_layout.addWidget(self.output_text)

        # Añadir el grid de controles al layout principal
        main_layout.insertLayout(1, controls_layout)

        # Añadir el frame principal al layout de la ventana
        layout.addWidget(main_frame)
        self.setCentralWidget(widget)

    def updateKeyField(self):
        if not hasattr(self, 'key_input'):
            return

        cipher = self.combo_cipher.currentText()
        operation = self.combo_operation.currentText()
        
        # Configurar el placeholder según el tipo de cifrado
        key_formats = {
            "Afin": "Formato: a b (ejemplo: 3 7) - a debe ser coprimo con 26",
            "Desplazamiento": "Número entero entre 0 y 25",
            "Hill": "Matriz cuadrada (ejemplo para 2x2: ADBE)",
            "Permutación": "Formato n k (n divide la longitud del mensaje, k es la k-ésima permutación (orden lexicográfico))",
            "Sustitución": "Número entero k (k-ésima permutación) o alfabeto de 26 letras",
            "Vigenere": "Palabra clave (solo letras)",
            "RSA": {
                "Encriptar": "Clave pública (n,e)",
                "Desencriptar": "Clave privada (n,d)",
                "Ataque": "Clave privada (n,d)"
            },
            "Elgamal": {
                "Encriptar": "Clave pública en formato p,g,h",
                "Desencriptar": "Formato: public_key-private_key"
            }
        }

        # Actualizar el placeholder según el cifrado y la operación
        if cipher in ["RSA", "Elgamal"]:
            placeholder = key_formats[cipher].get(operation, "")
        else:
            placeholder = key_formats.get(cipher, "")

        self.key_input.setPlaceholderText(placeholder)
        
        # Actualizar el label
        key_labels = {
            "Afin": "Coeficientes (a,b):",
            "Desplazamiento": "Desplazamiento:",
            "Hill": "Matriz de cifrado:",
            "Permutación": "Permutación:",
            "Sustitución": "Alfabeto de sustitución:",
            "Vigenere": "Palabra clave:",
            "RSA": {
                "Encriptar": "Clave pública (n,e):",
                "Desencriptar": "Clave privada (n,d):",
                "Ataque": "Clave privada (n,d):"
            },
            "Elgamal": {
                "Encriptar": "Clave pública (p,g,h):",
                "Desencriptar": "Claves (pub-priv):"
            }
        }

        if cipher in ["RSA", "Elgamal"]:
            label = key_labels[cipher].get(operation, "Clave:")
        else:
            label = key_labels.get(cipher, "Clave:")
        
        self.key_label.setText(label)

    def toggleKeyField(self):
        if not hasattr(self, 'key_label') or not hasattr(self, 'key_input'):
            return

        operation = self.combo_operation.currentText()
        cipher = self.combo_cipher.currentText()
        
        # Mostrar el campo de clave para:
        # 1. Operaciones de encriptado y desencriptado
        # 2. Ataque RSA (que necesita la clave pública)
        # 3. Ataque Hill (que necesita texto claro conocido)
        show_key = (operation in ["Encriptar", "Desencriptar"] or 
                   (operation == "Ataque" and cipher == "RSA") or
                   (operation == "Ataque" and cipher == "Hill"))
        
        # Actualizar el placeholder para el campo de clave en caso de ataque Hill
        if operation == "Ataque" and cipher == "Hill":
            self.key_input.setPlaceholderText("Ingrese el texto claro conocido")
            self.key_label.setText("Texto claro conocido:")
        else:
            self.updateKeyField()  # Restaurar el placeholder normal
        
        self.key_label.setVisible(show_key)
        self.key_input.setVisible(show_key)

    def executeOperation(self):
        if self.category_type == "brauer":
            text = self.input_text.toPlainText()
            try:
                n_size = self.n_size.value()
                atack_brauer.iniciar_visualizacion(text, n_size)
                self.output_text.setPlainText("Análisis de Brauer iniciado. Por favor revise la ventana de visualización.")
            except Exception as e:
                self.output_text.setPlainText(f"Error: {str(e)}")
            return

        cipher_type = self.combo_cipher.currentText()
        operation = self.combo_operation.currentText()
        text = self.input_text.toPlainText()
        key = self.key_input.text() if self.key_input.isVisible() else None

        result = ""
        try:
            if operation == "Encriptar":
                if cipher_type == "Afin":
                    result = affine_cipher.AffineCipher.encrypt(text, key)
                elif cipher_type == "Desplazamiento":
                    result = caesar_cipher.CaesarCipher.encrypt(text, key)
                elif cipher_type == "Hill":
                    result = hill_cipher.HillCipher.encrypt(text, key)
                elif cipher_type == "Permutación":
                    result = permutation_cipher.PermutationCipher.encrypt(text, key)
                elif cipher_type == "Sustitución":
                    result = substitution_cipher.SubstitutionCipher.encrypt(text, key)
                elif cipher_type == "Vigenere":
                    result = vigenere_cipher.VigenereCipher.encrypt(text, key)
                elif cipher_type == "Elgamal":
                    public_key, private_key = elgamal_cipher.generate_keys(32)
                    ciphertext = elgamal_cipher.encrypt(public_key, text)
                    result = (f"Texto cifrado:\n{ciphertext}\n\nClaves generadas:\n"
                            f"Pública: {public_key}\nPrivada: {private_key}")
                elif cipher_type == "RSA":
                    public_key, private_key = rsa_cipher.generate_keypair()
                    ciphertext = rsa_cipher.encrypt(public_key, text)
                    result = (f"Texto cifrado:\n{ciphertext}\n\nClaves generadas:\n"
                            f"Pública: {public_key}\nPrivada: {private_key}")
            elif operation == "Desencriptar":
                if cipher_type == "Afin":
                    result = affine_cipher.AffineCipher.decrypt(text, key)
                elif cipher_type == "Desplazamiento":
                    result = caesar_cipher.CaesarCipher.decrypt(text, key)
                elif cipher_type == "Hill":
                    result = hill_cipher.HillCipher.decrypt(text, key)
                elif cipher_type == "Permutación":
                    result = permutation_cipher.PermutationCipher.decrypt(text, key)
                elif cipher_type == "Sustitución":
                    result = substitution_cipher.SubstitutionCipher.decrypt(text, key)
                elif cipher_type == "Vigenere":
                    result = vigenere_cipher.VigenereCipher.decrypt(text, key)
                elif cipher_type == "Elgamal":
                    try:
                        public_key_str, private_key_str = key.split("-")
                        public_key = ast.literal_eval(public_key_str)
                        private_key = int(private_key_str)
                        textTuple = ast.literal_eval(text)
                        result = elgamal_cipher.decrypt(public_key, private_key, textTuple)
                    except Exception as e:
                        result = "Error: Formato de clave inválido. Use: public_key-private_key"
                elif cipher_type == "RSA":
                    try:
                        partes = key.split(',')
                        if len(partes) != 2:
                            raise ValueError("Ingrese n, d separados por comas.")
                        n = int(partes[0].strip())
                        d = int(partes[1].strip())
                        c = atack_rsa.parse_ciphertext(text.strip())
                        result = atack_rsa.ataque_rsa(n, d, c)
                    except Exception as ex:
                        result = f"Error en el ataque RSA: {str(ex)}"
            elif operation == "Ataque":
                if cipher_type == "RSA":
                    try:
                        partes = key.split(',')
                        if len(partes) != 2:
                            raise ValueError("Ingrese n, e separados por comas.")
                        e = int(partes[0].strip())
                        n = int(partes[1].strip())
                        c = atack_rsa.parse_ciphertext(text.strip())
                        result = atack_rsa.ataque_rsa(n, e, c)
                    except Exception as ex:
                        result = f"Error en el ataque RSA: {str(ex)}"
                elif cipher_type == "Afin":
                    result = affine_cipher.AffineCipher.attack(text)
                elif cipher_type == "Desplazamiento":
                    result = caesar_cipher.CaesarCipher.attack(text)
                    # Capturar la salida del print en el resultado
                    result = "Posibles soluciones:\n" + "\n".join([f"Clave {i}: {sol}" for i, sol in enumerate(result)])
                elif cipher_type == "Hill":
                    # Para Hill necesitamos texto claro conocido
                    known_plaintext = None
                    if key:  # Si hay texto en el campo de clave, lo usamos como texto claro conocido
                        known_plaintext = key
                    result = hill_cipher.HillCipher.attack(text, known_plaintext)
                elif cipher_type == "Sustitución":
                    result = substitution_cipher.SubstitutionCipher.attack(text)
                elif cipher_type == "Vigenere":
                    result = vigenere_cipher.VigenereCipher.attack(text)
                else:
                    # Para cualquier otro cifrado que no tenga implementado su propio ataque
                    atack_brauer.iniciar_visualizacion(text)
                    result = "Análisis de Brauer iniciado. Por favor revise la ventana de visualización."
        except Exception as e:
            result = f"Error: {str(e)}"

        self.output_text.setPlainText(result)


class ImageWindow(QMainWindow):
    def __init__(self):
        super(ImageWindow, self).__init__()
        self.setWindowTitle("Cifrado de Imágenes")
        self.setGeometry(150, 150, 800, 700)
        self.showMaximized()
        self.setStyleSheet(STYLE_SHEET)
        self.image_path = None
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        # Contenedor principal con margen
        main_frame = QFrame()
        main_frame.setProperty("class", "card")
        main_layout = QVBoxLayout(main_frame)

        # Título
        title = QLabel("Cifrado de Imágenes con AES")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # Grid para los controles
        controls_layout = QGridLayout()
        controls_layout.setSpacing(10)

        # Campo para la clave AES
        controls_layout.addWidget(QLabel("Clave AES:"), 0, 0)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Ingrese la clave para el cifrado AES")
        controls_layout.addWidget(self.key_input, 0, 1)

        # Selector de operación
        controls_layout.addWidget(QLabel("Operación:"), 1, 0)
        self.combo_operation = QComboBox()
        self.combo_operation.addItems(["Encriptar", "Desencriptar", "Ataque"])
        controls_layout.addWidget(self.combo_operation, 1, 1)

        # Selector de modo de encripción
        controls_layout.addWidget(QLabel("Modo de encripción:"), 2, 0)
        self.enc_mode = QComboBox()
        self.enc_mode.addItems(['CBC', 'CFB', 'OFB', 'CTR'])
        controls_layout.addWidget(self.enc_mode, 2, 1)

        main_layout.addLayout(controls_layout)

        # Sección de imagen
        image_section = QFrame()
        image_section.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 10px;
                margin: 20px 0;
            }
        """)
        image_layout = QVBoxLayout(image_section)

        # Botón para seleccionar imagen
        self.btn_choose = QPushButton("Seleccionar Imagen")
        self.btn_choose.clicked.connect(self.selectImage)
        self.btn_choose.setStyleSheet("""
            QPushButton {
                margin: 10px 0;
                font-size: 16px;
                min-height: 40px;
            }
        """)
        image_layout.addWidget(self.btn_choose)

        # Label para mostrar la imagen
        self.image_label = QLabel("Seleccione una imagen para comenzar")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setMinimumSize(400, 300)
        self.image_label.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 2px dashed #bdc3c7;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        image_layout.addWidget(self.image_label)

        main_layout.addWidget(image_section)

        # Botón para ejecutar
        self.btn_execute = QPushButton("Ejecutar")
        self.btn_execute.clicked.connect(self.executeAES)
        self.btn_execute.setStyleSheet("""
            QPushButton {
                margin: 20px 0;
                font-size: 16px;
                min-height: 40px;
            }
        """)
        main_layout.addWidget(self.btn_execute)

        # Añadir el frame principal al layout de la ventana
        layout.addWidget(main_frame)
        self.setCentralWidget(widget)

    def selectImage(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar Imagen", "", 
            "Imágenes (*.png *.jpg *.jpeg *.bmp);;Todos los archivos (*)", 
            options=options
        )
        if fileName:
            self.image_path = fileName
            pixmap = QPixmap(fileName)
            scaled_pixmap = pixmap.scaled(
                self.image_label.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            self.image_label.setPixmap(scaled_pixmap)
            self.image_label.setStyleSheet("""
                QLabel {
                    background-color: white;
                    border: 2px solid #bdc3c7;
                    border-radius: 5px;
                    padding: 10px;
                }
            """)

    def executeAES(self):
        if not self.image_path:
            self.showMessage("Por favor seleccione una imagen primero.")
            return

        key = self.key_input.text()
        msg = ""
        if not key:
            self.showMessage("Por favor ingrese una clave AES.")
            return

        operation = self.combo_operation.currentText()
        mode = self.enc_mode.currentText()
        if operation != "Ataque" and not self.key_input.text():
            self.showMessage("Ingrese una clave AES.")
            return
        key = self.key_input.text()  # Puede estar vacío en el caso de Ataque
        output_path = None

        try:
            if operation == "Encriptar":
                if mode == "CBC":
                    # Se utiliza el módulo CBC_cipher para el modo CBC
                    result = CBC_cipher.encrypt_image(self.image_path, key, CBC_cipher.encryption_path, mode=mode)
                    output_path = CBC_cipher.encryption_path
                else:
                    result = AES_cipher.encrypt_image(self.image_path, key, AES_cipher.encryption_path, mode)
                    output_path = AES_cipher.encryption_path

            elif operation == "Desencriptar":
                if mode == "CBC":
                    result = CBC_cipher.decrypt_image(self.image_path, key, CBC_cipher.decryption_path, mode=mode)
                    output_path = CBC_cipher.decryption_path
                else:
                    result = AES_cipher.decrypt_image(self.image_path, key, AES_cipher.decryption_path, mode)
                    output_path = AES_cipher.decryption_path

            elif operation == "Ataque":
                # Se asume que la imagen cifrada en modo CBC se encuentra en CBC_cipher.encryption_path
                encrypted_path = CBC_cipher.encryption_path
                key_found, decrypted_data = CBC_attack.brute_force(encrypted_path)
                if key_found:
                    self.showMessage("Clave encontrada: " + str(key_found))
                    # Se guarda el resultado del ataque en un archivo
                    output_path = os.path.join(project_dir, "library", "img", "attackedCBC_image.png")
                    with open(output_path, "wb") as f:
                        f.write(decrypted_data)
                else:
                    self.showMessage("No se encontró la clave.")
                    return

            else:
                self.showMessage("Operación no válida.")
                return

            # Si se obtuvo un archivo de salida, se muestra la imagen resultante
            if output_path:
                pixmap = QPixmap(output_path)
                self.image_label.setPixmap(pixmap.scaled(self.image_label.size()))
                self.image_label.setScaledContents(True)
                self.showMessage(operation + " completado.")
            else:
                self.showMessage("Error en el proceso de " + operation.lower() + ".")
        except Exception as e:
            msg = f"Error: {str(e)}"
            self.showMessage(msg)

    def showMessage(self, message):
        QMessageBox.information(self, "Información", message)


class SignatureWindow(QMainWindow):
    def __init__(self):
        super(SignatureWindow, self).__init__()
        self.setWindowTitle("Firmas Digitales")
        self.setGeometry(150, 150, 900, 700)
        self.showMaximized()
        self.setStyleSheet(STYLE_SHEET)
        self.ds = digital_signatures.DigitalSignature()
        self.signature_path = None
        self.initUI()

    def initUI(self):
        # Create the main widget
        widget = QWidget()
        widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)  # Allow resizing

        # Create the main layout
        layout = QVBoxLayout(widget)

        # Contenedor principal
        main_frame = QFrame()
        main_frame.setProperty("class", "card")
        main_layout = QVBoxLayout(main_frame)


        # Título principal con icono simulado
        title_bar = QHBoxLayout()
        # title_icon = QLabel("🔐")
        # title_icon.setStyleSheet("font-size: 28px; margin-right: 10px;")
        title = QLabel("Sistema de Firmas Digitales")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #2c3e50;")
        # title_bar.addWidget(title_icon)
        title_bar.addWidget(title)
        title_bar.addStretch()
        main_layout.addLayout(title_bar)
        
        # Descripción
        description = QLabel("Creación, gestión y verificación de firmas digitales para la integridad y autenticidad de documentos")
        description.setStyleSheet("color: #7f8c8d; font-size: 14px; margin-bottom: 20px;")
        description.setWordWrap(True)
        main_layout.addWidget(description)

        # Línea separadora
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("border: 1px solid #e0e0e0; margin: 10px 0px 20px 0px;")
        main_layout.addWidget(separator)

        # Crear un layout horizontal para las dos secciones principales
        sections_layout = QHBoxLayout()

        # ---- SECCIÓN IZQUIERDA: GENERACIÓN DE CLAVES ----
        key_section = QFrame()
        key_section.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 8px;
                padding: 20px;
                margin: 5px;
                border: 1px solid #e0e0e0;
            }
        """)
        key_layout = QVBoxLayout(key_section)

        # Título con icono
        key_title_layout = QHBoxLayout()
        # key_icon = QLabel("🔑")
        # key_icon.setStyleSheet("font-size: 22px; margin-right: 10px;")
        key_title = QLabel("Generación de Claves")
        key_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2980b9;")
        # key_title_layout.addWidget(key_icon)
        key_title_layout.addWidget(key_title)
        key_title_layout.addStretch()
        key_layout.addLayout(key_title_layout)

        # Descripción de la sección
        key_desc = QLabel("Crea pares de claves criptográficas para firmar y verificar documentos")
        key_desc.setWordWrap(True)
        key_desc.setStyleSheet("color: #7f8c8d; margin-bottom: 15px;")
        key_layout.addWidget(key_desc)

        # Selector de algoritmo con estilo mejorado
        algo_frame = QFrame()
        algo_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 6px;
                padding: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        algo_layout = QVBoxLayout(algo_frame)
        
        algo_label = QLabel("Selecciona el algoritmo:")
        algo_label.setStyleSheet("font-weight: bold; color: #34495e;")
        algo_layout.addWidget(algo_label)
        
        algo_desc_layout = QHBoxLayout()
        
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(['RSA', 'DSA', 'ECDSA'])
        self.algo_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                background-color: white;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox::down-arrow {
                image: url(dropdown.png);
                width: 14px;
                height: 14px;
            }
        """)
        
        algo_info = QLabel("ℹ️")
        algo_info.setStyleSheet("font-size: 16px; color: #3498db;")
        algo_info.setToolTip("RSA: Mayor seguridad, más recursos\nDSA: Rápido para firmar\nECDSA: Claves más pequeñas")
        
        algo_desc_layout.addWidget(self.algo_combo)
        algo_desc_layout.addWidget(algo_info)
        algo_layout.addLayout(algo_desc_layout)
        
        key_layout.addWidget(algo_frame)

        # Parámetros adicionales (opcional)
        params_frame = QFrame()
        params_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 6px;
                padding: 10px;
                margin-top: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        params_layout = QVBoxLayout(params_frame)
        
        params_label = QLabel("Configuración (opcional):")
        params_label.setStyleSheet("font-weight: bold; color: #34495e;")
        params_layout.addWidget(params_label)
        
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Tamaño de clave:"))
        key_size_combo = QComboBox()
        key_size_combo.addItems(['2048 bits', '3072 bits', '4096 bits'])
        key_size_combo.setStyleSheet("padding: 5px; border: 1px solid #bdc3c7; border-radius: 3px;")
        key_size_layout.addWidget(key_size_combo)
        params_layout.addLayout(key_size_layout)
        
        key_layout.addWidget(params_frame)
        from PyQt5.QtWidgets import QStyle
        # Botón para generar claves con estilo mejorado
        gen_key_btn = QPushButton("Generar Par de Claves")
        gen_key_btn.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
        gen_key_btn.clicked.connect(self.generate_keys)
        gen_key_btn.setStyleSheet("""
            QPushButton {
                background-color: #2980b9;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-weight: bold;
                margin-top: 15px;
            }
            QPushButton:hover {
                background-color: #3498db;
            }
            QPushButton:pressed {
                background-color: #1c6ea4;
            }
        """)
        key_layout.addWidget(gen_key_btn)
        
        # Espacio adicional al final
        key_layout.addStretch()

        # ---- SECCIÓN DERECHA: FIRMA Y VERIFICACIÓN ----
        sign_section = QFrame()
        sign_section.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 8px;
                padding: 20px;
                margin: 5px;
                border: 1px solid #e0e0e0;
            }
        """)
        sign_layout = QVBoxLayout(sign_section)

        # Título con icono
        sign_title_layout = QHBoxLayout()
        # sign_icon = QLabel("📝")
        # sign_icon.setStyleSheet("font-size: 22px; margin-right: 10px;")
        sign_title = QLabel("Firma y Verificación")
        sign_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #27ae60;")
        # sign_title_layout.addWidget(sign_icon)
        sign_title_layout.addWidget(sign_title)
        sign_title_layout.addStretch()
        sign_layout.addLayout(sign_title_layout)

        # Descripción de la sección
        sign_desc = QLabel("Firma documentos para garantizar su autenticidad o verifica firmas existentes")
        sign_desc.setWordWrap(True)
        sign_desc.setStyleSheet("color: #7f8c8d; margin-bottom: 15px;")
        sign_layout.addWidget(sign_desc)

        # Selector de operación con estilo mejorado
        op_frame = QFrame()
        op_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 6px;
                padding: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        op_layout = QVBoxLayout(op_frame)
        
        op_label = QLabel("Operación:")
        op_label.setStyleSheet("font-weight: bold; color: #34495e;")
        op_layout.addWidget(op_label)
        
        self.op_combo = QComboBox()
        self.op_combo.addItems(['Firmar Documento', 'Verificar Firma'])
        self.op_combo.currentIndexChanged.connect(self.toggle_key_selection)
        self.op_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                background-color: white;
            }
        """)
        op_layout.addWidget(self.op_combo)
        
        sign_layout.addWidget(op_frame)

        # Selección de archivo con estilo mejorado
        file_frame = QFrame()
        file_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 6px;
                padding: 10px;
                margin-top: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        file_layout = QVBoxLayout(file_frame)
        
        file_label = QLabel("Documento:")
        file_label.setStyleSheet("font-weight: bold; color: #34495e;")
        file_layout.addWidget(file_label)
        
        file_input_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Seleccione un archivo...")
        self.file_path.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }
        """)
        browse_btn = QPushButton("Examinar")
        browse_btn.clicked.connect(self.browse_file)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        file_input_layout.addWidget(self.file_path)
        file_input_layout.addWidget(browse_btn)
        file_layout.addLayout(file_input_layout)
        
        sign_layout.addWidget(file_frame)

        # Selección de clave con estilo mejorado
        key_frame = QFrame()
        key_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 6px;
                padding: 10px;
                margin-top: 10px;
                border: 1px solid #e0e0e0;
            }
        """)
        key_input_layout = QVBoxLayout(key_frame)
        
        self.key_label = QLabel("Archivo de clave:")
        self.key_label.setStyleSheet("font-weight: bold; color: #34495e;")
        key_input_layout.addWidget(self.key_label)
        
        key_browse_layout = QHBoxLayout()
        self.key_path = QLineEdit()
        self.key_path.setPlaceholderText("Seleccione archivo de clave...")
        self.key_path.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
            }
        """)
        key_browse_btn = QPushButton("Examinar")
        key_browse_btn.clicked.connect(self.browse_key)
        key_browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        key_browse_layout.addWidget(self.key_path)
        key_browse_layout.addWidget(key_browse_btn)
        key_input_layout.addLayout(key_browse_layout)
        
        sign_layout.addWidget(key_frame)

        # Botón de ejecución con estilo mejorado
        execute_btn = QPushButton("Ejecutar Operación")
        execute_btn.clicked.connect(self.execute_operation)
        execute_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-weight: bold;
                margin-top: 15px;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
            QPushButton:pressed {
                background-color: #219653;
            }
        """)
        sign_layout.addWidget(execute_btn)
        
        # Espacio adicional al final
        sign_layout.addStretch()

        # Añadir las dos secciones al layout horizontal
        sections_layout.addWidget(key_section, 40)  # 40% del espacio
        sections_layout.addWidget(sign_section, 60)  # 60% del espacio
        main_layout.addLayout(sections_layout)

        # Área de resultados con estilo mejorado
        result_section = QFrame()
        result_section.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 8px;
                padding: 15px;
                margin-top: 15px;
                border: 1px solid #e0e0e0;
            }
        """)
        result_layout = QVBoxLayout(result_section)
        
        result_header = QHBoxLayout()
        # result_icon = QLabel("📋")
        # result_icon.setStyleSheet("font-size: 18px; margin-right: 10px;")
        result_label = QLabel("Resultado de la Operación")
        result_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #34495e;")
        # result_header.addWidget(result_icon)
        result_header.addWidget(result_label)
        result_header.addStretch()
        
        # Añadir botón para copiar resultado
        copy_btn = QPushButton("Copiar")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #7f8c8d;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #95a5a6;
            }
        """)
        copy_btn.clicked.connect(self.copy_result)
        result_header.addWidget(copy_btn)
        
        result_layout.addLayout(result_header)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setMinimumHeight(120)
        self.result_text.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 10px;
                font-family: "Courier New", monospace;
            }
        """)
        result_layout.addWidget(self.result_text)
        
        main_layout.addWidget(result_section)

        # Estado de verificación (visible solo cuando es relevante)
        self.verification_status = QFrame()
        self.verification_status.setVisible(False)
        self.verification_status.setStyleSheet("""
            QFrame {
                border-radius: 5px;
                padding: 10px;
                margin-top: 10px;
            }
        """)
        verification_layout = QHBoxLayout(self.verification_status)
        
        self.status_icon = QLabel()
        self.status_icon.setStyleSheet("font-size: 24px; margin-right: 10px;")
        verification_layout.addWidget(self.status_icon)
        
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        verification_layout.addWidget(self.status_label)
        verification_layout.addStretch()
        
        main_layout.addWidget(self.verification_status)

        # Add the main_frame to the layout
        layout.addWidget(main_frame)

        # Create a QScrollArea
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)  # Allow the widget to resize
        scroll_area.setWidget(widget)  # Set the main widget as the scrollable widget

        # Set the QScrollArea as the central widget
        self.setCentralWidget(scroll_area)

        # Inicializar la selección
        self.toggle_key_selection()

    def toggle_key_selection(self):
        operation = self.op_combo.currentText()
        if operation == 'Firmar Documento':
            self.key_label.setText("Archivo de clave privada:")
            self.key_path.setPlaceholderText("Seleccione archivo de clave privada (*.pem)...")
            # Ocultar el estado de verificación
            self.verification_status.setVisible(False)
        else:
            self.key_label.setText("Archivo de clave pública:")
            self.key_path.setPlaceholderText("Seleccione archivo de clave pública (*.pem)...")

    def browse_file(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar Documento", "", 
            "Todos los archivos (*);;Documentos de texto (*.txt);;PDF (*.pdf);;Word (*.docx)", 
            options=options
        )
        if fileName:
            self.file_path.setText(fileName)
            # Si estamos en modo verificación, intentar encontrar un archivo de firma automáticamente
            if self.op_combo.currentText() == 'Verificar Firma':
                signature_path = fileName + '.sig'
                if os.path.exists(signature_path):
                    self.signature_path = signature_path
                    self.show_status_message("Archivo de firma encontrado", is_info=True)
                else:
                    self.signature_path = None
                    self.show_status_message("No se encontró un archivo de firma automáticamente", is_info=True)

    def browse_key(self):
        options = QFileDialog.Options()
        operation = self.op_combo.currentText()
        dialog_title = "Seleccionar Clave Privada" if operation == 'Firmar Documento' else "Seleccionar Clave Pública"
        
        fileName, _ = QFileDialog.getOpenFileName(
            self, dialog_title, "", 
            "Archivos PEM (*.pem);;Todos los archivos (*)", 
            options=options
        )
        if fileName:
            self.key_path.setText(fileName)

    def copy_result(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.result_text.toPlainText())
        self.show_message("Resultado copiado al portapapeles")

    def generate_keys(self):
        try:
            algorithm = self.algo_combo.currentText()
            # Crear directorio para las claves si no existe
            keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
            os.makedirs(keys_dir, exist_ok=True)
            
            # Generar par de claves
            self.ds.generate_key_pair(algorithm=algorithm, save_path=keys_dir)
            
            # Formatear mensaje de resultado
            private_key_path = os.path.join(keys_dir, f"private_key_{algorithm.lower()}.pem")
            public_key_path = os.path.join(keys_dir, f"public_key_{algorithm.lower()}.pem")
            
            result_msg = (
                f"✅ Par de claves {algorithm} generado exitosamente.\n\n"
                f"📂 Ubicación: {keys_dir}\n\n"
                f"📄 Archivos generados:\n"
                f"  • 🔐 Clave privada: private_key_{algorithm.lower()}.pem\n"
                f"  • 🔑 Clave pública: public_key_{algorithm.lower()}.pem\n\n"
                f"⚠️ IMPORTANTE: Mantenga su clave privada segura y nunca la comparta."
            )
            
            self.result_text.setPlainText(result_msg)
            self.show_status_message("Claves generadas con éxito", True)
            
        except Exception as e:
            error_msg = f"❌ Error al generar las claves: {str(e)}"
            self.result_text.setPlainText(error_msg)
            self.show_status_message("Error al generar claves", False)

    def execute_operation(self):
        if not self.file_path.text():
            self.show_message("Por favor seleccione un archivo.")
            return
        if not self.key_path.text():
            self.show_message("Por favor seleccione un archivo de clave.")
            return

        try:
            operation = self.op_combo.currentText()
            if operation == 'Firmar Documento':
                # Para firmar, solo necesitamos la clave privada
                with open(self.key_path.text(), 'rb') as f:
                    private_key = load_pem_private_key(f.read(), password=None)
                
                # Firmar documento
                signature_path = self.ds.sign_document(
                    private_key, 
                    self.file_path.text(), 
                    self.algo_combo.currentText()
                )
                
                # Formatear resultado de firma
                result_msg = (
                    f"✅ Documento firmado exitosamente\n\n"
                    f"📄 Documento: {os.path.basename(self.file_path.text())}\n"
                    f"🔏 Algoritmo: {self.algo_combo.currentText()}\n"
                    f"📂 Firma guardada en: {signature_path}\n\n"
                    f"El archivo de firma puede distribuirse junto con el documento\n"
                    f"para permitir a otros verificar su autenticidad."
                )
                
                self.result_text.setPlainText(result_msg)
                self.show_status_message("Documento firmado con éxito", True)
                
            else:  # Verificar firma
                # Para verificar, solo necesitamos la clave pública
                with open(self.key_path.text(), 'rb') as f:
                    public_key = load_pem_public_key(f.read())
                
                # Verificar firma
                if self.signature_path:
                    signature_path = self.signature_path
                else:
                    signature_path = self.file_path.text() + '.sig'
                
                if not os.path.exists(signature_path):
                    raise FileNotFoundError("No se encontró el archivo de firma (.sig).")
                
                is_valid = self.ds.verify_signature(
                    public_key,
                    self.file_path.text(),
                    signature_path
                )
                
                # Mostrar estado de verificación
                self.show_verification_status(is_valid)
                
                # Formatear resultado de verificación
                result_msg = (
                    f"{'✅ La firma es válida. El documento es auténtico.' if is_valid else '❌ La firma NO es válida. El documento puede haber sido modificado.'}\n\n"
                    f"📄 Documento verificado: {os.path.basename(self.file_path.text())}\n"
                    f"🔏 Archivo de firma: {os.path.basename(signature_path)}\n"
                )
                
                # Añadir hash del documento
                file_hash = self.ds.get_file_hash(self.file_path.text())
                result_msg += f"\n📊 Hash SHA-256 del documento:\n{file_hash}"
                
                self.result_text.setPlainText(result_msg)

        except Exception as e:
            error_msg = f"❌ Error: {str(e)}"
            self.result_text.setPlainText(error_msg)
            self.show_status_message("Error en la operación", False)

    def show_verification_status(self, is_valid):
        self.verification_status.setVisible(True)
        
        if is_valid:
            self.verification_status.setStyleSheet("""
                QFrame {
                    background-color: #d4edda;
                    border: 1px solid #c3e6cb;
                    border-radius: 5px;
                    padding: 15px;
                    margin-top: 10px;
                }
            """)
            self.status_icon.setText("✅")
            self.status_label.setText("Verificación Exitosa: Documento auténtico y sin modificaciones")
            self.status_label.setStyleSheet("color: #155724; font-size: 16px; font-weight: bold;")
        else:
            self.verification_status.setStyleSheet("""
                QFrame {
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 5px;
                    padding: 15px;
                    margin-top: 10px;
                }
            """)
            self.status_icon.setText("❌")
            self.status_label.setText("Verificación Fallida: La firma no es válida o el documento ha sido modificado")
            self.status_label.setStyleSheet("color: #721c24; font-size: 16px; font-weight: bold;")

    def show_status_message(self, message, success=True, is_info=False):
        self.verification_status.setVisible(True)
        
        if is_info:
            self.verification_status.setStyleSheet("""
                QFrame {
                    background-color: #cce5ff;
                    border: 1px solid #b8daff;
                    border-radius: 5px;
                    padding: 15px;
                    margin-top: 10px;
                }
            """)
            self.status_icon.setText("ℹ️")
            self.status_label.setStyleSheet("color: #004085; font-size: 16px; font-weight: bold;")
        elif success:
            self.verification_status.setStyleSheet("""
                QFrame {
                    background-color: #d4edda;
                    border: 1px solid #c3e6cb;
                    border-radius: 5px;
                    padding: 15px;
                    margin-top: 10px;
                }
            """)
            self.status_icon.setText("✅")
            self.status_label.setStyleSheet("color: #155724; font-size: 16px; font-weight: bold;")
        else:
            self.verification_status.setStyleSheet("""
                QFrame {
                    background-color: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 5px;
                    padding: 15px;
                    margin-top: 10px;
                }
            """)
            self.status_icon.setText("❌")
            self.status_label.setStyleSheet("color: #721c24; font-size: 16px; font-weight: bold;")
            
        self.status_label.setText(message)

    def show_message(self, message):
        QMessageBox.information(self, "Información", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
