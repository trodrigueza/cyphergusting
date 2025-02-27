import sys
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
import library.digital_signatures as digital_signatures

# Se asume que en el módulo AES_cipher se definen:
# AES_cipher.encryption_path = "library/img/encrypted_image"
# AES_cipher.decryption_path = "library/img/decrypted_image"

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
            "Afin": "Formato: a,b (ejemplo: 3,7) - a debe ser coprimo con 26",
            "Desplazamiento": "Número entero entre 0 y 25",
            "Hill": "Matriz cuadrada (ejemplo para 2x2: 2,3,1,4)",
            "Permutación": "Permutación de números (ejemplo: 3,1,4,2)",
            "Sustitución": "Alfabeto de sustitución de 26 letras",
            "Vigenere": "Palabra clave (solo letras)",
            "RSA": {
                "Encriptar": "Clave pública (n,e)",
                "Desencriptar": "Clave privada (n,d)",
                "Ataque": "Clave pública (e,n)"
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
            "Caesar": "Desplazamiento:",
            "Hill": "Matriz de cifrado:",
            "Permutativo": "Permutación:",
            "Sustitutivo": "Alfabeto de sustitución:",
            "Vigenere": "Palabra clave:",
            "RSA": {
                "Encriptar": "Clave pública (n,e):",
                "Desencriptar": "Clave privada (n,d):",
                "Ataque": "Clave pública (e,n):"
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
        show_key = operation in ["Encriptar", "Desencriptar"] or (operation == "Ataque" and cipher == "RSA")
        
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
                elif cipher_type == "Caesar":
                    result = caesar_cipher.CaesarCipher.encrypt(text, key)
                elif cipher_type == "Hill":
                    result = hill_cipher.HillCipher.encrypt(text, key)
                elif cipher_type == "Permutativo":
                    result = permutation_cipher.PermutationCipher.encrypt(text, key)
                elif cipher_type == "Sustitutivo":
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
                elif cipher_type == "Caesar":
                    result = caesar_cipher.CaesarCipher.decrypt(text, key)
                elif cipher_type == "Hill":
                    result = hill_cipher.HillCipher.decrypt(text, key)
                elif cipher_type == "Permutativo":
                    result = permutation_cipher.PermutationCipher.decrypt(text, key)
                elif cipher_type == "Sustitutivo":
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
                        private_key = ast.literal_eval(key)
                        textTuple = ast.literal_eval(text)
                        result = rsa_cipher.decrypt(private_key, textTuple)
                    except Exception as e:
                        result = f"Error: Formato de clave inválido - {str(e)}"
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
                else:
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
        self.combo_operation.addItems(["Encriptar", "Desencriptar"])
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
        if not key:
            self.showMessage("Por favor ingrese una clave AES.")
            return

        operation = self.combo_operation.currentText()
        mode = self.enc_mode.currentText()
        output_path = None

        try:
            if operation == "Encriptar":
                result = AES_cipher.encrypt_image(self.image_path, key, AES_cipher.encryption_path, mode)
                output_path = AES_cipher.encryption_path
            else:  # Desencriptar
                result = AES_cipher.decrypt_image(self.image_path, key, AES_cipher.decryption_path, mode)
                output_path = AES_cipher.decryption_path

            if result:
                msg = f"Operación de {operation.lower()} completada exitosamente."
                pixmap = QPixmap(output_path)
                scaled_pixmap = pixmap.scaled(
                    self.image_label.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
                self.image_label.setPixmap(scaled_pixmap)
            else:
                msg = f"Error en el proceso de {operation.lower()}."
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
        self.setStyleSheet(STYLE_SHEET)
        self.ds = digital_signatures.DigitalSignature()
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)

        # Contenedor principal
        main_frame = QFrame()
        main_frame.setProperty("class", "card")
        main_layout = QVBoxLayout(main_frame)

        # Título
        title = QLabel("Firmas Digitales")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # Sección de generación de claves
        key_section = QFrame()
        key_section.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
                margin: 10px 0;
            }
        """)
        key_layout = QVBoxLayout(key_section)

        key_title = QLabel("Generación de Claves")
        key_title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        key_layout.addWidget(key_title)

        # Selector de algoritmo
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Algoritmo:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(['RSA', 'DSA', 'ECDSA'])
        algo_layout.addWidget(self.algo_combo)
        key_layout.addLayout(algo_layout)

        # Botón para generar claves
        gen_key_btn = QPushButton("Generar Par de Claves")
        gen_key_btn.clicked.connect(self.generate_keys)
        key_layout.addWidget(gen_key_btn)

        main_layout.addWidget(key_section)

        # Sección de firma y verificación
        sign_section = QFrame()
        sign_section.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
                margin: 10px 0;
            }
        """)
        sign_layout = QVBoxLayout(sign_section)

        # Selector de operación
        op_layout = QHBoxLayout()
        op_layout.addWidget(QLabel("Operación:"))
        self.op_combo = QComboBox()
        self.op_combo.addItems(['Firmar Documento', 'Verificar Firma'])
        self.op_combo.currentIndexChanged.connect(self.toggle_key_selection)
        op_layout.addWidget(self.op_combo)
        sign_layout.addLayout(op_layout)

        # Selección de archivo
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Seleccione un archivo...")
        file_layout.addWidget(self.file_path)
        browse_btn = QPushButton("Examinar")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        sign_layout.addLayout(file_layout)

        # Selección de clave
        self.key_selection = QHBoxLayout()
        self.key_path = QLineEdit()
        self.key_path.setPlaceholderText("Seleccione archivo de clave...")
        self.key_selection.addWidget(self.key_path)
        key_browse_btn = QPushButton("Examinar")
        key_browse_btn.clicked.connect(self.browse_key)
        self.key_selection.addWidget(key_browse_btn)
        sign_layout.addLayout(self.key_selection)

        # Botón de ejecución
        execute_btn = QPushButton("Ejecutar")
        execute_btn.clicked.connect(self.execute_operation)
        sign_layout.addWidget(execute_btn)

        main_layout.addWidget(sign_section)

        # Área de resultados
        result_label = QLabel("Resultado:")
        main_layout.addWidget(result_label)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setMinimumHeight(100)
        main_layout.addWidget(self.result_text)

        layout.addWidget(main_frame)
        self.setCentralWidget(widget)

    def toggle_key_selection(self):
        operation = self.op_combo.currentText()
        if operation == 'Firmar Documento':
            self.key_path.setPlaceholderText("Seleccione archivo de clave privada...")
        else:
            self.key_path.setPlaceholderText("Seleccione archivo de clave pública...")

    def browse_file(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar Documento", "", 
            "Todos los archivos (*);;Documentos de texto (*.txt);;PDF (*.pdf);;Word (*.docx)", 
            options=options
        )
        if fileName:
            self.file_path.setText(fileName)

    def browse_key(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar Archivo de Clave", "", 
            "Archivos PEM (*.pem);;Todos los archivos (*)", 
            options=options
        )
        if fileName:
            self.key_path.setText(fileName)

    def generate_keys(self):
        try:
            algorithm = self.algo_combo.currentText()
            # Crear directorio para las claves si no existe
            keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
            os.makedirs(keys_dir, exist_ok=True)
            
            # Generar par de claves
            self.ds.generate_key_pair(algorithm=algorithm, save_path=keys_dir)
            
            self.result_text.setPlainText(
                f"Par de claves {algorithm} generado exitosamente.\n"
                f"Ubicación: {keys_dir}\n"
                f"Archivos generados:\n"
                f"- private_key_{algorithm.lower()}.pem\n"
                f"- public_key_{algorithm.lower()}.pem"
            )
        except Exception as e:
            self.result_text.setPlainText(f"Error al generar las claves: {str(e)}")

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
                self.result_text.setPlainText(
                    f"Documento firmado exitosamente.\n"
                    f"Firma guardada en: {signature_path}"
                )
            else:  # Verificar firma
                # Para verificar, solo necesitamos la clave pública
                with open(self.key_path.text(), 'rb') as f:
                    public_key = load_pem_public_key(f.read())
                
                # Verificar firma
                signature_path = self.file_path.text() + '.sig'
                if not os.path.exists(signature_path):
                    raise FileNotFoundError("No se encontró el archivo de firma.")
                
                is_valid = self.ds.verify_signature(
                    public_key,
                    self.file_path.text(),
                    signature_path
                )
                
                if is_valid:
                    self.result_text.setPlainText("La firma es válida. El documento no ha sido modificado.")
                else:
                    self.result_text.setPlainText("La firma NO es válida. El documento puede haber sido modificado.")
                
                # Mostrar el hash del documento
                file_hash = self.ds.get_file_hash(self.file_path.text())
                self.result_text.append(f"\nHash del documento (SHA-256):\n{file_hash}")

        except Exception as e:
            self.result_text.setPlainText(f"Error: {str(e)}")
            # Mostrar más detalles del error en modo debug
            import traceback
            print("Error detallado:", traceback.format_exc())

    def show_message(self, message):
        QMessageBox.information(self, "Información", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
