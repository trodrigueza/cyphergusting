import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton,
    QVBoxLayout, QLabel, QComboBox, QTextEdit, QLineEdit, QFileDialog, QMessageBox
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
import ast

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

# Se asume que en el módulo AES_cipher se definen:
# AES_cipher.encryption_path = "library/img/encrypted_image"
# AES_cipher.decryption_path = "library/img/decrypted_image"


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Cyphergusting")
        self.setGeometry(100, 100, 600, 400)
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Título principal
        title = QLabel("Cyphergusting")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 30px; font-weight: bold;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        # Subtítulo con nombres
        subtitle = QLabel("Hecho por:\nJuan Camilo Daza Gutiérrez\nNicolás Duque Molina\nAndrés Felipe Poveda Bellon\nTomás David Rodríguez Agudelo")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(subtitle, alignment=Qt.AlignCenter)

        label = QLabel("Seleccione el tipo de cifrado:")
        label.setStyleSheet("font-size: 20px; margin-bottom: 10px;")
        layout.addWidget(label, alignment=Qt.AlignCenter)

        # Botón para cifrado de texto
        btn_text = QPushButton("Cifrado de Texto")
        btn_text.clicked.connect(self.openTextWindow)
        btn_text.setStyleSheet("font-size: 22px;")
        layout.addWidget(btn_text, alignment=Qt.AlignCenter)

        # Botón para cifrado de imagen
        btn_image = QPushButton("Cifrado de Imagen")
        btn_image.clicked.connect(self.openImageWindow)
        btn_image.setStyleSheet("font-size: 22px;")
        layout.addWidget(btn_image, alignment=Qt.AlignCenter)

        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def openTextWindow(self):
        self.textWindow = TextWindow()
        self.textWindow.show()

    def openImageWindow(self):
        self.imageWindow = ImageWindow()
        self.imageWindow.show()


class TextWindow(QMainWindow):
    def __init__(self):
        super(TextWindow, self).__init__()
        self.setWindowTitle("Cifrado de Texto")
        self.setGeometry(150, 150, 500, 450)
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Menú desplegable para seleccionar el tipo de cifrado
        layout.addWidget(QLabel("Seleccione el tipo de cifrado:"))
        self.combo_cipher = QComboBox()
        self.combo_cipher.addItems(["Afin", "Caesar", "Hill", "Permutativo", "Sustitutivo", "Vigenere", "Elgamal", "RSA"])
        layout.addWidget(self.combo_cipher)

        # Menú desplegable para seleccionar la operación
        layout.addWidget(QLabel("Seleccione la operación:"))
        self.combo_operation = QComboBox()
        self.combo_operation.addItems(["Ataque", "Encriptar", "Desencriptar"])
        self.combo_operation.currentIndexChanged.connect(self.toggleKeyField)  # Detecta cambios en la operación
        layout.addWidget(self.combo_operation)

        # Campo para ingresar la clave (visible solo si es Encriptar/Desencriptar)
        self.key_label = QLabel("Clave:")
        self.key_label.setVisible(False)
        layout.addWidget(self.key_label)
        self.key_input = QLineEdit()
        self.key_input.setVisible(False)
        layout.addWidget(self.key_input)

        # Cuadro de texto para ingresar el mensaje
        layout.addWidget(QLabel("Texto de entrada:"))
        self.input_text = QTextEdit()
        layout.addWidget(self.input_text)

        # Botón para ejecutar la operación
        self.btn_execute = QPushButton("Ejecutar")
        self.btn_execute.clicked.connect(self.executeOperation)
        layout.addWidget(self.btn_execute)

        # Área de texto para mostrar el resultado
        layout.addWidget(QLabel("Resultado:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def toggleKeyField(self):
        """ Muestra u oculta el campo de clave según la operación seleccionada. """
        operation = self.combo_operation.currentText()
        is_key_required = operation in ["Encriptar", "Desencriptar"]
        self.key_label.setVisible(is_key_required)
        self.key_input.setVisible(is_key_required)

    def executeOperation(self):
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
                    # Genera las claves para Elgamal
                    public_key, private_key = elgamal_cipher.generate_keys(32)
                    ciphertext = elgamal_cipher.encrypt(public_key, text)
                    # Se muestran las claves junto con el texto cifrado
                    result = (f"{ciphertext}\n\nClaves generadas:\n"
                            f"Publica: {public_key}\nPrivada: {private_key}")
                elif cipher_type == "RSA":
                    # Genera las claves para RSA
                    public_key, private_key = rsa_cipher.generate_keypair()
                    ciphertext = rsa_cipher.encrypt(public_key, text)
                    result = (f"{ciphertext}\n\nClaves generadas:\n"
                            f"Publica: {public_key}\nPrivada: {private_key}")
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
                # Para desencriptar se espera que el usuario ingrese las claves en un formato definido, por ejemplo: "publica|privada"
                    try:
                        # Suponiendo que 'key' es la cadena ingresada por el usuario:
                        public_key_str, private_key_str = key.split("-")
                        print(public_key_str, " - ", private_key_str)
                        public_key = ast.literal_eval(public_key_str)  # Convierte la cadena a tupla, ej.: (3482710657, 5, 829267584)
                        print(public_key)
                        print(type(public_key))
                        private_key = int(private_key_str)              # Convierte la parte de la clave privada a entero
                        print(type(private_key))
                        textTuple = ast.literal_eval(text)
                    except Exception as e:
                        result = "Formato de clave inválido. Use: public_key-private_key"
                    else:
                        result = elgamal_cipher.decrypt(public_key, private_key, textTuple)
                elif cipher_type == "RSA":
                    # Para RSA se espera que se ingrese la clave privada en el campo de clave
                    private_key = ast.literal_eval(key)  # Convierte la cadena a tupla, ej.: (3482710657, 5, 829267584)
                    textTuple = ast.literal_eval(text)
                    result = rsa_cipher.decrypt(private_key, textTuple)
            else:
                result = "El ataque aún no está implementado para este cifrado."
        except Exception as e:
            result = f"Error: {str(e)}"

        self.output_text.setPlainText(result)


class ImageWindow(QMainWindow):
    def __init__(self):
        super(ImageWindow, self).__init__()
        self.setWindowTitle("Cifrado de Imagen")
        self.setGeometry(150, 150, 600, 500)
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Cifrado de imágenes utilizando AES"))

        # Campo para ingresar la clave AES
        self.key_label = QLabel("Clave AES:")
        layout.addWidget(self.key_label)
        self.key_input = QLineEdit()
        layout.addWidget(self.key_input)

        # Menú desplegable para seleccionar la operación
        layout.addWidget(QLabel("Seleccione la operación:"))
        self.combo_operation = QComboBox()
        self.combo_operation.addItems(["Encriptar", "Desencriptar"])
        layout.addWidget(self.combo_operation)

        # Menú desplegable para seleccionar modo de encripcion
        layout.addWidget(QLabel("Seleccione el modo de encripcion:"))
        self.enc_mode = QComboBox()
        self.enc_mode.addItems(['CBC', 'CFB', 'OFB', 'CTR'])
        layout.addWidget(self.enc_mode)

        # Botón para seleccionar la imagen
        self.btn_choose = QPushButton("Seleccionar Imagen")
        self.btn_choose.clicked.connect(self.selectImage)
        layout.addWidget(self.btn_choose)

        # Botón para ejecutar el proceso AES
        self.btn_execute = QPushButton("Ejecutar")
        self.btn_execute.clicked.connect(self.executeAES)
        layout.addWidget(self.btn_execute)

        # Label para mostrar la imagen seleccionada o resultante
        self.image_label = QLabel("La imagen encriptada/desencriptada se mostrará aquí")
        self.image_label.setFixedSize(300, 300)
        self.image_label.setStyleSheet("border: 1px solid black;")
        layout.addWidget(self.image_label, alignment=Qt.AlignCenter)

        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def selectImage(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar Imagen", "", "Images (*.png *.jpg *.jpeg *.bmp)", options=options)
        if fileName:
            self.image_path = fileName
            # Mostrar la imagen seleccionada en el label
            pixmap = QPixmap(fileName)
            self.image_label.setPixmap(pixmap.scaled(self.image_label.size()))
            self.image_label.setScaledContents(True)

    def executeAES(self):
        key = self.key_input.text()
        if not key:
            self.showMessage("Ingrese una clave AES.")
            return

        operation = self.combo_operation.currentText()
        mode = self.enc_mode.currentText()
        output_path = None
        try:
            if operation == "Encriptar":
                # Se asume que encrypt_image guarda la imagen en AES_cipher.encryption_path
                result = AES_cipher.encrypt_image(self.image_path, key, AES_cipher.encryption_path, mode)
                output_path = AES_cipher.encryption_path
            else:  # Desencriptar
                result = AES_cipher.decrypt_image(self.image_path, key, AES_cipher.decryption_path, mode)
                output_path = AES_cipher.decryption_path

            if result:
                msg = f"{operation} completado."
                # Cargar la imagen resultante desde el path definido
                pixmap = QPixmap(output_path)
                self.image_label.setPixmap(pixmap.scaled(self.image_label.size()))
                self.image_label.setScaledContents(True)
            else:
                msg = f"Error en el proceso de {operation.lower()}."
        except Exception as e:
            msg = f"Error: {str(e)}"

        self.showMessage(msg)

    def showMessage(self, message):
        QMessageBox.information(self, "Información", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
