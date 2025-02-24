import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QPushButton,
    QVBoxLayout, QLabel, QComboBox, QTextEdit, QLineEdit, QFileDialog
)

# Importamos las funciones de cifrado
import library.src.affine_cipher as affine_cipher
import library.src.caesar_cipher as caesar_cipher
import library.src.hill_cipher as hill_cipher
import library.src.permutation_cipher as permutation_cipher
import library.src.substitution_cipher as substitution_cipher
import library.src.vigenere_cipher as vigenere_cipher
import library.AES as AES_cipher


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Selección de Cifrado")
        self.setGeometry(100, 100, 300, 200)
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()

        label = QLabel("Seleccione el tipo de cifrado:")
        layout.addWidget(label)

        # Botón para cifrado de texto
        btn_text = QPushButton("Cifrado de Texto")
        btn_text.clicked.connect(self.openTextWindow)
        layout.addWidget(btn_text)

        # Botón para cifrado de imagen
        btn_image = QPushButton("Cifrado de Imagen")
        btn_image.clicked.connect(self.openImageWindow)
        layout.addWidget(btn_image)

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
        self.combo_cipher.addItems(["Afin", "Caesar", "Hill", "Permutativo", "Sustitutivo", "Vigenere"])
        layout.addWidget(self.combo_cipher)

        # Menú desplegable para seleccionar la operación
        layout.addWidget(QLabel("Seleccione la operación:"))
        self.combo_operation = QComboBox()
        self.combo_operation.addItems(["Ataque", "Encriptar", "Desencriptar"])
        self.combo_operation.currentIndexChanged.connect(self.toggleKeyField)  # Detecta cambios en el tipo de operación
        layout.addWidget(self.combo_operation)

        # Campo para ingresar la clave (se muestra solo cuando es encriptar/desencriptar)
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
        key = self.key_input.text() if self.key_input.isVisible() else None  # Solo obtiene la clave si es necesaria

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

            else:  # "Ataque"
                result = "El ataque aún no está implementado para este cifrado."

        except Exception as e:
            result = f"Error: {str(e)}"

        self.output_text.setPlainText(result)


class ImageWindow(QMainWindow):
    def __init__(self):
        super(ImageWindow, self).__init__()
        self.setWindowTitle("Cifrado de Imagen")
        self.setGeometry(150, 150, 400, 300)
        self.initUI()

    def initUI(self):
        widget = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Cifrado de imágenes utilizando AES"))

        # Campo para ingresar la clave de cifrado AES
        self.key_label = QLabel("Clave AES:")
        layout.addWidget(self.key_label)

        self.key_input = QLineEdit()
        layout.addWidget(self.key_input)

        # Botón para seleccionar la imagen
        self.btn_choose = QPushButton("Seleccionar Imagen")
        self.btn_choose.clicked.connect(self.selectImage)
        layout.addWidget(self.btn_choose)

        # Botón para ejecutar el cifrado
        self.btn_execute = QPushButton("Ejecutar Cifrado AES")
        self.btn_execute.clicked.connect(self.executeAES)
        layout.addWidget(self.btn_execute)

        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def selectImage(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Seleccionar Imagen", "", "Images (*.png *.jpg *.jpeg *.bmp)", options=options)
        if fileName:
            self.image_path = fileName

    def executeAES(self):
        key = self.key_input.text()
        if not key:
            self.showMessage("Ingrese una clave AES.")
            return

        try:
            result = AES_cipher.encrypt_image(self.image_path, key, AES_cipher.encryption_path, mode='OFB')
            msg = "Cifrado completado." if result else "Error en el cifrado."
        except Exception as e:
            msg = f"Error: {str(e)}"

        self.showMessage(msg)

    def showMessage(self, message):
        self.msg_label = QLabel(message)
        self.msg_label.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
