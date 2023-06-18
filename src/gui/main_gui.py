import sys
import os
from datetime import datetime
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QFileDialog, QButtonGroup
from PyQt5.QtWidgets import QListWidgetItem
from PyQt5.QtWidgets import QListWidget, QListWidgetItem
from PyQt5.QtGui import QStandardItemModel, QStandardItem



# Get the absolute path of the project's root directory
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Add the root directory to the system path
sys.path.append(root_dir)

from Keyring import Keyring
from AsymmetricCipher import *
from Key import PrivateKeyWrapper


script_dir = os.path.dirname(os.path.abspath(__file__))

# Initializing keyrings
privateKeyring = None
publicKeyring = None
keyring_password = None

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        ui_file = os.path.join(script_dir, "test.ui")
        loadUi(ui_file, self)

        # Keys
        self.actionGenerate_new_Key.triggered.connect(self.goToGenerateNewKey)
        # self.actionRemove_existing_Key.triggered.connect(self.goToRemoveExistingKey)
        # self.actionImport_Key_2.triggered.connect(self.goToImportKey)
        # self.actionExport_Key_2.triggered.connect(self.goToExportKey)

        # Messages
        self.actionSend_Message.triggered.connect(self.goToSendMessage)
        self.actionReceive_Message.triggered.connect(self.goToReceiveMessage)
        
        # Update the ListView with existing private keys
        if privateKeyring is not None:
            private_keys_lv = self.privateKeysLV
            model = QStandardItemModel()
            private_keys_lv.setModel(model)
            model.clear()  # Clear the existing items
            for private_key in privateKeyring.getKeys():
                item = QStandardItem(f"{private_key.name} ({private_key.email})")
                model.appendRow(item)

    def goToGenerateNewKey(self):
        generateNewKey = GenerateNewKey()
        widget.addWidget(generateNewKey)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def goToSendMessage(self):
        sendMessage = SendMessage()
        widget.addWidget(sendMessage)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def goToReceiveMessage(self):
        receiveMessage = ReceiveMessage()
        widget.addWidget(receiveMessage)
        widget.setCurrentIndex(widget.currentIndex() + 1)




class GenerateNewKey(QDialog):
    def __init__(self):
        super(GenerateNewKey, self).__init__()

        ui_file = os.path.join(script_dir, "generateNewKey.ui")
        loadUi(ui_file, self)

        self.UiComponents()

        self.selected_algorithm = None
        self.name = ""
        self.email = ""
        self.id = -1

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.generateButton.clicked.connect(self.goToSavePrivateKey)




    def goToSavePrivateKey(self):
        button_group = QButtonGroup()
        button_group.addButton(self.RB1024, 0)
        button_group.addButton(self.RB2048, 1)

        selected_algorithm = self.algorithmCB.currentText()

        # if selected_algorithm == "RSA":
        #     print("\n\tA: RSA___" + self.algorithmCB.currentText() + "\n")
        # else:
        #     print("\n\tB: ELGAMALDSA___" + self.algorithmCB.currentText() + "\n")


        self.id = button_group.checkedId()
        if self.id == -1:
            print("No radio button selected")
        elif self.id == 0:
            print("Radio button '1024' selected")
        elif self.id == 1:
            print("Radio button '2048' selected")

        if self.nameTB.text().strip() == "" or self.emailTB.text().strip() == "" or id == -1:
            self.errorLabel.setText("You must fill in all the required fields.")
            self.errorLabel.setStyleSheet("color: red;")
        else:
            savePrivateKey = SavePrivateKey(self)
            widget.addWidget(savePrivateKey)
            widget.setCurrentIndex(widget.currentIndex() + 1)

    # Action method
    def back(self):
        # Get the current index of the widget you want to remove
        current_index = widget.currentIndex()

        # Remove the widget at the current index
        widget.removeWidget(widget.widget(current_index))




class EnterPassword(QDialog):
    def __init__(self):
        super(EnterPassword, self).__init__()

        ui_file = os.path.join(script_dir, "enterPassword.ui")
        loadUi(ui_file, self)

        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.confirmButton.clicked.connect(self.goToShowPrivateKeyring)


    # Action method
    def goToShowPrivateKeyring(self):

        # Check if Password matches
        # if self.passwordTB.text().strip() == "":
        #     self.errorLabel.setText("You must enter password.")
        #     self.errorLabel.setStyleSheet("color: red;")
        # elif self.passwordTB.text() != 
        #     self.errorLabel.setText("Wrong Password")
        #     self.errorLabel.setStyleSheet("color: red;")
        # else:
        #     # Go back one level at the end
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))

    def back(self): 
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))




class SavePrivateKey(QDialog):
    def __init__(self, generateNewKey):
        super(SavePrivateKey, self).__init__()

        ui_file = os.path.join(script_dir, "savePrivateKey.ui")
        loadUi(ui_file, self)

        self.generateNewKey = generateNewKey

        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.saveButton.clicked.connect(self.getBackToMainWindow)

        # Access the values from GenerateNewKey
        selected_algorithm = self.generateNewKey.selected_algorithm
        name = self.generateNewKey.nameTB.text()
        email = self.generateNewKey.emailTB.text()
        id = self.generateNewKey.id

        # Use the values as needed
        print(f"Selected Algorithm: {selected_algorithm}")
        print(f"Name: {name}")
        print(f"Email: {email}")
        print(f"ID: {id}")

    # Action method
    def getBackToMainWindow(self):
        if self.passwordTB.text().strip() == "" or self.confirmPasswordTB.text().strip() == "":
            self.errorLabel.setText("You must fill both fields.")
            self.errorLabel.setStyleSheet("color: red;")
        elif self.passwordTB.text() != self.confirmPasswordTB.text():
            self.errorLabel.setText("Passwords do NOT match.")
            self.errorLabel.setStyleSheet("color: red;")
        else:
            name = self.generateNewKey.nameTB.text()
            email = self.generateNewKey.emailTB.text()
            id = self.generateNewKey.id
            bits = 0

            if self.generateNewKey.id == 0:
                bits = 1024
            else:
                bits = 2048

            selected_algorithm = self.generateNewKey.algorithmCB.currentText()  # Get the selected algorithm

            # Passwords match
            password = self.passwordTB.text().encode()
            timestamp = datetime.now()
            public_key = RSA.generate(bits)

            private_key = PrivateKeyWrapper(timestamp, public_key, name, email, RSACipher(), password)

            privateKeyring.addKey(private_key)

            # Update the ListView in the MainWindow
            main_window = widget.widget(1)  # Assuming MainWindow is at index 0
            private_keys_lv = main_window.privateKeysLV
            model = private_keys_lv.model()
            print_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            item = QStandardItem(
                f"{private_key.name} ({private_key.email})[{print_timestamp}, {selected_algorithm}: {bits}] ID: {repr(private_key.getKeyIdHexString())}"
            )
            model.appendRow(item)

            current_index = widget.currentIndex()
            widget.removeWidget(widget.widget(current_index))
            current_index = widget.currentIndex()
            widget.removeWidget(widget.widget(current_index))

    def back(self):
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))




class SendMessage(QDialog):
    def __init__(self):
        super(SendMessage, self).__init__()

        ui_file = os.path.join(script_dir, "sendMessage.ui")
        loadUi(ui_file, self)

        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.sendMessageButton.clicked.connect(self.goToSendAndReturn)

    def goToSendAndReturn(self):
        message = self.messageTB.toPlainText()  # Get the text from the QTextEdit widget
        secret  = self.secretCB.isChecked()
        sign = self.signCB.isChecked()
        zip = self.zipCB.isChecked()
        r64 = self.R64CB.isChecked()

        if sign:
            enterPassword = EnterPassword()
            widget.addWidget(enterPassword)
            widget.setCurrentIndex(widget.currentIndex() + 1)

            

        
        # Save the message to a file
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Message", "", "Text Files (*.txt)")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(message)

        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))

    # Action method
    def back(self):
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))




class ReceiveMessage(QDialog):
    def __init__(self):
        super(ReceiveMessage, self).__init__()
        
        ui_file = os.path.join(script_dir, "receiveMessage.ui")
        loadUi(ui_file, self)
        
        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.browseFileButton.clicked.connect(self.browse_file)
        self.saveFileButton.clicked.connect(self.goToSaveFileAndReturnToMain)

        # self.decryptionEmptyLabel.setText('DaLiJeUpsesno')
        # self.verificationLabel.setText('DaLiJeUpsesno')
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.textEdit.setText(content)


    def goToSaveFileAndReturnToMain(self): 
        # Check where to save
        # Save the message to a file
        file_path, _ = QFileDialog.getSaveFileName(self, "Save a File", "", "Text Files (*.txt)")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.textEdit.toPlainText())

        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))

    def back(self):
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))


class FirstWindow(QMainWindow):
    def __init__(self):
        super(FirstWindow, self).__init__()

        ring_folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Ring'))

        if len(os.listdir(ring_folder_path)) == 0:
            ui_file = os.path.join(script_dir, "makePass.ui")
            loadUi(ui_file, self)
            self.makeButton.clicked.connect(self.CheckAndOpenMainWindow)
        else:
            ui_file = os.path.join(script_dir, "unlock.ui")
            loadUi(ui_file, self)
            self.unlockButton.clicked.connect(self.openMainWindow)
        
    def CheckAndOpenMainWindow(self):
        global privateKeyring, publicKeyring, keyring_password

        if self.passwordTB.text().strip() == "" or self.confirmPasswordTB.text().strip() == "":
            self.errorLabel.setText("You must fill both fields.")
            self.errorLabel.setStyleSheet("color: red;")
        elif self.passwordTB.text() != self.confirmPasswordTB.text():
            self.errorLabel.setText("Passwords do NOT match.")
            self.errorLabel.setStyleSheet("color: red;")
        else:
            keyring_password = self.passwordTB.text().encode()
            privateKeyring = Keyring(True)
            publicKeyring = Keyring(False)
            
            # Save in files
            privateKeyring.saveToFile("../Ring/private_keyring.bin", keyring_password)
            publicKeyring.saveToFile("../Ring/public_keyring.bin", keyring_password)

            main_window = MainWindow()
            widget.addWidget(main_window)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            self.close()

    def openMainWindow(self):
        global keyring_password  # Declare keyring_password as global
        entered_password = self.passwordTB.text().encode()

        if self.passwordTB.text().strip() == "":
            self.errorLabel.setText("You must enter the password.")
            self.errorLabel.setStyleSheet("color: red;")
        elif entered_password != keyring_password:
            self.errorLabel.setText("Wrong password")
            self.errorLabel.setStyleSheet("color: red;")
        else:
            main_window = MainWindow()
            widget.addWidget(main_window)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            self.close()





# main
app = QApplication(sys.argv)

app.setApplicationDisplayName("PGP Mitic-Davidovic")

widget = QtWidgets.QStackedWidget()
firstWindow = FirstWindow()

widget.addWidget(firstWindow)
widget.setFixedHeight(380)
widget.setFixedWidth(600)
widget.show()
firstWindow.show()

try:
    sys.exit(app.exec_())
except:
    print("Exiting")