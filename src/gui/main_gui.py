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


myPath = "src"
# Get the absolute path of the project's root directory
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Add the root directory to the system path
sys.path.append(root_dir)

from Keyring import Keyring
from AsymmetricCipher import *
from Key import PrivateKeyWrapper
from Message import Message
from SymmetricCipher import AESCipher, TripleDES
script_dir = os.path.dirname(os.path.abspath(__file__))


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        ui_file = os.path.join(script_dir, "test.ui")
        loadUi(ui_file, self)

        # Keys
        self.actionGenerate_new_Key.triggered.connect(self.goToGenerateNewKey)
        # self.actionRemove_existing_Key.triggered.connect(self.goToRemoveExistingKey)
        self.exportPublicKeyMenuBar.triggered.connect(self.goToExportPublicKey)
        self.exportPrivateKeyMenuBar.triggered.connect(self.goToExportPrivateKey)

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
                time = private_key.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                selected_algorithm = private_key.algorithm.getAlgorithmCode()
                selected_algorithm = "RSA" if selected_algorithm == b'\x01' else "ElGamalDSA"
                item = QStandardItem(f"{private_key.name} ({private_key.email})[{time}, {selected_algorithm}: {private_key.size}] ID: {repr(private_key.getKeyIdHexString())}")
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


    def goToExportPublicKey(self):
        private = self.privateKeysLV.selectedIndexes()
        public  = self.publicKeysLV.selectedIndexes()

        if selected_indexes:
            selected_index = selected_indexes[0]
            selected_item_data = self.privateKeysLV.model().data(selected_index)
            print(selected_item_data)
        else:
            print("No item selected")

    def goToExportPrivateKey(self):
        selected_indexes = self.privateKeysLV.selectedIndexes()
        if selected_indexes:
            selected_index = selected_indexes[0]
            selected_item_data = self.privateKeysLV.model().data(selected_index)
            keyId = selected_item_data.split("ID: ")[1].strip("'")
            receiver_key = privateKeyring.getKeyByKeyIdHexString(keyId)

            file_path, _ = QFileDialog.getSaveFileName(self, "Save a File", "", "Pem Format (*.pem)")
            if file_path:
                receiver_key.exportPublicKeyToFile(file_path)

        else:
            print("No item selected")



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
        global privateKeyring, publicKeyring, keyring_password
        print(globals())
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
            privateKeyring.saveToFile(myPath+"/Ring/private_keyring.bin", keyring_password)
            # Update the ListView in the MainWindow
            main_window = widget.widget(1)  # Assuming MainWindow is at index 0
            private_keys_lv = main_window.privateKeysLV
            model = private_keys_lv.model()
            print_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            selected_algorithm = private_key.algorithm.getAlgorithmCode()
            selected_algorithm = "RSA" if selected_algorithm == b'\x01' else "ElGamalDSA"
            item = QStandardItem(
                f"{private_key.name} ({private_key.email})[{private_key.timestamp}, {selected_algorithm}: {private_key.size}] ID: {repr(private_key.getKeyIdHexString())}"
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

        self.publicKeyComboBox.setEnabled(False)
        self.symAlgoComboBox.setEnabled(False)
        self.privateKeyComboBox.setEnabled(False)
        self.passwordTB.setEnabled(False)

        #self.symAlgoComboBox.addItem("Select symmetric algorithm")
        #load the public keys
        #self.publicKeyComboBox.addItem("Select public key")
        for key in publicKeyring.getKeys():
            self.publicKeyComboBox.addItem(f"{key.name} ({key.email}), ID: {repr(key.getKeyIdHexString())}")

        #load the private keys
        #self.privateKeyComboBox.addItem("Select private key")
        for key in privateKeyring.getKeys():
            self.privateKeyComboBox.addItem(f"{key.name} ({key.email}), ID: {repr(key.getKeyIdHexString())}")
            self.publicKeyComboBox.addItem(f"{key.name} ({key.email}), ID: {repr(key.getKeyIdHexString())}")
        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.sendMessageButton.clicked.connect(self.goToSendAndReturn)
        self.secretCB.stateChanged.connect(self.secretCBChanged)
        self.signCB.stateChanged.connect(self.signCBChanged)

    def goToSendAndReturn(self):
        message = self.messageTB.toPlainText()  # Get the text from the QTextEdit widget
        isSecret = self.secretCB.isChecked()
        isSigned = self.signCB.isChecked()
        isCompressed = self.ZIPCB.isChecked()
        isRadix64 = self.R64CB.isChecked()
        password = None
        algo = None
        sender_key = None
        receiver_key = None
        if isSecret:
            
            keyId = self.publicKeyComboBox.currentText().split("ID: ")[1].strip("'")
            receiver_key = publicKeyring.getKeyByKeyIdHexString(keyId)
            if receiver_key is None:
                receiver_key = privateKeyring.getKeyByKeyIdHexString(keyId)
            algo = self.symAlgoComboBox.currentText()
            print(receiver_key)
            if algo == "TripleDES":
                algo = TripleDES()
            elif algo == "AES128":
                algo = AESCipher()
        
        if isSigned:
            keyId = self.privateKeyComboBox.currentText().split("ID: ")[1].strip("'")
            sender_key = privateKeyring.getKeyByKeyIdHexString(keyId)
            password = self.passwordTB.text().encode()
            if not sender_key.checkPassword(password):
                self.errorLabel.setText("Wrong password")
                return
            
            print(sender_key)

            


        self.publicKeyComboBox
        message = message.encode()
        msg = Message(b"filename",message)

        
        # Save the message to a file
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Message", "", "Text Files (*.txt)")
        if file_path:
            out = msg.createOuputBytes(signed=isSigned, senderKey=sender_key, zipped=isCompressed, base64=isRadix64, encrypted=isSecret, receiverKey=receiver_key, symmetricCipher=algo, password=password)
            try:
                out = out.encode()
            except:
                pass
            with open(file_path, 'wb') as file:
                file.write(out)

        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))

    # Action method
    def back(self):
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))
    
    def secretCBChanged(self):
        if self.secretCB.isChecked():
            self.publicKeyComboBox.setEnabled(True)
            self.symAlgoComboBox.setEnabled(True)
        else:
            self.publicKeyComboBox.setEnabled(False)
            self.symAlgoComboBox.setEnabled(False)
            


    def signCBChanged(self):
        if self.signCB.isChecked():
            self.privateKeyComboBox.setEnabled(True)
            self.passwordTB.setEnabled(True)
        else:
            self.privateKeyComboBox.setEnabled(False)
            self.passwordTB.setEnabled(False)




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
            privateKeyring.saveToFile(myPath+"/Ring/private_keyring.bin", keyring_password)
            publicKeyring.saveToFile(myPath+"/Ring/public_keyring.bin", keyring_password)

            main_window = MainWindow()
            widget.addWidget(main_window)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            self.close()

    def openMainWindow(self):
        global keyring_password  # Declare keyring_password as global
        entered_password = self.passwordTB.text().encode()
        global privateKeyring, publicKeyring
        privateKeyring = Keyring.loadFromFile(myPath+"/Ring/private_keyring.bin", entered_password)
        publicKeyring = Keyring.loadFromFile(myPath+"/Ring/public_keyring.bin", entered_password)
        
        if self.passwordTB.text().strip() == "":
            self.errorLabel.setText("You must enter the password.")
            self.errorLabel.setStyleSheet("color: red;")
        elif privateKeyring is None or publicKeyring is None:
            self.errorLabel.setText("Wrong password")
            self.errorLabel.setStyleSheet("color: red;")
        else:
            main_window = MainWindow()
            widget.addWidget(main_window)
            widget.setCurrentIndex(widget.currentIndex() + 1)
            self.close()





# main
if __name__ == "__main__":

    # Initializing keyrings
    privateKeyring = None
    publicKeyring = None
    keyring_password = b'1234'
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