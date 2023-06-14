import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow
from PyQt5.QtCore import Qt
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Main Window Title")  # Set the title for the main window

        ui_file = os.path.join(script_dir, "test.ui")
        loadUi(ui_file, self)

        # Keys
        self.actionGenerate_new_Key.triggered.connect(self.goToGenerateNewKey)
        # self.actionRemove_existing_Key.triggered.connect(self.goToRemoveExistingKey)
        # self.actionImport_Key_2.triggered.connect(self.goToImportKey)
        # self.actionExport_Key_2.triggered.connect(self.goToExportKey)
        self.actionShow_Keyrings.triggered.connect(self.goToShowKeyrings)

        # Messages
        self.actionSend_Message.triggered.connect(self.goToSendMessage)
        self.actionReceive_Message.triggered.connect(self.goToReceiveMessage)

    def goToGenerateNewKey(self):
        generateNewKey = GenerateNewKey()
        widget.addWidget(generateNewKey)
        widget.setCurrentIndex(widget.currentIndex() + 1)
    
    def goToShowKeyrings(self):
        keyrings = Keyrings()
        widget.addWidget(keyrings)
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

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.generateButton.clicked.connect(self.goToSavePrivateKey)

    def goToSavePrivateKey(self):
        savePrivateKey = SavePrivateKey()
        widget.addWidget(savePrivateKey)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    # Action method
    def back(self):
        # Get the current index of the widget you want to remove
        current_index = widget.currentIndex()

        # Remove the widget at the current index
        widget.removeWidget(widget.widget(current_index))




class Keyrings(QDialog):
    def __init__(self):
        super(Keyrings, self).__init__()
        
        ui_file = os.path.join(script_dir, "keyrings.ui")
        loadUi(ui_file, self)
        
        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        #self.browseFileButton.clicked.connect(self.<foo>)
        self.showPrivateKeysButton.clicked.connect(self.goToEnterPassword)

    def goToEnterPassword(self):
        enterPassword = EnterPassword()
        widget.addWidget(enterPassword)
        widget.setCurrentIndex(widget.currentIndex() + 1)


    # Action method
    def getBackToMainWindow(self):
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))


    # Action method
    def back(self):
        current_index = widget.currentIndex()
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

        # Go back one level at the end
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))

    def back(self): 
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))




class SavePrivateKey(QDialog):
    def __init__(self):
        super(SavePrivateKey, self).__init__()

        ui_file = os.path.join(script_dir, "savePrivateKey.ui")
        loadUi(ui_file, self)

        self.UiComponents()

    # Method for widgets
    def UiComponents(self):
        self.backButton.clicked.connect(self.back)
        self.saveButton.clicked.connect(self.getBackToMainWindow)


    # Action method
    def getBackToMainWindow(self):
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
        
        # Send the message

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
        self.saveFileButton.clicked.connect(self.goToSaveFileAndReturnToMain)

        # self.decryptionEmptyLabel.setText('DaLiJeUpsesno')
        # self.verificationLabel.setText('DaLiJeUpsesno')
        

    def goToSaveFileAndReturnToMain(self):
        
        # Check where to save

        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))

    def back(self):
        current_index = widget.currentIndex()
        widget.removeWidget(widget.widget(current_index))


# main
app = QApplication(sys.argv)

app.setApplicationDisplayName("PGP Mitic-Davidovic")

widget = QtWidgets.QStackedWidget()
mainWindow = MainWindow()

widget.addWidget(mainWindow)
widget.setFixedHeight(350)
widget.setFixedWidth(600)
widget.show()
mainWindow.show()

try:
    sys.exit(app.exec_())

except:
    print("Exiting")
