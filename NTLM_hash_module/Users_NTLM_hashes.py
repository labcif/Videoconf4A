import jarray
import inspect
import os
import json
from subprocess import Popen, PIPE
import csv

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import JRadioButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import BoxLayout
from javax.swing import ImageIcon
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from javax.swing import JComponent
from javax.swing import JTextField
from javax.swing import JList
from javax.swing import JFrame
from javax.swing import ListSelectionModel
from javax.swing import DefaultListModel
from javax.swing import SwingUtilities
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt.event import KeyListener
from java.awt.event import KeyEvent
from java.awt.event import KeyAdapter
from java.awt import Dimension
from javax.swing.event import DocumentEvent
from javax.swing.event import DocumentListener
from javax.swing import BorderFactory

from java.lang import Class
from java.lang import System
from java.lang import IllegalArgumentException
# from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.util import ArrayList
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleFactory
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils


# from org.sleuthkit.datamodel import CommunicationsManager
# from org.sleuthkit.datamodel import Relationship
# from org.sleuthkit.datamodel import Account


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class UsersNTLMHashesIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Users NTLM Hashes"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Retrieves NTLM Hashes for users passwords"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return UsersNTLMHashesIngestModuleGUISettingsPanel(self.settings)

    def createDataSourceIngestModule(self, ingestOptions):
        return UsersNTLMHashesIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class UsersNTLMHashesIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(UsersNTLMHashesIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)
        self._logger.log(Level.SEVERE, "Starting of plugin")
        self.fbPeopleDict = {}
        self.chatMessages = []
        self.fbOwnerId = 0

    def startUp(self, context):
        self.context = context
        if PlatformUtil.isWindowsOS():
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntlm_hash_retrieval.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("ntlm_hash_retrieval.exe was not found in module folder")
            mimikatz_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mimikatz.exe")
            if not os.path.exists(mimikatz_file):
                raise  IngestModuleException("mimikatz.exe was not found in module folder")
        else:
            raise IngestModuleException(UsersNTLMHashesIngestModule.moduleName + "module can only run on Windows.")

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        fileManager = Case.getCurrentCase().getServices().getFileManager()

        # Create Event Log directory in temp directory, if it exists then continue on processing
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "USERS_NTLM_HASHES_TEMP")

        try:
            os.mkdir(temporaryDirectory)
        except:
            pass
            self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)

        # Retrieve SYSTEM and SAM files
        system_file = fileManager.findFiles(dataSource, "SYSTEM", "config")
        self.log(Level.INFO, "Size of system_file is " + str(len(system_file)))

        sam_file = fileManager.findFiles(dataSource, "SAM", "config")
        self.log(Level.INFO, "Size of sam_file is " + str(len(sam_file)))


        return IngestModule.ProcessResult.OK

    def copy_file_to_temp(self, file, directory):
        current_user = self.check_user_from_file(file)
        if current_user != "":
            extracted_local_state_file_path = os.path.join(directory, file.getName() + "_" + current_user)
        else:
            extracted_local_state_file_path = os.path.join(directory, file.getName())
            i = 1
            while os.path.exists(extracted_local_state_file_path):
                extracted_local_state_file_path = os.path.join(directory, file.getName() + "_" + i)

        ContentUtils.writeToFile(file, File(extracted_local_state_file_path))

        return extracted_local_state_file_path

class UsersNTLMHashesIngestModuleGUISettingsPanel(IngestModuleIngestJobSettingsPanel):

    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()

    def onClickExport(self, e):
        chooseFile = JFileChooser()
        currentDirectory = self.local_settings.getSetting('User_Directory')
        if currentDirectory is not None and os.path.exists(currentDirectory):
            chooseFile.setCurrentDirectory(File(currentDirectory))

        ret = chooseFile.showDialog(self, "Specify a file to save")

        if ret == JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            canonical_file = file.getCanonicalPath()
            self.local_settings.setSetting('output_file', canonical_file)
            self.selectedFileLabel.setText(os.path.basename(canonical_file))

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        # main panel
        panelTop = JPanel()
        panelTop.setLayout(BoxLayout(panelTop, BoxLayout.Y_AXIS))
        panelTop.add(JLabel(" "))
        labelTop = JLabel("<html><strong>Users NTLM Hashes Settings</strong></html>")
        panelTop.add(labelTop)
        panelTop.add(JLabel(" "))

        # export file
        panelExport = JPanel()
        panelExport.setLayout(BoxLayout(panelExport, BoxLayout.X_AXIS))
        panelExport.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.importButton = JButton("Results export file location", actionPerformed=self.onClickExport)
        panelExport.add(self.importButton)
        panelExport.add(JLabel(" "))
        self.selectedFileLabel = JLabel("")
        panelExport.add(self.selectedFileLabel)




