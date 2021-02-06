import jarray
import inspect
import os
from subprocess import Popen, PIPE
import shutil

from javax.swing import JCheckBox
import java.awt.Color
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

from java.awt import Panel, BorderLayout, EventQueue, GridLayout, GridBagLayout, GridBagConstraints, Font, Color
from java.awt.event import ActionListener, ActionEvent
from java.lang import IllegalArgumentException
from java.lang import System
from java.util.logging import Level
from javax.swing import BoxLayout
from javax.swing import JCheckBox
from javax.swing.border import TitledBorder, EtchedBorder, EmptyBorder

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

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return UsersNTLMHashesIngestModuleGUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

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
                raise IngestModuleException("mimikatz.exe was not found in module folder")
        else:
            raise IngestModuleException(UsersNTLMHashesIngestModule.moduleName + "module can only run on Windows.")

        # Validate settings
        output_file = self.local_settings.getSetting("output_file")
        file_type = self.local_settings.getSetting("output_file_type")
        if file_type is None:
            raise IngestModuleException("File type is not define")
        if output_file is None:
            raise IngestModuleException("Output file is not define")

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
        if len(system_file) == 0:
            raise IngestModuleException("No SYSTEM hive file found.")

        sam_file = fileManager.findFiles(dataSource, "SAM", "config")
        if len(sam_file) == 0:
            raise IngestModuleException("No SAM hive file found.")

        extracted_system_file_path = self.copy_file_to_temp(system_file[0], temporaryDirectory)
        extracted_sam_file_path = self.copy_file_to_temp(sam_file[0], temporaryDirectory)

        # Retrieve output file from settings
        output_type = self.local_settings.getSetting("output_file_type")
        output_file = self.local_settings.getSetting("output_file")

        # Get mimikatz file
        mimikatz_file_path = os.path.dirname(os.path.realpath(__file__)) + "\\mimikatz.exe"

        command_line = [str(self.pathToExe), extracted_system_file_path, extracted_sam_file_path, output_type, output_file, mimikatz_file_path]

        self.log(Level.INFO, str(command_line))

        pipe = Popen(command_line, shell=False, stdout=PIPE, stderr=PIPE)
        outputFromRun = pipe.communicate()[0]
        self.log(Level.INFO, "Output from Run is ==> " + outputFromRun)

        # Clean temporary directory
        shutil.rmtree(temporaryDirectory)

        return IngestModule.ProcessResult.OK

    def copy_file_to_temp(self, file, directory):
        current_user = self.check_user_from_file(file)
        if current_user != "":
            extracted_file_path = os.path.join(directory, file.getName() + "_" + current_user)
        else:
            extracted_file_path = os.path.join(directory, file.getName())
            i = 1
            while os.path.exists(extracted_file_path):
                extracted_file_path = os.path.join(directory, file.getName() + "_" + str(i))
                i += 1

        ContentUtils.writeToFile(file, File(extracted_file_path))

        return extracted_file_path

    def check_user_from_file(self, file):
        if "/Users/" in str(file.getParentPath()):
            current_user = str(file.getParentPath()).split("/")[2]
            return current_user
        return ""

class UsersNTLMHashesIngestModuleGUISettingsPanel(IngestModuleIngestJobSettingsPanel):

    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def onClickExport(self, e):
        chooseFile = JFileChooser()

        file_type = self.local_settings.getSetting("output_file_type")

        if file_type == "csv":
            filter = FileNameExtensionFilter("CSV (Comma Delimited) (*.csv)", [file_type])
        elif file_type == "json":
            filter = FileNameExtensionFilter("JSON (JavaScript Object Notation) (*.json)", [file_type])
        else:
            filter = FileNameExtensionFilter("CSV (Comma Delimited) (*.csv)", [file_type])


        chooseFile.setFileFilter(filter)

        ret = chooseFile.showDialog(self, "Specify a file to save")

        if ret == JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            canonical_file = file.getCanonicalPath()
            if ("." + file_type) not in canonical_file:
                canonical_file = canonical_file + "." + file_type
            self.local_settings.setSetting('output_file', canonical_file)
            self.selectedFileLabel.setText(os.path.basename(canonical_file))
        else:
            self.local_settings.setSetting('output_file', None)
            self.selectedFileLabel.setText('(no file)')

    def radioBtnEvent(self, e):
        isJsonSelected = self.radioBtnJson.isSelected()
        self.local_settings.setSetting('output_file_type', 'json' if isJsonSelected else 'csv')
        selected_file = self.local_settings.getSetting('output_file')
        if selected_file is not None:
            filename, extension = os.path.splitext(os.path.basename(selected_file))
            self.selectedFileLabel.setText(filename + "." + self.local_settings.getSetting("output_file_type"))

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        # main panel
        panelTop = JPanel()
        panelTop.setLayout(BoxLayout(panelTop, BoxLayout.Y_AXIS))
        panelTop.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        labelTop = JLabel("<html><strong>Users NTLM Hashes Settings</strong></html>")
        panelTop.add(labelTop)
        panelTop.add(JLabel(" "))

        # radio btn json export file
        panelRadioBtnJson = JPanel()
        panelRadioBtnJson.setLayout(BoxLayout(panelRadioBtnJson, BoxLayout.X_AXIS))
        panelRadioBtnJson.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.radioBtnJson = JRadioButton("JSON", actionPerformed=self.radioBtnEvent)
        panelRadioBtnJson.add(self.radioBtnJson)

        # radio btn json export file
        panelRadioBtnCsv = JPanel()
        panelRadioBtnCsv.setLayout(BoxLayout(panelRadioBtnCsv, BoxLayout.X_AXIS))
        panelRadioBtnCsv.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.radioBtnCsv = JRadioButton("CSV", actionPerformed=self.radioBtnEvent)
        panelRadioBtnCsv.add(self.radioBtnCsv)

        # export file
        panelExport = JPanel()
        panelExport.setLayout(BoxLayout(panelExport, BoxLayout.X_AXIS))
        panelExport.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.exportBtn = JButton("Results export file location", actionPerformed=self.onClickExport)
        panelExport.add(self.exportBtn)
        panelExport.add(JLabel(" "))
        self.selectedFileLabel = JLabel("")
        panelExport.add(self.selectedFileLabel)

        # group radiobuttons and export file
        panelGroupRadioBtns = JPanel()
        panelGroupRadioBtns.setLayout(BoxLayout(panelGroupRadioBtns, BoxLayout.X_AXIS))
        panelGroupRadioBtns.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        buttonGroup = ButtonGroup()
        buttonGroup.add(self.radioBtnJson)
        buttonGroup.add(self.radioBtnCsv)
        panelGroupRadioBtns.add(JLabel(" "))
        panelGroupRadioBtns.add(panelRadioBtnJson)
        panelGroupRadioBtns.add(JLabel(" "))
        panelGroupRadioBtns.add(panelRadioBtnCsv)
        panelGroupRadioBtns.setBorder(BorderFactory.createTitledBorder("Output file type"))

        self.add(panelTop)
        self.add(panelGroupRadioBtns)
        self.add(JLabel(" "))
        self.add(panelExport)

    def customizeComponents(self):
        # file type
        file_type = self.local_settings.getSetting("output_file_type")
        # Set default type to CSV
        if file_type is None:
            self.local_settings.setSetting("output_file_type", "csv")


        # output file
        selected_file = self.local_settings.getSetting('output_file')
        if selected_file is not None:
            if os.path.isfile(selected_file):
                self.selectedFileLabel.setText(os.path.basename(selected_file))
            else:
                self.local_settings.setSetting('output_file', None)
                self.selectedFileLabel.setText('(no file)')
        else:
            self.selectedFileLabel.setText('(no file)')

    # Return the settings used
    def getSettings(self):
        return self.local_settings




