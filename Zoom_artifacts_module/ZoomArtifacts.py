import jarray
import inspect
import os
import json
from subprocess import Popen, PIPE
import csv
import glob
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
class Videoconf4AIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Videoconf4A"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Retrieves artifacts related to Zoom Video Conference"

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
        return Videoconf4AIngestModuleGUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Videoconf4AIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class Videoconf4AIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(Videoconf4AIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        self._logger = Logger.getLogger(self.__class__.__name__)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self._logger = Logger.getLogger(self.__class__.__name__)

    def startUp(self, context):
        self.context = context
        if PlatformUtil.isWindowsOS():
            self.log(Level.INFO, os.path.join(os.path.dirname(os.path.abspath(__file__))))
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypt_chrome.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("artifacts_decipher\\main.exe was not found in module folder")
        else:
            raise IngestModuleException(Videoconf4AIngestModuleFactory.moduleName + "module can only run on Windows.")

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Zoom artifacts
        self.art_chrome_cookies = self.create_artifact_type("ZOOM_COOKIES", "Zoom Chrome Cookies", blackboard)
        self.art_chrome_cookies = self.create_artifact_type("ZOOM_LOGIN_DATA", "Zoom Chrome Login Data", blackboard)

        # Cookies Attributes
        self.att_key = self.create_attribute_type("COOKIES_ZOOM_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Key", blackboard)
        self.att_name = self.create_attribute_type("COOKIES_ZOOM_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name", blackboard)
        self.att_value = self.create_attribute_type("COOKIES_ZOOM_VALUE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Value", blackboard)

        # Login Data Attributes
        self.att_url = self.create_attribute_type("LOGIN_DATA_ZOOM_URL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "URL", blackboard)
        self.att_user_type = self.create_attribute_type("LOGIN_DATA_ZOOM_USER_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Username type", blackboard)
        self.att_username = self.create_attribute_type("LOGIN_DATA_ZOOM_USERNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Username", blackboard)
        self.att_password = self.create_attribute_type("LOGIN_DATA_ZOOM_PASSWORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Password", blackboard)

        # Validate settings
        users_passwords_file = self.local_settings.getSetting("users_passwords_file")
        file_type = self.local_settings.getSetting("file_type")
        if file_type is None:
            raise IngestModuleException("File type is not define")
        if users_passwords_file is None:
            raise IngestModuleException("Users Passwords file is not define")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Create Event Log directory in temp directory, if it exists then continue on processing
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "ZOOM_ARTIFACTS_TEMP")

        try:
            os.mkdir(temporaryDirectory)
        except:
            pass
            self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)

        # Read the users passwords file
        users_passwords = self.read_users_passwords_file()

        # Retrieve MasterKey files
        master_keys = self.retrieve_master_keys(fileManager, dataSource, temporaryDirectory)

        for user_password in users_passwords:
            user = user_password["user"]
            password = user_password["password"]

            # Google Chrome artifacts

            ## Artifact files without the user path
            chrome_artifact_files = [
                # Local State file (required to decrypt SQLite files)
                "/AppData/Local/Google/Chrome/User Data/Local State",
                # Cookies File
                "/AppData/Local/Google/Chrome/User Data/Default/Cookies",
                # Saved login info file
                "/AppData/Local/Google/Chrome/User Data/Default/Login Data",
                # History file
                "/AppData/Local/Google/Chrome/User Data/Default/History"
            ]

            # Extract artifact files to temporary directory for users
            extracted_files = self.extract_files_from_user(fileManager, dataSource, user, chrome_artifact_files, temporaryDirectory)

            user_temporary_directory = os.path.join(temporaryDirectory, user)

            local_state_files = glob.glob(user_temporary_directory + "/Local State*")
            cookies_files = glob.glob(user_temporary_directory + "/Cookies*")
            login_data_files = glob.glob(user_temporary_directory + "/Login Data*")

            chrome_files = zip(cookies_files, login_data_files)

            self.log(Level.INFO, str(chrome_files))

            master_key_list = []

            for master_key in master_keys:
                if master_key["user"] == user:
                    master_key_list.append(master_key)

            correct_files = False

            for local_state_file in local_state_files:
                for files in chrome_files:
                    for master_key_obj in master_key_list:

                        command_line = [str(self.pathToExe), local_state_file, master_key_obj["sid"], password, master_key_obj["master_key_extracted_dir"], files[0], files[1], user_temporary_directory]

                        self.log(Level.INFO, str(command_line))

                        pipe = Popen(command_line, shell=False, stdout=PIPE, stderr=PIPE)
                        outputFromRun = pipe.communicate()[0]
                        rc = pipe.returncode
                        self.log(Level.INFO, "Output from Run is ==> " + outputFromRun)

                        # If return code is 0 means script was successful and masterkey was the correct else continue
                        if rc == 0:
                            #correct_files = True
                            for extracted_file in extracted_files:
                                if extracted_file["file_extracted_path"] == files[0]:
                                    file_obj = extracted_file["file"]
                                    art = file_obj.newArtifact(self.art_chrome_cookies.getTypeID())
                                    # Iterate cookies and add attribute
                                    #art.addAttribute(BlackboardAttribute(self.att_key, self.moduleName, str()))
                            break
                    # if correct_files is True:
                    #     break

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Zoom Cookies Decrypt", "Zoom Cookies Have Been Decrypted")
        IngestServices.getInstance().postMessage(message)

        # Clean temporary directory
        shutil.rmtree(temporaryDirectory)

        return IngestModule.ProcessResult.OK

    def read_users_passwords_file(self):
        # Retrieve data from users passwords
        users_passwords_file_type = self.local_settings.getSetting("file_type")
        users_passwords_file_path = self.local_settings.getSetting("users_passwords_file")
        users_passwords_file = open(users_passwords_file_path, "r")

        users_passwords = []

        if users_passwords_file_type == "json":
            users_passwords = json.loads(users_passwords_file.read())
            for user_password in users_passwords:
                if "user" not in user_password or "password" not in user_password:
                    raise IngestModuleException("JSON File syntax incorrect. Please read the module description for the correct syntax.")
            self.log(Level.INFO, "Users passwords data retrieved. Found " + str(len(users_passwords)) + " users passwords.")
        elif users_passwords_file_type == "csv":
            csv_reader = csv.reader(users_passwords_file, delimiter=",")
            line_count = 0
            for row in csv_reader:
                if line_count == 0:
                    if row[0] == "User" and row[1] == "Password":
                        line_count += 1
                    else:
                        raise IngestModuleException("CSV File syntax incorrect. Please read the module description for the correct syntax.")
                else:
                    users_passwords.append({"user": row[0], "password": row[1]})
                    line_count += 1
            self.log(Level.INFO, "Users passwords data retrieved. Found " + str(line_count) + " users passwords.")

        return users_passwords

    def extract_files_from_user(self, fileManager, dataSource, user, filesName, extractDirectory):

        # Check if user exists
        users_dirs = fileManager.findFiles(dataSource, user, "Users")
        if len(users_dirs) <= 0:
            self.log(Level.WARNING, "Could not find user \"" + user + "\". Skipping...")
            raise UserNotFoundException

        home_dir = None

        if len(users_dirs) > 1:
            self.log(Level.WARNING, "Several directories that matched */Users/" + user + "/*. Iterating to find the correct home dir")
            # Check for a path like /Users/{user}/Desktop
            for user_home_dir in users_dirs:
                path = user_home_dir.getParentPath() + user_home_dir.getName()

                desktop_path = "/Users/" + user + "/Desktop"
                desktop_folders = fileManager.findFiles(dataSource, "Desktop", path)
                self.log(Level.INFO, "Searched path -> " + path + "/Desktop" + ". Found " + str(len(desktop_folders)) + " matches")
                for desktop_folder in desktop_folders:
                    path = desktop_folder.getParentPath() + desktop_folder.getName()
                    if path == desktop_path:
                        home_dir = user_home_dir
                        self.log(Level.INFO, "Found home directory!")
                        break

                if home_dir is not None:
                    break

            if home_dir is None:
                raise UserNotFoundException
        else:
            path = users_dirs[0].getParentPath() + users_dirs[0].getName()
            if path == ("/Users/" + user + "/Desktop"):
                home_dir = users_dirs[0]
                self.log(Level.INFO, str(home_dir))
            else:
                raise UserNotFoundException

        home_dir_path = home_dir.getParentPath() + home_dir.getName()
        self.log(Level.INFO, "Found user \"" + user + "\". User's home directory -> " + home_dir_path)

        # Create an user specific temporary folder
        user_extract_folder = os.path.join(extractDirectory, user)

        # Create user temporary folder
        try:
            os.mkdir(user_extract_folder)
        except:
            pass
            self.log(Level.INFO, "Temporary user folder already created -> " + user_extract_folder + ".")

        # Append the home dir to the filesName.
        extracted_files = []
        for i, _ in enumerate(filesName):
            filesName[i] = home_dir_path + filesName[i]

            path, filename = os.path.split(filesName[i])

            files = fileManager.findFiles(dataSource, filename, path)
            self.log(Level.INFO, "Found " + str(len(files)) + " matches for file path -> " + filesName[i] + ".")

            if len(files) <= 0:
                self.log(Level.WARNING, "No files found with path like *" + filesName[i] + "*. Skipping...")
                continue

            if len(files) > 1:
                for j, file_to_extract in enumerate(files):
                    if j == 0:
                        name_iteration = ""
                    else:
                        name_iteration = "_" + str(j)
                    extracted_path = self.copy_file_to_temp(file_to_extract, user_extract_folder, file_to_extract.getName() + name_iteration)
                    extracted_files.append({"file": file_to_extract, "file_extracted_path": extracted_path})
                self.log(Level.INFO, "Extracted " + str(len(files)) + " files named \"" + filename + "\".")
            else:
                file_to_extract = files[0]
                extracted_path = self.copy_file_to_temp(file_to_extract, user_extract_folder, file_to_extract.getName())
                extracted_files.append({"file": file_to_extract, "file_extracted_path": extracted_path})
                self.log(Level.INFO, "Extracted 1 file named \"" + filename + "\".")
        return extracted_files


    def retrieve_master_keys(self, fileManager, dataSource, extractDirectory):
        # Retrieve MasterKey files
        master_key_dirs = fileManager.findFiles(dataSource, "S-1-5-21-%", "Protect")

        master_keys = []

        for master_key_dir in master_key_dirs:
            current_user = self.check_user_from_file(master_key_dir)
            full_path = master_key_dir.getParentPath() + master_key_dir.getName()
            master_keys_files = fileManager.findFiles(dataSource, "%", full_path)

            if len(master_keys_files) == 0:
                raise MasterKeysNotFoundException

            excluded_files = [".", "..", "Preferred"]
            # Should only be one master key?
            #i = 0
            for master_key_file in master_keys_files:
                # if i == 0:
                #     name_iteration = ""
                # else:
                #     name_iteration = "_" + str(i)

                if master_key_file.getName() in excluded_files:
                    continue
                # Extract master_key
                user_extract_directory = os.path.join(extractDirectory, current_user)
                try:
                    os.mkdir(user_extract_directory)
                except:
                    self.log(Level.INFO, "Temporary user folder already created -> " + current_user + ".")
                    pass

                extracted_master_key_file = self.copy_file_to_temp(master_key_file, user_extract_directory, master_key_file.getName())# + name_iteration)
                master_keys.append({
                    "user": current_user,
                    "sid": master_key_dir.getName(),
                    "master_key_file": master_key_file.getName(),
                    "master_key_dir": full_path,
                    "master_key_extracted_dir": extracted_master_key_file
                })
                #i += 1
        return master_keys

    def create_artifact_type(self, art_name, art_desc, blackboard):
        try:
            art = blackboard.getOrAddArtifactType(art_name, art_desc)
        except Exception as e:
            self.log(Level.INFO, "Error getting or adding artifact type: " + art_desc + " " + str(e))
        return art

    def create_attribute_type(self, att_name, type_name, att_desc, blackboard):
        try:
            att_type = blackboard.getOrAddAttributeType(att_name, type_name, att_desc)
        except Exception as e:
            self.log(Level.INFO, "Error getting or adding attribute type: " + att_desc + " " + str(e))
        return att_type

    def copy_file_to_temp(self, file, directory, filename):
        extracted_local_state_file_path = os.path.join(directory, filename)

        ContentUtils.writeToFile(file, File(extracted_local_state_file_path))

        return extracted_local_state_file_path

    def check_user_from_file(self, file):
        if "/Users/" in str(file.getParentPath()):
            current_user = str(file.getParentPath()).split("/")[2]
            return current_user
        return ""


class Videoconf4AIngestModuleGUISettingsPanel(IngestModuleIngestJobSettingsPanel):

    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    def onClickImport(self, e):
        chooseFile = JFileChooser()

        file_type = self.local_settings.getSetting("file_type")

        if file_type == "csv":
            filter = FileNameExtensionFilter("CSV (Comma Delimited) (*.csv)", [file_type])
        elif file_type == "json":
            filter = FileNameExtensionFilter("JSON (JavaScript Object Notation) (*.json)", [file_type])
        else:
            filter = FileNameExtensionFilter("CSV (Comma Delimited) (*.csv)", [file_type])


        chooseFile.setFileFilter(filter)

        ret = chooseFile.showDialog(self, "Open")

        if ret == JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            canonical_file = file.getCanonicalPath()
            if ("." + file_type) not in canonical_file:
                canonical_file = canonical_file + "." + file_type
            self.local_settings.setSetting('users_passwords_file', canonical_file)
            self.selectedFileLabel.setText(os.path.basename(canonical_file))
        else:
            self.local_settings.setSetting('users_passwords_file', None)
            self.selectedFileLabel.setText('(no file)')

    def radioBtnEvent(self, e):
        isJsonSelected = self.radioBtnJson.isSelected()
        self.local_settings.setSetting('file_type', 'json' if isJsonSelected else 'csv')
        selected_file = self.local_settings.getSetting('users_passwords_file')
        if selected_file is not None:
            filename, extension = os.path.splitext(os.path.basename(selected_file))
            self.selectedFileLabel.setText(filename + "." + self.local_settings.getSetting("file_type"))

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        # main panel
        panelTop = JPanel()
        panelTop.setLayout(BoxLayout(panelTop, BoxLayout.Y_AXIS))
        panelTop.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        labelTop = JLabel("<html><strong>Videoconf4A Settings</strong></html>")
        panelTop.add(labelTop)
        panelTop.add(JLabel(" "))

        # radio btn json export file
        panelRadioBtnJson = JPanel()
        panelRadioBtnJson.setLayout(BoxLayout(panelRadioBtnJson, BoxLayout.X_AXIS))
        panelRadioBtnJson.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.radioBtnJson = JRadioButton("JSON", actionPerformed=self.radioBtnEvent)
        panelRadioBtnJson.add(self.radioBtnJson)

        # radio btn csv export file
        panelRadioBtnCsv = JPanel()
        panelRadioBtnCsv.setLayout(BoxLayout(panelRadioBtnCsv, BoxLayout.X_AXIS))
        panelRadioBtnCsv.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.radioBtnCsv = JRadioButton("CSV", actionPerformed=self.radioBtnEvent)
        panelRadioBtnCsv.add(self.radioBtnCsv)

        # import file
        panelExport = JPanel()
        panelExport.setLayout(BoxLayout(panelExport, BoxLayout.X_AXIS))
        panelExport.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        self.exportBtn = JButton("Users passwords file location", actionPerformed=self.onClickImport)
        panelExport.add(self.exportBtn)
        panelExport.add(JLabel(" "))
        self.selectedFileLabel = JLabel("")
        panelExport.add(self.selectedFileLabel)

        # group radiobuttons
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
        panelGroupRadioBtns.setBorder(BorderFactory.createTitledBorder("File type"))

        # Group file type and file setting
        panelUsersPasswords = JPanel()
        labelDescriptionUsersPasswords = JLabel(
            "<html>This module will retrieve artifacts from the Zoom application for video conference.<br>"
            "Part of the module execution requires the users and corresponding passwords knowledge.<br>"
            "For that we require a file to be provided before the module execution.<br>"
            "The users passwords file can either be a <strong>JSON</strong> or <strong>CSV</strong> file.<br><br>"
            "For the JSON type the syntax is as follows:<br>"
            "<code>[<br>&ensp{\"user\": \"johnny\", \"password\": \"12345\"},<br>&ensp{\"user\": \"mike\", \"password\": \"abcd\"}<br>]</code><br><br>"
            "For the CSV type the syntax is as follows:<br><table><thead><tr><th>User</th><th>Password</th></tr></thead><tbody><tr><td>johnny</td><td>12345</td></tr><tr><td>mike</td><td>abcd</td></tr></tbody></table><br><strong>NOTE</strong>: If the file type is CSV the delimiter should be a comma. (\",\")</html>")
        panelUsersPasswords.setLayout(BoxLayout(panelUsersPasswords, BoxLayout.Y_AXIS))
        panelUsersPasswords.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        panelUsersPasswords.add(labelDescriptionUsersPasswords)
        panelUsersPasswords.add(JLabel(" "))
        panelUsersPasswords.add(panelGroupRadioBtns)
        panelUsersPasswords.add(JLabel(" "))
        panelUsersPasswords.add(panelExport)
        panelUsersPasswords.add(JLabel(" "))
        panelUsersPasswords.setBorder(BorderFactory.createTitledBorder("Users passwords settings"))


        self.add(panelTop)
        self.add(JLabel(" "))
        self.add(panelUsersPasswords)
        self.add(JLabel(" "))
        #self.add(panelExport)

    def customizeComponents(self):
        # file type
        file_type = self.local_settings.getSetting("users_passwords_file")
        # Set default type to CSV
        if file_type is None:
            self.local_settings.setSetting("file_type", "csv")


        # output file
        selected_file = self.local_settings.getSetting('users_passwords_file')
        if selected_file is not None:
            if os.path.isfile(selected_file):
                self.selectedFileLabel.setText(os.path.basename(selected_file))
            else:
                self.local_settings.setSetting('users_passwords_file', None)
                self.selectedFileLabel.setText('(no file)')
        else:
            self.selectedFileLabel.setText('(no file)')

    # Return the settings used
    def getSettings(self):
        return self.local_settings


class UserNotFoundException(Exception):
    pass

class FilesNotFoundException(Exception):
    pass

class MasterKeysNotFoundException(Exception):
    pass


