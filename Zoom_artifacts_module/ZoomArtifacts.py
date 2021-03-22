import jarray
import inspect
import os
import json
from subprocess import Popen, PIPE
import csv
import sys
from com.ziclix.python.sql import zxJDBC
import glob
import shutil
from time import sleep

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

def getConnection(jdbc_url, driverName):
    """
        Given the name of a JDBC driver class and the url to be used
        to connect to a database, attempt to obtain a connection to
        the database.
    """

    try:
        # no user/password combo needed here, hence the None, None
        dbConn = zxJDBC.connect(jdbc_url, None, None, driverName)
    except zxJDBC.DatabaseError, msg:
        print msg
        sys.exit(-1)

    return dbConn


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
            self.path_decrypt_chromium = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypt_chromium.exe")
            self.path_leveldb_parse = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hindsight.exe")
            if not os.path.exists(self.path_decrypt_chromium) and not os.path.exists(self.path_leveldb_parse):
                raise IngestModuleException("Required executable files not found on module directory. Required executables are \"decrypt_chromium.exe\" and \"hindsight.exe\"")
        else:
            raise IngestModuleException(Videoconf4AIngestModuleFactory.moduleName + "module can only run on Windows.")

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Zoom artifacts
        self.art_cookies = self.create_artifact_type("ZOOM_COOKIES", "Zoom Cookies", blackboard)
        self.art_login_data = self.create_artifact_type("ZOOM_LOGIN_DATA", "Zoom Login Data", blackboard)
        self.art_levelDB = self.create_artifact_type("ZOOM_LEVELDB", "Zoom LevelDB parsed", blackboard)

        # Generic Attributes
        self.att_win_user = self.create_attribute_type("WIN_USER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Windows User", blackboard)
        self.att_browser = self.create_attribute_type("BROWSER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Browser", blackboard)
        self.att_key = self.create_attribute_type("KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Key", blackboard)
        self.att_value = self.create_attribute_type("VALUE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Value", blackboard)

        # Cookies Attributes
        self.att_name = self.create_attribute_type("COOKIES_ZOOM_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name", blackboard)

        # Login Data Attributes
        self.att_url = self.create_attribute_type("LOGIN_DATA_ZOOM_URL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "URL", blackboard)
        self.att_user_type = self.create_attribute_type("LOGIN_DATA_ZOOM_USER_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Username type", blackboard)
        self.att_username = self.create_attribute_type("LOGIN_DATA_ZOOM_USERNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Username", blackboard)
        self.att_password = self.create_attribute_type("LOGIN_DATA_ZOOM_PASSWORD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Password", blackboard)

        # LevelDB Parser Attributes
        self.att_origin = self.create_attribute_type("LEVELDB_ZOOM_ORIGIN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Origin", blackboard)
        self.att_state = self.create_attribute_type("LEVELDB_ZOOM_STATE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "State", blackboard)

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

        self.moduleName = Videoconf4AIngestModuleFactory.moduleName

        # Create Event Log directory in temp directory, if it exists then continue on processing
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "ZOOM_ARTIFACTS_TEMP")

        try:
            os.mkdir(temporaryDirectory)
        except:
            pass
            self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)

        # LevelDB parsing
        browser_data = fileManager.findFiles(dataSource, "%", "/Users/%/AppData/Local/%/%/User Data")
        self.browser_dirs_extract(browser_data, temporaryDirectory)

        data_in_dir = os.listdir(temporaryDirectory)
        users = []
        for data in data_in_dir:
            if os.path.isdir(os.path.join(temporaryDirectory, data)):
                users.append(data)

        for user in users:
            user_temporary_directory = os.path.join(temporaryDirectory, user)
            data_in_dir = os.listdir(user_temporary_directory)
            browsers = []
            for data in data_in_dir:
                if os.path.isdir(os.path.join(user_temporary_directory, data)):
                    browsers.append(data)

            for browser in browsers:
                browser_temp_dir = os.path.join(user_temporary_directory, browser)
                default_temp_dir = os.path.join(browser_temp_dir, "User Data", "Default")

                if not os.path.exists(default_temp_dir):
                    self.log(Level.WARNING, "Could not find \"Default\" directory for LevelDB parsing for browser " + browser + " and user " + user)
                    continue

                output_file = os.path.join(browser_temp_dir, "leveldb_parsed")

                command_line = [str(self.path_leveldb_parse), "-i", str(default_temp_dir), "-o", str(output_file), "-f", "sqlite"]
                self.log(Level.INFO, str(command_line))

                pipe = Popen(command_line, shell=False, stdout=PIPE, stderr=PIPE)
                outputFromRun = pipe.communicate()[0]
                rc = pipe.returncode

                self.log(Level.INFO, "Output from LevelDB parse is ==> " + outputFromRun)

                # If return code is 0 means script was successful and masterkey was the correct one. Else continue
                if rc == 0:
                    output_file = output_file + ".sqlite"
                    JDBC_URL = "jdbc:sqlite:%s" % output_file
                    JDBC_DRIVER = "org.sqlite.JDBC"

                    conn = getConnection(JDBC_URL, JDBC_DRIVER)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin, key, value, state, source_path FROM storage WHERE origin LIKE '%zoom%'")

                    for result in cursor.fetchall():
                        source_path = result[4]

                        splited_path = source_path.split("\\")

                        data_source_files = fileManager.findFiles(dataSource, splited_path[-1], splited_path[-2])
                        for data_source_file in data_source_files:
                            data_source_path = data_source_file.getName() + data_source_file.getParentPath()
                            if (browser + "/User Data/Default") in data_source_path and user in data_source_path:
                                self.leveldb_artifact(data_source_file, browser, result, user)
                                break


        # Read the users passwords file (TODO: Make optional)
        users_passwords = self.read_users_passwords_file()

        # Retrieve MasterKey files
        master_keys = self.retrieve_master_keys(fileManager, dataSource, temporaryDirectory)

        for user_password in users_passwords:
            user = user_password["user"]
            password = user_password["password"]

            user_temporary_directory = os.path.join(temporaryDirectory, user)

            data_in_dir = os.listdir(user_temporary_directory)
            browsers = []
            for data in data_in_dir:
                if os.path.isdir(os.path.join(user_temporary_directory, data)):
                    browsers.append(data)

            for browser in browsers:

                browser_temp_dir = os.path.join(user_temporary_directory, browser)

                # Get file instances for artifacts
                cookies_file = None
                login_data_file = None
                for data in browser_data:
                    path = data.getParentPath() + data.getName()
                    search_cookies_path = browser + "/User Data/Default/Cookies"
                    search_login_data_path = browser + "/User Data/Default/Login Data"
                    if search_cookies_path in path:
                        cookies_file = data
                    if search_login_data_path in path:
                        login_data_file = data

                local_state_file_path = os.path.join(user_temporary_directory, browser, "User Data", "Local State")

                if not os.path.exists(local_state_file_path):
                    self.log(Level.WARNING, "Cannot retrieve \"Local State\" file to search artifacts on browser " + browser + " for user " + user)
                    continue

                cookies_file_path = os.path.join(user_temporary_directory, browser, "User Data", "Default", "Cookies")

                if not os.path.exists(cookies_file_path):
                    self.log(Level.WARNING, "Cannot retrieve \"Cookies\" file to search artifacts on browser " + browser + " for user " + user)
                    continue

                login_data_file_path = os.path.join(user_temporary_directory, browser, "User Data", "Default", "Login Data")

                if not os.path.exists(login_data_file_path):
                    self.log(Level.WARNING, "Cannot retrieve \"Login Data\" file to search artifacts on browser " + browser + " for user " + user)
                    continue

                master_key_list = []

                for master_key in master_keys:
                    if master_key["user"] == user:
                        master_key_list.append(master_key)

                for master_key_obj in master_key_list:

                    command_line = [str(self.path_decrypt_chromium), local_state_file_path, master_key_obj["sid"], password, master_key_obj["master_key_extracted_dir"], cookies_file_path, login_data_file_path, browser_temp_dir]

                    self.log(Level.INFO, str(command_line))

                    pipe = Popen(command_line, shell=False, stdout=PIPE, stderr=PIPE)
                    outputFromRun = pipe.communicate()[0]
                    rc = pipe.returncode
                    self.log(Level.INFO, "Output from Chromium decryption for browser " + browser + " and user " + user + " is --> " + outputFromRun)

                    # If return code is 0 means script was successful and masterkey was the correct one. Else continue
                    if rc == 0:
                        self.log(Level.INFO, "Retrieved artifacts for user " + user + " and browser " + browser)
                        self.cookies_artifact(cookies_file, browser, os.path.join(browser_temp_dir, "cookies_results.json"), user)
                        self.login_data_artifact(login_data_file, browser, os.path.join(browser_temp_dir, "login_data_results.json"), user)
                        break

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Zoom Cookies Decrypt", "Zoom Cookies Have Been Decrypted")
        IngestServices.getInstance().postMessage(message)

        # Clean temporary directory
        shutil.rmtree(temporaryDirectory)

        return IngestModule.ProcessResult.OK

    def browser_dirs_extract(self, browser_data, temporaryDirectory):
        for data in browser_data:
            if data.getName() == "." or data.getName() == "..":
                continue
            path = data.getParentPath() + data.getName()
            user = path.split("/")[2]
            browser = path.split("/")[6]
            user_temporary_directory = self.create_user_temp_dir(temporaryDirectory, user)

            # Build path for default
            user_browser_default_path = os.path.join(user_temporary_directory, browser, "User Data")

            try:
                os.makedirs(user_browser_default_path)
            except OSError:
                pass

            path_chain = user_browser_default_path
            if "/User Data/Default" in path:
                path_chain = os.path.join(user_browser_default_path, "Default")
                try:
                    os.mkdir(path_chain)
                except OSError:
                    pass
                after_default_path = path.split("Default")[1].split("/")
                # Build path chain until current dir/file on Default dir
                if len(after_default_path) > 2:
                    size_default_path = len(after_default_path)
                    for i, directory in enumerate(after_default_path):
                        next_index = i + 1
                        if next_index == size_default_path:
                            break
                        try:
                            dir_path = os.path.join(path_chain, directory)
                            if os.path.exists(dir_path):
                                path_chain = dir_path
                                continue
                            path_chain = dir_path
                            os.mkdir(dir_path)
                        except OSError:
                            pass

            data_type = str(data.dirType)

            if data_type == "DIR":
                try:
                    if path_chain == user_browser_default_path:
                        if data.getName() == "Default":
                            dir_path = os.path.join(path_chain, data.getName())
                            os.mkdir(dir_path)
                    else:
                        dir_path = os.path.join(path_chain, data.getName())
                        os.mkdir(dir_path)
                except OSError:
                    pass
            elif data_type == "REG":
                self.copy_file_to_temp(data, path_chain, data.getName())


    def create_user_temp_dir(self, directory, user):
        # Create an user specific temporary folder
        user_extract_folder = os.path.join(directory, user)

        # Create user temporary folder
        try:
            os.mkdir(user_extract_folder)
        except:
            pass
            #self.log(Level.INFO, "Temporary user folder already created -> " + user_extract_folder + ".")

        return user_extract_folder

    def leveldb_artifact(self, file_obj, browser, attributes, user):
        art = file_obj.newArtifact(self.art_levelDB.getTypeID())
        art.addAttribute(BlackboardAttribute(self.att_win_user, self.moduleName, str(user)))
        art.addAttribute(BlackboardAttribute(self.att_browser, self.moduleName, str(browser)))
        art.addAttribute(BlackboardAttribute(self.att_origin, self.moduleName, str(attributes[0])))
        art.addAttribute(BlackboardAttribute(self.att_key, self.moduleName, str(attributes[1])))
        art.addAttribute(BlackboardAttribute(self.att_value, self.moduleName, str(attributes[2])))
        art.addAttribute(BlackboardAttribute(self.att_state, self.moduleName, str(attributes[3])))


    def cookies_artifact(self, file_obj, browser, cookies_file_path, user):
        cookies_file_obj = open(cookies_file_path, "r")
        cookies_file = json.loads(cookies_file_obj.read())

        for cookie in cookies_file:
            if "zoom" in cookie["key"]:
                self.log(Level.INFO, "Creating Zoom cookies artifacts and attributes for user " + user + " on browser " + browser)
                art = file_obj.newArtifact(self.art_cookies.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_win_user, self.moduleName, str(user)))
                art.addAttribute(BlackboardAttribute(self.att_browser, self.moduleName, str(browser)))
                art.addAttribute(BlackboardAttribute(self.att_key, self.moduleName, str(cookie["key"])))
                art.addAttribute(BlackboardAttribute(self.att_name, self.moduleName, str(cookie["name"])))
                art.addAttribute(BlackboardAttribute(self.att_value, self.moduleName, str(cookie["value"])))

        cookies_file_obj.close()

    def login_data_artifact(self, file_obj, browser, login_data_path, user):
        login_data_file_obj = open(login_data_path, "r")
        login_data_file = json.loads(login_data_file_obj.read())

        for login_data in login_data_file:
            if "zoom" in login_data["url"]:
                self.log(Level.INFO, "Creating Zoom login data artifacts and attributes for user " + user + " on browser " + browser)
                art = file_obj.newArtifact(self.art_login_data.getTypeID())
                art.addAttribute(BlackboardAttribute(self.att_win_user, self.moduleName, str(user)))
                art.addAttribute(BlackboardAttribute(self.att_browser, self.moduleName, str(browser)))
                art.addAttribute(BlackboardAttribute(self.att_url, self.moduleName, str(login_data["url"])))
                art.addAttribute(BlackboardAttribute(self.att_user_type, self.moduleName, str(login_data["username_type"])))
                art.addAttribute(BlackboardAttribute(self.att_username, self.moduleName, str(login_data["username"])))
                art.addAttribute(BlackboardAttribute(self.att_password, self.moduleName, str(login_data["password"])))

        login_data_file_obj.close()

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
            return None
        return art

    def create_attribute_type(self, att_name, type_name, att_desc, blackboard):
        try:
            att_type = blackboard.getOrAddAttributeType(att_name, type_name, att_desc)
        except Exception as e:
            self.log(Level.INFO, "Error getting or adding attribute type: " + att_desc + " " + str(e))
            return None
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


