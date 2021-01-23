import jarray
import inspect
import os
import json
from subprocess import Popen, PIPE
import csv

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
class ZoomArtifactsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Zoom Artifacts"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Retrieves artifacts related to Zoom Video Conference"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ZoomArtifactsIngestModule(self.settings)


# Data Source-level ingest module.  One gets created per data source.
class ZoomArtifactsIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(ZoomArtifactsIngestModuleFactory.moduleName)

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
            self.pathToExe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts_decypher/main.exe")
            if not os.path.exists(self.pathToExe):
                raise IngestModuleException("decrypt_cookies.exe was not found in module folder")
        else:
            raise IngestModuleException(ZoomArtifactsIngestModuleFactory.moduleName + "module can only run on Windows.")

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Generic Attributes
        self.att_key = self.create_attribute_type("ZA_KEY",
                                                  BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Key",
                                                  blackboard)
        self.att_value = self.create_attribute_type("ZA_VALUE",
                                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                    "Value", blackboard)

    # Where the analysis is done.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        fileManager = Case.getCurrentCase().getServices().getFileManager()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Retrieve MasterKey files
        master_key_files = fileManager.findFiles(dataSource, "*", "S-1-5-21-*")
        for master_key_file in master_key_files:
            self.log(Level.INFO, master_key_file.getName())

        exit(0)

        # Find the LocalState file(s) needed to decrypt SQLite contents
        local_state_files = fileManager.findFiles(dataSource, "Local State", "Chrome")
        num_local_state_files = len(local_state_files)
        self.log(Level.INFO, "found " + str(num_local_state_files) + " local state files")

        # Find the Cookies file(s) for Chrome
        cookies_files = fileManager.findFiles(dataSource, "Cookies", "User Data")
        num_cookies_files = len(cookies_files)
        self.log(Level.INFO, "found " + str(num_cookies_files) + " cookies files")

        # Create Event Log directory in temp directory, if it exists then continue on processing
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "ZOOM_ARTIFACTS_TEMP")

        try:
            os.mkdir(temporaryDirectory)
        except:
            pass
            self.log(Level.INFO, "Temporary directory already exists " + temporaryDirectory)

        # Iterate on "Local State" files
        for local_state_file in local_state_files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Copying Local State File: " + local_state_file.getParentPath() + local_state_file.getName())

            extracted_local_state_file_path = self.copy_file_to_temp(local_state_file, temporaryDirectory)

            current_user = self.check_user_from_file(local_state_file)

            if current_user != "":
                self.log(Level.INFO, "Found current user name -> " + current_user)
            else:
                self.log(Level.INFO, "Could not found user name... Continuing")

            # Iterate "Cookie" files
            for cookie_file in cookies_files:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.log(Level.INFO, "Copying Cookie File: " + cookie_file.getParentPath() + cookie_file.getName())

                extracted_cookie_file_path = self.copy_file_to_temp(cookie_file, temporaryDirectory)
                self.log(Level.INFO, "Local State file -> " + "\"" + extracted_local_state_file_path + "\"")
                self.log(Level.INFO, "Cookie file -> " + "\"" + extracted_cookie_file_path + "\"")

                pipe = Popen([self.pathToExe, "\"" + extracted_local_state_file_path + "\"", "\"" + extracted_cookie_file_path + "\""], stdout=PIPE, stderr=PIPE)
                outputFromRun = pipe.communicate()[0]
                self.log(Level.INFO, "Output from Run is ==> " + outputFromRun)

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Zoom Cookies Decrypt", "Zoom Cookies Have Been Decrypted")
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

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

    def check_user_from_file(self, file):
        if "/Users/" in str(file.getParentPath()):
            current_user = str(file.getParentPath()).split("/")[2]
            return current_user
        return ""
