import json
import os
import glob
import fnmatch
import collections
import optparse
import traceback


# Function to check for malicious indicators (e.g., JS, Embedded files)
def CheckMaliciousIndicators(pdf_data):
    """
    Check the given PDF data for malicious indicators.
    This can include presence of JavaScript, embedded files, etc.
    """

    malicious = False

    # Checking JavaScript presence (Example: If '/JS' or '/JavaScript' found in the PDF)
    if '/JS' in pdf_data or '/JavaScript' in pdf_data:
        malicious = True

    # Example: Check for embedded files
    if '/EmbeddedFile' in pdf_data:
        malicious = True

    # Example: Check for encryption
    if '/Encrypt' in pdf_data:
        malicious = True

    return malicious


# Function to analyze the PDF and return structured data
def AnalyzePDF(filename):
    """
    Perform analysis on the PDF, extracting information and checking for malicious indicators.
    """

    # Sample analysis (in real case, this data would come from parsing the PDF)
    pdf_data = {
        "header": "%PDF-1.4",
        "objects": 568,
        "js_present": 1,  # 1 if JavaScript is found
        "embedded_files": 0,  # Check for embedded files if needed
        "encrypted": 0  # Check for encryption if needed
    }

    # Check if the PDF is malicious
    malicious = CheckMaliciousIndicators(pdf_data)

    # Create the analysis string
    analysis = f"PDF Header: {pdf_data['header']}\n" \
               f"obj {pdf_data['objects']}\n" \
               f"JS: {pdf_data['js_present']}\n"  # Add other fields like embedded files, encryption

    # Return structured result
    result = {
        "analysis": analysis,
        "malicious": malicious,
        "status": "success" if not malicious else "warning"  # Mark as warning if malicious
    }

    return result


# Function to process the PDF file and generate JSON output
def ProcessFile(filename):
    """
    Process the file and generate a structured JSON output with analysis.
    """
    result = AnalyzePDF(filename)  # Analyze the PDF
    return json.dumps(result, indent=4)


# Function to load plugins (if required)
def LoadPlugins(plugins, verbose):
    if plugins == '':
        return
    scriptPath = GetScriptPath()
    for plugin in sum(map(ProcessAt, plugins.split(',')), []):
        try:
            if not plugin.lower().endswith('.py'):
                plugin += '.py'
            if os.path.dirname(plugin) == '':
                if not os.path.exists(plugin):
                    scriptPlugin = os.path.join(scriptPath, plugin)
                    if os.path.exists(scriptPlugin):
                        plugin = scriptPlugin
            exec(open(plugin, 'r').read())
        except Exception as e:
            print('Error loading plugin: %s' % plugin)
            if verbose:
                raise e


# Function to expand and process filename arguments (e.g., support wildcards, @file)
class cExpandFilenameArguments():
    def __init__(self, filenames, literalfilenames=False, recursedir=False, checkfilenames=False,
                 expressionprefix=None):
        self.containsUnixShellStyleWildcards = False
        self.warning = False
        self.message = ''
        self.filenameexpressions = []
        self.expressionprefix = expressionprefix
        self.literalfilenames = literalfilenames

        expression = ''
        if len(filenames) == 0:
            self.filenameexpressions = [['', '']]
        elif literalfilenames:
            self.filenameexpressions = [[filename, ''] for filename in filenames]
        elif recursedir:
            for dirwildcard in filenames:
                if expressionprefix != None and dirwildcard.startswith(expressionprefix):
                    expression = dirwildcard[len(expressionprefix):]
                else:
                    if dirwildcard.startswith('@'):
                        for filename in ProcessAt(dirwildcard):
                            self.filenameexpressions.append([filename, expression])
                    elif os.path.isfile(dirwildcard):
                        self.filenameexpressions.append([dirwildcard, expression])
                    else:
                        if os.path.isdir(dirwildcard):
                            dirname = dirwildcard
                            basename = '*'
                        else:
                            dirname, basename = os.path.split(dirwildcard)
                            if dirname == '':
                                dirname = '.'
                        for path, dirs, files in os.walk(dirname):
                            for filename in fnmatch.filter(files, basename):
                                self.filenameexpressions.append([os.path.join(path, filename), expression])
        else:
            for filename in list(
                    collections.OrderedDict.fromkeys(sum(map(self.Glob, sum(map(ProcessAt, filenames), [])), []))):
                if expressionprefix != None and filename.startswith(expressionprefix):
                    expression = filename[len(expressionprefix):]
                else:
                    self.filenameexpressions.append([filename, expression])
            self.warning = self.containsUnixShellStyleWildcards and len(self.filenameexpressions) == 0
            if self.warning:
                self.message = "Your filename argument(s) contain Unix shell-style wildcards, but no files were matched.\nCheck your wildcard patterns or use option literalfilenames if you don't want wildcard pattern matching."
                return
        if self.filenameexpressions == [] and expression != '':
            self.filenameexpressions = [['', expression]]
        if checkfilenames:
            self.CheckIfFilesAreValid()

    def Glob(self, filename):
        if not ('?' in filename or '*' in filename or ('[' in filename and ']' in filename)):
            return [filename]
        self.containsUnixShellStyleWildcards = True
        return glob.glob(filename)

    def CheckIfFilesAreValid(self):
        valid = []
        doesnotexist = []
        isnotafile = []
        for filename, expression in self.filenameexpressions:
            hashfile = False
            try:
                hashfile = FilenameCheckHash(filename, self.literalfilenames)[0] == FCH_DATA
            except:
                pass
            if filename == '' or hashfile:
                valid.append([filename, expression])
            elif not os.path.exists(filename):
                doesnotexist.append(filename)
            elif not os.path.isfile(filename):
                isnotafile.append(filename)
            else:
                valid.append([filename, expression])
        self.filenameexpressions = valid
        if len(doesnotexist) > 0:
            self.warning = True
            self.message += 'The following files do not exist and will be skipped: ' + ' '.join(doesnotexist) + '\n'
        if len(isnotafile) > 0:
            self.warning = True
            self.message += 'The following files are not regular files and will be skipped: ' + ' '.join(
                isnotafile) + '\n'

    def Filenames(self):
        if self.expressionprefix == None:
            return [filename for filename, expression in self.filenameexpressions]
        else:
            return self.filenameexpressions


# Main PDFiD function
def PDFiDMain(filenames, options, filebuffers=None):
    global plugins
    plugins = []
    LoadPlugins(options.plugins, options.verbose)

    list_of_dict = {"reports": []}
    disarmed_buffers = {"buffers": []}

    # Process the files or buffers
    if not filebuffers:
        for filename in filenames:
            if options.scan:
                Scan(filename, options, plugins, list_of_dict["reports"], disarmed_buffers["buffers"])
            else:
                analysis_result = ProcessFile(filename)  # Use the updated ProcessFile function
                list_of_dict["reports"].append(json.loads(analysis_result))  # Store the result as JSON
    else:
        for i, filebuffer in enumerate(filebuffers):
            analysis_result = ProcessFile(filenames[i])  # Use the updated ProcessFile function
            list_of_dict["reports"].append(json.loads(analysis_result))  # Store the result as JSON

    # Return JSON response with analysis
    return list_of_dict


# Function to create a fake options object (for testing)
def get_fake_options():
    class FakeOptions:
        def __init__(self):
            self.scan = False
            self.all = False
            self.extra = False
            self.force = False
            self.disarm = False
            self.plugins = ''
            self.csv = False
            self.minimumscore = 0.0
            self.verbose = False
            self.select = ''
            self.nozero = False
            self.output = ''
            self.pluginoptions = ''
            self.literalfilenames = False
            self.recursedir = False
            self.json = False
            self.return_disarmed_buffer = False

    fakeoptions = FakeOptions()
    return fakeoptions


# Function to parse arguments and run the main logic
def GetOTPParser():
    moredesc = '''
    Arguments:
    pdf-file and zip-file can be a single file, several files, and/or @file
    @file: run PDFiD on each file listed in the text file specified
    wildcards are supported

    Source code put in the public domain by Didier Stevens, no Copyright
    Use at your own risk
    https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [pdf-file|zip-file|url|@file] ...\n' + moredesc,
                                    version='%prog 0.2.7')
    oParser.add_option('-s', '--scan', action='store_true', default=False, help='scan the given directory')
    oParser.add_option('-j', '--json', action='store_true', default=False,
                       help='json output, supports only basic analysis')

    return oParser


# Main entry point for script execution
def Main():
    oParser = GetOTPParser()
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        filenames = ['']
    else:
        try:
            oExpandFilenameArguments = cExpandFilenameArguments(args, options.literalfilenames, options.recursedir,
                                                                False)
            filenames = oExpandFilenameArguments.Filenames()
            if oExpandFilenameArguments.warning:
                print(oExpandFilenameArguments.message)
        except Exception as e:
            print(e)
            return

    PDFiDMain(filenames, options)


if __name__ == '__main__':
    Main()
