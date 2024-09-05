#include "common/common.h"
#include "common/json.h"
#include "openssl.h"
#include "macho.h"
#include "bundle.h"
#include <libgen.h>
#include <dirent.h>
#include <getopt.h>
#include <iostream>

struct Option {
	const char* name;
	int argument;
	int value;
	const char* description;
	const char* defaultValue;  // Added field for default value
};

const Option options[] = {
	{"debug", no_argument, 'd', "Generate debug output files. (.zsign_debug folder)", ""},
	{"force", no_argument, 'f', "Force sign without cache when signing folder.", ""},
	{"verbose", no_argument, 'v', "Enable verbose output.", ""},
	{"cert", required_argument, 'c', "Path to certificate file. (PEM or DER format)", ""},
	{"pkey", required_argument, 'k', "Path to private key or p12 file. (PEM or DER format)", ""},
	{"prov", required_argument, 'm', "Path to mobile provisioning profile.", ""},
	{"password", required_argument, 'p', "Password for private key or p12 file.", ""},
	{"bundle_id", required_argument, 'b', "New bundle id to change.", ""},
	{"bundle_name", required_argument, 'n', "New bundle name to change.", ""},
	{"bundle_version", required_argument, 'r', "New bundle version to change.", ""},
	{"entitlements", required_argument, 'e', "New entitlements to change.", ""},
	{"output", required_argument, 'o', "Path to output ipa file.", ""},
	{"zip_level", required_argument, 'z', "Compressed level when outputting the ipa file. (0-9)", "0"},
	{"dylib", required_argument, 'l', "Path to inject dylib file.", ""},
	{"weak", no_argument, 'w', "Inject dylib as LC_LOAD_WEAK_DYLIB.", ""},
	{"install", no_argument, 'i', "Install ipa file using ideviceinstaller command for testing.", ""},
	{"remove_mobileprovision", no_argument, 'j', "Remove Mobileprovision.", ""},
	{"quiet", no_argument, 'q', "Quiet operation.", ""},
	{"help", no_argument, 'h', "Display help (this message).", ""},
	{}
};

int usage() {
	std::cout << "Usage: zsign [-options] [-k privkey.pem] [-m dev.prov] [-o output.ipa] file|folder" << std::endl;
	std::cout << "options:" << std::endl;
	for (const Option* opt = options; opt->name; opt++) {
		std::cout << "-" << static_cast<char>(opt->value) << ", --" << opt->name << "\t\t\t\t" << opt->description;
		if (opt->defaultValue[0] != '\0') {
			std::cout << " (default: " << opt->defaultValue << ")";
		}
		std::cout << std::endl;
	}
	return -1;
}

struct Arguments {
	bool debug;
	bool force;
	bool verbose;
	bool install;
	bool weakInject;
	bool removeMobileprovision;
	uint32_t zipLevel;
	std::string certFile;
	std::string pkeyFile;
	std::string provFile;
	std::string password;
	std::string bundleId;
	std::string bundleVersion;
	std::string dyLibFile;
	std::string outputFile;
	std::string displayName;

	Arguments():
		debug(false),
		force(false),
		verbose(false),
		install(false),
		weakInject(false),
		removeMobileprovision(false),
		zipLevel(0)
	{}
};

Arguments parseArguments(int argc, char* argv[]) {
	Arguments args;
	int opt = 0;
	int argslot = -1;
	
	// Construct short_options string dynamically
	std::string short_options;
	struct option long_options[sizeof(options) / sizeof(Option)];
	
	for (size_t i = 0; i < sizeof(options) / sizeof(Option); i++) {
		long_options[i].name = options[i].name;
		long_options[i].has_arg = options[i].argument;
		long_options[i].val = options[i].value;

		// Add to the short_options string
		short_options.push_back(static_cast<char>(options[i].value));
		if (options[i].argument == required_argument) {
			short_options.push_back(':');
		}
	}

	while (-1 != (opt = getopt_long(argc, argv, short_options.c_str(), long_options, &argslot))) {
		// for (size_t i = 0; i < sizeof(options) / sizeof(Option); i++) {
			if (opt == 'c') args.certFile = optarg;
			else if (opt == 'k') args.pkeyFile = optarg;
			else if (opt == 'm') args.provFile = optarg;
			else if (opt == 'p') args.password = optarg;
			else if (opt == 'b') args.bundleId = optarg;
			else if (opt == 'r') args.bundleVersion = optarg;
			else if (opt == 'l') args.dyLibFile = optarg;
			else if (opt == 'o') args.outputFile = GetCanonicalizePath(optarg);
			else if (opt == 'z') args.zipLevel = atoi(optarg);
			else if (opt == 'd') args.debug = true;
			else if (opt == 'f') args.force = true;
			else if (opt == 'v') args.verbose = true;
			else if (opt == 'i') args.install = true;
			else if (opt == 'w') args.weakInject = true;
			else if (opt == 'j') args.removeMobileprovision = true;
			else if (opt == 'h' || opt == '?') {
				usage(); 
				exit(0);
			}
		// }
		
		ZLog::DebugV("Option:\t-%c, %s\n", opt, optarg);
	}

	if (optind >= argc) {
		usage();
		exit(0);
	}

	return args;
}

int main(int argc, char* argv[]) {
	ZTimer gtimer;
	Arguments args = parseArguments(argc, argv);

	if (args.debug) {
		ZLog::SetLogLever(ZLog::E_DEBUG);
	}

	if (args.verbose) {
		ZLog::SetLogLever(ZLog::E_NONE);
	}

	if (ZLog::IsDebug()) {
		CreateFolder("./.zsign_debug");
		for (int i = optind; i < argc; i++) {
			ZLog::DebugV("Argument:\t%s\n", argv[i]);
		}
	}

	std::string filePath = GetCanonicalizePath(argv[optind]);
	if (!IsFileExists(filePath.c_str())) {
		ZLog::ErrorV("Invalid Path! %s\n", filePath.c_str());
		return -1;
	}

	bool isZipFile = false;
	if (!IsFolder(filePath.c_str())) {
		isZipFile = IsZipFile(filePath.c_str());
		if (!isZipFile) {
			ZMachO macho;
			if (macho.Init(filePath.c_str())) {
				if (!args.dyLibFile.empty()) {
					bool create = false;
					macho.InjectDyLib(args.weakInject, args.dyLibFile.c_str(), create);
				}
				else {
					macho.PrintInfo();
				}
				macho.Free();
			}
			return 0;
		}
	}

	ZTimer timer;
	ZSignAsset zSignAsset;
	if (!zSignAsset.Init(args.certFile, args.pkeyFile, args.provFile, args.displayName, args.password)) {
		return -1;
	}

	bool enableCache = true;
	std::string folderPath = filePath;
	if (isZipFile) {
		args.force = true;
		enableCache = false;
		StringFormat(folderPath, "/tmp/zsign_folder_%llu", timer.Reset());
		ZLog::PrintV("Unzip:\t%s (%s) -> %s ... \n", filePath.c_str(), GetFileSizeString(filePath.c_str()).c_str(), folderPath.c_str());
		RemoveFolder(folderPath.c_str());
		if (!SystemExec("unzip -qq -d '%s' '%s'", folderPath.c_str(), filePath.c_str())) {
			RemoveFolder(folderPath.c_str());
			ZLog::ErrorV("Unzip Failed!\n");
			return -1;
		}
		timer.PrintResult(true, "Unzip OK!");
	}

	timer.Reset();
	ZAppBundle bundle;
	bool success = bundle.SignFolder(&zSignAsset, folderPath, args.bundleId, args.bundleVersion, args.displayName, args.dyLibFile, args.force, args.weakInject, enableCache, args.removeMobileprovision);
	if(success){
		timer.PrintResult(success, "Signed");
	}else{
		timer.PrintResult(success, "Failed!");
		return -1;
	}

	if (args.install && args.outputFile.empty()) {
		StringFormat(args.outputFile, "/tmp/zsign_temp_%llu.ipa", GetMicroSecond());
	}

	if (!args.outputFile.empty()) {
		timer.Reset();
		size_t pos = bundle.m_strAppFolder.rfind("/Payload");
		if (string::npos == pos) {
		    ZLog::Error("Can't Find Payload Directory!\n");
		    return -1;
		}
	
		ZLog::PrintV(">>> Archiving: \t%s ... \n", args.outputFile.c_str());
		string strBaseFolder = bundle.m_strAppFolder.substr(0, pos);
		char szOldFolder[PATH_MAX] = {0};
		if (NULL != getcwd(szOldFolder, PATH_MAX))
		{
			if (0 == chdir(strBaseFolder.c_str()))
			{
				args.zipLevel = args.zipLevel > 9 ? 9 : args.zipLevel;
				RemoveFile(args.outputFile.c_str());
				SystemExec("7z a -tzip -mx=0 -r '%s' Payload", args.outputFile.c_str());
				chdir(szOldFolder);
				if (!IsFileExists(args.outputFile.c_str()))
				{
					ZLog::Error(">>> Archive Failed!\n");
					return -1;
				}
			}
		}
		timer.PrintResult(true, ">>> Archive OK! (%s)", GetFileSizeString(args.outputFile.c_str()).c_str());
	    }

	if (success && args.install) {
		SystemExec("ideviceinstaller -i '%s'", args.outputFile.c_str());
	}

	if (0 == args.outputFile.find("/tmp/zsign_tmp_")) {
		RemoveFile(args.outputFile.c_str());
	}

	if (0 == folderPath.find("/tmp/zsign_folder_")) {
		RemoveFolder(folderPath.c_str());
	}

	gtimer.Print("Done.");
	return success ? 0 : -1;
}
