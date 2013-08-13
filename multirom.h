#ifndef MULTIROM_H
#define MULTIROM_H

#include <string>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>
#include <vector>
#include <errno.h>
#include <sys/mount.h>

#include "twinstall.h"
#include "minzip/Zip.h"
#include "roots.h"
#include "boot_img_hdr.h"
#include "data.hpp"
#include "mrominstaller.h"

enum { INSTALL_SUCCESS, INSTALL_ERROR, INSTALL_CORRUPT };

enum
{
	ROM_ANDROID_INTERNAL  = 0,
	ROM_ANDROID_USB_DIR   = 1,
	ROM_ANDROID_USB_IMG   = 2,
	ROM_UBUNTU_INTERNAL   = 3,
	ROM_UBUNTU_USB_DIR    = 4,
	ROM_UBUNTU_USB_IMG    = 5,
	ROM_INSTALLER_INTERNAL= 6,
	ROM_INSTALLER_USB_DIR = 7,
	ROM_INSTALLER_USB_IMG = 8,
	ROM_UTOUCH_INTERNAL   = 9,
	ROM_UTOUCH_USB_DIR    = 10,
	ROM_UTOUCH_USB_IMG    = 11,

	ROM_UNKNOWN,
};

enum
{
	CMPR_GZIP   = 0,
	CMPR_LZ4    = 1,
	CMPR_LZMA   = 2,
};

#define M(x) (1 << x)
#define MASK_UBUNTU (M(ROM_UBUNTU_INTERNAL) | M(ROM_UBUNTU_USB_IMG)| M(ROM_UBUNTU_USB_DIR))
#define MASK_ANDROID (M(ROM_ANDROID_USB_DIR) | M(ROM_ANDROID_USB_IMG) | M(ROM_ANDROID_INTERNAL))
#define MASK_IMAGES (M(ROM_ANDROID_USB_IMG) | M(ROM_UBUNTU_USB_IMG) | M(ROM_INSTALLER_USB_IMG) | M(ROM_UTOUCH_USB_IMG))
#define MASK_INTERNAL (M(ROM_ANDROID_INTERNAL) | M(ROM_UBUNTU_INTERNAL) | M(ROM_INSTALLER_INTERNAL) | M(ROM_UTOUCH_INTERNAL))
#define MASK_INSTALLER (M(ROM_INSTALLER_INTERNAL) | M(ROM_INSTALLER_USB_DIR) | M(ROM_INSTALLER_USB_IMG))

#define INTERNAL_NAME "Internal"
#define REALDATA "/realdata"
#define MAX_ROM_NAME 26
#define INTERNAL_MEM_LOC_TXT "Internal memory"
#define BOOT_DEV "/dev/block/mmcblk0p6"

// Not defined in android includes?
#define MS_RELATIME (1<<21)

#define MAX_BASE_FOLDER_CNT 5

struct base_folder
{
	base_folder(const std::string& name, int min_size, int size);
	base_folder(const base_folder& other);
	base_folder();

	std::string name;
	int min_size;
	int size;
};

class MultiROM
{
public:
	typedef std::map<std::string, base_folder> baseFolders;

	struct config {
		config();

		std::string current_rom;
		int auto_boot_seconds;
		std::string auto_boot_rom;
		int colors;
		int brightness;
		int enable_adb;
		int hide_internal;
		std::string int_display_name;
		int rotation;
	};

	struct file_backup {
		std::string name;
		char *content;
		int size;
	};

	static bool folderExists();
	static std::string getRomsPath();
	static std::string getPath();
	static int getType(std::string name);
	static std::string listRoms();
	static void setInstaller(MROMInstaller *i);
	static MROMInstaller *getInstaller(MROMInstaller *i);

	static void clearBaseFolders();
	static const base_folder& addBaseFolder(const std::string& name, int min, int def);
	static const base_folder& addBaseFolder(const base_folder& b);
	static baseFolders& getBaseFolders();
	static base_folder *getBaseFolder(const std::string& name);
	static void updateImageVariables();

	static bool move(std::string from, std::string to);
	static bool erase(std::string name);

	static bool flashZip(std::string rom, std::string file);
	static bool injectBoot(std::string img_path);
	static bool extractBootForROM(std::string base);
	static int copyBoot(std::string& orig, std::string rom);
	static bool wipe(std::string name, std::string what);

	static config loadConfig();
	static void saveConfig(const config& cfg);

	static bool addROM(std::string zip, int os, std::string loc);

	static std::string listInstallLocations();
	static void setRomsPath(std::string loc);
	static bool patchInit(std::string name);
	static bool disableFlashKernelAct(std::string name, std::string loc);
	static bool fakeBootPartition(const char *fakeImg);
	static void restoreBootPartition();
	static bool compareFiles(const char *path1, const char *path2);

private:
	static void findPath();
	static bool changeMounts(std::string base);
	static void restoreMounts();
	static bool prepareZIP(std::string& file, bool& format_system);
	static bool skipLine(const char *line);
	static std::string getNewRomName(std::string zip, std::string def);
	static bool createDirs(std::string name, int type);
	static bool compressRamdisk(const char *src, const char *dest, int cmpr);
	static int decompressRamdisk(const char *src, const char *dest);
	static bool installFromBackup(std::string name, std::string path, int type);
	static bool extractBackupFile(std::string path, std::string part);
	static int getType(int os, std::string loc);

	static bool ubuntuExtractImage(std::string name, std::string img_path, std::string dest);
	static bool patchUbuntuInit(std::string rootDir);
	static bool ubuntuUpdateInitramfs(std::string rootDir);
	static void setUpChroot(bool start, std::string rootDir);
	static void ubuntuDisableFlashKernel(bool initChroot, std::string rootDir);
	static bool mountUbuntuImage(std::string name, std::string& dest);

	static bool createImage(const std::string& base, const char *img, int size);
	static bool createImagesFromBase(const std::string& base);
	static bool createDirsFromBase(const std::string& base);
	static bool mountBaseImages(std::string base, std::string& dest);
	static void umountBaseImages(const std::string& base);

	static bool ubuntuTouchProcessBoot(const std::string& root);
	static bool ubuntuTouchProcess(const std::string& root, const std::string& name);

	static int system_args(const char *fmt, ...);
	static void translateToRealdata(std::string& path);
	static bool calculateMD5(const char *path, unsigned char *md5sum/*len: 16*/);
	static void normalizeROMPath(std::string& path);
	static void restoreROMPath();

	static std::string m_path;
	static std::vector<file_backup> m_mount_bak;
	static std::string m_mount_rom_paths[2];
	static std::string m_curr_roms_path;
	static MROMInstaller *m_installer;
	static baseFolders m_base_folders;
	static int m_base_folder_cnt;
};


#endif
