#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "multirom.h"

extern "C" {
#include "twcommon.h"
#include "digest/md5.h"
}

std::string MultiROM::m_path = "";
std::string MultiROM::m_mount_rom_paths[2] = { "", "" };
std::vector<MultiROM::file_backup> MultiROM::m_mount_bak;
std::string MultiROM::m_curr_roms_path = "";
MROMInstaller *MultiROM::m_installer = NULL;
MultiROM::baseFolders MultiROM::m_base_folders;
int MultiROM::m_base_folder_cnt = 0;

base_folder::base_folder(const std::string& name, int min_size, int size)
{
	this->name = name;
	this->min_size = min_size;
	this->size = size;
}

base_folder::base_folder(const base_folder& other)
{
	name = other.name;
	min_size = other.min_size;
	size = other.size;
}

base_folder::base_folder()
{
	min_size = 1;
	size = 1;
}

MultiROM::config::config()
{

	current_rom = INTERNAL_NAME;
	auto_boot_seconds = 5;
	auto_boot_rom = INTERNAL_NAME;
	colors = 0;
	brightness = 40;
	hide_internal = 0;
	int_display_name = INTERNAL_NAME;
	rotation = 0; // FIXME: should be device specific
}

bool MultiROM::folderExists()
{
	findPath();
	return !m_path.empty();
}

std::string MultiROM::getRomsPath()
{
	return m_curr_roms_path;
}

std::string MultiROM::getPath()
{
	return m_path;
}

void MultiROM::findPath()
{
	static const char *paths[] = {
		"/data/media/multirom",
		"/data/media/0/multirom",
		NULL
	};

	struct stat info;
	for(int i = 0; paths[i]; ++i)
	{
		if(stat(paths[i], &info) >= 0)
		{
			m_path = paths[i];
			m_curr_roms_path = m_path + "/roms/";
			return;
		}
	}
	m_path.clear();
}

void MultiROM::setRomsPath(std::string loc)
{
	umount("/mnt"); // umount last thing mounted there

	if(loc.compare(INTERNAL_MEM_LOC_TXT) == 0)
	{
		m_curr_roms_path = m_path + "/roms/";
		return;
	}

	size_t idx = loc.find(' ');
	if(idx == std::string::npos)
	{
		m_curr_roms_path.clear();
		return;
	}

	std::string dev = loc.substr(0, idx);
	mkdir("/mnt", 0777); // in case it does not exist

	char cmd[256];
	if(loc.find("(ntfs") == std::string::npos)
		sprintf(cmd, "mount %s /mnt", dev.c_str());
	else
		sprintf(cmd, "%s/ntfs-3g %s /mnt", m_path.c_str(), dev.c_str());
	system(cmd);

	m_curr_roms_path = "/mnt/multirom/";
	mkdir("/mnt/multirom/", 0777);
}

std::string MultiROM::listInstallLocations()
{
	std::string res = INTERNAL_MEM_LOC_TXT"\n";

	system("blkid > /tmp/blkid.txt");
	FILE *f = fopen("/tmp/blkid.txt", "r");
	if(!f)
		return res;

	char line[1024];
	std::string blk;
	size_t idx1, idx2;
	while((fgets(line, sizeof(line), f)))
	{
		if(!strstr(line, "/dev/block/sd"))
			continue;

		blk = line;
		idx1 = blk.find(':');
		if(idx1 == std::string::npos)
			continue;

		res += blk.substr(0, idx1);

		blk = line;
		idx1 = blk.find("TYPE=");
		if(idx1 == std::string::npos)
			continue;

		idx1 += strlen("TYPE=\"");
		idx2 = blk.find('"', idx1);
		if(idx2 == std::string::npos)
			continue;

		res += " (" + blk.substr(idx1, idx2-idx1) + ")\n";
	}

	fclose(f);
	return res;
}

bool MultiROM::move(std::string from, std::string to)
{
	std::string roms = getRomsPath();
	std::string cmd = "mv \"" + roms + "/" + from + "\" ";
	cmd += "\"" + roms + "/" + to + "\"";

	gui_print("Moving ROM \"%s\" to \"%s\"...\n", from.c_str(), to.c_str());

	return system(cmd.c_str()) == 0;
}

bool MultiROM::erase(std::string name)
{
	std::string path = getRomsPath() + "/" + name;

	gui_print("Erasing ROM \"%s\"...\n", name.c_str());

	int res = system_args("chattr -R -i \"%s\"", path.c_str());
	if(res != 0)
	{
		gui_print("Failed to remove immutable attribute from that folder!\n");
		return false;
	}
	res = system_args("rm -rf \"%s\"", path.c_str());
	sync();
	return res == 0;
}

bool MultiROM::wipe(std::string name, std::string what)
{
	gui_print("Changing mountpoints...\n");
	if(!changeMounts(name))
	{
		gui_print("Failed to change mountpoints!\n");
		return false;
	}

	char cmd[256];
	bool res = true;
	if(what == "dalvik")
	{
		static const char *dirs[] = {
			"data/dalvik-cache",
			"cache/dalvik-cache",
			"cache/dc",
		};

		for(uint8_t i = 0; res && i < sizeof(dirs)/sizeof(dirs[0]); ++i)
		{
			sprintf(cmd, "rm -rf \"/%s\"", dirs[i]);
			gui_print("Wiping dalvik: %s...\n", dirs[i]);
			res = (system(cmd) == 0);
		}
	}
	else
	{
		sprintf(cmd, "rm -rf \"/%s/\"*", what.c_str());
		gui_print("Wiping ROM's /%s...\n", what.c_str());
		res = (system(cmd) == 0);
	}

	sync();

	if(!res)
		gui_print("ERROR: Failed to erase %s!\n", what.c_str());

	gui_print("Restoring mountpoints...\n");
	restoreMounts();
	return res;
}

int MultiROM::getType(std::string name)
{
	std::string path = getRomsPath() + "/" + name + "/";
	struct stat info;

	if(getRomsPath().find("/mnt") != 0) // Internal memory
	{
		if (stat((path + "system").c_str(), &info) >= 0 &&
			stat((path + "data").c_str(), &info) >= 0 &&
			stat((path + "cache").c_str(), &info) >= 0)
			return ROM_ANDROID_INTERNAL;


		if(stat((path + "root").c_str(), &info) >= 0)
			return ROM_UBUNTU_INTERNAL;
	}
	else // USB roms
	{
		if (stat((path + "system").c_str(), &info) >= 0 &&
			stat((path + "data").c_str(), &info) >= 0 &&
			stat((path + "cache").c_str(), &info) >= 0)
			return ROM_ANDROID_USB_DIR;

		if (stat((path + "system.img").c_str(), &info) >= 0 &&
			stat((path + "data.img").c_str(), &info) >= 0 &&
			stat((path + "cache.img").c_str(), &info) >= 0)
			return ROM_ANDROID_USB_IMG;

		if(stat((path + "root").c_str(), &info) >= 0)
			return ROM_UBUNTU_USB_DIR;

		if(stat((path + "root.img").c_str(), &info) >= 0)
			return ROM_UBUNTU_USB_IMG;
	}
	return ROM_UNKNOWN;
}

static bool rom_sort(std::string a, std::string b)
{
	if(a == INTERNAL_NAME)
		return true;
	if(b == INTERNAL_NAME)
		return false;
	return a.compare(b) < 0;
}

std::string MultiROM::listRoms()
{
	DIR *d = opendir(getRomsPath().c_str());
	if(!d)
		return "";

	std::vector<std::string> vec;
	struct dirent *dr;
	while((dr = readdir(d)) != NULL)
	{
		if(dr->d_type != DT_DIR)
			continue;

		if(dr->d_name[0] == '.')
			continue;

		vec.push_back(dr->d_name);
	}
	closedir(d);

	std::sort(vec.begin(), vec.end(), rom_sort);

	std::string res = "";
	for(size_t i = 0; i < vec.size(); ++i)
		res += vec[i] + "\n";
	return res;
}

MultiROM::config MultiROM::loadConfig()
{
	config cfg;

	FILE *f = fopen((m_path + "/multirom.ini").c_str(), "r");
	if(f)
	{
		char line[512];
		char *p;
		std::string name, val;
		while(fgets(line, sizeof(line), f))
		{
			p = strtok(line, "=\n");
			if(!p)
				continue;
			name = p;

			p = strtok(NULL, "=\n");
			if(!p)
				continue;
			val = p;

			if(name == "current_rom")
				cfg.current_rom = val;
			else if(name == "auto_boot_seconds")
				cfg.auto_boot_seconds = atoi(val.c_str());
			else if(name == "auto_boot_rom")
				cfg.auto_boot_rom = val;
			else if(name == "colors")
				cfg.colors = atoi(val.c_str());
			else if(name == "brightness")
				cfg.brightness = atoi(val.c_str());
			else if(name == "enable_adb")
				cfg.enable_adb = atoi(val.c_str());
			else if(name == "hide_internal")
				cfg.hide_internal = atoi(val.c_str());
			else if(name == "int_display_name")
				cfg.int_display_name = val;
			else if(name == "rotation")
				cfg.rotation = atoi(val.c_str());
		}
		fclose(f);
	}
	return cfg;
}

void MultiROM::saveConfig(const MultiROM::config& cfg)
{
	FILE *f = fopen((m_path + "/multirom.ini").c_str(), "w");
	if(!f)
		return;

	fprintf(f, "current_rom=%s\n", cfg.current_rom.c_str());
	fprintf(f, "auto_boot_seconds=%d\n", cfg.auto_boot_seconds);
	fprintf(f, "auto_boot_rom=%s\n", cfg.auto_boot_rom.c_str());
	fprintf(f, "colors=%d\n", cfg.colors);
	fprintf(f, "brightness=%d\n", cfg.brightness);
	fprintf(f, "enable_adb=%d\n", cfg.enable_adb);
	fprintf(f, "hide_internal=%d\n", cfg.hide_internal);
	fprintf(f, "int_display_name=%s\n", cfg.int_display_name.c_str());
	fprintf(f, "rotation=%d\n", cfg.rotation);

	fclose(f);
}

bool MultiROM::changeMounts(std::string name)
{
	int type = getType(name);
	std::string base = getRomsPath() + name;
	normalizeROMPath(base);

	mkdir(REALDATA, 0777);
	if(mount("/dev/block/platform/msm_sdcc.1/by-name/userdata",
	    REALDATA, "ext4", MS_RELATIME | MS_NOATIME,
		"user_xattr,acl,barrier=1,data=ordered,discard") < 0)
	{
		gui_print("Failed to mount realdata: %d (%s)", errno, strerror(errno));
		return false;
	}

	if(M(type) & MASK_INTERNAL)
		base.replace(0, 5, REALDATA);

	static const char *files[] = {
		"/etc/fstab",
		"/etc/recovery.fstab",
		NULL
	};

	for(size_t i = 0; i < m_mount_bak.size(); ++i)
		delete[] m_mount_bak[i].content;
	m_mount_bak.clear();

	for(int i = 0; files[i]; ++i)
	{
		FILE *f = fopen(files[i], "r");
		if(!f)
			return false;

		fseek(f, 0, SEEK_END);
		int size = ftell(f);
		rewind(f);

		file_backup b;
		b.name = files[i];
		b.size = size;
		b.content = new char[size]();
		fread(b.content, 1, size, f);
		fclose(f);

		m_mount_bak.push_back(b);
	}
	system("sync; umount -d /system /data /cache");

	FILE *f_fstab = fopen("/etc/fstab", "w");
	if(!f_fstab)
		return false;

	FILE *f_rec = fopen("/etc/recovery.fstab", "w");
	if(!f_rec)
	{
		fclose(f_fstab);
		return false;
	}

	fprintf(f_rec, "# mount point\tfstype\t\tdevice\n");
	if(!(M(type) & MASK_IMAGES))
	{
		fprintf(f_rec, "/system\t\text4\t\t%s/system\n", base.c_str());
		fprintf(f_rec, "/cache\t\text4\t\t%s/cache\n", base.c_str());
		fprintf(f_rec, "/data\t\text4\t\t%s/data\n", base.c_str());
	}
	else
	{
		fprintf(f_rec, "/system\t\text4\t\t%s/system.img\n", base.c_str());
		fprintf(f_rec, "/cache\t\text4\t\t%s/cache.img\n", base.c_str());
		fprintf(f_rec, "/data\t\text4\t\t%s/data.img\n", base.c_str());
	}
	fprintf(f_rec, "/misc\t\temmc\t\t/dev/block/platform/msm_sdcc.1/by-name/misc\n");
	fprintf(f_rec, "/boot\t\temmc\t\t/dev/block/platform/msm_sdcc.1/by-name/boot\n");
	fprintf(f_rec, "/recovery\t\temmc\t\t/dev/block/platform/msm_sdcc.1/by-name/recovery\n");
	fprintf(f_rec, "/usb-otg\t\tvfat\t\t/dev/block/sda1\n");
	fclose(f_rec);

	if(!(M(type) & MASK_IMAGES))
	{
		fprintf(f_fstab, "%s/system /system ext4 rw,bind\n", base.c_str());
		fprintf(f_fstab, "%s/cache /cache ext4 rw,bind\n", base.c_str());
		fprintf(f_fstab, "%s/data /data ext4 rw,bind\n", base.c_str());
	}
	else
	{
		fprintf(f_fstab, "%s/system.img /system ext4 loop 0 0\n", base.c_str());
		fprintf(f_fstab, "%s/cache.img /cache ext4 loop 0 0\n", base.c_str());
		fprintf(f_fstab, "%s/data.img /data ext4 loop 0 0\n", base.c_str());
	}
	fprintf(f_fstab, "/usb-otg vfat rw\n");
	fclose(f_fstab);

	system("mount /system");
	system("mount /data");
	system("mount /cache");

	system("mv /sbin/umount /sbin/umount.bak");

	//load_volume_table();
	return true;
}

void MultiROM::restoreMounts()
{
	system("mv /sbin/umount.bak /sbin/umount");
	system("umount -d /system /data /cache");

	for(size_t i = 0; i < m_mount_bak.size(); ++i)
	{
		file_backup &b = m_mount_bak[i];
		FILE *f = fopen(b.name.c_str(), "w");
		if(f)
		{
			fwrite(b.content, 1, b.size, f);
			fclose(f);
		}
		delete[] b.content;
	}
	m_mount_bak.clear();

	system("umount "REALDATA);
	//load_volume_table();
	system("mount /data");

	restoreROMPath();
}

void MultiROM::translateToRealdata(std::string& path)
{
	if(path.find("/sdcard/") != std::string::npos)
	{
		struct stat info;
		if(stat(REALDATA"/media/0", &info) >= 0)
			path.replace(0, strlen("/sdcard/"), REALDATA"/media/0/");
		else
			path.replace(0, strlen("/sdcard/"), REALDATA"/media/");
	}
	else if(path.find("/data/media/") != std::string::npos)
		path.replace(0, strlen("/data/"), REALDATA"/");
}

void MultiROM::normalizeROMPath(std::string& path)
{
	if(!m_mount_rom_paths[0].empty())
	{
		path = m_mount_rom_paths[1];
		return;
	}

	// remove spaces from path
	size_t idx = path.find(' ');
	if(idx == std::string::npos)
	{
		m_mount_rom_paths[0].clear();
		return;
	}

	m_mount_rom_paths[0] = path;
	while(idx != std::string::npos)
	{
		path.replace(idx, 1, "-");
		idx = path.find(' ', idx);
	}

	struct stat info;
	while(stat(path.c_str(), &info) >= 0)
		path += "a";

	m_mount_rom_paths[1] = path;
	system_args("mv \"%s\" \"%s\"", m_mount_rom_paths[0].c_str(), path.c_str());
}

void MultiROM::restoreROMPath()
{
	if(m_mount_rom_paths[0].empty())
		return;

	system_args("mv \"%s\" \"%s\"", m_mount_rom_paths[1].c_str(), m_mount_rom_paths[0].c_str());
	m_mount_rom_paths[0].clear();
}

#define MR_UPDATE_SCRIPT_PATH  "META-INF/com/google/android/"
#define MR_UPDATE_SCRIPT_NAME  "META-INF/com/google/android/updater-script"

bool MultiROM::flashZip(std::string rom, std::string file)
{
	gui_print("Flashing ZIP file %s\n", file.c_str());
	gui_print("ROM: %s\n", rom.c_str());

	bool format_system = false;

	gui_print("Preparing ZIP file...\n");
	if(!prepareZIP(file, format_system))
		return false;

	gui_print("Changing mountpoints\n");
	if(!changeMounts(rom))
	{
		gui_print("Failed to change mountpoints!\n");
		return false;
	}

	std::string boot = getRomsPath() + rom;
	normalizeROMPath(boot);
	boot += "/boot.img";

	translateToRealdata(file);
	translateToRealdata(boot);
	
	if(!fakeBootPartition(boot.c_str()))
	{
		restoreMounts();
		return false;
	}

	if(format_system)
	{
		gui_print("Clearing ROM's /system dir");
		system("chattr -R -i /system/*; rm -rf /system/*");
	}

	int wipe_cache = 0;
	int status = TWinstall_zip(file.c_str(), &wipe_cache);

	system("rm -r "MR_UPDATE_SCRIPT_PATH);
	if(file == "/tmp/mr_update.zip")
		system("rm /tmp/mr_update.zip");

	if(status != INSTALL_SUCCESS)
		gui_print("Failed to install ZIP!\n");
	else
		gui_print("ZIP successfully installed\n");

	restoreBootPartition();
	restoreMounts();
	return (status == INSTALL_SUCCESS);
}

bool MultiROM::skipLine(const char *line)
{
	if(strstr(line, "mount") && (!strstr(line, "bin/mount") || strstr(line, "run_program")))
		return true;

	if(strstr(line, "format"))
		return true;

	if (strstr(line, "boot.img") || strstr(line, BOOT_DEV) ||
		strstr(line, "/dev/block/platform/msm_sdcc.1/by-name/boot"))
	{
		return false;
	}

	if(strstr(line, "/dev/block/platform/msm_sdcc.1/"))
		return true;

	return false;
}

bool MultiROM::prepareZIP(std::string& file, bool& format_system)
{
	bool res = false;

	const ZipEntry *script_entry;
	int script_len;
	char* script_data;
	int itr = 0;
	char *token;
	bool changed = false;

	char cmd[512];
	system("rm /tmp/mr_update.zip");

	struct stat info;
	if(stat(file.c_str(), &info) >= 0 && info.st_size < 450*1024*1024)
	{
		gui_print("Copying ZIP to /tmp...\n");
		sprintf(cmd, "cp \"%s\" /tmp/mr_update.zip", file.c_str());
		system(cmd);
		file = "/tmp/mr_update.zip";
	}
	else
	{
		gui_print(" \n");
		gui_print("=======================================================\n");
		gui_print("WARN: Modifying the real ZIP, it is too big!\n");
		gui_print("The ZIP file is now unusable for non-MultiROM flashing!\n");
		gui_print("=======================================================\n");
		gui_print(" \n");
	}

	sprintf(cmd, "mkdir -p /tmp/%s", MR_UPDATE_SCRIPT_PATH);
	system(cmd);

	sprintf(cmd, "/tmp/%s", MR_UPDATE_SCRIPT_NAME);

	FILE *new_script = fopen(cmd, "w");
	if(!new_script)
		return false;

	ZipArchive zip;
	if (mzOpenZipArchive(file.c_str(), &zip) != 0)
		goto exit;

	script_entry = mzFindZipEntry(&zip, MR_UPDATE_SCRIPT_NAME);
	if(!script_entry)
		goto exit;

	if (read_data(&zip, script_entry, &script_data, &script_len) < 0)
		goto exit;

	mzCloseZipArchive(&zip);

	token = strtok(script_data, "\n");
	while(token)
	{
		if(!skipLine(token))
		{
			fputs(token, new_script);
			fputc('\n', new_script);
		}
		else
		{
			changed = true;

			if (strstr(token, "format") == token &&
				(strstr(token, "/system") || strstr(token, "/dev/block/platform/msm_sdcc.1/by-name/system")))
			{
				format_system = true;
			}
		}
		token = strtok(NULL, "\n");
	}

	free(script_data);
	fclose(new_script);

	if(changed)
	{
		sprintf(cmd, "cd /tmp && zip %s %s", file.c_str(), MR_UPDATE_SCRIPT_NAME);
		if(system(cmd) < 0)
			return false;
	}
	else
		gui_print("No need to change ZIP.\n");

	return true;

exit:
	mzCloseZipArchive(&zip);
	fclose(new_script);
	return false;
}

bool MultiROM::injectBoot(std::string img_path)
{
	char cmd[256];
	std::string path_trampoline = m_path + "/trampoline";
	struct stat info;

	if (stat(path_trampoline.c_str(), &info) < 0)
	{
		gui_print("%s not found!\n", path_trampoline.c_str());
		return false;
	}

	// EXTRACT BOOTIMG
	gui_print("Extracting boot image...\n");
	system("rm -r /tmp/boot; mkdir /tmp/boot");
	sprintf(cmd, "unpackbootimg -i \"%s\" -o /tmp/boot/", img_path.c_str());
	system(cmd);

	std::string p = img_path.substr(img_path.find_last_of("/")+1);
	sprintf(cmd, "/tmp/boot/%s-zImage", p.c_str());
	if(stat(cmd, &info) < 0)
	{
		gui_print("Failed to unpack boot img!\n");
		return false;
	}

	// DECOMPRESS RAMDISK
	gui_print("Decompressing ramdisk...\n");
	system("mkdir /tmp/boot/rd");
	sprintf(cmd, "/tmp/boot/%s-ramdisk.gz", p.c_str());
	int rd_cmpr = decompressRamdisk(cmd, "/tmp/boot/rd/");
	if(rd_cmpr == -1 || stat("/tmp/boot/rd/init", &info) < 0)
	{
		gui_print("Failed to decompress ramdisk!\n");
		return false;
	}

	// COPY TRAMPOLINE
	gui_print("Copying trampoline...\n");
	if(stat("/tmp/boot/rd/main_init", &info) < 0)
		system("mv /tmp/boot/rd/init /tmp/boot/rd/main_init");

	sprintf(cmd, "cp \"%s\" /tmp/boot/rd/init", path_trampoline.c_str());
	system(cmd);
	system("chmod 750 /tmp/boot/rd/init");
	system("ln -sf ../main_init /tmp/boot/rd/sbin/ueventd");
	system("ln -sf ../main_init /tmp/boot/rd/sbin/watchdogd");

	// COMPRESS RAMDISK
	gui_print("Compressing ramdisk...\n");
	sprintf(cmd, "/tmp/boot/%s-ramdisk.gz", p.c_str());
	if(!compressRamdisk("/tmp/boot/rd", cmd, rd_cmpr))
		return false;

	// PACK BOOT IMG
	gui_print("Packing boot image\n");
	FILE *script = fopen("/tmp/boot/create.sh", "w");
	if(!script)
	{
		gui_print("Failed to open script file!\n");
		return false;
	}
	std::string base_cmd = "mkbootimg --kernel /tmp/boot/%s-zImage --ramdisk /tmp/boot/%s-ramdisk.gz "
		"--cmdline \"$(cat /tmp/boot/%s-cmdline)\" --base $(cat /tmp/boot/%s-base) --output /tmp/newboot.img\n";
	for(size_t idx = base_cmd.find("%s", 0); idx != std::string::npos; idx = base_cmd.find("%s", idx))
		base_cmd.replace(idx, 2, p);

	fputs(base_cmd.c_str(), script);
	fclose(script);

	system("chmod 777 /tmp/boot/create.sh && /tmp/boot/create.sh");
	if(stat("/tmp/newboot.img", &info) < 0)
	{
		gui_print("Failed to pack boot image!\n");
		return false;
	}
	system("rm -r /tmp/boot");
	if(img_path == BOOT_DEV)
		system("dd bs=4096 if=/tmp/newboot.img of="BOOT_DEV);
	else
	{
		sprintf(cmd, "cp /tmp/newboot.img \"%s\"", img_path.c_str());;
		system(cmd);
	}
	return true;
}

int MultiROM::decompressRamdisk(const char *src, const char* dest)
{
	FILE *f = fopen(src, "r");
	if(!f)
	{
		gui_print("Failed to open initrd\n");
		return -1;
	}

	char m[4];
	if(fread(m, 1, sizeof(m), f) != sizeof(m))
	{
		gui_print("Failed to read initrd magic\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	char cmd[256];
	// gzip
	if(*((uint16_t*)m) == 0x8B1F)
	{
		gui_print("Ramdisk uses GZIP compression\n");
		sprintf(cmd, "cd \"%s\" && gzip -d -c \"%s\" | cpio -i", dest, src);
		system(cmd);
		return CMPR_GZIP;
	}
	// lz4
	else if(*((uint32_t*)m) == 0x184C2102)
	{
		gui_print("Ramdisk uses LZ4 compression\n");
		sprintf(cmd, "cd \"%s\" && lz4 -d \"%s\" stdout | cpio -i", dest, src);
		system(cmd);
		return CMPR_LZ4;
	}
	// lzma
	else if(*((uint32_t*)m) == 0x0000005D || *((uint32_t*)m) == 0x8000005D)
	{
		gui_print("Ramdisk uses LZMA compression\n");
		sprintf(cmd, "cd \"%s\" && lzma -d -c \"%s\" | cpio -i", dest, src);
		system(cmd);
		return CMPR_LZMA;
	}
	else
		gui_print("Unknown ramdisk compression (%X %X %X %X)\n", m[0], m[1], m[2], m[3]);

	return -1;
}

bool MultiROM::compressRamdisk(const char* src, const char* dst, int cmpr)
{
	char cmd[256];
	switch(cmpr)
	{
		case CMPR_GZIP:
			sprintf(cmd, "cd \"%s\" && find . | cpio -o -H newc | gzip > \"%s\"", src, dst);
			system(cmd);
			return true;
		case CMPR_LZ4:
			sprintf(cmd, "cd \"%s\" && find . | cpio -o -H newc | lz4 stdin \"%s\"", src, dst);
			system(cmd);
			return true;
		// FIXME: busybox can't compress with lzma
		case CMPR_LZMA:
			gui_print("Recovery can't compress ramdisk using LZMA!\n");
			return false;
//			sprintf(cmd, "cd \"%s\" && find . | cpio -o -H newc | lzma > \"%s\"", src, dst);
//			system(cmd);
//			return true;
		default:
			gui_print("Invalid compression type: %d", cmpr);
			return false;
	}
}

int MultiROM::copyBoot(std::string& orig, std::string rom)
{
	std::string img_path = getRomsPath() + "/" + rom + "/boot.img";
	char cmd[256];
	sprintf(cmd, "cp \"%s\" \"%s\"", orig.c_str(), img_path.c_str());
	if(system(cmd) != 0)
		return 1;

	orig.swap(img_path);
	return 0;
}

std::string MultiROM::getNewRomName(std::string zip, std::string def)
{
	std::string name = "ROM";
	if(def.empty())
	{
		size_t idx = zip.find_last_of("/");
		size_t idx_dot = zip.find_last_of(".");

		if(zip.substr(idx) == "/rootfs.img")
			name = "Ubuntu";
		else if(idx != std::string::npos)
		{
			// android backups
			if(DataManager::GetStrValue("tw_multirom_add_source") == "backup")
				name = "bckp_" + zip.substr(idx+1);
			// ZIP files
			else if(idx_dot != std::string::npos && idx_dot > idx)
				name = zip.substr(idx+1, idx_dot-idx-1);
		}
	}
	else
		name = def;

	if(name.size() > MAX_ROM_NAME)
		name.resize(MAX_ROM_NAME);

	DIR *d = opendir(getRomsPath().c_str());
	if(!d)
		return "";

	std::vector<std::string> roms;
	struct dirent *dr;
	while((dr = readdir(d)))
	{
		if(dr->d_name[0] == '.')
			continue;

		if(dr->d_type != DT_DIR && dr->d_type != DT_LNK)
			continue;

		roms.push_back(dr->d_name);
	}

	closedir(d);

	std::string res = name;
	char num[8] = { 0 };
	int c = 1;
	for(size_t i = 0; i < roms.size();)
	{
		if(roms[i] == res)
		{
			res = name;
			sprintf(num, "%d", c++);
			if(res.size() + strlen(num) > MAX_ROM_NAME)
				res.replace(res.size()-strlen(num), strlen(num), num);
			else
				res += num;
			i = 0;
		}
		else
			++i;
	}

	return res;
}

bool MultiROM::createImage(const std::string& base, const char *img, int size)
{
	gui_print("Creating %s.img...\n", img);

	if(size <= 0)
	{
		gui_print("Failed to create %s image: invalid size (%d)\n", img, size);
		return false;
	}

	char cmd[256];
	sprintf(cmd, "dd if=/dev/zero of=\"%s/%s.img\" bs=1M count=%d", base.c_str(), img, size);
	system(cmd);

	struct stat info;
	sprintf(cmd, "%s/%s.img", base.c_str(), img);
	if(stat(cmd, &info) < 0)
	{
		gui_print("Failed to create %s image, probably not enough space.\n", img);
		return false;
	}

	sprintf(cmd, "make_ext4fs -l %dM \"%s/%s.img\"", size, base.c_str(), img);
	system(cmd);
	return true;
}

bool MultiROM::createImagesFromBase(const std::string& base)
{
	for(baseFolders::const_iterator itr = m_base_folders.begin(); itr != m_base_folders.end(); ++itr)
		if(!createImage(base, itr->first.c_str(), itr->second.size))
			return false;

	return true;
}

bool MultiROM::createDirsFromBase(const string& base)
{
	for(baseFolders::const_iterator itr = m_base_folders.begin(); itr != m_base_folders.end(); ++itr)
	{
		if (mkdir((base + "/" + itr->first).c_str(), 0777) < 0)
		{
			gui_print("Failed to create folder %s/%s!\n", base.c_str(), itr->first.c_str());
			return false;
		}
	}
	return true;
}

bool MultiROM::createDirs(std::string name, int type)
{
	std::string base = getRomsPath() + "/" + name;
	if(mkdir(base.c_str(), 0777) < 0)
	{
		gui_print("Failed to create ROM folder!\n");
		return false;
	}

	gui_print("Creating folders and images for type %d\n", type);

	switch(type)
	{
		case ROM_ANDROID_INTERNAL:
		case ROM_ANDROID_USB_DIR:
			if (mkdir((base + "/boot").c_str(), 0777) < 0 ||
				mkdir((base + "/system").c_str(), 0755) < 0 ||
				mkdir((base + "/data").c_str(), 0771) < 0 ||
				mkdir((base + "/cache").c_str(), 0770) < 0)
			{
				gui_print("Failed to create android folders!\n");
				return false;
			}
			break;
		case ROM_UTOUCH_INTERNAL:
		case ROM_UTOUCH_USB_DIR:
			if (mkdir((base + "/system").c_str(), 0755) < 0 ||
				mkdir((base + "/data").c_str(), 0771) < 0 ||
				mkdir((base + "/cache").c_str(), 0770) < 0)
			{
				gui_print("Failed to create ubuntu touch folders!\n");
				return false;
			}
			break;
		case ROM_ANDROID_USB_IMG:
			if (mkdir((base + "/boot").c_str(), 0777) < 0)
			{
				gui_print("Failed to create android folders!\n");
				return false;
			}

			if(!createImagesFromBase(base))
				return false;
			break;
		case ROM_UBUNTU_INTERNAL:
		case ROM_UBUNTU_USB_DIR:
		case ROM_INSTALLER_INTERNAL:
		case ROM_INSTALLER_USB_DIR:
			if(!createDirsFromBase(base))
				return false;
			break;
		case ROM_UBUNTU_USB_IMG:
		case ROM_INSTALLER_USB_IMG:
		case ROM_UTOUCH_USB_IMG:
			if(!createImagesFromBase(base))
				return false;
			break;
		default:
			gui_print("Unknown ROM type %d!\n", type);
			return false;

	}
	return true;
}

bool MultiROM::extractBootForROM(std::string base)
{
	char cmd[256];

	gui_print("Extracting contents of boot.img...\n");
	system_args("rm -r \"%s/boot/\"*", base.c_str());
	system_args("unpackbootimg -i \"%s/boot.img\" -o \"%s/boot/\"", base.c_str(), base.c_str());

	sprintf(cmd, "%s/boot/boot.img-zImage", base.c_str());
	if(access(cmd, F_OK) < 0)
	{
		gui_print("Failed to unpack boot.img!\n");
		return false;
	}

	static const char *keep[] = { "zImage", "ramdisk.gz", "cmdline", NULL };
	for(int i = 0; keep[i]; ++i)
		system_args("mv \"%s/boot/boot.img-%s\" \"%s/boot/%s\"", base.c_str(), keep[i], base.c_str(), keep[i]);

	system_args("rm \"%s/boot/boot.img-\"*", base.c_str());

	system("rm -r /tmp/boot");
	system("mkdir /tmp/boot");

	sprintf(cmd, "%s/boot/ramdisk.gz", base.c_str());
	int rd_cmpr = decompressRamdisk(cmd, "/tmp/boot");
	if(rd_cmpr == -1 || access("/tmp/boot/init", F_OK) < 0)
	{
		gui_print("Failed to extract ramdisk!\n");
		return false;
	}

	// copy needed files
	static const char *cp_f[] = {
		"*.rc", "default.prop", "init", "main_init",
		// Since Android 4.3 - for SELinux
		"file_contexts", "property_contexts", "seapp_contexts", "sepolicy",
		NULL
	};
	for(int i = 0; cp_f[i]; ++i)
		system_args("cp -a /tmp/boot/%s \"%s/boot/\"", cp_f[i], base.c_str());

	// check if main_init exists
	sprintf(cmd, "%s/boot/main_init", base.c_str());
	if(access(cmd, F_OK) < 0)
		system_args("mv \"%s/boot/init\" \"%s/boot/main_init\"", base.c_str(), base.c_str());

	system("rm -r /tmp/boot");
	system_args("cd \"%s/boot\" && rm cmdline ramdisk.gz zImage", base.c_str());

	if (DataManager::GetIntValue("tw_multirom_share_kernel") == 0)
	{
		gui_print("Injecting boot.img..\n");
		if(!injectBoot(base + "/boot.img") != 0)
			return false;
	}
	else
		system_args("rm \"%s/boot.img\"", base.c_str());
	return true;
}

bool MultiROM::ubuntuExtractImage(std::string name, std::string img_path, std::string dest)
{
	char cmd[256];
	struct stat info;

	if(img_path.find("img.gz") != std::string::npos)
	{
		gui_print("Decompressing the image (may take a while)...\n");
		sprintf(cmd, "gzip -d \"%s\"", img_path.c_str());
		system(cmd);

		img_path.erase(img_path.size()-3);
		if(stat(img_path.c_str(), &info) < 0)
		{
			gui_print("Failed to decompress the image, more space needed?");
			return false;
		}
	}

	system("mkdir /mnt_ub_img");
	system("umount -d /mnt_ub_img");

	gui_print("Converting the image (may take a while)...\n");
	sprintf(cmd, "simg2img \"%s\" /tmp/rootfs.img", img_path.c_str());
	system(cmd);

	system("mount /tmp/rootfs.img /mnt_ub_img");

	if(stat("/mnt_ub_img/rootfs.tar.gz", &info) < 0)
	{
		system("umount -d /mnt_ub_img");
		system("rm /tmp/rootfs.img");
		gui_print("Invalid Ubuntu image (rootfs.tar.gz not found)!\n");
		return false;
	}

	gui_print("Extracting rootfs.tar.gz (will take a while)...\n");
	sprintf(cmd, "zcat /mnt_ub_img/rootfs.tar.gz | gnutar x --numeric-owner -C \"%s\"",  dest.c_str());
	system(cmd);

	sync();

	system("umount -d /mnt_ub_img");
	system("rm /tmp/rootfs.img");

	sprintf(cmd, "%s/boot/vmlinuz", dest.c_str());
	if(stat(cmd, &info) < 0)
	{
		gui_print("Failed to extract rootfs!\n");
		return false;
	}
	return true;
}

bool MultiROM::patchUbuntuInit(std::string rootDir)
{
	gui_print("Patching ubuntu init...\n");

	std::string initPath = rootDir + "/usr/share/initramfs-tools/";
	std::string locPath = rootDir + "/usr/share/initramfs-tools/scripts/";

	struct stat info;
	if(stat(initPath.c_str(), &info) < 0 || stat(locPath.c_str(), &info) < 0)
	{
		gui_print("init paths do not exits\n");
		return false;
	}

	char cmd[512];
	sprintf(cmd, "cp -a \"%s/ubuntu-init/init\" \"%s\"", m_path.c_str(), initPath.c_str());
	system(cmd);
	sprintf(cmd, "cp -a \"%s/ubuntu-init/local\" \"%s\"", m_path.c_str(), locPath.c_str());
	system(cmd);

	sprintf(cmd, "echo \"none	 /proc 	proc 	nodev,noexec,nosuid 	0 	0\" > \"%s/etc/fstab\"", rootDir.c_str());
	system(cmd);
	return true;
}

void MultiROM::setUpChroot(bool start, std::string rootDir)
{
	char cmd[512];
	static const char *dirs[] = { "dev", "sys", "proc" };
	for(size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i)
	{
		if(start)
			sprintf(cmd, "mount -o bind /%s \"%s/%s\"", dirs[i], rootDir.c_str(), dirs[i]);
		else
			sprintf(cmd, "umount \"%s/%s\"", rootDir.c_str(), dirs[i]);
		system(cmd);
	}
}

bool MultiROM::ubuntuUpdateInitramfs(std::string rootDir)
{
	gui_print("Removing tarball installer...\n");

	setUpChroot(true, rootDir);

	char cmd[512];

	sprintf(cmd, "chroot \"%s\" apt-get -y --force-yes purge ac100-tarball-installer flash-kernel", rootDir.c_str());
	system(cmd);

	ubuntuDisableFlashKernel(false, rootDir);

	gui_print("Updating initramfs...\n");
	sprintf(cmd, "chroot \"%s\" update-initramfs -u", rootDir.c_str());
	system(cmd);

	// make proper link to initrd.img
	sprintf(cmd, "chroot \"%s\" bash -c 'cd /boot; ln -sf $(ls initrd.img-* | head -n1) initrd.img'", rootDir.c_str());
	system(cmd);

	setUpChroot(false, rootDir);
	return true;
}

void MultiROM::ubuntuDisableFlashKernel(bool initChroot, std::string rootDir)
{
	gui_print("Disabling flash-kernel\n");
	char cmd[512];
	if(initChroot)
	{
		setUpChroot(true, rootDir);
		sprintf(cmd, "chroot \"%s\" apt-get -y --force-yes purge flash-kernel", rootDir.c_str());
		system(cmd);
	}

	// We don't want flash-kernel to be active, ever.
	sprintf(cmd, "chroot \"%s\" bash -c \"echo flash-kernel hold | dpkg --set-selections\"", rootDir.c_str());
	system(cmd);

	sprintf(cmd, "if [ \"$(grep FLASH_KERNEL_SKIP '%s/etc/environment')\" == \"\" ]; then "
			"chroot \"%s\" bash -c \"echo FLASH_KERNEL_SKIP=1 >> /etc/environment\"; fi;",
			rootDir.c_str(), rootDir.c_str());
	system(cmd);

	if(initChroot)
		setUpChroot(false, rootDir);
}

bool MultiROM::disableFlashKernelAct(std::string name, std::string loc)
{
	int type = getType(2, loc);
	std::string dest = getRomsPath() + "/" + name + "/root";
	if(type == ROM_UBUNTU_USB_IMG && !mountUbuntuImage(name, dest))
		return false;

	ubuntuDisableFlashKernel(true, dest);

	sync();

	if(type == ROM_UBUNTU_USB_IMG)
		umount(dest.c_str());
	return true;
}

int MultiROM::getType(int os, std::string loc)
{
	bool ext = loc.find("(ext") != std::string::npos;
	switch(os)
	{
		case 1: // android
			if(loc == INTERNAL_MEM_LOC_TXT)
				return ROM_ANDROID_INTERNAL;
			else if(ext)
				return ROM_ANDROID_USB_DIR;
			else
				return ROM_ANDROID_USB_IMG;
			break;
		case 2: // ubuntu
			if(loc == INTERNAL_MEM_LOC_TXT)
				return ROM_UBUNTU_INTERNAL;
			else if(ext)
				return ROM_UBUNTU_USB_DIR;
			else
				return ROM_UBUNTU_USB_IMG;
			break;
		case 3: // installer
			return m_installer->getRomType();
		case 4:
			if(loc == INTERNAL_MEM_LOC_TXT)
				return ROM_UTOUCH_INTERNAL;
			else if(ext)
				return ROM_UTOUCH_USB_DIR;
			else
				return ROM_UTOUCH_USB_IMG;
			break;
	}
	return ROM_UNKNOWN;
}

bool MultiROM::mountUbuntuImage(std::string name, std::string& dest)
{
	mkdir("/mnt_ubuntu", 0777);

	char cmd[256];
	sprintf(cmd, "mount -o loop %s/%s/root.img /mnt_ubuntu", getRomsPath().c_str(), name.c_str());

	if(system(cmd) != 0)
	{
		gui_print("Failed to mount ubuntu image!\n");
		return false;
	}
	dest = "/mnt_ubuntu";
	return true;
}

bool MultiROM::addROM(std::string zip, int os, std::string loc)
{
	MultiROM::setRomsPath(loc);

	std::string name;
	if(m_installer)
		name = m_installer->getValue("rom_name", name);

	name = getNewRomName(zip, name);
	if(name.empty())
	{
		gui_print("Failed to fixup ROMs name!\n");
		return false;
	}
	gui_print("Installing ROM %s...\n", name.c_str());

	int type = getType(os, loc);

	if((M(type) & MASK_INSTALLER) && !m_installer->checkFreeSpace(getRomsPath(), type == ROM_INSTALLER_USB_IMG))
		return false;

	if(!createDirs(name, type))
		return false;

	std::string root = getRomsPath() + "/" + name;
	bool res = false;
	switch(type)
	{
		case ROM_ANDROID_INTERNAL:
		case ROM_ANDROID_USB_DIR:
		case ROM_ANDROID_USB_IMG:
		{
			std::string src = DataManager::GetStrValue("tw_multirom_add_source");
			if(src == "zip")
			{
				if(!flashZip(name, zip))
					break;

				if(!extractBootForROM(root))
					break;
			}
			else if(src == "backup")
			{
				if(!installFromBackup(name, zip, type))
					break;
			}
			else
			{
				gui_print("Wrong source: %s\n", src.c_str());
				break;
			}
			res = true;
			break;
		}
		case ROM_UBUNTU_INTERNAL:
		case ROM_UBUNTU_USB_DIR:
		case ROM_UBUNTU_USB_IMG:
		{
			std::string dest = root + "/root";
			if(type == ROM_UBUNTU_USB_IMG && !mountUbuntuImage(name, dest))
				break;

			if (ubuntuExtractImage(name, zip, dest) &&
				patchUbuntuInit(dest) && ubuntuUpdateInitramfs(dest))
				res = true;

			char cmd[512];
			sprintf(cmd, "touch %s/var/lib/oem-config/run", dest.c_str());
			system(cmd);

			sprintf(cmd, "cp \"%s/infos/ubuntu.txt\" \"%s/%s/rom_info.txt\"",
					m_path.c_str(), getRomsPath().c_str(), name.c_str());
			system(cmd);

			if(type == ROM_UBUNTU_USB_IMG)
				umount(dest.c_str());
			break;
		}
		case ROM_INSTALLER_INTERNAL:
		case ROM_INSTALLER_USB_DIR:
		case ROM_INSTALLER_USB_IMG:
		{
			std::string text = m_installer->getValue("install_text");
			if(!text.empty())
			{
				size_t start_pos = 0;
				while((start_pos = text.find("\\n", start_pos)) != std::string::npos) {
					text.replace(start_pos, 2, "\n");
					++start_pos;
				}

				gui_print("  \n");
				gui_print(text.c_str());
				gui_print("  \n");
			}

			std::string base = root;
			if(type == ROM_INSTALLER_USB_IMG && !mountBaseImages(root, base))
				break;

			res = true;

			if(res && !m_installer->runScripts("pre_install", base, root))
				res = false;

			if(res && !m_installer->extractDir("root_dir", root))
				res = false;

			if(res && !m_installer->extractTarballs(base))
				res = false;

			if(res && !m_installer->runScripts("post_install", base, root))
				res = false;

			if(type == ROM_INSTALLER_USB_IMG)
				 umountBaseImages(base);
			break;
		}
		case ROM_UTOUCH_INTERNAL:
		case ROM_UTOUCH_USB_DIR:
		case ROM_UTOUCH_USB_IMG:
		{
			std::string device_zip = DataManager::GetStrValue("tw_touch_filename_device");
			std::string core_zip = DataManager::GetStrValue("tw_touch_filename_core");

			gui_print("  \n");
			gui_print("Flashing device zip...\n");
			if(!flashZip(name, device_zip))
				break;

			gui_print("  \n");
			gui_print("Flashing core zip...\n");

			system("ln -sf /sbin/gnutar /sbin/tar");
			bool flash_res = flashZip(name, core_zip);
			system("ln -sf /sbin/busybox /sbin/tar");
			if(!flash_res)
				break;

			if(!ubuntuTouchProcessBoot(root))
				break;

			if(!ubuntuTouchProcess(root, name))
				break;

			res = true;
			break;
		}
	}

	if(!res)
	{
		gui_print("Erasing incomplete ROM...\n");
		std::string cmd = "rm -rf \"" + root + "\"";
		system(cmd.c_str());
	}

	sync();

	MultiROM::setRomsPath(INTERNAL_MEM_LOC_TXT);

	delete m_installer;
	m_installer = NULL;

	DataManager::SetValue("tw_multirom_add_source", "");

	return res;
}

bool MultiROM::patchInit(std::string name)
{
	gui_print("Patching init for rom %s...\n", name.c_str());
	int type = getType(name);
	if(!(M(type) & MASK_UBUNTU))
	{
		gui_print("This is not ubuntu ROM. (%d)\n", type);
		return false;
	}
	std::string dest;
	switch(type)
	{
		case ROM_UBUNTU_INTERNAL:
		case ROM_UBUNTU_USB_DIR:
			dest = getRomsPath() + name + "/root/";
			break;
		case ROM_UBUNTU_USB_IMG:
		{
			mkdir("/mnt_ubuntu", 0777);

			char cmd[256];
			sprintf(cmd, "mount -o loop %s/%s/root.img /mnt_ubuntu", getRomsPath().c_str(), name.c_str());

			if(system(cmd) != 0)
			{
				gui_print("Failed to mount ubuntu image!\n");
				return false;
			}
			dest = "/mnt_ubuntu/";
			break;
		}
	}

	bool res = false;
	if(patchUbuntuInit(dest) && ubuntuUpdateInitramfs(dest))
		res = true;

	sync();

	if(type == ROM_UBUNTU_USB_IMG)
		system("umount -d /mnt_ubuntu");;
	return res;
}

bool MultiROM::installFromBackup(std::string name, std::string path, int type)
{
	struct stat info;
	char cmd[256];
	std::string base = getRomsPath() + "/" + name;
	int has_system = 0, has_data = 0;

	if(stat((path + "/boot.emmc.win").c_str(), &info) < 0)
	{
		gui_print("Backup must contain boot image!\n");
		return false;
	}

	DIR *d = opendir(path.c_str());
	if(!d)
	{
		gui_print("Failed to list backup folder\n");
		return false;
	}

	struct dirent *dr;
	while((!has_system || !has_data) && (dr = readdir(d)))
	{
		if(strstr(dr->d_name, "system.ext4"))
			has_system = 1;
		else if(strstr(dr->d_name, "data.ext4"))
			has_data = 1;
	}
	closedir(d);

	if(!has_system)
	{
		gui_print("Backup must contain system image!\n");
		return false;
	}

	sprintf(cmd, "cp \"%s/boot.emmc.win\" \"%s/boot.img\"", path.c_str(), base.c_str());
	system(cmd);

	if(!extractBootForROM(base))
		return false;

	gui_print("Changing mountpoints\n");
	if(!changeMounts(name))
	{
		gui_print("Failed to change mountpoints!\n");
		return false;
	}

	// real /data is mounted to /realdata
	if(path.find("/data/media") == 0)
		path.replace(0, 5, REALDATA);

	bool res = (extractBackupFile(path, "system") && (!has_data || extractBackupFile(path, "data")));
	restoreMounts();
	return res;
}

bool MultiROM::extractBackupFile(std::string path, std::string part)
{
	gui_print("Extracting backup of %s partition...\n", part.c_str());

	struct stat info;
	std::string filename = part + ".ext4.win";
	std::string full_path =  path + "/" + filename;
	int index = 0;
	char split_index[5];
	char cmd[256];

	if (stat(full_path.c_str(), &info) < 0) // multiple archives
	{
		sprintf(split_index, "%03i", index);
		full_path = path + "/" + filename + split_index;
		while (stat(full_path.c_str(), &info) >= 0)
		{
			gui_print("Restoring archive #%i...\n", ++index);

			sprintf(cmd, "cd / && gnutar -xf \"%s\"", full_path.c_str());
			LOGI("Restore cmd: %s\n", cmd);
			system(cmd);

			sprintf(split_index, "%03i", index);
			full_path = path + "/" + filename + split_index;
		}

		if (index == 0)
		{
			gui_print("Failed to locate backup file %s\n", full_path.c_str());
			return false;
		}
	}
	else
	{
		sprintf(cmd, "cd /%s && gnutar -xf \"%s\"", part.c_str(), full_path.c_str());
		LOGI("Restore cmd: %s\n", cmd);
		system(cmd);
	}
	return true;
}

void MultiROM::setInstaller(MROMInstaller *i)
{
	m_installer = i;
}

MROMInstaller *MultiROM::getInstaller(MROMInstaller *i)
{
	return m_installer;
}

void MultiROM::clearBaseFolders()
{
	m_base_folder_cnt = 0;
	m_base_folders.clear();

	char name[32];
	for(int i = 1; i <= MAX_BASE_FOLDER_CNT; ++i)
	{
		sprintf(name, "tw_mrom_image%d", i);
		DataManager::SetValue(name, "");
		DataManager::SetValue(std::string(name) + "_size", 0);
	}
}

void MultiROM::updateImageVariables()
{
	char name[32];
	int i = 1;
	for(baseFolders::const_iterator itr = m_base_folders.begin(); itr != m_base_folders.end(); ++itr)
	{
		sprintf(name, "tw_mrom_image%d", i++);
		DataManager::SetValue(name, itr->first);
		DataManager::SetValue(std::string(name) + "_size", itr->second.size);
	}
}

const base_folder& MultiROM::addBaseFolder(const std::string& name, int min, int def)
{
	base_folder b(name, min, def);
	return addBaseFolder(b);
}

const base_folder& MultiROM::addBaseFolder(const base_folder& b)
{
	LOGI("MROMInstaller: base folder: %s (min: %dMB def: %dMB)\n", b.name.c_str(), b.min_size, b.size);
	return m_base_folders.insert(std::make_pair<std::string, base_folder>(b.name, b)).first->second;
}

MultiROM::baseFolders& MultiROM::getBaseFolders()
{
	return m_base_folders;
}

base_folder *MultiROM::getBaseFolder(const std::string& name)
{
	baseFolders::iterator itr = m_base_folders.find(name);
	if(itr == m_base_folders.end())
		return NULL;
	return &itr->second;
}

bool MultiROM::mountBaseImages(std::string base, std::string& dest)
{
	mkdir("/mnt_installer", 0777);

	char cmd[256];

	for(baseFolders::const_iterator itr = m_base_folders.begin(); itr != m_base_folders.end(); ++itr)
	{
		sprintf(cmd, "/mnt_installer/%s", itr->first.c_str());
		mkdir(cmd, 0777);

		sprintf(cmd, "mount -o loop %s/%s.img /mnt_installer/%s", base.c_str(), itr->first.c_str(), itr->first.c_str());
		if(system(cmd) != 0)
		{
			gui_print("Failed to mount image %s image!\n", itr->first.c_str());
			return false;
		}
	}
	dest = "/mnt_installer";
	return true;
}

void MultiROM::umountBaseImages(const std::string& base)
{
	sync();

	char cmd[256];
	for(baseFolders::const_iterator itr = m_base_folders.begin(); itr != m_base_folders.end(); ++itr)
	{
		sprintf(cmd, "umount -d %s/%s", base.c_str(), itr->first.c_str());
		system(cmd);

		sprintf(cmd, "%s/%s", base.c_str(), itr->first.c_str());
		rmdir(cmd);
	}
	rmdir(base.c_str());
}

bool MultiROM::ubuntuTouchProcessBoot(const std::string& root)
{
	int rd_cmpr;

	gui_print("Processing boot.img for Ubuntu Touch\n");
	system("rm /tmp/boot.img");
	system_args("mv %s/boot.img /tmp/boot.img", root.c_str());

	if(access("/tmp/boot.img", F_OK) < 0)
	{
		gui_print("boot.img was not found!\b");
		return false;
	}

	// EXTRACT BOOTIMG
	gui_print("Extracting boot image...\n");
	system("rm -r /tmp/boot; mkdir /tmp/boot");
	system("unpackbootimg -i /tmp/boot.img -o /tmp/boot/");
	if(access("/tmp/boot/boot.img-zImage", F_OK) < 0)
	{
		gui_print("Failed to unpack boot img!\n");
		goto fail_inject;
	}

	// DECOMPRESS RAMDISK
	gui_print("Decompressing ramdisk...\n");
	system("mkdir /tmp/boot/rd");
	rd_cmpr = decompressRamdisk("/tmp/boot/boot.img-ramdisk.gz", "/tmp/boot/rd/");
	if(rd_cmpr == -1 || access("/tmp/boot/rd/init", F_OK) < 0)
	{
		gui_print("Failed to decompress ramdisk!\n");
		goto fail_inject;
	}

	// COPY INIT FILES
	system_args("cp -ra %s/ubuntu-touch-init/* /tmp/boot/rd/", m_path.c_str());

	// COMPRESS RAMDISK
	gui_print("Compressing ramdisk...\n");
	if(!compressRamdisk("/tmp/boot/rd", "/tmp/boot/boot.img-ramdisk.gz", rd_cmpr))
		return false;

	// DEPLOY
	system_args("cp /tmp/boot/boot.img-ramdisk.gz %s/initrd.img", root.c_str());
	system_args("cp /tmp/boot/boot.img-zImage %s/zImage", root.c_str());

	system("rm /tmp/boot.img");
	system("rm -r /tmp/boot");
	return true;

fail_inject:
	system("rm /tmp/boot.img");
	system("rm -r /tmp/boot");
	return false;
}

bool MultiROM::ubuntuTouchProcess(const std::string& root, const std::string& name)
{
	// rom_info.txt
	system_args("cp %s/infos/ubuntu_touch.txt %s/rom_info.txt", m_path.c_str(), root.c_str());

	gui_print("Changing mountpoints\n");
	if(!changeMounts(name))
	{
		gui_print("Failed to change mountpoints\n");
		return false;
	}

	// fstab
	system("mkdir -p /data/ubuntu/systemorig");
	system("echo \"/dev/mmcblk0p3\t/systemorig\text4\tro\t0\t0\" >> /data/ubuntu/etc/fstab");
	system("echo \"/system/vendor\t/vendor\tauto\tro,bind\t0\t0\" >> /data/ubuntu/etc/fstab");

	// change the way android lxc is initiated
	system("echo -e \""
		"if [ \\\"\\$INITRD\\\" = \\\"/boot/android-ramdisk.img\\\" ]; then\\n"
		"    sed -i \\\"/mount_all /d\\\" \\$LXC_ROOTFS_PATH/init.*.rc\\n"
		"    sed -i \\\"/on nonencrypted/d\\\" \\$LXC_ROOTFS_PATH/init.rc\\n"
		"    folders=\\\"data system cache\\\"\\n"
		"    for dir in \\$folders; do\\n"
		"        mkdir -p \\$LXC_ROOTFS_PATH/\\$dir\\n"
		"        mount -n -o bind,recurse /mrom_dir/\\$dir \\$LXC_ROOTFS_PATH/\\$dir\\n"
		"    done\\n"
		"fi\\n"
		"\" >> /data/ubuntu/var/lib/lxc/android/pre-start.sh");

	gui_print("Restoring mounts\n");
	restoreMounts();
	return true;
}

int MultiROM::system_args(const char *fmt, ...)
{
	char cmd[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);

	return system(cmd);
}

bool MultiROM::fakeBootPartition(const char *fakeImg)
{
	if(access(BOOT_DEV"-orig", F_OK) >= 0)
	{
		gui_print("Failed to fake boot partition, "BOOT_DEV"-orig already exists!\n");
		return false;
	}

	if(access(fakeImg, F_OK) < 0)
	{
		int fd = creat(fakeImg, 0644);
		if(fd < 0)
		{
			gui_print("Failed to create fake boot image file %s (%s)!\n", fakeImg, strerror(errno));
			return false;
		}
		close(fd);

		// Copy current boot.img as base
		system_args("dd if="BOOT_DEV" of=\"%s\"", fakeImg);
		gui_print("Current boot sector was used as base for fake boot.img!\n");
	}

	system("mv "BOOT_DEV" "BOOT_DEV"-orig");
	system_args("ln -s \"%s\" "BOOT_DEV, fakeImg);
	return true;
}

void MultiROM::restoreBootPartition()
{
	if(access(BOOT_DEV"-orig", F_OK) < 0)
	{
		gui_print("Failed to restore boot partition, "BOOT_DEV"-orig does not exist!\n");
		return;
	}

	system("rm "BOOT_DEV);
	system("mv "BOOT_DEV"-orig "BOOT_DEV);
}

bool MultiROM::calculateMD5(const char *path, unsigned char *md5sum/*len: 16*/)
{
	FILE *f = fopen(path, "rb");
	if(!f)
	{
		gui_print("Failed to open file %s to calculate MD5 sum!\n", path);
		return false;
	}

	struct MD5Context md5c;
	int len;
	unsigned char buff[1024];

	MD5Init(&md5c);
	while((len = fread(buff, 1, sizeof(buff), f)) > 0)
		MD5Update(&md5c, buff, len);

	MD5Final(md5sum ,&md5c);
	fclose(f);
	return true;
}

bool MultiROM::compareFiles(const char *path1, const char *path2)
{
	unsigned char md5sum1[MD5LENGTH];
	unsigned char md5sum2[MD5LENGTH];

	if(!calculateMD5(path1, md5sum1) || !calculateMD5(path2, md5sum2))
		return false;

	int i;
	for(i = 0; i < MD5LENGTH; ++i)
		if(md5sum1[i] != md5sum2[i])
			return false;

	return true;
}
