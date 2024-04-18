#include "extension/extension.h"
#include "path/path.h"           /* translate_path,  */
#include "path/temp.h"           /* create_temp_file,  */
#include <limits.h>              /* INT_MAX,  */
#include <linux/limits.h>        /* PATH_MAX,  */
#include <string.h>              /* strlen, strcmp */

static void mountinfo_check_open_path(Tracee *tracee, char path[PATH_MAX]) {
	/* Try matching "/proc/<PID>/mountinfo"  */
	size_t len = strlen(path);
	if (
			len > (6 + 10) &&
			0 == strncmp(path, "/proc/", 6) &&
			0 == strcmp(path + (len - 10), "/mountinfo")
	   ) {
		/* Check if current root is under /data and if so replace contents
		 * of /proc/<PID>/mountinfo to make it contain /data as / mountpoint.
		 * This is needed because on Android / is read only mount
		 *
		 * https://github.com/termux/proot/issues/294
		 */
		char *path_end = NULL;
		long target_pid = strtol(path + 6, &path_end, 10);
		if (path_end != path + (len - 10) || target_pid <= 0 || target_pid > INT_MAX) {
			return;
		}
		Tracee *target_tracee = get_tracee(tracee, target_pid, false);
		if (target_tracee == NULL) {
			return;
		}

		/* Check if our root is under "/data"  */
		char root_path[PATH_MAX]; // Host path to guest root
		translate_path(target_tracee, root_path, AT_FDCWD, "/", true);
		Comparison compare_result = compare_paths(root_path, "/data");
		if (compare_result != PATH2_IS_PREFIX && compare_result != PATHS_ARE_EQUAL) {
			return;
		}

		/* Open real /proc/<PID>/mountinfo  */
		FILE *real_mountinfo_fp = fopen(path, "r");
		if (real_mountinfo_fp == NULL) {
			return;
		}

		/* Prepare faked mountinfo  */
		const char *new_path = create_temp_file(tracee->ctx, "mountinfo");
		FILE *new_mountinfo_fp = fopen(new_path, "w");
		if (new_mountinfo_fp == NULL) {
			fclose(real_mountinfo_fp);
			return;
		}

		char *line = NULL;
		size_t line_buf_len = 0;
		ssize_t line_len = 0;
		bool found_line = false;
		while ((line_len = getline(&line, &line_buf_len, real_mountinfo_fp)) > 0) {
			char *chunk = line;
			/* Skip columns before 'root'  */
			for (int i = 0; i < 4 && chunk - line < line_len; i++) {
				chunk = strchr(chunk, ' ');
				if (chunk == NULL) goto end_line_scan;
				chunk++;
			}

			/* Match path  */
			char *chunk_end = strchr(chunk, ' ');
			if (chunk_end == NULL) continue;

			if (chunk_end - chunk == 5 && 0 == memcmp(chunk, "/data", 5)) {
				/* Write line into new file keeping only "/" from root column  */
				fwrite(line, chunk - line + 1, 1, new_mountinfo_fp);
				fwrite(chunk_end, line_len - (chunk_end - line), 1, new_mountinfo_fp);
				found_line = true;
				break;
			}
end_line_scan: ;
		}

		/* Once root was added, rescan and add other standard mounts  */
		if (found_line) {
			fseek(real_mountinfo_fp, 0, SEEK_SET);
			while ((line_len = getline(&line, &line_buf_len, real_mountinfo_fp)) > 0) {
				char *chunk = line;
				/* Skip columns before 'root'  */
				for (int i = 0; i < 4 && chunk - line < line_len; i++) {
					chunk = strchr(chunk, ' ');
					if (chunk == NULL) goto end_line_scan2;
					chunk++;
				}

				/* Match path  */
				char *chunk_end = strchr(chunk, ' ');
				if (chunk_end == NULL) continue;

				size_t mount_len = chunk_end - chunk;
				if (
						(mount_len == 4 && 0 == memcmp(chunk, "/dev", 4)) ||
						(mount_len >= 5 && 0 == memcmp(chunk, "/dev/", 5)) ||
						(mount_len == 5 && 0 == memcmp(chunk, "/proc", 5)) ||
						(mount_len == 4 && 0 == memcmp(chunk, "/sys", 4)) ||
						(mount_len >= 5 && 0 == memcmp(chunk, "/sys/", 5)) ||
						(mount_len == 4 && 0 == memcmp(chunk, "/tmp", 4))
						) {
					/* Copy line into new file verbatim  */
					fwrite(line, line_len, 1, new_mountinfo_fp);
				}
end_line_scan2: ;
			}
		}

		free(line);
		fclose(new_mountinfo_fp);
		fclose(real_mountinfo_fp);

		/* Redirect open to our temp file  */
		if (found_line) {
			strncpy(path, new_path, PATH_MAX);
		}
		return;
	}

}

int mountinfo_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case TRANSLATED_PATH:
	{
		Tracee *tracee = TRACEE(extension);
		Sysnum num = get_sysnum(tracee, ORIGINAL);
		if (num == PR_open || num == PR_openat) {
			mountinfo_check_open_path(tracee, (char*) data1);
		}
        return 0;
	}

    default:
        return 0;
    }
}
