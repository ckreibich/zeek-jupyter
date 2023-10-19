module Jupyter;

export {
	const log_archive_dir = Installation::log_dir &redef;
}

# Rotate logs every 10 minutes into a subdirectory in the spool.
# zeek-archiver will pick up logs from there.
redef Log::default_rotation_interval = 10 mins;
redef Log::default_rotation_dir = fmt("%s/%s", Installation::spool_dir, "logs");

# Log in JSON by default.
redef LogAscii::use_json = T;

# Ignore checksums by default since we'll be capturing local packets a lot.
redef ignore_checksums = T;

# A rotation file formatter compatible with zeek-archiver.
function archiver_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath {
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$close);
	local base = fmt("%s__%s__%s__", ri$path, open_str, close_str);
	local rval = Log::RotationPath($file_basename=base);
	return rval;
}

redef Log::rotation_format_func = archiver_rotation_format_func;

# We kick off zeek-archiver manually within Zeek instead of putting in place a
# system-level config for it.
event log_archival() {
	local cmd = fmt("zeek-archiver -1 %s %s", 
	    Log::default_rotation_dir,
	    log_archive_dir);

	system(cmd);
	schedule Log::default_rotation_interval { log_archival() };
}

event zeek_init() {
	schedule Log::default_rotation_interval { log_archival() };
}
