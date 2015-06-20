local ffi = require("ffi")

ffi.cdef[[
typedef struct ssh_session_struct* ssh_session;
typedef struct ssh_channel_struct* ssh_channel;
typedef struct ssh_scp_struct* ssh_scp;

ssh_session ssh_new(void);
void ssh_free (ssh_session session);
int ssh_connect (ssh_session session);
void ssh_disconnect (ssh_session session);
int ssh_userauth_password (ssh_session session, const char *username, const char *password);
int ssh_options_set(ssh_session session, int type, const void* value);

ssh_channel ssh_channel_new(ssh_session session);
int ssh_channel_open_session(ssh_channel channel);
int ssh_channel_close(ssh_channel channel);
void ssh_channel_free(ssh_channel channel);
int ssh_channel_request_exec (ssh_channel channel, const char *	cmd);
int ssh_channel_read(ssh_channel channel, void *dest, uint32_t count, int is_stderr);
int ssh_channel_send_eof(ssh_channel channel);



ssh_scp ssh_scp_new(ssh_session session, int mode, const char *directory);
int ssh_scp_init(ssh_scp scp);
int ssh_scp_push_file(ssh_scp scp, const char *filename, size_t size, int mode); 
int ssh_scp_write(ssh_scp scp, const void *buffer, unsigned int len); 	
int ssh_scp_close(ssh_scp scp);
int ssh_scp_free(ssh_scp scp);

]]

local libssh = ffi.load("../bin/libssh.so")

local function ssh_new()
	local session = libssh.ssh_new()
	if session == nil then
		return nil, "Error creating session"
	end

	return session
end

local function ssh_options(session, option, value)
	if option == "host" then
		return libssh.ssh_options_set(session, 0, value) == 0
	elseif option == "port" then
		return libssh.ssh_options_set(session, 1, ffi.new("int[1]", value)) == 0
	elseif option == "user" then
		return libssh.ssh_options_set(session, 4, value) == 0
	elseif option == "timeout" then
		return libssh.ssh_options_set(session, 9, ffi.new("int[1]", value)) == 0
	end
end

local function ssh_connect(session, host, port, user)
	ssh_options(session, "host", host)
	ssh_options(session, "port", port)
	ssh_options(session, "user", user)
	ret = libssh.ssh_connect(session)
	print(ret)
end

local function ssh_disconnect(session)
	libssh.ssh_disconnect(session)
end

local function ssh_free(session)
	libssh.ssh_free(session)
end

local function ssh_password(session, password)
	libssh.ssh_userauth_password(session, nil, password)
end

local function ssh_execute(session, command)
	channel = libssh.ssh_channel_new(session)(session)
	if channel == nil then
		return nil, "Error creating channel"
	end
	if libssh.ssh_channel_open_session(channel) == 0 then
		return nil, "Error opening channel in session"
	end
	
	if libssh.ssh_channel_request_exec(channel, command) == 0 then
		return nil, "Error requesting execute"
	end
	
	local buffer = ffi.new("char[4096]", {})
	local length = libssh.ssh_channel_read(channel, buffer, 4096, 0);
	local ret = ""
	while length > 0 do
		local s = ffi.string(buffer, length)
		ret = ret .. ss	
		length = libssh.ssh_channel_read(channel, buffer, 4096, 0);
	end

	if length < 0 then
		libssh.ssh_channel_close(channel);
		libssh.ssh_channel_free(channel);
		return nil, "Error reading from channel"
	end
	
	libssh.ssh_channel_send_eof(channel)
	libssh.ssh_channel_close(channel)
	libssh.ssh_channel_free(channel)	

	return ret
end



test = ssh_new()
ssh_options(test, "timeout", 20)
ssh_connect(test, "10.5.11.164", 22, "root")
ssh_password(test, "root")

io.write(ssh_execute(test, "ps -A | grep Edge"))
io.write(ssh_execute(test, "cat /sys/class/gpio/gpio169/value"))
io.write(ssh_execute(test, "cat /sys/class/gpio/gpio169/value"))
io.write(ssh_execute(test, "cat /sys/class/gpio/gpio169/value"))
io.write(ssh_execute(test, "cat /sys/class/gpio/gpio169/value"))

ssh_disconnect(test)
ssh_free(test)

