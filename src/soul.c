#include <sys/types.h>

#include <arpa/inet.h>
#include <bsd/md5.h>
#include <err.h>
#include <linux/limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOST_NAME_MAX 255

#define CONFIG_PATH "/soul/soul.conf"
#define XDG_CONFIG_DEFAULT "/.config"

static int configfile_path(char *path)
{
	char *xdg_config_home = getenv("XDG_CONFIG_HOME");

	if (xdg_config_home) {
		strcat(path, xdg_config_home);
		strcat(path, CONFIG_PATH);

		if (access(path, R_OK) == 0)
			return 1;
	}

	path[0] = '\0';

	char *home = getenv("HOME");

	if (home) {
		strcat(path, home);
		strcat(path, XDG_CONFIG_DEFAULT);
		strcat(path, CONFIG_PATH);

		if (access(path, R_OK) == 0)
			return 1;
	}

	char *xdg_config_dirs = getenv("XDG_CONFIG_DIRS");

	if (!xdg_config_dirs) {
		xdg_config_dirs = "/etc/xdg";
	}

	char *dirs = strdup(xdg_config_dirs);
	char *bkp = NULL;
	char *dir = strtok_r(dirs, ":", &bkp);
	while (dir) {

		path[0] = '\0';
		strcat(path, dir);
		strcat(path, CONFIG_PATH);

		printf("test %s\n", path);
		if (access(path, R_OK) == 0) {
			free(dirs);
			return 1;
		}
		dir = strtok_r(NULL, ":", &bkp);
	}

	free(dirs);

	return 0;
}

struct options {
	char *user;
	char *password;
	char *location;
	char *data;
	char *server;
	char *port;
	char *srcaddr;
};

static int parse_config_file(const char *path, struct options *opt)
{
	FILE *file = fopen(path, "r");

	if (!file)
		return 0;

	char *line = NULL;
	size_t sz = 0;

	while (getline(&line, &sz, file) != -1) {

		int idx = strcspn(line, " \t\n=");

		if (idx == 0)
			continue;

		char *key = line;

		key[idx] = '\0';

		char *value = line + idx + 1 + strspn(line + idx + 1, " \t\n=");

		idx = strcspn(value, " \t\n=");
		value[idx] = '\0';

		if (!strcmp(key, "user")) {
			opt->user = strdup(value);
		} else if (!strcmp(key, "password")) {
			opt->password = strdup(value);
		} else if (!strcmp(key, "location")) {
			opt->location = strdup(value);
		} else if (!strcmp(key, "data")) {
			opt->data = strdup(value);
		} else if (!strcmp(key, "server")) {
			opt->server = strdup(value);
		} else if (!strcmp(key, "port")) {
			opt->port = strdup(value);
		} else if (!strcmp(key, "srcaddr")) {
			opt->srcaddr = strdup(value);
		} else {
			warnx("unknown value \"%s\" in config file %s\n", key, path);
		}

		free(line);
		line = NULL;
		sz = 0;
	}

	return 1;
}

static void clean_config(struct options *opts)
{
	strfry(opts->password);

	free(opts->data);
	free(opts->location);
	free(opts->password);
	free(opts->port);
	free(opts->server);
	free(opts->srcaddr);
	free(opts->user);
}

static int ns_auth(const char *input, char *challenge, struct options *opts)
{
	char *hash;
	char *host;
	unsigned long port;

	int rc = sscanf(input, "salut %*d %ms %ms %lu %*d\n", &hash, &host, &port);

	if (rc != 3) {
		free(hash);
		free(host);
		return 1;
	}

	char *c;

	asprintf(&c, "%s-%s/%lu%s", hash, host, port, opts->password);

	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, (u_int8_t *)c, strlen(c));
	MD5End(&ctx, challenge);

	free(c);
	free(hash);
	free(host);

	return 0;
}

static int ns_rep(const char *buf, char **message)
{
	unsigned code;

	if (message && (sscanf(buf, "rep %u -- %m[^\n]\n", &code, message) != 1)) {
		err(1, "protocol error");
	} else if (sscanf(buf, "rep %u -- %*[^\n]\n", &code) != 1) {
		err(1, "protocol error");
	}

	return code;
}

static int ns_read_rep(int fd, char *buf, size_t size)
{
	int rc;

	rc = read(fd, buf, size);
	buf[rc] = '\0';
	if (ns_rep(buf, NULL) != 2) {
		char *msg;
		unsigned code = ns_rep(buf, &msg);

		printf("error, rep : %u(%s)\n", code, msg);
		free(msg);
		return -1;
	}

	printf("OK\n");
	return 0;
}

int main(void)
{
	struct options opts = { 0 };

	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		.ai_socktype = SOCK_STREAM,
	};

	struct addrinfo *res;

	char cfg_path[PATH_MAX] = { 0 };

	if (!configfile_path(cfg_path)) {
		errx(1, "no config file found");
		return 1;
	}

	parse_config_file(cfg_path, &opts);

	int rc = getaddrinfo(opts.server, opts.port, &hints, &res);

	if (rc != 0) {
		err(1, "unable to getaddrinfo");
	}

	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if (fd == -1) {
		err(1, "unable to open socket");
	}

	if (opts.srcaddr) {
		char buf[sizeof(struct in6_addr)] = { 0 };

		if (inet_pton(AF_INET6, opts.srcaddr, buf) == 1) {
			struct sockaddr_in6 sockaddr = {
				.sin6_family = AF_INET6,
				.sin6_port = 0,
			};

			memcpy(&sockaddr.sin6_addr, buf, sizeof(struct in6_addr));

			if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_in6)) < 0) {
				warn("unable to bind to %s", opts.srcaddr);
			}
		} else if (inet_pton(AF_INET, opts.srcaddr, buf) == 1) {
			struct sockaddr_in sockaddr = {
				.sin_family = AF_INET,
				.sin_port = 0,
			};

			memcpy(&sockaddr.sin_addr, buf, sizeof(struct in_addr));

			if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_in)) < 0) {
				warn("unable to bind to %s", opts.srcaddr);
			}
		} else {
			warnx("invalid srcaddr \"%s\"", opts.srcaddr);
		}

	}

	if (!opts.location) {
		opts.location = calloc(HOST_NAME_MAX, sizeof(char));
		if (gethostname(opts.location, HOST_NAME_MAX * sizeof(char)) < 0) {
			warn("unable to get hostname");
		}
	}

	rc = connect(fd, res->ai_addr, res->ai_addrlen);
	if (rc == -1) {
		err(1, "unable to connect to %s", res->ai_canonname);
	}

	freeaddrinfo(res);

	char buf[1000];

	rc = read(fd, buf, sizeof(buf));
	buf[rc] = '\0';

	printf("<- %s", buf);

	char challenge[MD5_DIGEST_STRING_LENGTH];

	ns_auth(buf, challenge, &opts);

	dprintf(fd, "auth_ag ext_user none none\n");
	ns_read_rep(fd, buf, sizeof(buf));

	dprintf(fd, "ext_user_log %s %s %s %s\n",
			opts.user, challenge, opts.location, opts.data ? opts.data : "data");
	ns_read_rep(fd, buf, sizeof(buf));

	clean_config(&opts);

	for (;;) {
		rc = read(fd, buf, sizeof(buf));
		buf[rc] = '\0';
		printf("<- %s\n", buf);

		int p;

		if (sscanf(buf, "ping %d\n", &p) == 1) {
			write(fd, buf, strlen(buf));
		}
	}

	close(fd);


	return 0;
}
