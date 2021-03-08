/*
 * restmbmaster.c - Rest API gateway to Modbus slaves
 * Copyright (C) 2019 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <modbus.h>
#include <microhttpd.h>

static int __parse_uint(const char *str, size_t max, char **p_endptr)
{
	bool check_end = !p_endptr;
        char *endptr;
        unsigned long int val;

        val = strtoul(str, &endptr, 10);
        if (endptr == str || !isdigit(*str) || (check_end && *endptr != '\0')) {
		errno = EINVAL;
		return -1;
	}
        if (val > max) {
		errno = ERANGE;
		return -1;
	}
	if (p_endptr)
		*p_endptr = endptr;
        return val;
}

static int parse_uint8(const char *str, uint8_t *dest)
{
	int err = __parse_uint(str, UCHAR_MAX, NULL);

	if (err == -1)
		return -1;
	*dest = err;
	return 0;
}

static int __parse_uint16(const char *str, uint16_t *dest, char **p_endptr)
{
	int err = __parse_uint(str, USHRT_MAX, p_endptr);

	if (err == -1)
		return -1;
	*dest = err;
	return 0;
}

static int parse_uint16(const char *str, uint16_t *dest)
{
	return __parse_uint16(str, dest, NULL);
}

enum rmm_cmd {
	RMM_CMD_RUN,
	RMM_CMD_HELP,
	RMM_CMD_VERSION,
};

enum rmm_modbus_connection_type {
	RMM_MODBUS_CONNECTION_TYPE_RTU,
	RMM_MODBUS_CONNECTION_TYPE_TCP,
};

struct rmm {
	enum rmm_cmd cmd; /* run is the default */
	char *argv0;
	char *connect_uri;
	uint16_t port;
	unsigned int debug;
	enum rmm_modbus_connection_type connection_type;
	modbus_t *mb;
	struct MHD_Daemon *mhd;
	char *page;
	bool mb_connected;
};

#define pr_dbg(rmm, args...)	\
	if (rmm->debug)		\
		fprintf(stdout, ##args)

#define pr_err(args...)	\
	fprintf(stderr, ##args)

enum rmm_modbus_obj_type {
	RMM_MODBUS_OBJ_TYPE_COIL,
	RMM_MODBUS_OBJ_TYPE_DISCRETE_INPUT,
	RMM_MODBUS_OBJ_TYPE_INPUT_REGISTER,
	RMM_MODBUS_OBJ_TYPE_HOLDING_REGISTER,
};

static int rmm_modbus_obj_type_parse(const char *str,
				     enum rmm_modbus_obj_type *obj_type)
{
	if (!strcmp(str, "coils"))
		*obj_type = RMM_MODBUS_OBJ_TYPE_COIL;
	else if (!strcmp(str, "discrete-inputs"))
		*obj_type = RMM_MODBUS_OBJ_TYPE_DISCRETE_INPUT;
	else if (!strcmp(str, "input-registers"))
		*obj_type = RMM_MODBUS_OBJ_TYPE_INPUT_REGISTER;
	else if (!strcmp(str, "holding-registers"))
		*obj_type = RMM_MODBUS_OBJ_TYPE_HOLDING_REGISTER;
	else
		return -1;
	return 0;
}

#define RMM_ITEM_COUNT_MAX 128

struct rmm_modbus_obj_ops {
	int (*get)(struct rmm *rmm, uint8_t slave_address,
		   uint16_t item_address, uint16_t item_count,
		   char *page, size_t page_size, unsigned int *status_code);
	int (*put)(struct rmm *rmm, uint8_t slave_address,
		   uint16_t item_address, uint16_t item_count,
		   uint16_t *item_input_vals, char *page, size_t page_size,
		   unsigned int *status_code);
};

static int rmm_page_value_put(uint16_t value, char *page, size_t page_size,
			      unsigned int *status_code, size_t *page_offset)
{
	int len;

	len = snprintf(page + *page_offset, page_size - *page_offset,
		       "%s%u", *page_offset ? " " : "", value);
	if (len < 0 || page_size - *page_offset - 1 < len) {
		snprintf(page, page_size, "Failed to put values");
		*status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
		return -1;
	}
	*page_offset += len;
	return 0;
}

static int rmm_modbus_coils_get(struct rmm *rmm, uint8_t slave_address,
				uint16_t item_address, uint16_t item_count,
				char *page, size_t page_size,
				unsigned int *status_code)
{
	uint8_t vals[RMM_ITEM_COUNT_MAX];
	bool retry_done = false;
	size_t page_offset = 0;
	int err;
	int i;

again:
	modbus_set_slave(rmm->mb, slave_address);
	err = modbus_read_bits(rmm->mb, item_address, item_count, vals);
	if (err == -1) {
		if (!retry_done && errno == ECONNRESET) {
			retry_done = true;
			goto again;
		}
		snprintf(page, page_size, "Unable to read modbus coils: %s",
			 modbus_strerror(errno));
		*status_code = MHD_HTTP_BAD_REQUEST;
		return -1;
	}
	for (i = 0; i < item_count; i++) {
		err = rmm_page_value_put(vals[i], page, page_size,
					 status_code, &page_offset);
		if (err == -1)
			return -1;
	}
	return 0;
}

static int rmm_modbus_coils_put(struct rmm *rmm, uint8_t slave_address,
				uint16_t item_address, uint16_t item_count,
				uint16_t *item_input_vals,
				char *page, size_t page_size,
				unsigned int *status_code)
{
	uint8_t vals[RMM_ITEM_COUNT_MAX];
	bool retry_done = false;
	int err;
	int i;

	for (i = 0; i < item_count; i++) {
		if (item_input_vals[i] > 1) {
			snprintf(page, page_size, "Wrong input value (has to be either 0 or 1)");
			*status_code = MHD_HTTP_BAD_REQUEST;
			return -1;
		}
		vals[i] = item_input_vals[i];
	}

again:
	modbus_set_slave(rmm->mb, slave_address);
	err = modbus_write_bits(rmm->mb, item_address, item_count, vals);
	if (err == -1) {
		if (!retry_done && errno == ECONNRESET) {
			retry_done = true;
			goto again;
		}
		snprintf(page, page_size, "Unable to write modbus coils: %s",
			 modbus_strerror(errno));
		*status_code = MHD_HTTP_BAD_REQUEST;
		return -1;
	}
	return 0;
}

static int rmm_modbus_discrete_inputs_get(struct rmm *rmm,
					  uint8_t slave_address,
					  uint16_t item_address,
					  uint16_t item_count,
					  char *page, size_t page_size,
					  unsigned int *status_code)
{
	uint8_t vals[RMM_ITEM_COUNT_MAX];
	bool retry_done = false;
	size_t page_offset = 0;
	int err;
	int i;

again:
	modbus_set_slave(rmm->mb, slave_address);
	err = modbus_read_input_bits(rmm->mb, item_address, item_count, vals);
	if (err == -1) {
		if (!retry_done && errno == ECONNRESET) {
			retry_done = true;
			goto again;
		}
		snprintf(page, page_size, "Unable to read modbus discrete inputs: %s",
			 modbus_strerror(errno));
		*status_code = MHD_HTTP_BAD_REQUEST;
		return -1;
	}
	for (i = 0; i < item_count; i++) {
		err = rmm_page_value_put(vals[i], page, page_size,
					 status_code, &page_offset);
		if (err == -1)
			return -1;
	}
	return 0;
}

static int rmm_modbus_input_registers_get(struct rmm *rmm,
					  uint8_t slave_address,
					  uint16_t item_address,
					  uint16_t item_count,
					  char *page, size_t page_size,
					  unsigned int *status_code)
{
	uint16_t regs[RMM_ITEM_COUNT_MAX];
	bool retry_done = false;
	size_t page_offset = 0;
	int err;
	int i;

again:
	modbus_set_slave(rmm->mb, slave_address);
	err = modbus_read_input_registers(rmm->mb, item_address,
					  item_count, regs);
	if (err == -1) {
		if (!retry_done && errno == ECONNRESET) {
			retry_done = true;
			goto again;
		}
		snprintf(page, page_size, "Unable to read modbus input registers: %s",
			 modbus_strerror(errno));
		*status_code = MHD_HTTP_BAD_REQUEST;
		return -1;
	}
	for (i = 0; i < item_count; i++) {
		err = rmm_page_value_put(regs[i], page, page_size,
					 status_code, &page_offset);
		if (err == -1)
			return -1;
	}
	return 0;
}

static int rmm_modbus_holding_registers_get(struct rmm *rmm,
					    uint8_t slave_address,
					    uint16_t item_address,
					    uint16_t item_count,
					    char *page, size_t page_size,
					    unsigned int *status_code)
{
	uint16_t regs[RMM_ITEM_COUNT_MAX];
	bool retry_done = false;
	size_t page_offset = 0;
	int err;
	int i;

again:
	modbus_set_slave(rmm->mb, slave_address);
	err = modbus_read_registers(rmm->mb, item_address, item_count, regs);
	if (err == -1) {
		if (!retry_done && errno == ECONNRESET) {
			retry_done = true;
			goto again;
		}
		snprintf(page, page_size, "Unable to read modbus holding registers: %s",
			 modbus_strerror(errno));
		*status_code = MHD_HTTP_BAD_REQUEST;
		return -1;
	}
	for (i = 0; i < item_count; i++) {
		err = rmm_page_value_put(regs[i], page, page_size,
					 status_code, &page_offset);
		if (err == -1)
			return -1;
	}
	return 0;
}

static int rmm_modbus_holding_registers_put(struct rmm *rmm,
					    uint8_t slave_address,
					    uint16_t item_address,
					    uint16_t item_count,
					    uint16_t *item_input_vals,
					    char *page, size_t page_size,
					    unsigned int *status_code)
{
	bool retry_done = false;
	int err;

again:
	modbus_set_slave(rmm->mb, slave_address);
	err = modbus_write_registers(rmm->mb, item_address, item_count, item_input_vals);
	if (err == -1) {
		if (!retry_done && errno == ECONNRESET) {
			retry_done = true;
			goto again;
		}
		snprintf(page, page_size, "Unable to write modbus holding registers: %s",
			 modbus_strerror(errno));
		*status_code = MHD_HTTP_BAD_REQUEST;
		return -1;
	}
	return 0;
}

static const struct rmm_modbus_obj_ops rmm_modbus_obj_ops[] = {
	[RMM_MODBUS_OBJ_TYPE_COIL] = {
		.get = rmm_modbus_coils_get,
		.put = rmm_modbus_coils_put,
	},
	[RMM_MODBUS_OBJ_TYPE_DISCRETE_INPUT] = {
		.get = rmm_modbus_discrete_inputs_get,
	},
	[RMM_MODBUS_OBJ_TYPE_INPUT_REGISTER] = {
		.get = rmm_modbus_input_registers_get,
	},
	[RMM_MODBUS_OBJ_TYPE_HOLDING_REGISTER] = {
		.get = rmm_modbus_holding_registers_get,
		.put = rmm_modbus_holding_registers_put,
	},
};

static const char *rmm_next_slash(char **pos)
{
	char *slash, *str = *pos;

	if (!*pos)
		return NULL;

	slash = strchr(str, '/');
	if (slash) {
		slash[0] = '\0';
		*pos = slash + 1;
	} else {
		*pos = NULL;
	}
	return str;
}

/*
 *  /slaves/SLAVE_ADDRESS/coils/INDEX[?count=NUMBER_OF_ITEMS]
 *  PUT - success 204 (MHD_HTTP_NO_CONTENT)
 *        error   400 (MHD_HTTP_BAD_REQUEST)
 *  GET - success 200 (MHD_HTTP_OK)
 *
 * wrong path 404 (MHD_HTTP_NOT_FOUND)
 * method not supported 405 (MHD_HTTP_METHOD_NOT_ALLOWED)
 *
 */

#define RMM_PAGE_SIZE (128 * 8)
#define RMM_URL_MAX 64

struct rmm_post_context {
	char buf[RMM_PAGE_SIZE];
	size_t offset;
};

static void
rmm_request_completed_callback(void *cls, struct MHD_Connection *connection,
			       void **con_cls,
			       enum MHD_RequestTerminationCode toe)
{
	struct rmm_post_context *post_context = *con_cls;

	if (!post_context)
		return;
	free(post_context);
}

static enum MHD_Result rmm_ahcb(void *cls, struct MHD_Connection *connection,
				const char *_url, const char *method,
				const char *version, const char *upload_data,
				size_t *upload_data_size, void **ptr)
{
	const struct rmm_modbus_obj_ops *modbus_obj_ops;
	struct rmm_post_context *post_context = *ptr;
	uint16_t item_input_vals[RMM_ITEM_COUNT_MAX];
	enum rmm_modbus_obj_type obj_type;
	struct MHD_Response *response;
	unsigned int status_code;
	const char *input = NULL;
	uint16_t item_count = 1;
	uint16_t item_address;
	uint8_t slave_address;
	struct rmm *rmm = cls;
	char *page = rmm->page;
	char url[RMM_URL_MAX];
	char *pos = url;
	const char *str;
	int err;

	memset(page, 0, RMM_PAGE_SIZE);

	if (!strcmp(method, MHD_HTTP_METHOD_PUT)) {
		if (!post_context) {
			str = MHD_lookup_connection_value(connection,
							  MHD_HEADER_KIND,
							  MHD_HTTP_HEADER_CONTENT_TYPE);
			if (str && strcmp(str, "text/plain")) {
				snprintf(page, RMM_PAGE_SIZE, "Wrong content type, expected \"text/plain\"");
				status_code = MHD_HTTP_BAD_REQUEST;
				goto response;
			}

			post_context = calloc(1, sizeof(*post_context));
			if (!post_context) {
				fprintf(stderr, "Failed to allocate POST context: %s\n",
					strerror(errno));
				status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
				goto response;
			}
			*ptr = post_context;
			return MHD_YES;
		} else {
			size_t size = *upload_data_size;

			if (size) {
				if (size + post_context->offset >
				    sizeof(post_context->buf))
					return MHD_NO;
				memcpy(post_context->buf + post_context->offset,
				       upload_data, size);
				post_context->offset += size;
				*upload_data_size = 0;
				return MHD_YES;
			}
			input = post_context->buf;
		}
	}
	if (!strcmp(method, MHD_HTTP_METHOD_GET) && *upload_data_size)
		return MHD_NO;

	if (strlen(_url) + 1 > sizeof(url))
		goto wrong_path;

	strcpy(url, _url);

	str = rmm_next_slash(&pos);
	if (!str || strlen(str))
		goto wrong_path;

	str = rmm_next_slash(&pos);
	if (!str || !strlen(str))
		goto wrong_path;

	if (strcmp(str, "slaves"))
		goto wrong_path;

	str = rmm_next_slash(&pos);
	if (!str || !strlen(str))
		goto wrong_path;

	err = parse_uint8(str, &slave_address);
	if (err == -1) {
		snprintf(page, RMM_PAGE_SIZE, "Failed to parse slave address: %s",
			 strerror(errno));
		status_code = MHD_HTTP_BAD_REQUEST;
		goto response;
	}

	str = rmm_next_slash(&pos);
	if (!str)
		goto wrong_path;

	err = rmm_modbus_obj_type_parse(str, &obj_type);
	if (err == -1)
		goto wrong_path;
	modbus_obj_ops = &rmm_modbus_obj_ops[obj_type];

	str = rmm_next_slash(&pos);
	if (!str || !strlen(str))
		goto wrong_path;

	err = parse_uint16(str, &item_address);
	if (err == -1) {
		snprintf(page, RMM_PAGE_SIZE, "Failed to parse item address: %s",
			 strerror(errno));
		status_code = MHD_HTTP_BAD_REQUEST;
		goto response;
	}

	/* Nothing else expected in the URL */
	str = rmm_next_slash(&pos);
	if (str)
		goto wrong_path;

	if (!strcmp(method, MHD_HTTP_METHOD_PUT)) {
		const char *pos = input;
		char *endptr;

		item_count = 0;
		do {
			err = __parse_uint16(pos,
					     &item_input_vals[item_count++],
					     &endptr);
			if (err) {
				snprintf(page, RMM_PAGE_SIZE, "Failed to parse input values: %s",
					 strerror(errno));
				status_code = MHD_HTTP_BAD_REQUEST;
				goto response;

			}
			pos = endptr + 1;

		} while (*endptr != '\0');
	}

	str = MHD_lookup_connection_value(connection,
					  MHD_GET_ARGUMENT_KIND, "count");
	if (str) {
		uint16_t arg_item_count;

		err = parse_uint16(str, &arg_item_count);
		if (err == -1) {
			snprintf(page, RMM_PAGE_SIZE, "Failed to parse count arg: %s",
				 strerror(errno));
			status_code = MHD_HTTP_BAD_REQUEST;
			goto response;
		}
		if (arg_item_count > RMM_ITEM_COUNT_MAX) {
			snprintf(page, RMM_PAGE_SIZE, "Count is bigger than max");
			status_code = MHD_HTTP_BAD_REQUEST;
			goto response;
		}
		if (!strcmp(method, MHD_HTTP_METHOD_PUT) &&
		    item_count != arg_item_count) {
			snprintf(page, RMM_PAGE_SIZE, "Count arg is not in sync with number of input values");
			status_code = MHD_HTTP_BAD_REQUEST;
			goto response;
		}
		item_count = arg_item_count;
	}

	if (!rmm->mb_connected) {
		err = modbus_connect(rmm->mb);
		if (err == -1) {
			snprintf(page, RMM_PAGE_SIZE, "Unabled to connect to modbus");
			status_code = MHD_HTTP_BAD_REQUEST;
			goto response;
		} else {
			rmm->mb_connected = true;
		}
	}

	if (!strcmp(method, MHD_HTTP_METHOD_GET)) {
		err = modbus_obj_ops->get(rmm, slave_address, item_address,
					  item_count, page, RMM_PAGE_SIZE, &status_code);
	} else if (!strcmp(method, MHD_HTTP_METHOD_PUT)) {
		if (!modbus_obj_ops->put)
			goto unexpected_method;
		err = modbus_obj_ops->put(rmm, slave_address, item_address,
					  item_count, item_input_vals,
					  page, RMM_PAGE_SIZE, &status_code);
	} else {
		goto unexpected_method;
	}

	if (!err)
		status_code = MHD_HTTP_OK;

response:
	response = MHD_create_response_from_buffer(strlen(page), page,
						   MHD_RESPMEM_PERSISTENT);
	if (!response)
		return MHD_NO;

	if (MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				    "text/plain") == MHD_NO)
		return MHD_NO;

	err = MHD_queue_response(connection, status_code, response);
	MHD_destroy_response(response);
	return err;

wrong_path:
	page[0] = '\0';
	status_code = MHD_HTTP_NOT_FOUND;
	goto response;

unexpected_method:
	snprintf(page, RMM_PAGE_SIZE, "Allow: GET%s",
		 modbus_obj_ops->put ? ", PUT" : "");
	status_code = MHD_HTTP_METHOD_NOT_ALLOWED;
	goto response;
}

static int rmm_main_loop_run(struct rmm *rmm)
{
	MHD_UNSIGNED_LONG_LONG mhd_timeout;
	struct timeval tv, *tvp;
	fd_set fds[3];
	int fdmax = 0;
	int i;

again:
	for (i = 0; i < 3; i++)
		FD_ZERO(&fds[i]);
	fdmax = 0;
	if (MHD_get_fdset(rmm->mhd, &fds[0], &fds[1], &fds[2], &fdmax) ==
	    MHD_NO) {
		pr_err("Unable to get webserver fdset\n");
		return -1;
	}

	if (MHD_get_timeout(rmm->mhd, &mhd_timeout) == MHD_YES) {
		tv.tv_sec = mhd_timeout / 1000;
		tv.tv_usec = (mhd_timeout - tv.tv_sec * 1000) * 1000;
		tvp = &tv;
	} else {
		tvp = NULL;
	}

	while (select(fdmax + 1, &fds[0], &fds[1], &fds[2], tvp) < 0) {
		if (errno == EINTR)
			continue;
		pr_err("Select failed\n");
		return -1;
	}
	MHD_run_from_select(rmm->mhd, &fds[0], &fds[1], &fds[2]);

	goto again;
}

static int rmm_webserver_init(struct rmm *rmm)
{
	rmm->mhd = MHD_start_daemon(MHD_USE_ERROR_LOG, rmm->port, NULL, NULL,
				    &rmm_ahcb, rmm,
				    MHD_OPTION_NOTIFY_COMPLETED,
				    &rmm_request_completed_callback, NULL,
				    MHD_OPTION_END);
	if (!rmm->mhd) {
		pr_err("Unable to start webserver\n");
		return -1;
	}
	return 0;
}

static void rmm_webserver_fini(struct rmm *rmm)
{
	MHD_stop_daemon(rmm->mhd);
}

static int host_to_ip(char *host, char *ip)
{
	struct addrinfo hints = {
		.ai_family = AF_INET,
	};
	struct sockaddr_in sa_in;
	struct addrinfo *result;
	int err;

	err = getaddrinfo(host, NULL, &hints, &result);
	if (err) {
		pr_err("Unable to resolve hostname: %s\n", gai_strerror(err));
		return -1;
	}
	memcpy(&sa_in, result->ai_addr, sizeof(sa_in));
	freeaddrinfo(result);

	if (!inet_ntop(AF_INET, &sa_in.sin_addr, ip, INET_ADDRSTRLEN)) {
		pr_err("Unable to convert address to string\n");
		return -1;
	}

	return 0;
}

#define RMM_MODBUS_RTU_PREFIX "rtu:"
#define RMM_MODBUS_RTU_BAUD_DEFAULT 115200
#define RMM_MODBUS_TCP_PREFIX "tcp://"

static int rmm_modbus_init(struct rmm *rmm)
{
	int err;

	if (!strncmp(rmm->connect_uri, RMM_MODBUS_RTU_PREFIX,
		     strlen(RMM_MODBUS_RTU_PREFIX))) {
		int baud = RMM_MODBUS_RTU_BAUD_DEFAULT;
		char *device, *sep;

		rmm->connection_type = RMM_MODBUS_CONNECTION_TYPE_RTU;
		device = rmm->connect_uri + strlen(RMM_MODBUS_RTU_PREFIX);
		sep = strchr(device, '?');
		if (sep) {
			err = sscanf(sep, "?baud=%u", &baud);
			if (err != 1) {
				pr_err("Failed to parse RTU parameters\n");
				return -1;
			}
			sep[0] = '\0';
		}
		pr_dbg(rmm, "RTU, %s, %u\n", device, baud);
		rmm->mb = modbus_new_rtu(device, baud, 'N', 8, 1);
	} else if (!strncmp(rmm->connect_uri, RMM_MODBUS_TCP_PREFIX,
			    strlen(RMM_MODBUS_TCP_PREFIX))) {
		int port = MODBUS_TCP_DEFAULT_PORT;
		char ip[INET_ADDRSTRLEN];
		char *host, *sep;

		rmm->connection_type = RMM_MODBUS_CONNECTION_TYPE_TCP;
		host = rmm->connect_uri + strlen(RMM_MODBUS_TCP_PREFIX);
		sep = strchr(host, ':');
		if (sep) {
			err = sscanf(sep, ":%u", &port);
			if (err != 1) {
				pr_err("Failed to parse TCP port\n");
				return -1;
			}
			sep[0] = '\0';
		}
		err = host_to_ip(host, ip);
		if (err == -1)
			return -1;
		pr_dbg(rmm, "TCP, %s, %u\n", ip, port);
		rmm->mb = modbus_new_tcp(ip, port);
	} else {
		pr_err("Unsupported target type\n");
		return -1;
	}
	if (!rmm->mb) {
		pr_err("Unable to allocate libmodbus context: %s\n",
		       modbus_strerror(errno));
		return -1;
	}

	err = modbus_set_error_recovery(rmm->mb, MODBUS_ERROR_RECOVERY_LINK |
						 MODBUS_ERROR_RECOVERY_PROTOCOL);
	if (err == -1) {
		pr_err("Unable set error recovery: %s\n",
		       modbus_strerror(errno));
		modbus_free(rmm->mb);
		return -1;
	}

	err = modbus_connect(rmm->mb);
	if (err == -1)
		pr_err("Unable to connect to modbus: %s\n",
		       modbus_strerror(errno));
	else
		rmm->mb_connected = true;

	return 0;
}

static void rmm_modbus_fini(struct rmm *rmm)
{
	modbus_close(rmm->mb);
	modbus_free(rmm->mb);
}

static char *ident_from_argv0(struct rmm *rmm, char *argv0)
{
	char *p;

	if ((p = strrchr(argv0, '/')))
		return p + 1;
	return argv0;
}

static int parse_port(const char *str, uint16_t *port)
{
	int err;

	err = parse_uint16(str, port);
	if (err == -1) {
		if (errno == EINVAL)
			pr_err("Port is garbage\n");
		else if (errno == ERANGE)
			pr_err("Port number is outside value range\n");
		return -1;
	}
        return 0;
}

static bool stronlyblanks(const char *str)
{
	int i;

	for (i = 0; i < strlen(str); i++)
		if (!isblank(str[i]))
			return false;
	return true;
}

static char *strtrim(char *str)
{
	int i;

	for (i = strlen(str) - 1; i >= 0; i--) {
		if (!isblank(str[i]))
			break;
		str[i] = '\0';
	}
	for (i = 0; i < strlen(str); i++)
		if (!isblank(str[i]))
			return &str[i];
	return NULL;
}

static int rmm_parse_config(struct rmm *rmm, const char *path)
{
	char *pos, *key, *val;
	char buffer[128];
	int linecnt = 0;
	char *rpath;
	FILE *f;
	int err;

	rpath = realpath(optarg, NULL);
	if (!rpath) {
		pr_err("Failed to get absolute path of \"%s\": %s\n",
		       path, strerror(errno));
		return -1;
	}
	f = fopen(rpath, "r");
	if (!f) {
		pr_err("Failed to open config file \"%s\": %s\n",
		       rpath, strerror(errno));
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), f)) {
		buffer[strlen(buffer) - 1] = '\0';
		linecnt++;
		pos = strchr(buffer, '#');
		if (pos)
			*pos = '\0';
		if (stronlyblanks(buffer))
			continue;
		pos = strchr(buffer, '=');
		if (pos) {
			*pos = '\0';
			val = pos + 1;
			val = strtrim(val);
		} else {
			val = NULL;
		}
		key = buffer;
		key = strtrim(key);

		if (!strcmp(key, "connect")) {
			if (!val)
				goto err_value_missing;
			free(rmm->connect_uri);
			rmm->connect_uri = strdup(val);
		} else if (!strcmp(key, "port")) {
			if (!val)
				goto err_value_missing;
			err = parse_port(val, &rmm->port);
			if (err)
				goto err_out;
		} else if (!strcmp(key, "debug")) {
			if (val)
				goto err_value_should_not_be_there;
			rmm->debug++;
		} else {
			pr_err("Config, line %d: Key \"%s\" is unknown.\n",
			       linecnt, key);
			goto err_out;
		}
	}

	fclose(f);
	return 0;

err_value_missing:
	pr_err("Config, line %d: Key \"%s\" requires a value.\n",
	       linecnt, key);
	goto err_out;
err_value_should_not_be_there:
	pr_err("Config, line %d: Key \"%s\" does not allow value.\n",
	       linecnt, key);
err_out:
	fclose(f);
	return -1;
}

static int rmm_parse_cmdline(struct rmm *rmm, int argc, char *argv[])
{
	static const struct option long_options[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "version",	no_argument,		NULL, 'v' },
		{ "connect",	required_argument,	NULL, 'c' },
		{ "port",	required_argument,	NULL, 'p' },
		{ "debug",	no_argument,		NULL, 'd' },
		{ "config",	required_argument,	NULL, 'f' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	int err;

	rmm->argv0 = ident_from_argv0(rmm, argv[0]);

	while ((opt = getopt_long(argc, argv, "hvc:p:df:",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			rmm->cmd = RMM_CMD_HELP;
			break;
		case 'v':
			rmm->cmd = RMM_CMD_VERSION;
			break;
		case 'c':
			free(rmm->connect_uri);
			rmm->connect_uri = strdup(optarg);
			break;
		case 'p':
			err = parse_port(optarg, &rmm->port);
			if (err)
				return -1;
			break;
		case 'd':
			rmm->debug++;
			break;
		case 'f':
			err = rmm_parse_config(rmm, optarg);
			if (err)
				return -1;
			break;
		default:
			return -1;
		}
	}

	if (optind < argc) {
		pr_err("Too many arguments\n");
		return -1;
	}

	return 0;
}

static void rmm_print_help(struct rmm *rmm)
{
	printf(
            "%s [options]\n"
            "    -h --help                Show this help\n"
            "    -v --version             Show version\n"
            "    -d --debug               Increase verbosity\n"
            "    -c --connect=CONNECT_URI Modbus target to connect to. Supported formats:\n"
	    "                             tcp://HOSTNAME[:PORT]\n"
	    "                                 (e.g tcp://test.abc:1000)\n"
	    "                             Default PORT is 502\n"
	    "                             rtu:DEVICEPATH[?baud=BAUDRATE]\n"
	    "                                 (e.g. rtu:/dev/ttyS0?baud=9600\n"
	    "                             Default BAUDRATE is 115200\n"
            "    -p --port=PORT           Port on which the webserver is listening\n"
            "    -f --config=FILE         Load the specified configuration file\n",
            rmm->argv0);
}

static int rmm_check_config(struct rmm *rmm)
{
	if (!rmm->connect_uri) {
		pr_err("Connect URI is unspecified\n");
		return -1;
	}
	if (!rmm->port) {
		pr_err("Webserver port is undefined\n");
		return -1;
	}
	return 0;
}

static struct rmm *rmm_alloc(void)
{
	struct rmm *rmm = calloc(1, sizeof(struct rmm));

	if (!rmm)
		return NULL;
	rmm->page = malloc(RMM_PAGE_SIZE);
	if (!rmm->page) {
		free(rmm);
		return NULL;
	}
	return rmm;
}

static void rmm_free(struct rmm *rmm)
{
	free(rmm->connect_uri);
	free(rmm->page);
	free(rmm);
}

int main(int argc, char *argv[])
{
	struct rmm *rmm;
	int err;

	rmm = rmm_alloc();
	if (!rmm) {
		pr_err("Unable to allocate rmm context\n");
		return EXIT_FAILURE;
	}

	err = rmm_parse_cmdline(rmm, argc, argv);
	if (err) {
		err = EXIT_FAILURE;
		goto rmm_free;
	}

	switch (rmm->cmd) {
	case RMM_CMD_HELP:
		rmm_print_help(rmm);
		err = EXIT_SUCCESS;
		goto rmm_free;
	case RMM_CMD_VERSION:
		printf("%s "PACKAGE_VERSION"\n", rmm->argv0);
		err = EXIT_SUCCESS;
		goto rmm_free;
	case RMM_CMD_RUN:
		break;
	}

	err = rmm_check_config(rmm);
	if (err) {
		rmm_print_help(rmm);
		err = EXIT_FAILURE;
		goto rmm_free;
	}

	err = rmm_modbus_init(rmm);
	if (err) {
		err = EXIT_FAILURE;
		goto rmm_free;
	}

	err = rmm_webserver_init(rmm);
	if (err) {
		err = EXIT_FAILURE;
		goto rmm_modbus_fini;
	}

	err = rmm_main_loop_run(rmm);
	err = err ? EXIT_FAILURE : EXIT_SUCCESS;

	rmm_webserver_fini(rmm);
rmm_modbus_fini:
	rmm_modbus_fini(rmm);
rmm_free:
	rmm_free(rmm);
	return err;
}
