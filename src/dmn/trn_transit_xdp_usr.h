// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file trn_agent_xdp_usr.h
 * @author Sherif Abdelwahab (@zasherif)
 *         Phu Tran          (@phudtran)
 *
 * @brief User space APIs and data structures to program transit
 * xdp program.
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#pragma once

#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <search.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include "extern/cJSON.h"

#include "trn_datamodel.h"

struct user_metadata_t {
	struct tunnel_iface_t eth;
	int ifindex;
	__u32 xdp_flags;
	int prog_fd;
	__u32 prog_id;
	char pcapfile[256];
	int itf_idx[TRAN_MAX_ITF];

	int networks_map_fd;
	int vpc_map_fd;
	int endpoints_map_fd;
	int interface_config_map_fd;
	int hosted_endpoints_iface_map_fd;
	int interfaces_map_fd;

	struct bpf_map *networks_map;
	struct bpf_map *vpc_map;
	struct bpf_map *endpoints_map;
	struct bpf_map *hosted_endpoints_iface_map;
	struct bpf_map *interface_config_map;
	struct bpf_map *interfaces_map;
	struct bpf_map *xdpcap_hook_map;

	struct bpf_prog_info info;
	struct bpf_object *obj;
};

int trn_user_metadata_free(struct user_metadata_t *md);

int trn_bpf_maps_init(struct user_metadata_t *md);

int trn_update_network(struct user_metadata_t *md, struct network_key_t *netkey,
		       struct network_t *net);

int trn_update_endpoint(struct user_metadata_t *md,
			struct endpoint_key_t *epkey, struct endpoint_t *ep);

int trn_update_vpc(struct user_metadata_t *md, struct vpc_key_t *vpckey,
		   struct vpc_t *vpc);

int trn_get_network(struct user_metadata_t *md, struct network_key_t *netkey,
		    struct network_t *net);

int trn_get_endpoint(struct user_metadata_t *md, struct endpoint_key_t *epkey,
		     struct endpoint_t *ep);

int trn_get_vpc(struct user_metadata_t *md, struct vpc_key_t *vpckey,
		struct vpc_t *vpc);

int trn_delete_vpc(struct user_metadata_t *md, struct vpc_key_t *vpckey);

int trn_delete_endpoint(struct user_metadata_t *md,
			struct endpoint_key_t *epkey);

int trn_delete_network(struct user_metadata_t *md,
		       struct network_key_t *netkey);

int trn_user_metadata_init(struct user_metadata_t *md, char *itf,
			   char *kern_path, int xdp_flags);

uint32_t trn_get_interface_ipv4(int itf_idx);
