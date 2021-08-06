/*
 * Copyright (c) 1999-2021 Logitech, Inc.
 * Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <json-glib/json-glib.h>
#include <string.h>

#include "fu-logitech-bulkcontroller-common.h"
#include "fu-logitech-bulkcontroller-device.h"

/**
 * FU_LOGITECH_BULKCONTROLLER_DEVICE_FLAG_IS_MINI:
 *
 * Some devices have a compact memory layout and the application code starts
 * earlier.
 *
 * Since: 1.7.0
 */
#define FU_LOGITECH_BULKCONTROLLER_DEVICE_FLAG_IS_MINI (1 << 0)

enum { SHA_256, SHA_512, MD5 };

enum { EP_OUT, EP_IN, EP_LAST };

enum { BULK_INTERFACE_UPD, BULK_INTERFACE_SYNC };

#define MAX_DATA_SIZE	   16384 /* 16k */
#define PACKET_HEADER_SIZE (2 * sizeof(guint32))

#define MAX_DATA_SIZE_UPD 8192 /* 8k */
#define PAYLOAD_SIZE	  MAX_DATA_SIZE_UPD - PACKET_HEADER_SIZE
#define ACK_PKT_SIZE	  12

typedef enum {
	CMD_CHECK_BUFFERSIZE = 0xCC00,
	CMD_INIT = 0xCC01,
	CMD_START_TRANSFER = 0xCC02,
	CMD_DATA_TRANSFER = 0xCC03,
	CMD_END_TRANSFER = 0xCC04,
	CMD_UNINIT = 0xCC05,
	CMD_BUFFER_READ = 0xCC06,
	CMD_BUFFER_WRITE = 0xCC07,
	CMD_UNINIT_BUFFER = 0xCC08,
	CMD_ACK = 0xFF01,
	CMD_TIMEOUT = 0xFF02,
	CMD_NACK = 0xFF03
} UsbCommands;

struct _FuLogitechBulkcontrollerDevice {
	FuUsbDevice parent_instance;
	guint sync_ep[EP_LAST];
	guint update_ep[EP_LAST];
	guint sync_iface;
	guint update_iface;
	FuLogitechBulkcontrollerDeviceStatus status;
	FuLogitechBulkcontrollerDeviceUpdateState update_status;
};

G_DEFINE_TYPE(FuLogitechBulkcontrollerDevice, fu_logitech_bulkcontroller_device, FU_TYPE_USB_DEVICE)

#define UPD_INTERFACE_SUBPROTOCOL_ID  117
#define SYNC_INTERFACE_SUBPROTOCOL_ID 118

static void
fu_logitech_bulkcontroller_device_to_string(FuDevice *device, guint idt, GString *str)
{
	FuLogitechBulkcontrollerDevice *self = FU_LOGITECH_BULKCONTROLLER_DEVICE(device);
	fu_common_string_append_kx(str, idt, "SyncIface", self->sync_iface);
	fu_common_string_append_kx(str, idt, "UpdateIface", self->update_iface);
	fu_common_string_append_kv(
	    str,
	    idt,
	    "Status",
	    fu_logitech_bulkcontroller_device_status_to_string(self->status));
	fu_common_string_append_kv(
	    str,
	    idt,
	    "UpdateState",
	    fu_logitech_bulkcontroller_device_update_state_to_string(self->update_status));
}

static gboolean
fu_logitech_bulkcontroller_device_probe(FuDevice *device, GError **error)
{
	FuLogitechBulkcontrollerDevice *self = FU_LOGITECH_BULKCONTROLLER_DEVICE(device);
	g_autoptr(GPtrArray) intfs = NULL;

	intfs = g_usb_device_get_interfaces(fu_usb_device_get_dev(FU_USB_DEVICE(self)), error);
	if (intfs == NULL)
		return FALSE;
	for (guint i = 0; i < intfs->len; i++) {
		GUsbInterface *intf = g_ptr_array_index(intfs, i);
		if (g_usb_interface_get_class(intf) == G_USB_DEVICE_CLASS_VENDOR_SPECIFIC &&
		    g_usb_interface_get_protocol(intf) == 0x1) {
			if (g_usb_interface_get_subclass(intf) == SYNC_INTERFACE_SUBPROTOCOL_ID) {
				g_autoptr(GPtrArray) endpoints =
				    g_usb_interface_get_endpoints(intf);
				self->sync_iface = g_usb_interface_get_number(intf);
				if (endpoints == NULL)
					continue;
				for (guint j = 0; j < endpoints->len; j++) {
					GUsbEndpoint *ep = g_ptr_array_index(endpoints, j);
					if (j == EP_OUT)
						self->sync_ep[EP_OUT] =
						    g_usb_endpoint_get_address(ep);
					else
						self->sync_ep[EP_IN] =
						    g_usb_endpoint_get_address(ep);
				}
			} else if (g_usb_interface_get_subclass(intf) ==
				   UPD_INTERFACE_SUBPROTOCOL_ID) {
				g_autoptr(GPtrArray) endpoints =
				    g_usb_interface_get_endpoints(intf);
				self->sync_iface = g_usb_interface_get_number(intf);
				if (endpoints == NULL)
					continue;
				for (guint j = 0; j < endpoints->len; j++) {
					GUsbEndpoint *ep = g_ptr_array_index(endpoints, j);
					if (j == EP_OUT)
						self->update_ep[EP_OUT] =
						    g_usb_endpoint_get_address(ep);
					else
						self->update_ep[EP_IN] =
						    g_usb_endpoint_get_address(ep);
				}
			}
		}
	}
	return TRUE;
}

static gboolean
fu_logitech_bulkcontroller_device_send(FuLogitechBulkcontrollerDevice *self,
				       GByteArray *buf,
				       gint interface_id,
				       GError **error)
{
	gsize transferred = 0;
	gint ep;

	g_return_val_if_fail(buf != NULL, FALSE);

	if (interface_id == BULK_INTERFACE_SYNC) {
		ep = self->sync_ep[EP_OUT];
	} else if (interface_id == BULK_INTERFACE_UPD) {
		ep = self->update_ep[EP_OUT];
	} else {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "interface is invalid");
		return FALSE;
	}
	if (!g_usb_device_bulk_transfer(fu_usb_device_get_dev(FU_USB_DEVICE(self)),
					ep,
					(guint8 *)buf->data,
					buf->len,
					&transferred,
					100,
					NULL,
					error)) {
		/* We have added this as a solution. Some time when transaction is completed in
		 * kernel context, it will return to libusb context where it encounters some error
		 * that's not known to libusb. So we ignored it as transactions as completed
		 * properly.
		 */
		g_prefix_error(error, "bulk transfer failed: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_logitech_bulkcontroller_device_recv(FuLogitechBulkcontrollerDevice *self,
				       GByteArray *buf,
				       gint interface_id,
				       guint timeout,
				       GError **error)
{
	gsize received_length = 0;
	gint ep;

	g_return_val_if_fail(buf != NULL, FALSE);

	if (interface_id == BULK_INTERFACE_SYNC) {
		ep = self->sync_ep[EP_IN];
	} else if (interface_id == BULK_INTERFACE_UPD) {
		ep = self->update_ep[EP_IN];
	} else {
		g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "interface is invalid");
		return FALSE;
	}
	if (!g_usb_device_bulk_transfer(fu_usb_device_get_dev(FU_USB_DEVICE(self)),
					ep,
					buf->data,
					buf->len,
					&received_length,
					timeout,
					NULL,
					error)) {
		/* We have added this as a solution. Some time when transaction is completed in
		 * kernel context, it will return to libusb context where it encounters some error
		 * that's not known to libusb. So we ignored it as transactions as completed
		 * properly.
		 */
		g_prefix_error(error, "bulk transfer failed: ");
		return FALSE;
	}
	return TRUE;
}

static GByteArray *
fu_logitech_bulkcontroller_device_send_upd_cmd(FuLogitechBulkcontrollerDevice *self,
					       guint32 cmd,
					       GByteArray *buf,
					       GError **error)
{
	guint32 cmd_tmp = 0x0;
	g_autoptr(GByteArray) buf_pkt = g_byte_array_new();
	g_autoptr(GByteArray) buf_ack = g_byte_array_new();
	g_autoptr(GByteArray) buf_new = g_byte_array_new();

	fu_byte_array_append_uint32(buf_pkt, cmd, G_LITTLE_ENDIAN);
	fu_byte_array_append_uint32(buf_pkt, buf != NULL ? buf->len : 0, G_LITTLE_ENDIAN);
	if (buf != NULL)
		g_byte_array_append(buf_pkt, buf->data, buf->len);
	if (!fu_logitech_bulkcontroller_device_send(self, buf_pkt, BULK_INTERFACE_UPD, error))
		return NULL;

	/* receiving INIT ACK */
	fu_byte_array_set_size(buf_ack, ACK_PKT_SIZE + 4);
	if (!fu_logitech_bulkcontroller_device_recv(self, buf_ack, BULK_INTERFACE_UPD, 5000, error))
		return NULL;
	if (!fu_common_read_uint32_safe(buf_ack->data,
					buf_ack->len,
					0x0,
					&cmd_tmp,
					G_LITTLE_ENDIAN,
					error))
		return NULL;
	if (cmd_tmp != CMD_ACK) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "not CMD_ACK, got %x", cmd);
		return NULL;
	}
	if (!fu_common_read_uint32_safe(buf_ack->data,
					buf_ack->len,
					0x4,
					&cmd_tmp,
					G_LITTLE_ENDIAN,
					error))
		return NULL;
	if (cmd_tmp != CMD_ACK) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "not CMD_ACK data, got %x", cmd);
		return NULL;
	}
	return g_byte_array_append(buf_new, buf_ack->data + 0x8, buf_ack->len - 0x8);
}

static gchar *
fu_logitech_bulkcontroller_device_compute_hash(GBytes *data)
{
	guint8 md5buf[16] = {0};
	gsize data_len = sizeof(md5buf);
	GChecksum *checksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(checksum, g_bytes_get_data(data, NULL), g_bytes_get_size(data));
	g_checksum_get_digest(checksum, (guint8 *)&md5buf, &data_len);
	return g_base64_encode(md5buf, sizeof(md5buf));
}

static gboolean
fu_logitech_bulkcontroller_device_write_firmware(FuDevice *device,
						 FuFirmware *firmware,
						 FwupdInstallFlags flags,
						 GError **error)
{
	FuLogitechBulkcontrollerDevice *self = FU_LOGITECH_BULKCONTROLLER_DEVICE(device);
	g_autofree gchar *base64hash = NULL;
	g_autoptr(GByteArray) end_ack = NULL;
	g_autoptr(GByteArray) end_pkt = g_byte_array_new();
	g_autoptr(GByteArray) init_ack = NULL;
	g_autoptr(GByteArray) start_ack = NULL;
	g_autoptr(GByteArray) start_pkt = g_byte_array_new();
	g_autoptr(GByteArray) uninit_ack = NULL;
	g_autoptr(GBytes) fw = NULL;
	g_autoptr(GPtrArray) chunks = NULL;

	/* get default image */
	fw = fu_firmware_get_bytes(firmware, error);
	if (fw == NULL)
		return FALSE;

	/* Sending INIT */
	init_ack = fu_logitech_bulkcontroller_device_send_upd_cmd(self, CMD_INIT, NULL, error);
	if (init_ack == NULL) {
		g_prefix_error(error, "error in writing init transfer packet: ");
		return FALSE;
	}

	/* transfer sent */
	fu_device_set_status(device, FWUPD_STATUS_DEVICE_WRITE);
	fu_byte_array_append_uint64(start_pkt, g_bytes_get_size(fw), G_LITTLE_ENDIAN);
	start_ack = fu_logitech_bulkcontroller_device_send_upd_cmd(self,
								   CMD_START_TRANSFER,
								   start_pkt,
								   error);
	if (start_ack == NULL) {
		g_prefix_error(error, "error in writing init transfer packet: ");
		return FALSE;
	}

	/* each block */
	chunks = fu_chunk_array_new_from_bytes(fw, 0x0, 0x0, PAYLOAD_SIZE);
	for (guint i = 0; i < chunks->len; i++) {
		FuChunk *chk = g_ptr_array_index(chunks, i);
		g_autoptr(GByteArray) data_ack = NULL;
		g_autoptr(GByteArray) data_pkt = g_byte_array_new();

		g_byte_array_append(data_pkt, fu_chunk_get_data(chk), fu_chunk_get_data_sz(chk));
		data_ack = fu_logitech_bulkcontroller_device_send_upd_cmd(self,
									  CMD_DATA_TRANSFER,
									  data_pkt,
									  error);
		if (data_ack == NULL) {
			g_prefix_error(error, "failed to send data packet 0x%x: ", i);
			return FALSE;
		}
		fu_device_set_progress_full(FU_DEVICE(self), i + 1, chunks->len);
	}

	/* sending end transfer */
	base64hash = fu_logitech_bulkcontroller_device_compute_hash(fw);
	fu_byte_array_append_uint32(end_pkt, 1, G_LITTLE_ENDIAN);   /* update */
	fu_byte_array_append_uint32(end_pkt, 0, G_LITTLE_ENDIAN);   /* force */
	fu_byte_array_append_uint32(end_pkt, MD5, G_LITTLE_ENDIAN); /* checksum type */
	g_byte_array_append(end_pkt, (const guint8 *)base64hash, strlen(base64hash));
	end_ack =
	    fu_logitech_bulkcontroller_device_send_upd_cmd(self, CMD_END_TRANSFER, end_pkt, error);
	if (end_ack == NULL) {
		g_prefix_error(error, "error in writing init transfer packet: ");
		return FALSE;
	}

	/* send uninit */
	uninit_ack = fu_logitech_bulkcontroller_device_send_upd_cmd(self, CMD_UNINIT, NULL, error);
	if (uninit_ack == NULL) {
		g_prefix_error(error, "error in writing finish transfer packet: ");
		return FALSE;
	}

	/* success! */
	return TRUE;
}

static gboolean
fu_logitech_bulkcontroller_device_open(FuDevice *device, GError **error)
{
	FuLogitechBulkcontrollerDevice *self = FU_LOGITECH_BULKCONTROLLER_DEVICE(device);
	GUsbDevice *usb_device = fu_usb_device_get_dev(FU_USB_DEVICE(device));

	/* FuUsbDevice->open */
	if (!FU_DEVICE_CLASS(fu_logitech_bulkcontroller_device_parent_class)->open(device, error))
		return FALSE;

	/* claim both interfaces */
	if (!g_usb_device_claim_interface(usb_device,
					  self->update_iface,
					  G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
					  error)) {
		g_prefix_error(error, "failed to claim update interface: ");
		return FALSE;
	}
	if (!g_usb_device_claim_interface(usb_device,
					  self->sync_iface,
					  G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
					  error)) {
		g_prefix_error(error, "failed to claim sync interface: ");
		return FALSE;
	}

	/* success */
	return TRUE;
}

static gboolean
fu_logitech_bulkcontroller_device_close(FuDevice *device, GError **error)
{
	FuLogitechBulkcontrollerDevice *self = FU_LOGITECH_BULKCONTROLLER_DEVICE(device);
	GUsbDevice *usb_device = fu_usb_device_get_dev(FU_USB_DEVICE(device));

	if (!g_usb_device_release_interface(usb_device,
					    self->update_iface,
					    G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
					    error)) {
		g_prefix_error(error, "failed to release update interface: ");
		return FALSE;
	}
	if (!g_usb_device_release_interface(usb_device,
					    self->sync_iface,
					    G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER,
					    error)) {
		g_prefix_error(error, "failed to release sync interface: ");
		return FALSE;
	}

	/* FuUsbDevice->close */
	return FU_DEVICE_CLASS(fu_logitech_bulkcontroller_device_parent_class)->open(device, error);
}

static gboolean
fu_logitech_bulkcontroller_device_setup(FuDevice *device, GError **error)
{
	FuLogitechBulkcontrollerDevice *self = FU_LOGITECH_BULKCONTROLLER_DEVICE(device);
	JsonArray *json_devices;
	JsonNode *json_root;
	JsonObject *json_device;
	JsonObject *json_object;
	JsonObject *json_payload;
	g_autoptr(JsonParser) json_parser = json_parser_new();
	g_autoptr(GByteArray) msg1 = NULL;
	g_autoptr(GByteArray) msg2 = g_byte_array_new();
	g_autoptr(GByteArray) msg3 = NULL;
	FuLogitechBulkcontrollerProtoId proto_id = kProtoId_UnknownId;

	/* FuUsbDevice->setup */
	if (!FU_DEVICE_CLASS(fu_logitech_bulkcontroller_device_parent_class)->setup(device, error))
		return FALSE;

	/* sending GetDeviceInfoRequest */
	msg1 = proto_manager_generate_get_device_info_request();
	if (!fu_logitech_bulkcontroller_device_send(self, msg1, BULK_INTERFACE_SYNC, error))
		return FALSE;

	/* wait for the response */
	g_usleep(G_USEC_PER_SEC);
	fu_byte_array_set_size(msg2, MAX_DATA_SIZE);
	if (!fu_logitech_bulkcontroller_device_recv(self, msg2, BULK_INTERFACE_SYNC, 5000, error))
		return FALSE;
	msg3 = proto_manager_decode_message(msg2->data, msg2->len, &proto_id, error);
	if (msg3 == NULL)
		return FALSE;
	if (proto_id != kProtoId_GetDeviceInfoResponse) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_INVALID_DATA,
			    "incorrect response (%u) expected, kProtoId_GetDeviceInfoResponse",
			    proto_id);
		return FALSE;
	}

	/* parse JSON reply */
	if (!json_parser_load_from_data(json_parser, (const gchar *)msg3->data, msg3->len, error)) {
		g_prefix_error(error, "error in parsing json data: ");
		return FALSE;
	}
	json_root = json_parser_get_root(json_parser);
	if (json_root == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "did not get JSON root");
		return FALSE;
	}
	json_object = json_node_get_object(json_root);
	json_payload = json_object_get_object_member(json_object, "payload");
	if (json_payload == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "did not get JSON payload");
		return FALSE;
	}
	json_devices = json_object_get_array_member(json_payload, "devices");
	if (json_devices == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "did not get JSON devices");
		return FALSE;
	}
	json_device = json_array_get_object_element(json_devices, 0);
	if (json_device == NULL) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_DATA,
				    "did not get JSON device");
		return FALSE;
	}
	if (json_object_has_member(json_device, "name"))
		fu_device_set_name(device, json_object_get_string_member(json_device, "name"));
	if (json_object_has_member(json_device, "sw"))
		fu_device_set_version(device, json_object_get_string_member(json_device, "sw"));
	if (json_object_has_member(json_device, "type"))
		fu_device_add_instance_id(device,
					  json_object_get_string_member(json_device, "type"));
	if (json_object_has_member(json_device, "status"))
		self->status = json_object_get_int_member(json_device, "status");
	if (json_object_has_member(json_device, "updateStatus"))
		self->update_status = json_object_get_int_member(json_device, "updateStatus");

	/* success */
	return TRUE;
}

static void
fu_logitech_bulkcontroller_device_init(FuLogitechBulkcontrollerDevice *self)
{
	fu_device_add_protocol(FU_DEVICE(self), "com.logitech.vc.proto");
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_TRIPLET);
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_register_private_flag(FU_DEVICE(self),
					FU_LOGITECH_BULKCONTROLLER_DEVICE_FLAG_IS_MINI,
					"is-mini");
}

static void
fu_logitech_bulkcontroller_device_class_init(FuLogitechBulkcontrollerDeviceClass *klass)
{
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);
	klass_device->to_string = fu_logitech_bulkcontroller_device_to_string;
	klass_device->write_firmware = fu_logitech_bulkcontroller_device_write_firmware;
	klass_device->probe = fu_logitech_bulkcontroller_device_probe;
	klass_device->setup = fu_logitech_bulkcontroller_device_setup;
	klass_device->open = fu_logitech_bulkcontroller_device_open;
	klass_device->close = fu_logitech_bulkcontroller_device_close;
}
