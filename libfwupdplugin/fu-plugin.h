/*
 * Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>
#ifdef HAVE_GUSB
#include <gusb.h>
#endif

#include "fu-bluez-device.h"
#include "fu-common.h"
#include "fu-common-guid.h"
#include "fu-common-version.h"
#include "fu-context.h"
#include "fu-device.h"
#include "fu-device-locker.h"
#include "fu-usb-device.h"
//#include "fu-hid-device.h"
#ifdef HAVE_GUDEV
#include "fu-udev-device.h"
#endif
#include <libfwupd/fwupd-common.h>
#include <libfwupd/fwupd-plugin.h>

#define FU_TYPE_PLUGIN (fu_plugin_get_type ())
G_DECLARE_DERIVABLE_TYPE (FuPlugin, fu_plugin, FU, PLUGIN, FwupdPlugin)

#define fu_plugin_get_flags(p)			fwupd_plugin_get_flags(FWUPD_PLUGIN(p))
#define fu_plugin_has_flag(p,f)			fwupd_plugin_has_flag(FWUPD_PLUGIN(p),f)
#define fu_plugin_add_flag(p,f)			fwupd_plugin_add_flag(FWUPD_PLUGIN(p),f)
#define fu_plugin_remove_flag(p,f)		fwupd_plugin_remove_flag(FWUPD_PLUGIN(p),f)

struct _FuPluginClass
{
	FwupdPluginClass parent_class;
	/* signals */
	void		 (* device_added)		(FuPlugin	*self,
							 FuDevice	*device);
	void		 (* device_removed)		(FuPlugin	*self,
							 FuDevice	*device);
	void		 (* status_changed)		(FuPlugin	*self,
							 FwupdStatus	 status);
	void		 (* percentage_changed)		(FuPlugin	*self,
							 guint		 percentage);
	void		 (* device_register)		(FuPlugin	*self,
							 FuDevice	*device);
	gboolean	 (* check_supported)		(FuPlugin	*self,
							 const gchar	*guid);
	void		 (* rules_changed)		(FuPlugin	*self);
	void (*config_changed)(FuPlugin *self);
	/*< private >*/
	gpointer padding[19];
};

/**
 * FuPluginVerifyFlags:
 * @FU_PLUGIN_VERIFY_FLAG_NONE:		No flags set
 *
 * Flags used when verifying, currently unused.
 **/
typedef enum {
	FU_PLUGIN_VERIFY_FLAG_NONE		= 0,
	/*< private >*/
	FU_PLUGIN_VERIFY_FLAG_LAST
} FuPluginVerifyFlags;

/**
 * FuPluginRule:
 * @FU_PLUGIN_RULE_CONFLICTS:		The plugin conflicts with another
 * @FU_PLUGIN_RULE_RUN_AFTER:		Order the plugin after another
 * @FU_PLUGIN_RULE_RUN_BEFORE:		Order the plugin before another
 * @FU_PLUGIN_RULE_BETTER_THAN:		Is better than another plugin
 * @FU_PLUGIN_RULE_INHIBITS_IDLE:	The plugin inhibits the idle shutdown
 * @FU_PLUGIN_RULE_METADATA_SOURCE:	Uses another plugin as a source of report metadata
 *
 * The rules used for ordering plugins.
 * Plugins are expected to add rules in fu_plugin_initialize().
 **/
typedef enum {
	FU_PLUGIN_RULE_CONFLICTS,
	FU_PLUGIN_RULE_RUN_AFTER,
	FU_PLUGIN_RULE_RUN_BEFORE,
	FU_PLUGIN_RULE_BETTER_THAN,
	FU_PLUGIN_RULE_INHIBITS_IDLE,
	FU_PLUGIN_RULE_METADATA_SOURCE,		/* Since: 1.3.6 */
	/*< private >*/
	FU_PLUGIN_RULE_LAST
} FuPluginRule;

/**
 * FuPluginData:
 *
 * The plugin-allocated private data.
 **/
typedef struct	FuPluginData	FuPluginData;

/* for plugins to use */
const gchar	*fu_plugin_get_name			(FuPlugin	*self);
FuPluginData	*fu_plugin_get_data			(FuPlugin	*self);
FuPluginData	*fu_plugin_alloc_data			(FuPlugin	*self,
							 gsize		 data_sz);
FuContext	*fu_plugin_get_context			(FuPlugin	*self);
void		 fu_plugin_set_build_hash		(FuPlugin	*self,
							 const gchar	*build_hash);
void		 fu_plugin_device_add			(FuPlugin	*self,
							 FuDevice	*device);
void		 fu_plugin_device_remove		(FuPlugin	*self,
							 FuDevice	*device);
void		 fu_plugin_device_register		(FuPlugin	*self,
							 FuDevice	*device);
void		 fu_plugin_add_device_gtype		(FuPlugin	*self,
							 GType		 device_gtype);
void		 fu_plugin_add_firmware_gtype		(FuPlugin	*self,
							 const gchar	*id,
							 GType		 gtype);
void		 fu_plugin_add_udev_subsystem		(FuPlugin	*self,
							 const gchar	*subsystem);
gpointer	 fu_plugin_cache_lookup			(FuPlugin	*self,
							 const gchar	*id);
void		 fu_plugin_cache_remove			(FuPlugin	*self,
							 const gchar	*id);
void		 fu_plugin_cache_add			(FuPlugin	*self,
							 const gchar	*id,
							 gpointer	 dev);
GPtrArray	*fu_plugin_get_devices			(FuPlugin	*self);
void		 fu_plugin_add_rule			(FuPlugin	*self,
							 FuPluginRule	 rule,
							 const gchar	*name);
void		 fu_plugin_add_report_metadata		(FuPlugin	*self,
							 const gchar	*key,
							 const gchar	*value);
gchar		*fu_plugin_get_config_value		(FuPlugin	*self,
							 const gchar	*key);
gboolean	 fu_plugin_get_config_value_boolean	(FuPlugin	*self,
							 const gchar	*key);
gboolean	 fu_plugin_has_custom_flag		(FuPlugin	*self,
							 const gchar	*flag);
