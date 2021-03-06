/*
 * Generated by gdbus-codegen 2.51.5. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __CK_MANAGER_GENERATED_H__
#define __CK_MANAGER_GENERATED_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for org.freedesktop.ConsoleKit.Manager */

#define CONSOLE_KIT_TYPE_MANAGER (console_kit_manager_get_type ())
#define CONSOLE_KIT_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CONSOLE_KIT_TYPE_MANAGER, ConsoleKitManager))
#define CONSOLE_KIT_IS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CONSOLE_KIT_TYPE_MANAGER))
#define CONSOLE_KIT_MANAGER_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), CONSOLE_KIT_TYPE_MANAGER, ConsoleKitManagerIface))

struct _ConsoleKitManager;
typedef struct _ConsoleKitManager ConsoleKitManager;
typedef struct _ConsoleKitManagerIface ConsoleKitManagerIface;

struct _ConsoleKitManagerIface
{
  GTypeInterface parent_iface;


  gboolean (*handle_can_restart) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_can_stop) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_close_session) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_cookie);

  gboolean (*handle_get_current_session) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_get_seats) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_get_session_for_cookie) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *arg_cookie);

  gboolean (*handle_get_session_for_unix_process) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    guint arg_pid);

  gboolean (*handle_get_sessions) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_get_sessions_for_unix_user) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    guint arg_uid);

  gboolean (*handle_get_sessions_for_user) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    guint arg_uid);

  gboolean (*handle_get_system_idle_hint) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_get_system_idle_since_hint) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_open_session) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_open_session_with_parameters) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    GVariant *arg_parameters);

  gboolean (*handle_restart) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  gboolean (*handle_stop) (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

  void (*seat_added) (
    ConsoleKitManager *object,
    const gchar *arg_sid);

  void (*seat_removed) (
    ConsoleKitManager *object,
    const gchar *arg_sid);

  void (*system_idle_hint_changed) (
    ConsoleKitManager *object,
    gboolean arg_hint);

};

GType console_kit_manager_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *console_kit_manager_interface_info (void);
guint console_kit_manager_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void console_kit_manager_complete_restart (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

void console_kit_manager_complete_can_restart (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    gboolean can_restart);

void console_kit_manager_complete_stop (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation);

void console_kit_manager_complete_can_stop (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    gboolean can_stop);

void console_kit_manager_complete_open_session (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *cookie);

void console_kit_manager_complete_open_session_with_parameters (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *cookie);

void console_kit_manager_complete_close_session (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    gboolean result);

void console_kit_manager_complete_get_seats (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *seats);

void console_kit_manager_complete_get_sessions (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *sessions);

void console_kit_manager_complete_get_session_for_cookie (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *ssid);

void console_kit_manager_complete_get_session_for_unix_process (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *ssid);

void console_kit_manager_complete_get_current_session (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *ssid);

void console_kit_manager_complete_get_sessions_for_unix_user (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *sessions);

void console_kit_manager_complete_get_sessions_for_user (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *const *sessions);

void console_kit_manager_complete_get_system_idle_hint (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    gboolean idle_hint);

void console_kit_manager_complete_get_system_idle_since_hint (
    ConsoleKitManager *object,
    GDBusMethodInvocation *invocation,
    const gchar *iso8601_datetime);



/* D-Bus signal emissions functions: */
void console_kit_manager_emit_seat_added (
    ConsoleKitManager *object,
    const gchar *arg_sid);

void console_kit_manager_emit_seat_removed (
    ConsoleKitManager *object,
    const gchar *arg_sid);

void console_kit_manager_emit_system_idle_hint_changed (
    ConsoleKitManager *object,
    gboolean arg_hint);



/* D-Bus method calls: */
void console_kit_manager_call_restart (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_restart_finish (
    ConsoleKitManager *proxy,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_restart_sync (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_can_restart (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_can_restart_finish (
    ConsoleKitManager *proxy,
    gboolean *out_can_restart,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_can_restart_sync (
    ConsoleKitManager *proxy,
    gboolean *out_can_restart,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_stop (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_stop_finish (
    ConsoleKitManager *proxy,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_stop_sync (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_can_stop (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_can_stop_finish (
    ConsoleKitManager *proxy,
    gboolean *out_can_stop,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_can_stop_sync (
    ConsoleKitManager *proxy,
    gboolean *out_can_stop,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_open_session (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_open_session_finish (
    ConsoleKitManager *proxy,
    gchar **out_cookie,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_open_session_sync (
    ConsoleKitManager *proxy,
    gchar **out_cookie,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_open_session_with_parameters (
    ConsoleKitManager *proxy,
    GVariant *arg_parameters,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_open_session_with_parameters_finish (
    ConsoleKitManager *proxy,
    gchar **out_cookie,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_open_session_with_parameters_sync (
    ConsoleKitManager *proxy,
    GVariant *arg_parameters,
    gchar **out_cookie,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_close_session (
    ConsoleKitManager *proxy,
    const gchar *arg_cookie,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_close_session_finish (
    ConsoleKitManager *proxy,
    gboolean *out_result,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_close_session_sync (
    ConsoleKitManager *proxy,
    const gchar *arg_cookie,
    gboolean *out_result,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_seats (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_seats_finish (
    ConsoleKitManager *proxy,
    gchar ***out_seats,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_seats_sync (
    ConsoleKitManager *proxy,
    gchar ***out_seats,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_sessions (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_sessions_finish (
    ConsoleKitManager *proxy,
    gchar ***out_sessions,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_sessions_sync (
    ConsoleKitManager *proxy,
    gchar ***out_sessions,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_session_for_cookie (
    ConsoleKitManager *proxy,
    const gchar *arg_cookie,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_session_for_cookie_finish (
    ConsoleKitManager *proxy,
    gchar **out_ssid,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_session_for_cookie_sync (
    ConsoleKitManager *proxy,
    const gchar *arg_cookie,
    gchar **out_ssid,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_session_for_unix_process (
    ConsoleKitManager *proxy,
    guint arg_pid,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_session_for_unix_process_finish (
    ConsoleKitManager *proxy,
    gchar **out_ssid,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_session_for_unix_process_sync (
    ConsoleKitManager *proxy,
    guint arg_pid,
    gchar **out_ssid,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_current_session (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_current_session_finish (
    ConsoleKitManager *proxy,
    gchar **out_ssid,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_current_session_sync (
    ConsoleKitManager *proxy,
    gchar **out_ssid,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_sessions_for_unix_user (
    ConsoleKitManager *proxy,
    guint arg_uid,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_sessions_for_unix_user_finish (
    ConsoleKitManager *proxy,
    gchar ***out_sessions,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_sessions_for_unix_user_sync (
    ConsoleKitManager *proxy,
    guint arg_uid,
    gchar ***out_sessions,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_sessions_for_user (
    ConsoleKitManager *proxy,
    guint arg_uid,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_sessions_for_user_finish (
    ConsoleKitManager *proxy,
    gchar ***out_sessions,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_sessions_for_user_sync (
    ConsoleKitManager *proxy,
    guint arg_uid,
    gchar ***out_sessions,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_system_idle_hint (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_system_idle_hint_finish (
    ConsoleKitManager *proxy,
    gboolean *out_idle_hint,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_system_idle_hint_sync (
    ConsoleKitManager *proxy,
    gboolean *out_idle_hint,
    GCancellable *cancellable,
    GError **error);

void console_kit_manager_call_get_system_idle_since_hint (
    ConsoleKitManager *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean console_kit_manager_call_get_system_idle_since_hint_finish (
    ConsoleKitManager *proxy,
    gchar **out_iso8601_datetime,
    GAsyncResult *res,
    GError **error);

gboolean console_kit_manager_call_get_system_idle_since_hint_sync (
    ConsoleKitManager *proxy,
    gchar **out_iso8601_datetime,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define CONSOLE_KIT_TYPE_MANAGER_PROXY (console_kit_manager_proxy_get_type ())
#define CONSOLE_KIT_MANAGER_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CONSOLE_KIT_TYPE_MANAGER_PROXY, ConsoleKitManagerProxy))
#define CONSOLE_KIT_MANAGER_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CONSOLE_KIT_TYPE_MANAGER_PROXY, ConsoleKitManagerProxyClass))
#define CONSOLE_KIT_MANAGER_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CONSOLE_KIT_TYPE_MANAGER_PROXY, ConsoleKitManagerProxyClass))
#define CONSOLE_KIT_IS_MANAGER_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CONSOLE_KIT_TYPE_MANAGER_PROXY))
#define CONSOLE_KIT_IS_MANAGER_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CONSOLE_KIT_TYPE_MANAGER_PROXY))

typedef struct _ConsoleKitManagerProxy ConsoleKitManagerProxy;
typedef struct _ConsoleKitManagerProxyClass ConsoleKitManagerProxyClass;
typedef struct _ConsoleKitManagerProxyPrivate ConsoleKitManagerProxyPrivate;

struct _ConsoleKitManagerProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  ConsoleKitManagerProxyPrivate *priv;
};

struct _ConsoleKitManagerProxyClass
{
  GDBusProxyClass parent_class;
};

GType console_kit_manager_proxy_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ConsoleKitManagerProxy, g_object_unref)
#endif

void console_kit_manager_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
ConsoleKitManager *console_kit_manager_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
ConsoleKitManager *console_kit_manager_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void console_kit_manager_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
ConsoleKitManager *console_kit_manager_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
ConsoleKitManager *console_kit_manager_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define CONSOLE_KIT_TYPE_MANAGER_SKELETON (console_kit_manager_skeleton_get_type ())
#define CONSOLE_KIT_MANAGER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), CONSOLE_KIT_TYPE_MANAGER_SKELETON, ConsoleKitManagerSkeleton))
#define CONSOLE_KIT_MANAGER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), CONSOLE_KIT_TYPE_MANAGER_SKELETON, ConsoleKitManagerSkeletonClass))
#define CONSOLE_KIT_MANAGER_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), CONSOLE_KIT_TYPE_MANAGER_SKELETON, ConsoleKitManagerSkeletonClass))
#define CONSOLE_KIT_IS_MANAGER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), CONSOLE_KIT_TYPE_MANAGER_SKELETON))
#define CONSOLE_KIT_IS_MANAGER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), CONSOLE_KIT_TYPE_MANAGER_SKELETON))

typedef struct _ConsoleKitManagerSkeleton ConsoleKitManagerSkeleton;
typedef struct _ConsoleKitManagerSkeletonClass ConsoleKitManagerSkeletonClass;
typedef struct _ConsoleKitManagerSkeletonPrivate ConsoleKitManagerSkeletonPrivate;

struct _ConsoleKitManagerSkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  ConsoleKitManagerSkeletonPrivate *priv;
};

struct _ConsoleKitManagerSkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType console_kit_manager_skeleton_get_type (void) G_GNUC_CONST;

#if GLIB_CHECK_VERSION(2, 44, 0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ConsoleKitManagerSkeleton, g_object_unref)
#endif

ConsoleKitManager *console_kit_manager_skeleton_new (void);


G_END_DECLS

#endif /* __CK_MANAGER_GENERATED_H__ */
