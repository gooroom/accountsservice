/*
 * Copyright (C) 2014 Canonical Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the licence, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Authors: Ryan Lortie <desrt@desrt.ca>
 */

#ifndef __WTMP_HELPER_H__
#define __WTMP_HELPER_H__

#include <glib.h>
#include <pwd.h>

const gchar *           wtmp_helper_get_path_for_monitor                (void);
struct passwd *         wtmp_helper_entry_generator                     (GHashTable *users,
                                                                         gpointer   *state);

#endif /* __WTMP_HELPER_H__ */
