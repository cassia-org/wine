/*
 * cassia driver initialisation functions
 *
 * Copyright 1996, 2013, 2017 Alexandre Julliard
 * Copyright 2023 Billy Laws
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "cassia.h"
#include "wine/server.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(cassia);

// TODO not this
unsigned int screen_width = 1920;
unsigned int screen_height = 1080;
RECT virtual_screen_rect = { 0, 0, 1920, 1080 };

static const unsigned int screen_bpp = 32;  /* we don't support other modes */


static RECT monitor_rc_work;
static BOOL force_display_devices_refresh;

typedef struct
{
    struct gdi_physdev dev;
} CASSIA_PDEVICE;

static const struct user_driver_funcs cassia_drv_funcs;

static void cassia_resize_desktop(void)
{
    RECT virtual_rect = NtUserGetVirtualScreenRect();
    NtUserSetWindowPos(NtUserGetDesktopWindow(), 0,
                       virtual_rect.left, virtual_rect.top,
                       virtual_rect.right - virtual_rect.left,
                       virtual_rect.bottom - virtual_rect.top,
                       SWP_NOZORDER | SWP_NOACTIVATE | SWP_DEFERERASE);
}


/******************************************************************************
 *           create_cassia_physdev
 */
static CASSIA_PDEVICE *create_cassia_physdev(void)
{
    CASSIA_PDEVICE *physdev;

    if (!(physdev = calloc( 1, sizeof(*physdev) ))) return NULL;
    return physdev;
}


/**********************************************************************
 *           CASSIA_CreateDC
 */
static BOOL CASSIA_CreateDC( PHYSDEV *pdev, LPCWSTR device, LPCWSTR output, const DEVMODEW *initData )
{
    CASSIA_PDEVICE *physdev = create_cassia_physdev();

    if (!physdev) return FALSE;

    push_dc_driver( pdev, &physdev->dev, &cassia_drv_funcs.dc_funcs );
    return TRUE;
}


/**********************************************************************
 *           CASSIA_CreateCompatibleDC
 */
static BOOL CASSIA_CreateCompatibleDC( PHYSDEV orig, PHYSDEV *pdev )
{
    CASSIA_PDEVICE *physdev = create_cassia_physdev();

    if (!physdev) return FALSE;

    push_dc_driver( pdev, &physdev->dev, &cassia_drv_funcs.dc_funcs );
    return TRUE;
}


/**********************************************************************
 *           CASSIA_DeleteDC
 */
static BOOL CASSIA_DeleteDC( PHYSDEV dev )
{
    free( dev );
    return TRUE;
}

/**********************************************************************
 *           WAYLAND_DesktopWindowProc
 */
LRESULT CASSIA_DesktopWindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_DISPLAYCHANGE:
        cassia_resize_desktop();
        break;
    }

    return NtUserMessageCall(hwnd, msg, wp, lp, 0, NtUserDefWindowProc, FALSE);
}



/***********************************************************************
 *           CASSIA_ChangeDisplaySettings
 */
LONG CASSIA_ChangeDisplaySettings( LPDEVMODEW displays, LPCWSTR primary_name, HWND hwnd, DWORD flags, LPVOID lpvoid )
{
    FIXME( "(%p,%s,%p,0x%08x,%p)\n", displays, debugstr_w(primary_name), hwnd, (int)flags, lpvoid );
    return DISP_CHANGE_SUCCESSFUL;
}


/***********************************************************************
 *           CASSIA_UpdateDisplayDevices
 */
BOOL CASSIA_UpdateDisplayDevices( const struct gdi_device_manager *device_manager, BOOL force, void *param )
{
    if (force || force_display_devices_refresh)
    {
        static const struct gdi_gpu gpu;
        static const struct gdi_adapter adapter =
        {
            .state_flags = DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE | DISPLAY_DEVICE_VGA_COMPATIBLE,
        };
        struct gdi_monitor gdi_monitor =
        {
            .rc_monitor = virtual_screen_rect,
            .rc_work = monitor_rc_work,
            .state_flags = DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_ATTACHED,
        };
        const DEVMODEW mode =
        {
            .dmFields = DM_DISPLAYORIENTATION | DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL |
                        DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY | DM_POSITION,
            .dmBitsPerPel = screen_bpp, .dmPelsWidth = screen_width, .dmPelsHeight = screen_height, .dmDisplayFrequency = 60,
        };
        device_manager->add_gpu( &gpu, param );
        device_manager->add_adapter( &adapter, param );
        device_manager->add_monitor( &gdi_monitor, param );
        device_manager->add_mode( &mode, TRUE, param );
        force_display_devices_refresh = FALSE;
    }

    return TRUE;
}


/***********************************************************************
 *           CASSIA_GetCurrentDisplaySettings
 */
BOOL CASSIA_GetCurrentDisplaySettings( LPCWSTR name, BOOL is_primary, LPDEVMODEW devmode )
{
    devmode->dmDisplayFlags = 0;
    devmode->dmPosition.x = 0;
    devmode->dmPosition.y = 0;
    devmode->dmDisplayOrientation = 0;
    devmode->dmDisplayFixedOutput = 0;
    devmode->dmPelsWidth = screen_width;
    devmode->dmPelsHeight = screen_height;
    devmode->dmBitsPerPel = screen_bpp;
    devmode->dmDisplayFrequency = 60;
    devmode->dmFields = DM_POSITION | DM_DISPLAYORIENTATION | DM_PELSWIDTH | DM_PELSHEIGHT |
                        DM_BITSPERPEL | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY;
    TRACE( "current mode -- %dx%d %d bpp @%d Hz\n",
           (int)devmode->dmPelsWidth, (int)devmode->dmPelsHeight,
           (int)devmode->dmBitsPerPel, (int)devmode->dmDisplayFrequency );
    return TRUE;
}

/**********************************************************************
 *           CASSIA_WindowMessage
 */
LRESULT CASSIA_WindowMessage(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    default:
        FIXME("got window msg %x hwnd %p wp %lx lp %lx\n", msg, hwnd, (long)wp, lp);
        return 0;
    }
}

/**********************************************************************
 *           CASSIA_wine_get_vulkan_driver
 */
static const struct vulkan_funcs *CASSIA_wine_get_vulkan_driver( UINT version )
{
    return get_vulkan_driver( version );
}

static const struct user_driver_funcs cassia_drv_funcs =
{
    .dc_funcs.pCreateCompatibleDC = CASSIA_CreateCompatibleDC,
    .dc_funcs.pCreateDC = CASSIA_CreateDC,
    .dc_funcs.pDeleteDC = CASSIA_DeleteDC,
    .dc_funcs.priority = GDI_PRIORITY_GRAPHICS_DRV,

    .pGetKeyNameText = NULL,
    .pMapVirtualKeyEx = NULL,
    .pVkKeyScanEx = NULL,
    .pSetCursor = NULL,
    .pChangeDisplaySettings = CASSIA_ChangeDisplaySettings,
    .pGetCurrentDisplaySettings = CASSIA_GetCurrentDisplaySettings,
    .pUpdateDisplayDevices = CASSIA_UpdateDisplayDevices,
    .pCreateDesktop = NULL,
    .pCreateWindow = NULL,
    .pDesktopWindowProc = CASSIA_DesktopWindowProc,
    .pDestroyWindow = NULL,
    .pProcessEvents = NULL,
    .pSetCapture = NULL,
    .pSetLayeredWindowAttributes = NULL,
    .pSetParent = NULL,
    .pSetWindowRgn = NULL,
    .pSetWindowStyle = NULL,
    .pShowWindow = NULL,
    .pUpdateLayeredWindow = NULL,
    .pWindowMessage = CASSIA_WindowMessage,
    .pWindowPosChanging = NULL,
    .pWindowPosChanged = NULL,
    .pwine_get_wgl_driver = NULL,
    .pwine_get_vulkan_driver = CASSIA_wine_get_vulkan_driver,

};

static HRESULT cassia_init( void *arg )
{
    struct init_params *params = arg;

    __wine_set_user_driver( &cassia_drv_funcs, WINE_GDI_DRIVER_VERSION );
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    cassia_init,
};


C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count );

#ifdef _WIN64

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    cassia_init,
};

#endif  /* _WIN64 */
