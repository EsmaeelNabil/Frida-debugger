@file:OptIn(ExperimentalFoundationApi::class)

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.FrameWindowScope
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.rememberWindowState
import components.DrawerComponent
import components.PagerArea
import components.TopBar
import io.socket.client.Socket
import kotlinx.coroutines.delay
import models.Application
import models.ApplicationsResponse
import models.Device
import models.DevicesResponse
import network.SocketEvents
import network.SocketManager
import theme.AppTheme


/**
 * This file contains the main application components for the Frida Debugger.
 * It includes the main application window, the application layout, and the application content wrapper.
 */

/**
 * This is a composition local that provides the current socket connection.
 */
val LocalSocket = staticCompositionLocalOf<Socket> {
    error("No socket provided")
}

/**
 * This is a composition local that provides the current window frame scope.
 */
val LocalWindowFrameScope = staticCompositionLocalOf<FrameWindowScope> {
    error("No socket provided")
}

/**
 * This is the main application component. It sets up the socket connection and the window for the application.
 * @param onCloseRequest A function to be called when the window close request is triggered.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FridaApp(onCloseRequest: () -> Unit = {}) {
    val socket = SocketManager.getClient().connect()

    CompositionLocalProvider(LocalSocket provides socket) {
        val windowState = rememberWindowState()
        Window(
            state = windowState,
            onCloseRequest = onCloseRequest,
            transparent = true,
            undecorated = true,
            title = "Frida Debugger"
        ) {
            AppTheme {
                WindowDraggableArea {
                    CompositionLocalProvider(LocalWindowFrameScope provides this) {
                        App(
                            onMainApplicationClose = onCloseRequest,
                            onMainApplicationMinimize = {
                                windowState.isMinimized = true
                            }
                        )
                    }
                }
            }
        }
    }
}

/**
 * This is the main application layout. It sets up the socket connection, fetches devices and applications, and sets up the main layout.
 * @param onMainApplicationClose A function to be called when the main application close request is triggered.
 * @param onMainApplicationMinimize A function to be called when the main application minimize request is triggered.
 */
@OptIn(ExperimentalFoundationApi::class)
@ExperimentalMaterial3Api
@Composable
fun App(
    onMainApplicationClose: () -> Unit = {},
    onMainApplicationMinimize: () -> Unit = {},
) {

    val socket = LocalSocket.current
    var selectedDevice by remember { mutableStateOf(Device()) }

    // fetch devices on each change to the selection
    LaunchedEffect(selectedDevice) {
        if (selectedDevice.deviceDetails.id.isNotEmpty()) {
            socket.emit(SocketEvents.GET_APPS.name, selectedDevice.deviceDetails.id)
        }
    }

    var selectedApp by remember { mutableStateOf(Application()) }

    val devices by SocketEvents.DEVICES.onEventFlow(
        socket = socket,
        evaluation = {
            val devices = DevicesResponse.getDevices(it.toString())
            selectedDevice = devices.lastOrNull() ?: Device()
            devices
        }
    ).collectAsState(listOf())

    val applications by SocketEvents.APPS.onEventFlow(
        socket = socket,
        evaluation = {
            ApplicationsResponse.getApplications(it.toString())
        }
    ).collectAsState(listOf())

    LaunchedEffect(Unit) {
        delay(500)
        socket.emit(SocketEvents.GET_DEVICES.name)
    }

    val partitionedApplications by remember {
        derivedStateOf {
            mutableStateOf(applications.partition { it.pid == 0 })
        }
    }

    val pages = listOf(Pages.APPS, Pages.SCRIPT)
    val pagerState = rememberPagerState(pageCount = { pages.size })

    Box(
        modifier = Modifier.fillMaxSize()
    ) {

        AppHomeContentWrapper(
            modifier = Modifier.padding(top = 85.dp),
            pagerState = pagerState,
            partitionedApplications = partitionedApplications,
            selectedDevice = selectedDevice,
            socket = socket,
            selectedApp = selectedApp
        ) {
            selectedApp = it
        }


        DrawerComponent(
            modifier = Modifier.align(Alignment.TopCenter)
                .fillMaxWidth()
                .padding(horizontal = 36.dp),
            devices = devices,
            selectedDevice = selectedDevice,
            onMainApplicationClose = onMainApplicationClose,
            onMainApplicationMinimize = onMainApplicationMinimize,
        ) {
            selectedDevice = it
        }


    }

}

/**
 * This is the main application content wrapper. It sets up the surface for the application content and includes the top bar and pager area.
 * @param modifier The modifier to be applied to the surface.
 * @param pagerState The state of the pager.
 * @param partitionedApplications The applications partitioned by whether they are running or not.
 * @param selectedDevice The currently selected device.
 * @param socket The current socket connection.
 * @param selectedApp The currently selected application.
 * @param onAppSelected A function to be called when an application is selected.
 */
@Composable
fun AppHomeContentWrapper(
    modifier: Modifier,
    pagerState: PagerState,
    partitionedApplications: MutableState<Pair<List<Application>, List<Application>>>,
    selectedDevice: Device = Device(),
    socket: Socket = LocalSocket.current,
    selectedApp: Application = Application(),
    onAppSelected: (Application) -> Unit = {}
) {
    Surface(
        modifier = modifier.fillMaxSize(),
        shape = MaterialTheme.shapes.extraLarge,
        color = Color.LightGray.copy(alpha = 0.8f)
    ) {

        Column {

            TopBar(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, top = 16.dp)
                    .clip(RoundedCornerShape(36.dp))
                    .setHorizontalGradient(),
                pagerState = pagerState,
                selectedDevice = selectedDevice
            )

            PagerArea(
                pagerState = pagerState,
                partitionedApplications = partitionedApplications,
                selectedDevice = selectedDevice,
                socket = socket,
                selectedApp = selectedApp
            ) {
                onAppSelected(it)
            }


        }
    }
}

