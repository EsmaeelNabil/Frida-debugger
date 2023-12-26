@file:OptIn(ExperimentalFoundationApi::class)

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.ComposeWindow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import applications.applicationsArea
import applications.SearchApplications
import io.socket.client.Socket
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import models.Application
import models.ApplicationsResponse
import models.Device
import models.DevicesResponse
import scripts.NamesListModel
import scripts.ScriptScreen

enum class Pages(val index: Int) {
    APPS(0),
    SCRIPT(1)
}

@OptIn(ExperimentalFoundationApi::class)
@ExperimentalMaterial3Api
@Composable
fun App(window: ComposeWindow, socket: Socket) {

    MaterialTheme {

        val devices by onEventFlow(
            socket = socket,
            event = SocketEvents.DEVICES.name,
            evaluation = {
                DevicesResponse.getDevices(it.toString())
            }
        ).collectAsState(listOf())

        val applications by onEventFlow(
            socket = socket,
            event = SocketEvents.APPS.name,
            evaluation = {
                ApplicationsResponse.getApplications(it.toString())
            }
        ).collectAsState(listOf())

        val scripts by onEventFlow(
            socket = socket,
            event = SocketEvents.SCRIPTS.name,
            evaluation = {
                Json.decodeFromString<List<NamesListModel>>(it.toString())
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

        var selectedDevice by remember { mutableStateOf(Device()) }
        var selectedApp by remember { mutableStateOf(Application()) }
        val drawerState = rememberDrawerState(initialValue = DrawerValue.Open)
        val scope = rememberCoroutineScope()
        val pages = listOf(Pages.APPS, Pages.SCRIPT)

        val pagerState = rememberPagerState(pageCount = {
            pages.size
        })


        Surface(Modifier.fillMaxSize(), color = Color(0XFFF2F7FF)) {


            ModalNavigationDrawer(
                drawerState = drawerState,
                drawerContent = {
                    ModalDrawerSheet {
                        Text("Devices", modifier = Modifier.padding(16.dp), fontWeight = FontWeight.Black)

                        devices.forEach { device ->
                            NavigationDrawerItem(
                                label = {
                                    val weight =
                                        if (device.deviceDetails.type == "usb") FontWeight.Medium else FontWeight.Thin
                                    Text(text = device.deviceDetails.name, fontWeight = weight)
                                },
                                selected = selectedDevice.deviceDetails.name == device.deviceDetails.name,
                                onClick = {
                                    selectedDevice = device
                                    socket.emit(SocketEvents.GET_APPS.name, device.deviceDetails.id)
                                    scope.launch {
                                        drawerState.close()
                                    }
                                }
                            )
                            Divider()
                        }
                    }
                }
            ) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    // padding of the scaffold is enforced to be used
                    Column {


                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {

                            IconButton(onClick = {
                                scope.launch {
                                    if (drawerState.isOpen)
                                        drawerState.close()
                                    else drawerState.open()
                                }
                            }) {
                                Icon(
                                    Icons.Filled.Menu,
                                    null,
                                    modifier = Modifier.size(24.dp)
                                )
                            }

                            if (pagerState.currentPage == Pages.APPS.index) {
                                SearchApplications(
                                    modifier = Modifier.weight(1f),
                                    onSearch = {
                                        socket.emit(SocketEvents.GET_APPS.name, selectedDevice.deviceDetails.id, it)
                                    }
                                )
                                IconButton(onClick = {
                                    socket.emit(SocketEvents.GET_APPS.name, selectedDevice.deviceDetails.id)
                                }) {
                                    Icon(
                                        Icons.Filled.Refresh,
                                        null,
                                        modifier = Modifier.size(24.dp)
                                    )
                                }
                            }

                        }


                        HorizontalPager(
                            userScrollEnabled = false,
                            state = pagerState
                        ) { page ->
                            when (page) {
                                Pages.APPS.index -> {
                                    ApplicationsComponent(
                                        partitionedApplications.value,
                                        selectedDevice,
                                        socket,
                                        onAppSelected = {
                                            selectedApp = it
                                            scope.launch {
                                                pagerState.animateScrollToPage(1)
                                            }
                                        }
                                    )
                                }

                                Pages.SCRIPT.index -> {
                                    ScriptScreen(socket, selectedDevice, selectedApp,
                                        onBack = {
                                            socket.emit(SocketEvents.UNLOAD_SCRIPTS.name)
                                            socket.emit(SocketEvents.GET_APPS.name, selectedDevice.deviceDetails.id)
                                            scope.launch {
                                                pagerState.animateScrollToPage(Pages.APPS.index)
                                            }
                                        })
                                }

                                else -> {
                                    Text(modifier = Modifier.fillMaxSize(), text = "others")
                                }
                            }
                        }

                    }
                }
            }

        }
        /*Column(
            Modifier.fillMaxSize().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Row {
                var scriptsPath by remember { mutableStateOf("") }
                TextField(value = scriptsPath, onValueChange = { scriptsPath = it })
                IconButton(
                    onClick = {
                        socket.emit(SocketEvents.SCRIPTS_PATH.name, scriptsPath)
                    }
                ) {
                    Icon(Icons.Filled.Add, null)
                }
                IconButton(
                    onClick = {
                        socket.emit(SocketEvents.GET_SCRIPTS.name, scriptsPath)
                    }
                ) {
                    Icon(Icons.Filled.KeyboardArrowDown, null)
                }
            }
            Row {
                LazyColumn {
                    items(scripts) { script ->
                        Text(script.scriptName)
                    }
                }
            }


        }*/
    }
}


@Composable
fun ApplicationsComponent(
    partitionedApplications: Pair<List<Application>, List<Application>>,
    selectedDevice: Device,
    socket: Socket,
    onAppSelected: (Application) -> Unit
) {
    Column {
        AnimatedVisibility(
            partitionedApplications.first.isNotEmpty() || partitionedApplications.second.isNotEmpty()
        ) {
            applicationsArea(
                offlineApps = partitionedApplications.first,
                activeApps = partitionedApplications.second,
            ) { selectedApp ->
                onAppSelected(selectedApp)
                // TODO: Enhance this to have an option or show it in a better way
                if (selectedApp.pid == 0)
                    socket.emit(
                        SocketEvents.RUN_APP.name,
                        listOf(
                            selectedDevice.deviceDetails.id,
                            selectedApp.identifier
                        )
                    )
                else
                    socket.emit(
                        SocketEvents.ATTACH.name,
                        listOf(
                            selectedDevice.deviceDetails.id,
                            selectedApp.name,
                            defaultScript
                        )
                    )

                socket.emit(SocketEvents.GET_APPS.name, selectedDevice.deviceDetails.id)

            }
        }
    }
}

val defaultScript = "send(\"hi from frida\");"