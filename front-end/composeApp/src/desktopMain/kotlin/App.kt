@file:OptIn(ExperimentalMaterialApi::class, ExperimentalFoundationApi::class)

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.ComposeWindow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import applications.ApplicationsArea
import devices.DevicesArea
import io.socket.client.Socket
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import models.ApplicationsResponse
import models.Device
import models.DevicesResponse
import scripts.NamesListModel


@Composable
fun App(window: ComposeWindow, socket: Socket) {


    MaterialTheme {

        val devicesStream by onEventFlow(
            socket = socket,
            event = SocketEvents.DEVICES.name,
            evaluation = {
                DevicesResponse.getDevices(it.toString())
            }
        ).collectAsState(listOf())

        var onlyUsb by remember { mutableStateOf(false) }
        val devices by remember {
            derivedStateOf {
                if (onlyUsb)
                    devicesStream.filter { it.deviceDetails?.type == "usb" }
                else devicesStream
            }
        }

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


        Surface(Modifier.fillMaxSize(), color = Color(0XFFF2F7FF)) {

            Column(
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




                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Devices")
                    IconButton(
                        onClick = {
                            socket.emit(SocketEvents.GET_DEVICES.name)
                        }
                    ) {
                        Icon(Icons.Filled.Refresh, null)
                    }

                    Row {
                        Text("Only USB ")
                        Checkbox(checked = onlyUsb, onCheckedChange = { onlyUsb = it })
                    }
                }

                var selectedDevice by remember { mutableStateOf(Device()) }

                AnimatedVisibility(devices.isNotEmpty()) {
                    DevicesArea(
                        devices = devices,
                        selectedDevice = selectedDevice,
                        onDeviceSelected = {
                            selectedDevice = it
                        },
                        onFetchApps = {
                            socket.emit(SocketEvents.GET_APPS.name, it.deviceDetails.id)
                        }
                    )
                }

                AnimatedVisibility(
                    partitionedApplications.value.first.isNotEmpty() || partitionedApplications.value.second.isNotEmpty()
                ) {
                    ApplicationsArea(
                        offlineApps = partitionedApplications.value.first,
                        activeApps = partitionedApplications.value.second,
                    ) { selectedApp ->
                        // TODO: Enhance this to have an option or show it in a better way
                        if (selectedApp.pid == 0)
                            socket.emit(
                                SocketEvents.LAUNCH.name,
                                listOf(
                                    selectedDevice.deviceDetails.id,
                                    selectedApp.identifier,
                                    "app_info",
                                    "send(`SPAWN - LAUNCHED app ${selectedApp.name}`)"
                                )
                            )
                        else
                            socket.emit(
                                SocketEvents.ATTACH.name,
                                listOf(
                                    selectedDevice.deviceDetails.id,
                                    selectedApp.name,
                                    "app_info",
                                    "send(`ATTACHED - to app ${selectedApp.name}`)"
                                )
                            )
                    }
                }

            }
        }
    }
}