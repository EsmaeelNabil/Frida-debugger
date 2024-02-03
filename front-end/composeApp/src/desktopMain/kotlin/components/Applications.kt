package components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import defaultScript
import io.socket.client.Socket
import models.Application
import models.Device
import network.SocketEvents


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


@Composable
fun applicationsArea(
    offlineApps: List<Application>,
    activeApps: List<Application>,
    onApplicationClicked: (Application) -> Unit
) {

    LazyColumn(modifier = Modifier.padding(24.dp).fillMaxWidth()) {
        if (activeApps.isNotEmpty()) {
            item {
                Text(
                    "Active Apps",
                    modifier = Modifier.padding(horizontal = 16.dp),
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            items(activeApps) { app ->
                ApplicationItem(app) {
                    onApplicationClicked(app)
                }
            }
        }

        if (offlineApps.isNotEmpty()) {
            item {
                Text(
                    "Offline Apps",
                    modifier = Modifier.padding(horizontal = 16.dp),
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            items(offlineApps) { app ->
                ApplicationItem(app) {
                    onApplicationClicked(app)
                }
            }
        }


    }

}

@Composable
fun ApplicationItem(app: Application = Application(), onClick: () -> Unit = {}) {
    val appIsRunning = app.pid.toString() != "0"
    var showMore by remember { mutableStateOf(false) }
    Column {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.Start,
            verticalAlignment = Alignment.CenterVertically
        ) {

            Surface(
                modifier = Modifier.weight(0.025f).size(20.dp).fillMaxHeight(),
                shape = CircleShape,
                elevation = 3.dp,
                color = if (appIsRunning.not()) Color.Red else Color.Green
            ) {}


            Surface(
                modifier = Modifier.fillMaxWidth().padding(16.dp).weight(1f)
                        then (Modifier.clickable { onClick() }),
                shape = RoundedCornerShape(8.dp),
                elevation = 3.dp,
                color = Color.White
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(start = 16.dp)
                ) {
                    Column(modifier = Modifier.weight(1f).padding(8.dp)) {
                        Text(app.name, fontWeight = FontWeight.Bold)
                        Text(app.identifier, fontWeight = FontWeight.Light, fontSize = 14.sp)
                        Text(app.pid.toString(), fontWeight = FontWeight.Light)
                    }

                    IconButton(onClick = {
                        showMore = !showMore
                    }) {
                        Icon(
                            Icons.Filled.ExpandMore, null,
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                }
            }
        }
        AnimatedVisibility(showMore) {
            Column(modifier = Modifier.padding(horizontal = 24.dp)) {
                ApplicationTreat("Build number : ${app.parameters.build}")
                ApplicationTreat("Version number : ${app.parameters.version}")
                ApplicationTreat("dataDir : ${app.parameters.dataDir}")
                ApplicationTreat("started : ${app.parameters.started}")
                ApplicationTreat("targetSdk : ${app.parameters.targetSdk}")
                ApplicationTreat("debuggable : ${app.parameters.debuggable}")

            }
        }
    }
}

@Composable
private fun ApplicationTreat(treat: String) {
    Text(
        treat,
        fontWeight = FontWeight.Thin,
        color = MaterialTheme.colorScheme.onSurface
    )
}
