@file:OptIn(ExperimentalFoundationApi::class, ExperimentalFoundationApi::class, ExperimentalMaterialApi::class)

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
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

@OptIn(ExperimentalFoundationApi::class)
@ExperimentalMaterial3Api
@Composable
fun App(
    onMainApplicationClose: () -> Unit = {},
    onMainApplicationMinimize: () -> Unit = {},
) {

    val socket = LocalSocket.current


    val devices by SocketEvents.DEVICES.onEventFlow(
        socket = socket,
        evaluation = {
            DevicesResponse.getDevices(it.toString())
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

    var selectedDevice by remember { mutableStateOf(Device()) }
    var selectedApp by remember { mutableStateOf(Application()) }

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

